"""
Zero-token Portfolio Gazette Blast-Radius Engine (`scan_portfolio_blast_radius` & Async Jobs).

Evaluates synchronous batches of up to 50 contracts OR asynchronous bounded-concurrency
enterprise jobs of 500–2,000+ contracts (including `.zip` archives of `.docx`/`.pdf`/`.txt`)
across bi-temporal statutory/P.U. gazette windows (`from_date` -> `to_date`), ranking
exposure by severity, newly broken clauses, strictest territorial deontic bounds, and
PII-safe delta remediation summaries.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import sqlite3
import threading
import uuid
import zipfile
from collections.abc import Callable, Collection
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

import httpx

from lexgraph_lah.compliance.clause_cache import (
    ClauseASTCache,
    compute_clause_ast_digest,
    compute_regime_set_hash,
    compute_statutory_graph_digest,
    default_clause_cache,
    record_cache_otel_event,
)
from lexgraph_lah.config import settings
from lexgraph_lah.graph.deontic_solver import normalize_regimes
from lexgraph_lah.graph.diff_engine import (
    compute_statutory_window_context,
    evaluate_contract_delta_impact,
)
from lexgraph_lah.ingestion.contract_ast import (
    build_contract_ast,
    extract_contract_paragraphs,
)
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    ContractDeltaAuditRequest,
    OutputPersona,
    PortfolioAsyncJobRequest,
    PortfolioBlastRadiusRequest,
    PortfolioBlastRadiusResponse,
    PortfolioContractImpact,
    PortfolioContractInput,
    PortfolioJobStatusResponse,
    RiskSeverity,
    TerritorialScope,
    WebhookDeliveryStatus,
)
from lexgraph_lah.security.attestation_ledger import (
    AttestationSigner,
    default_attestation_ledger,
)
from lexgraph_lah.security.doc_firewall import (
    scan_document_security,
    validate_zip_archive_safety,
)
from lexgraph_lah.security.webhooks import (
    DNSResolver,
    deliver_signed_webhook,
    validate_webhook_url_ssrf,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import emit_otel_attributes, measure_latency_ms

if TYPE_CHECKING:
    from lexgraph_lah.graph.temporal_store import TemporalGraphStore

_RISK_SCORE_WEIGHT: dict[RiskSeverity, float] = {
    RiskSeverity.LOW: 0.0,
    RiskSeverity.MEDIUM: 15.0,
    RiskSeverity.HIGH: 30.0,
    RiskSeverity.CRITICAL: 45.0,
}


def _window_cache_key(
    contract: PortfolioContractInput,
    default_regimes: list[str] | None,
    default_territorial_scope: TerritorialScope,
) -> tuple[tuple[str, ...] | None, TerritorialScope, list[str] | None]:
    eff_scope = contract.territorial_scope or default_territorial_scope
    raw_regimes = contract.regimes if contract.regimes is not None else default_regimes
    eff_regimes = normalize_regimes(raw_regimes) if raw_regimes else None
    reg_key = tuple(eff_regimes) if eff_regimes else None
    return reg_key, eff_scope, eff_regimes


def _build_window_cache(
    *,
    contracts: list[PortfolioContractInput],
    from_date: date,
    to_date: date,
    default_regimes: list[str] | None,
    default_territorial_scope: TerritorialScope,
    store: TemporalGraphStore,
) -> dict[tuple[tuple[str, ...] | None, TerritorialScope], dict[str, Any]]:
    cache: dict[tuple[tuple[str, ...] | None, TerritorialScope], dict[str, Any]] = {}
    for contract in contracts:
        reg_key, eff_scope, eff_regimes = _window_cache_key(
            contract, default_regimes, default_territorial_scope
        )
        key = (reg_key, eff_scope)
        if key not in cache:
            win = compute_statutory_window_context(
                from_date=from_date,
                to_date=to_date,
                regimes=eff_regimes,
                territorial_scope=eff_scope,
                store=store,
            )
            win["regime_set_hash"] = compute_regime_set_hash(eff_regimes)
            win["statutory_graph_digest"] = compute_statutory_graph_digest(
                store,
                as_of_date=to_date,
                territorial_scope=eff_scope,
                regimes=eff_regimes,
                active_nodes=win.get("active_nodes_to"),
            )
            cache[key] = win
    return cache


def _rehydrate_cached_impact(
    *,
    cached_entry: dict[str, Any],
    contract: PortfolioContractInput,
    clean_text: str,
) -> tuple[PortfolioContractImpact, set[str], set[str]]:
    raw_impact = dict(cached_entry["impact"])
    cur_pii = scrub_malaysian_pii(clean_text)
    rem_pract_tail = str(cached_entry.get("rem_pract_tail") or "")
    rem_rakyat_tail = str(cached_entry.get("rem_rakyat_tail") or "")
    raw_impact["document_id"] = contract.document_id
    raw_impact["title"] = contract.title
    raw_impact["pii_scrub"] = cur_pii.model_dump(mode="json")
    if rem_pract_tail:
        raw_impact["remediation_summary_practitioner"] = (
            f"[{contract.document_id}] {rem_pract_tail}"
        )
    if rem_rakyat_tail:
        raw_impact["remediation_summary_rakyat"] = (
            f"Contract '{contract.title or contract.document_id}' {rem_rakyat_tail}"
        )
    impact = PortfolioContractImpact.model_validate(raw_impact)
    gazettes = set(cached_entry.get("gazettes") or [])
    statutes = set(cached_entry.get("statutes") or [])
    return impact, gazettes, statutes


def _evaluate_single_portfolio_contract_with_cache(
    *,
    contract: PortfolioContractInput,
    from_date: date,
    to_date: date,
    default_regimes: list[str] | None,
    default_territorial_scope: TerritorialScope,
    persona: OutputPersona,
    store: TemporalGraphStore,
    precomputed_window: dict[str, Any] | None = None,
    clause_cache: ClauseASTCache | None = None,
    cache_bypass: bool = False,
    tenant_id: str | None = None,
) -> tuple[PortfolioContractImpact, set[str], set[str], bool]:
    """Evaluates one contract deterministically, optionally leveraging ClauseASTCache."""
    eff_scope = contract.territorial_scope or default_territorial_scope
    raw_regimes = contract.regimes if contract.regimes is not None else default_regimes
    eff_regimes = normalize_regimes(raw_regimes) if raw_regimes else None

    sec_report = scan_document_security(
        document_id=contract.document_id,
        raw_text=contract.raw_text,
    )
    clean_text = (
        sec_report.sanitized_text or "[ALL_ADVERSARIAL_CONTENT_QUARANTINED]"
        if sec_report.findings
        else (sec_report.sanitized_text or contract.raw_text)
    )

    win = precomputed_window or compute_statutory_window_context(
        from_date=from_date,
        to_date=to_date,
        regimes=eff_regimes,
        territorial_scope=eff_scope,
        store=store,
    )
    reg_hash = win.get("regime_set_hash") or compute_regime_set_hash(eff_regimes)
    stat_digest = win.get("statutory_graph_digest") or compute_statutory_graph_digest(
        store,
        as_of_date=to_date,
        territorial_scope=eff_scope,
        regimes=eff_regimes,
        active_nodes=win.get("active_nodes_to"),
    )

    digest: str | None = None
    if clause_cache is not None and not cache_bypass:
        ast_graph, _ = build_contract_ast(
            document_id=contract.document_id,
            raw_text=clean_text,
        )
        digest = compute_clause_ast_digest(
            ast_graph,
            as_of_date=to_date,
            from_date=from_date,
            territorial_scope=eff_scope,
            regime_set_hash=reg_hash,
            statutory_graph_digest=stat_digest,
            persona=persona.value,
            cache_namespace="portfolio",
        )
        cached_entry = clause_cache.get(digest)
        if isinstance(cached_entry, dict) and "impact" in cached_entry:
            record_cache_otel_event(
                cache_hit=True,
                digest=digest,
                surface="portfolio",
                tenant_id=tenant_id,
            )
            c_impact, c_gz, c_st = _rehydrate_cached_impact(
                cached_entry=cached_entry,
                contract=contract,
                clean_text=clean_text,
            )
            return c_impact, c_gz, c_st, True

    delta = evaluate_contract_delta_impact(
        ContractDeltaAuditRequest(
            document_id=contract.document_id,
            raw_text=clean_text,
            from_date=from_date,
            to_date=to_date,
            regimes=eff_regimes,
            territorial_scope=eff_scope,
            persona=persona,
        ),
        store=store,
        precomputed_window=win,
    )

    envelope = win["env_to"]
    bounds_summary: dict[str, Any] = {
        k: {
            "operator": b.operator,
            "strictest_value": b.strictest_value,
            "unit": b.unit,
            "dominating_regime": b.dominating_regime,
            "dominating_node_id": b.dominating_node_id,
            "dominating_citation": b.dominating_citation,
        }
        for k, b in envelope.resolved_bounds.items()
    }

    gazettes: set[str] = set(delta.newly_commenced_gazettes)
    statutes: set[str] = {
        diff.to_node_id for diff in delta.intervening_statutory_diffs if diff.to_node_id
    }
    broken_rule_ids = [f.rule_id for f in delta.delta_findings]
    contract_gazettes: list[str] = []
    seen_cg: set[str] = set()
    for finding in delta.delta_findings:
        for sid in finding.triggering_statute_ids:
            statutes.add(sid)
        for gz in finding.triggering_gazettes:
            gazettes.add(gz)
            if gz not in seen_cg:
                seen_cg.add(gz)
                contract_gazettes.append(gz)

    broken_count = len(delta.delta_findings)
    risk_pts = _RISK_SCORE_WEIGHT[delta.to_overall_risk]
    regression_pts = (
        30.0
        if delta.became_non_compliant
        else (15.0 if delta.compliance_regression_detected else 0.0)
    )
    clause_pts = min(25.0, float(broken_count) * 8.0)
    impact_score = round(min(100.0, risk_pts + regression_pts + clause_pts), 2)

    if broken_count > 0 or delta.became_non_compliant:
        bounds_hint = ", ".join(
            f"{bk}: {bv['operator']} {bv['strictest_value']} {bv['unit']}".strip()
            for bk, bv in sorted(bounds_summary.items())
        )
        rem_pract_tail = (
            f"Scope={eff_scope.value}; "
            f"Risk={delta.from_overall_risk.value}->{delta.to_overall_risk.value}; "
            f"Broken rules={', '.join(broken_rule_ids) or 'THRESHOLD_SHIFT'}. "
            f"Tighten clauses to satisfy [{bounds_hint}]."
        )
        rem_rakyat_tail = (
            f"({eff_scope.value}) "
            f"needs updates for {broken_count} new rule(s) taking effect by "
            f"{to_date.isoformat()}."
        )
    else:
        rem_pract_tail = (
            f"Scope={eff_scope.value}; no new statutory "
            f"delta regressions between {from_date.isoformat()} and {to_date.isoformat()}."
        )
        rem_rakyat_tail = (
            f"remained unaffected by "
            f"new rules between {from_date.isoformat()} and {to_date.isoformat()}."
        )

    rem_pract = f"[{contract.document_id}] {rem_pract_tail}"
    rem_rakyat = (
        f"Contract '{contract.title or contract.document_id}' {rem_rakyat_tail}"
    )

    impact = PortfolioContractImpact(
        document_id=contract.document_id,
        title=contract.title,
        territorial_scope=eff_scope,
        rank=1,
        impact_score=impact_score,
        from_overall_risk=delta.from_overall_risk,
        to_overall_risk=delta.to_overall_risk,
        became_non_compliant=delta.became_non_compliant,
        broken_clause_count=broken_count,
        broken_rule_ids=broken_rule_ids,
        triggering_gazettes=contract_gazettes,
        strictest_deontic_bounds=bounds_summary,
        pii_scrub=delta.pii_scrub,
        remediation_summary_practitioner=rem_pract,
        remediation_summary_rakyat=rem_rakyat,
        delta_findings=delta.delta_findings,
    )

    if clause_cache is not None and not cache_bypass and digest is not None:
        impact_dump = impact.model_dump(mode="json")
        if isinstance(impact_dump.get("pii_scrub"), dict):
            # Never persist raw PII placeholders in the isomorphic cache.
            impact_dump["pii_scrub"]["placeholders"] = {}
        clause_cache.set(
            digest,
            {
                "impact": impact_dump,
                "gazettes": sorted(gazettes),
                "statutes": sorted(statutes),
                "rem_pract_tail": rem_pract_tail,
                "rem_rakyat_tail": rem_rakyat_tail,
            },
        )
        record_cache_otel_event(
            cache_hit=False,
            digest=digest,
            surface="portfolio",
            tenant_id=tenant_id,
        )

    return impact, gazettes, statutes, False


def _evaluate_single_portfolio_contract(
    *,
    contract: PortfolioContractInput,
    from_date: date,
    to_date: date,
    default_regimes: list[str] | None,
    default_territorial_scope: TerritorialScope,
    persona: OutputPersona,
    store: TemporalGraphStore,
    precomputed_window: dict[str, Any] | None = None,
) -> tuple[PortfolioContractImpact, set[str], set[str]]:
    """Evaluates one contract deterministically without mutating shared store state."""
    impact, gazettes, statutes, _ = _evaluate_single_portfolio_contract_with_cache(
        contract=contract,
        from_date=from_date,
        to_date=to_date,
        default_regimes=default_regimes,
        default_territorial_scope=default_territorial_scope,
        persona=persona,
        store=store,
        precomputed_window=precomputed_window,
    )
    return impact, gazettes, statutes


def _assemble_portfolio_response(
    *,
    from_date: date,
    to_date: date,
    impacts: list[PortfolioContractImpact],
    all_gazettes: set[str],
    all_statutes: set[str],
    elapsed_ms: float,
) -> PortfolioBlastRadiusResponse:
    impacts.sort(
        key=lambda item: (
            -item.impact_score,
            not item.became_non_compliant,
            -item.broken_clause_count,
            item.document_id,
        )
    )
    ranked = [
        item.model_copy(update={"rank": idx})
        for idx, item in enumerate(impacts, start=1)
    ]

    impacted_count = sum(
        1
        for item in ranked
        if item.became_non_compliant
        or item.broken_clause_count > 0
        or item.to_overall_risk != item.from_overall_risk
    )
    newly_non_compliant_count = sum(1 for item in ranked if item.became_non_compliant)

    sorted_gazettes = sorted(all_gazettes)
    sorted_statutes = sorted(all_statutes)

    exec_pract = (
        f"Scanned {len(ranked)} contract(s) across {from_date.isoformat()} -> "
        f"{to_date.isoformat()}. Impacted={impacted_count}, "
        f"Newly Non-Compliant={newly_non_compliant_count}. "
        f"Gazettes={', '.join(sorted_gazettes) or 'None'}."
    )
    exec_rakyat = (
        f"Checked {len(ranked)} agreements for legal updates between "
        f"{from_date.isoformat()} and {to_date.isoformat()}: "
        f"{newly_non_compliant_count} became non-compliant and require redline remediation."
    )

    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_ms,
        retry_count=0,
        is_verified_grounded=True,
    )

    return PortfolioBlastRadiusResponse(
        from_date=from_date,
        to_date=to_date,
        total_contracts_scanned=len(ranked),
        impacted_contracts_count=impacted_count,
        newly_non_compliant_count=newly_non_compliant_count,
        newly_commenced_gazettes=sorted_gazettes,
        affected_statute_ids=sorted_statutes,
        ranked_impacts=ranked,
        executive_summary_practitioner=exec_pract,
        executive_summary_rakyat=exec_rakyat,
        telemetry=telemetry,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )


def scan_portfolio_blast_radius(
    req: PortfolioBlastRadiusRequest,
    store: TemporalGraphStore | None = None,
) -> PortfolioBlastRadiusResponse:
    """
    Deterministically scans a batch of contracts (1..50) against intervening
    Malaysian statutory amendments and P.U. gazette commencements ($0.00 USD / RM 0.00 MYR).
    """
    if req.from_date > req.to_date:
        raise ValueError(
            f"from_date ({req.from_date.isoformat()}) must be on or before to_date ({req.to_date.isoformat()})."
        )

    if store is None:
        from lexgraph_lah.graph.temporal_store import get_default_temporal_store

        store = get_default_temporal_store()

    with measure_latency_ms() as elapsed_holder:
        window_cache = _build_window_cache(
            contracts=req.contracts,
            from_date=req.from_date,
            to_date=req.to_date,
            default_regimes=req.regimes,
            default_territorial_scope=req.default_territorial_scope,
            store=store,
        )
        impacts: list[PortfolioContractImpact] = []
        all_gazettes: set[str] = set()
        all_statutes: set[str] = set()

        for contract in req.contracts:
            reg_key, eff_scope, _ = _window_cache_key(
                contract, req.regimes, req.default_territorial_scope
            )
            impact, gz, st = _evaluate_single_portfolio_contract(
                contract=contract,
                from_date=req.from_date,
                to_date=req.to_date,
                default_regimes=req.regimes,
                default_territorial_scope=req.default_territorial_scope,
                persona=req.persona,
                store=store,
                precomputed_window=window_cache[(reg_key, eff_scope)],
            )
            impacts.append(impact)
            all_gazettes.update(gz)
            all_statutes.update(st)

    return _assemble_portfolio_response(
        from_date=req.from_date,
        to_date=req.to_date,
        impacts=impacts,
        all_gazettes=all_gazettes,
        all_statutes=all_statutes,
        elapsed_ms=elapsed_holder[0],
    )


def extract_contracts_from_zip_archive(
    zip_bytes: bytes,
    *,
    max_files: int = 2000,
    max_uncompressed_bytes: int = 100 * 1024 * 1024,
) -> list[PortfolioContractInput]:
    """
    Validates a `.zip` archive of `.docx`/`.pdf`/`.txt` contracts using zip-bomb &
    path-traversal guards, extracting text payloads ready for async portfolio jobs.
    """
    validate_zip_archive_safety(
        zip_bytes,
        max_uncompressed_bytes=max_uncompressed_bytes,
        max_compression_ratio=settings.docx_max_compression_ratio,
        max_entries=max(settings.docx_max_entries, max_files + 100),
    )
    contracts: list[PortfolioContractInput] = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        for idx, info in enumerate(zf.infolist(), start=1):
            if info.is_dir():
                continue
            name = info.filename
            base = Path(name).name
            if name.startswith("__MACOSX/") or base.startswith("._"):
                continue
            ext = Path(base).suffix.lower()
            if ext not in {".docx", ".pdf", ".txt"}:
                continue
            if len(contracts) >= max_files:
                raise ValueError(
                    f"Archive contains more than the maximum allowed {max_files} contracts."
                )

            raw_entry = zf.read(info)
            if ext == ".txt":
                text_val = raw_entry.decode("utf-8", errors="replace").strip()
            else:
                _, _, text_val, _, _ = extract_contract_paragraphs(
                    file_bytes=raw_entry,
                    filename=base,
                )
            if not text_val.strip():
                text_val = f"[Empty extracted content from {base}]"
            doc_id = (
                "".join(
                    c if c.isalnum() or c in "-_." else "-" for c in Path(base).stem
                ).strip("-")
                or f"ZIP-DOC-{idx:04d}"
            )
            contracts.append(
                PortfolioContractInput(
                    document_id=doc_id,
                    title=base,
                    raw_text=text_val,
                )
            )

    if not contracts:
        raise ValueError(
            "Uploaded ZIP archive contained no supported .docx, .pdf, or .txt contract files."
        )
    return contracts


class IdempotencyConflictError(ValueError):
    """Raised when an Idempotency-Key is reused with a differing request payload."""


class PortfolioJobStateError(ValueError):
    """Raised when an illegal portfolio job state transition (e.g., requeue) is requested."""


def compute_job_payload_fingerprint(req: PortfolioAsyncJobRequest) -> str:
    """Computes canonical SHA-256 fingerprint of a `PortfolioAsyncJobRequest`."""
    canonical = json.dumps(
        req.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_iso_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    dt = datetime.fromisoformat(raw)
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class PortfolioJobStoreBackend(Protocol):
    """Durable job storage backend protocol (`memory`, `sqlite`, `postgres`)."""

    def save(self, job: PortfolioJobStatusResponse) -> None: ...

    def get(
        self, job_id: str, *, tenant_id: str | None = None
    ) -> PortfolioJobStatusResponse | None: ...

    def list_jobs(
        self, *, tenant_id: str | None = None, status: str | None = None
    ) -> list[PortfolioJobStatusResponse]: ...

    def register_idempotency(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        job_id: str,
        payload_fingerprint: str,
    ) -> None: ...

    def lookup_idempotency(
        self, *, tenant_id: str, idempotency_key: str
    ) -> tuple[str, str] | None: ...

    def save_request(self, job_id: str, req: PortfolioAsyncJobRequest) -> None: ...

    def get_request(self, job_id: str) -> PortfolioAsyncJobRequest | None: ...

    def save_checkpoint(
        self,
        *,
        job_id: str,
        contract_id: str,
        impact: PortfolioContractImpact,
        gazettes: Collection[str],
        statutes: Collection[str],
        is_hit: bool,
    ) -> None: ...

    def list_checkpoints(
        self, job_id: str
    ) -> dict[str, tuple[PortfolioContractImpact, list[str], list[str], bool]]: ...

    def clear_checkpoints(self, job_id: str) -> None: ...

    def claim_next_queued_job(
        self,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> PortfolioJobStatusResponse | None: ...

    def claim_job_by_id(
        self,
        job_id: str,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> PortfolioJobStatusResponse | None: ...

    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> bool: ...

    def reap_stale_leases(
        self, *, now: datetime | None = None
    ) -> list[PortfolioJobStatusResponse]: ...


class InMemoryPortfolioJobStore:
    """Thread-safe zero-config in-memory portfolio job store with leases & checkpoints."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, PortfolioJobStatusResponse] = {}
        self._idempotency: dict[tuple[str, str], tuple[str, str]] = {}
        self._requests: dict[str, PortfolioAsyncJobRequest] = {}
        self._checkpoints: dict[
            str, dict[str, tuple[PortfolioContractImpact, list[str], list[str], bool]]
        ] = {}

    def save(self, job: PortfolioJobStatusResponse) -> None:
        with self._lock:
            self._jobs[job.job_id] = job

    def get(
        self, job_id: str, *, tenant_id: str | None = None
    ) -> PortfolioJobStatusResponse | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if tenant_id is not None and job.tenant_id != tenant_id:
                return None
            return job

    def list_jobs(
        self, *, tenant_id: str | None = None, status: str | None = None
    ) -> list[PortfolioJobStatusResponse]:
        with self._lock:
            out: list[PortfolioJobStatusResponse] = []
            for job in self._jobs.values():
                if tenant_id is not None and job.tenant_id != tenant_id:
                    continue
                if status is not None and job.status != status:
                    continue
                out.append(job)
            return sorted(out, key=lambda j: j.created_at)

    def register_idempotency(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        job_id: str,
        payload_fingerprint: str,
    ) -> None:
        with self._lock:
            self._idempotency[(tenant_id, idempotency_key)] = (
                job_id,
                payload_fingerprint,
            )

    def lookup_idempotency(
        self, *, tenant_id: str, idempotency_key: str
    ) -> tuple[str, str] | None:
        with self._lock:
            return self._idempotency.get((tenant_id, idempotency_key))

    def save_request(self, job_id: str, req: PortfolioAsyncJobRequest) -> None:
        with self._lock:
            self._requests[job_id] = req

    def get_request(self, job_id: str) -> PortfolioAsyncJobRequest | None:
        with self._lock:
            return self._requests.get(job_id)

    def save_checkpoint(
        self,
        *,
        job_id: str,
        contract_id: str,
        impact: PortfolioContractImpact,
        gazettes: Collection[str],
        statutes: Collection[str],
        is_hit: bool,
    ) -> None:
        with self._lock:
            bucket = self._checkpoints.setdefault(job_id, {})
            bucket[contract_id] = (impact, sorted(gazettes), sorted(statutes), is_hit)

    def list_checkpoints(
        self, job_id: str
    ) -> dict[str, tuple[PortfolioContractImpact, list[str], list[str], bool]]:
        with self._lock:
            return dict(self._checkpoints.get(job_id, {}))

    def clear_checkpoints(self, job_id: str) -> None:
        with self._lock:
            self._checkpoints.pop(job_id, None)

    def _claim_locked(
        self,
        job: PortfolioJobStatusResponse,
        worker_id: str,
        lease_seconds: float,
        now_dt: datetime,
    ) -> PortfolioJobStatusResponse:
        now_iso = now_dt.isoformat()
        exp_iso = (now_dt + timedelta(seconds=max(0.01, lease_seconds))).isoformat()
        claimed = job.model_copy(
            update={
                "status": "RUNNING",
                "worker_id": worker_id,
                "heartbeat_at": now_iso,
                "lease_expires_at": exp_iso,
                "started_at": job.started_at or now_iso,
                "attempt_count": job.attempt_count + 1,
            }
        )
        self._jobs[job.job_id] = claimed
        return claimed

    def claim_next_queued_job(
        self,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> PortfolioJobStatusResponse | None:
        now_dt = now or datetime.now(UTC)
        with self._lock:
            queued = [j for j in self._jobs.values() if j.status == "QUEUED"]
            if not queued:
                return None
            queued.sort(key=lambda j: j.created_at)
            return self._claim_locked(queued[0], worker_id, lease_seconds, now_dt)

    def claim_job_by_id(
        self,
        job_id: str,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> PortfolioJobStatusResponse | None:
        now_dt = now or datetime.now(UTC)
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status != "QUEUED":
                return None
            return self._claim_locked(job, worker_id, lease_seconds, now_dt)

    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> bool:
        now_dt = now or datetime.now(UTC)
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status != "RUNNING" or job.worker_id != worker_id:
                return False
            self._jobs[job_id] = job.model_copy(
                update={
                    "heartbeat_at": now_dt.isoformat(),
                    "lease_expires_at": (
                        now_dt + timedelta(seconds=max(0.01, lease_seconds))
                    ).isoformat(),
                }
            )
            return True

    def reap_stale_leases(
        self, *, now: datetime | None = None
    ) -> list[PortfolioJobStatusResponse]:
        now_dt = now or datetime.now(UTC)
        reaped: list[PortfolioJobStatusResponse] = []
        with self._lock:
            for job_id, job in list(self._jobs.items()):
                if job.status != "RUNNING":
                    continue
                exp_dt = _parse_iso_dt(job.lease_expires_at)
                if exp_dt is None or exp_dt > now_dt:
                    continue
                if job.attempt_count >= job.max_attempts:
                    nxt = job.model_copy(
                        update={
                            "status": "DEAD_LETTER",
                            "worker_id": None,
                            "lease_expires_at": None,
                            "last_error_code": "LEASE_EXPIRED_MAX_ATTEMPTS",
                            "error": (
                                f"Worker lease expired after {job.attempt_count}/"
                                f"{job.max_attempts} attempts; moved to DEAD_LETTER."
                            ),
                            "completed_at": now_dt.isoformat(),
                        }
                    )
                else:
                    nxt = job.model_copy(
                        update={
                            "status": "QUEUED",
                            "worker_id": None,
                            "lease_expires_at": None,
                            "last_error_code": "LEASE_EXPIRED",
                            "error": (
                                f"Stale lease from worker '{job.worker_id}' expired at "
                                f"{job.lease_expires_at}; re-queued for crash recovery."
                            ),
                        }
                    )
                self._jobs[job_id] = nxt
                reaped.append(nxt)
        return reaped


class SQLitePortfolioJobStore:
    """SQLite WAL-backed durable portfolio job metadata, idempotency, checkpoints & leases."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        raw_path = str(
            db_path or settings.portfolio_job_db_path or "./lexgraph_portfolio_jobs.db"
        )
        self._db_path = raw_path
        self._lock = threading.RLock()
        if raw_path != ":memory:":
            Path(raw_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(raw_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_jobs (
                job_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_portfolio_jobs_tenant ON portfolio_jobs (tenant_id)"
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_job_idempotency (
                tenant_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                job_id TEXT NOT NULL,
                payload_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, idempotency_key)
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_job_requests (
                job_id TEXT PRIMARY KEY,
                request_json TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS portfolio_job_checkpoints (
                job_id TEXT NOT NULL,
                contract_id TEXT NOT NULL,
                impact_json TEXT NOT NULL,
                gazettes_json TEXT NOT NULL,
                statutes_json TEXT NOT NULL,
                is_hit INTEGER NOT NULL,
                PRIMARY KEY (job_id, contract_id)
            )
            """
        )
        self._conn.commit()

    def save(self, job: PortfolioJobStatusResponse) -> None:
        payload_json = job.model_dump_json()
        updated_at = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO portfolio_jobs
                    (job_id, tenant_id, status, payload_json, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (job.job_id, job.tenant_id, job.status, payload_json, updated_at),
            )
            self._conn.commit()

    def get(
        self, job_id: str, *, tenant_id: str | None = None
    ) -> PortfolioJobStatusResponse | None:
        with self._lock:
            if tenant_id is not None:
                row = self._conn.execute(
                    "SELECT payload_json FROM portfolio_jobs WHERE job_id = ? AND tenant_id = ?",
                    (job_id, tenant_id),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT payload_json FROM portfolio_jobs WHERE job_id = ?",
                    (job_id,),
                ).fetchone()
        if row is None:
            return None
        return PortfolioJobStatusResponse.model_validate_json(str(row[0]))

    def list_jobs(
        self, *, tenant_id: str | None = None, status: str | None = None
    ) -> list[PortfolioJobStatusResponse]:
        with self._lock:
            if tenant_id is not None and status is not None:
                rows = self._conn.execute(
                    "SELECT payload_json FROM portfolio_jobs WHERE tenant_id = ? AND status = ?",
                    (tenant_id, status),
                ).fetchall()
            elif tenant_id is not None:
                rows = self._conn.execute(
                    "SELECT payload_json FROM portfolio_jobs WHERE tenant_id = ?",
                    (tenant_id,),
                ).fetchall()
            elif status is not None:
                rows = self._conn.execute(
                    "SELECT payload_json FROM portfolio_jobs WHERE status = ?",
                    (status,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT payload_json FROM portfolio_jobs"
                ).fetchall()
        jobs = [PortfolioJobStatusResponse.model_validate_json(str(r[0])) for r in rows]
        return sorted(jobs, key=lambda j: j.created_at)

    def register_idempotency(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        job_id: str,
        payload_fingerprint: str,
    ) -> None:
        now_iso = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO portfolio_job_idempotency
                    (tenant_id, idempotency_key, job_id, payload_fingerprint, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (tenant_id, idempotency_key, job_id, payload_fingerprint, now_iso),
            )
            self._conn.commit()

    def lookup_idempotency(
        self, *, tenant_id: str, idempotency_key: str
    ) -> tuple[str, str] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT job_id, payload_fingerprint
                FROM portfolio_job_idempotency
                WHERE tenant_id = ? AND idempotency_key = ?
                """,
                (tenant_id, idempotency_key),
            ).fetchone()
        if row is None:
            return None
        return str(row[0]), str(row[1])

    def save_request(self, job_id: str, req: PortfolioAsyncJobRequest) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO portfolio_job_requests (job_id, request_json)
                VALUES (?, ?)
                """,
                (job_id, req.model_dump_json()),
            )
            self._conn.commit()

    def get_request(self, job_id: str) -> PortfolioAsyncJobRequest | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT request_json FROM portfolio_job_requests WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return PortfolioAsyncJobRequest.model_validate_json(str(row[0]))

    def save_checkpoint(
        self,
        *,
        job_id: str,
        contract_id: str,
        impact: PortfolioContractImpact,
        gazettes: Collection[str],
        statutes: Collection[str],
        is_hit: bool,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO portfolio_job_checkpoints
                    (job_id, contract_id, impact_json, gazettes_json, statutes_json, is_hit)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    contract_id,
                    impact.model_dump_json(),
                    json.dumps(sorted(gazettes)),
                    json.dumps(sorted(statutes)),
                    1 if is_hit else 0,
                ),
            )
            self._conn.commit()

    def list_checkpoints(
        self, job_id: str
    ) -> dict[str, tuple[PortfolioContractImpact, list[str], list[str], bool]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT contract_id, impact_json, gazettes_json, statutes_json, is_hit
                FROM portfolio_job_checkpoints
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchall()
        out: dict[str, tuple[PortfolioContractImpact, list[str], list[str], bool]] = {}
        for r in rows:
            out[str(r[0])] = (
                PortfolioContractImpact.model_validate_json(str(r[1])),
                list(json.loads(str(r[2]))),
                list(json.loads(str(r[3]))),
                bool(r[4]),
            )
        return out

    def clear_checkpoints(self, job_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM portfolio_job_checkpoints WHERE job_id = ?",
                (job_id,),
            )
            self._conn.commit()

    def _claim_job_locked(
        self,
        job: PortfolioJobStatusResponse,
        worker_id: str,
        lease_seconds: float,
        now_dt: datetime,
    ) -> PortfolioJobStatusResponse:
        now_iso = now_dt.isoformat()
        exp_iso = (now_dt + timedelta(seconds=max(0.01, lease_seconds))).isoformat()
        claimed = job.model_copy(
            update={
                "status": "RUNNING",
                "worker_id": worker_id,
                "heartbeat_at": now_iso,
                "lease_expires_at": exp_iso,
                "started_at": job.started_at or now_iso,
                "attempt_count": job.attempt_count + 1,
            }
        )
        self._conn.execute(
            """
            INSERT OR REPLACE INTO portfolio_jobs
                (job_id, tenant_id, status, payload_json, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                claimed.job_id,
                claimed.tenant_id,
                claimed.status,
                claimed.model_dump_json(),
                now_iso,
            ),
        )
        self._conn.commit()
        return claimed

    def claim_next_queued_job(
        self,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> PortfolioJobStatusResponse | None:
        now_dt = now or datetime.now(UTC)
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload_json FROM portfolio_jobs WHERE status = ?",
                ("QUEUED",),
            ).fetchall()
            if not rows:
                return None
            candidates = sorted(
                (
                    PortfolioJobStatusResponse.model_validate_json(str(r[0]))
                    for r in rows
                ),
                key=lambda j: j.created_at,
            )
            return self._claim_job_locked(
                candidates[0], worker_id, lease_seconds, now_dt
            )

    def claim_job_by_id(
        self,
        job_id: str,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> PortfolioJobStatusResponse | None:
        now_dt = now or datetime.now(UTC)
        with self._lock:
            row = self._conn.execute(
                "SELECT payload_json FROM portfolio_jobs WHERE job_id = ? AND status = ?",
                (job_id, "QUEUED"),
            ).fetchone()
            if row is None:
                return None
            job = PortfolioJobStatusResponse.model_validate_json(str(row[0]))
            return self._claim_job_locked(job, worker_id, lease_seconds, now_dt)

    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> bool:
        now_dt = now or datetime.now(UTC)
        with self._lock:
            job = self.get(job_id)
            if job is None or job.status != "RUNNING" or job.worker_id != worker_id:
                return False
            nxt = job.model_copy(
                update={
                    "heartbeat_at": now_dt.isoformat(),
                    "lease_expires_at": (
                        now_dt + timedelta(seconds=max(0.01, lease_seconds))
                    ).isoformat(),
                }
            )
            self.save(nxt)
            return True

    def reap_stale_leases(
        self, *, now: datetime | None = None
    ) -> list[PortfolioJobStatusResponse]:
        now_dt = now or datetime.now(UTC)
        reaped: list[PortfolioJobStatusResponse] = []
        with self._lock:
            for job in self.list_jobs(status="RUNNING"):
                exp_dt = _parse_iso_dt(job.lease_expires_at)
                if exp_dt is None or exp_dt > now_dt:
                    continue
                if job.attempt_count >= job.max_attempts:
                    nxt = job.model_copy(
                        update={
                            "status": "DEAD_LETTER",
                            "worker_id": None,
                            "lease_expires_at": None,
                            "last_error_code": "LEASE_EXPIRED_MAX_ATTEMPTS",
                            "error": (
                                f"Worker lease expired after {job.attempt_count}/"
                                f"{job.max_attempts} attempts; moved to DEAD_LETTER."
                            ),
                            "completed_at": now_dt.isoformat(),
                        }
                    )
                else:
                    nxt = job.model_copy(
                        update={
                            "status": "QUEUED",
                            "worker_id": None,
                            "lease_expires_at": None,
                            "last_error_code": "LEASE_EXPIRED",
                            "error": (
                                f"Stale lease from worker '{job.worker_id}' expired at "
                                f"{job.lease_expires_at}; re-queued for crash recovery."
                            ),
                        }
                    )
                self.save(nxt)
                reaped.append(nxt)
        return reaped

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class PostgresPortfolioJobStore:
    """PostgreSQL durable portfolio job store via `psycopg` or injectable `connection_factory`."""

    def __init__(
        self,
        dsn: str | None = None,
        *,
        connection_factory: Callable[[], Any] | None = None,
    ) -> None:
        resolved_dsn = (
            dsn if dsn is not None else settings.portfolio_job_postgres_dsn
        ).strip()
        if connection_factory is None and not resolved_dsn:
            raise RuntimeError(
                "PORTFOLIO_JOB_STORE='postgres' requires PORTFOLIO_JOB_POSTGRES_DSN."
            )
        self._dsn = resolved_dsn
        self._connection_factory = connection_factory
        self._lock = threading.RLock()
        self._conn: Any | None = None
        self._ensure_schema()

    def _get_conn(self) -> Any:
        if self._conn is None:
            if self._connection_factory is not None:
                self._conn = self._connection_factory()
            else:
                psycopg = importlib.import_module("psycopg")
                self._conn = psycopg.connect(self._dsn)
        return self._conn

    def _ensure_schema(self) -> None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS portfolio_jobs (
                        job_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS portfolio_job_idempotency (
                        tenant_id TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL,
                        job_id TEXT NOT NULL,
                        payload_fingerprint TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY (tenant_id, idempotency_key)
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS portfolio_job_requests (
                        job_id TEXT PRIMARY KEY,
                        request_json TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS portfolio_job_checkpoints (
                        job_id TEXT NOT NULL,
                        contract_id TEXT NOT NULL,
                        impact_json TEXT NOT NULL,
                        gazettes_json TEXT NOT NULL,
                        statutes_json TEXT NOT NULL,
                        is_hit BOOLEAN NOT NULL,
                        PRIMARY KEY (job_id, contract_id)
                    )
                    """
                )
            conn.commit()

    def save(self, job: PortfolioJobStatusResponse) -> None:
        payload_json = job.model_dump_json()
        updated_at = datetime.now(UTC).isoformat()
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO portfolio_jobs
                        (job_id, tenant_id, status, payload_json, updated_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (job_id) DO UPDATE SET
                        tenant_id = EXCLUDED.tenant_id,
                        status = EXCLUDED.status,
                        payload_json = EXCLUDED.payload_json,
                        updated_at = EXCLUDED.updated_at
                    """,
                    (job.job_id, job.tenant_id, job.status, payload_json, updated_at),
                )
            conn.commit()

    def get(
        self, job_id: str, *, tenant_id: str | None = None
    ) -> PortfolioJobStatusResponse | None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                if tenant_id is not None:
                    cur.execute(
                        "SELECT payload_json FROM portfolio_jobs WHERE job_id = %s AND tenant_id = %s",
                        (job_id, tenant_id),
                    )
                else:
                    cur.execute(
                        "SELECT payload_json FROM portfolio_jobs WHERE job_id = %s",
                        (job_id,),
                    )
                row = cur.fetchone()
        if row is None:
            return None
        return PortfolioJobStatusResponse.model_validate_json(str(row[0]))

    def list_jobs(
        self, *, tenant_id: str | None = None, status: str | None = None
    ) -> list[PortfolioJobStatusResponse]:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                if tenant_id is not None and status is not None:
                    cur.execute(
                        "SELECT payload_json FROM portfolio_jobs WHERE tenant_id = %s AND status = %s",
                        (tenant_id, status),
                    )
                elif tenant_id is not None:
                    cur.execute(
                        "SELECT payload_json FROM portfolio_jobs WHERE tenant_id = %s",
                        (tenant_id,),
                    )
                elif status is not None:
                    cur.execute(
                        "SELECT payload_json FROM portfolio_jobs WHERE status = %s",
                        (status,),
                    )
                else:
                    cur.execute("SELECT payload_json FROM portfolio_jobs")
                rows = cur.fetchall() if hasattr(cur, "fetchall") else []
        jobs = [PortfolioJobStatusResponse.model_validate_json(str(r[0])) for r in rows]
        return sorted(jobs, key=lambda j: j.created_at)

    def register_idempotency(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        job_id: str,
        payload_fingerprint: str,
    ) -> None:
        now_iso = datetime.now(UTC).isoformat()
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO portfolio_job_idempotency
                        (tenant_id, idempotency_key, job_id, payload_fingerprint, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, idempotency_key) DO UPDATE SET
                        job_id = EXCLUDED.job_id,
                        payload_fingerprint = EXCLUDED.payload_fingerprint
                    """,
                    (tenant_id, idempotency_key, job_id, payload_fingerprint, now_iso),
                )
            conn.commit()

    def lookup_idempotency(
        self, *, tenant_id: str, idempotency_key: str
    ) -> tuple[str, str] | None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT job_id, payload_fingerprint
                    FROM portfolio_job_idempotency
                    WHERE tenant_id = %s AND idempotency_key = %s
                    """,
                    (tenant_id, idempotency_key),
                )
                row = cur.fetchone()
        if row is None:
            return None
        return str(row[0]), str(row[1])

    def save_request(self, job_id: str, req: PortfolioAsyncJobRequest) -> None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO portfolio_job_requests (job_id, request_json)
                    VALUES (%s, %s)
                    ON CONFLICT (job_id) DO UPDATE SET request_json = EXCLUDED.request_json
                    """,
                    (job_id, req.model_dump_json()),
                )
            conn.commit()

    def get_request(self, job_id: str) -> PortfolioAsyncJobRequest | None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT request_json FROM portfolio_job_requests WHERE job_id = %s",
                    (job_id,),
                )
                row = cur.fetchone()
        if row is None:
            return None
        return PortfolioAsyncJobRequest.model_validate_json(str(row[0]))

    def save_checkpoint(
        self,
        *,
        job_id: str,
        contract_id: str,
        impact: PortfolioContractImpact,
        gazettes: Collection[str],
        statutes: Collection[str],
        is_hit: bool,
    ) -> None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO portfolio_job_checkpoints
                        (job_id, contract_id, impact_json, gazettes_json, statutes_json, is_hit)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (job_id, contract_id) DO UPDATE SET
                        impact_json = EXCLUDED.impact_json,
                        gazettes_json = EXCLUDED.gazettes_json,
                        statutes_json = EXCLUDED.statutes_json,
                        is_hit = EXCLUDED.is_hit
                    """,
                    (
                        job_id,
                        contract_id,
                        impact.model_dump_json(),
                        json.dumps(sorted(gazettes)),
                        json.dumps(sorted(statutes)),
                        bool(is_hit),
                    ),
                )
            conn.commit()

    def list_checkpoints(
        self, job_id: str
    ) -> dict[str, tuple[PortfolioContractImpact, list[str], list[str], bool]]:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT contract_id, impact_json, gazettes_json, statutes_json, is_hit
                    FROM portfolio_job_checkpoints
                    WHERE job_id = %s
                    """,
                    (job_id,),
                )
                rows = cur.fetchall() if hasattr(cur, "fetchall") else []
        out: dict[str, tuple[PortfolioContractImpact, list[str], list[str], bool]] = {}
        for r in rows:
            out[str(r[0])] = (
                PortfolioContractImpact.model_validate_json(str(r[1])),
                list(json.loads(str(r[2]))),
                list(json.loads(str(r[3]))),
                bool(r[4]),
            )
        return out

    def clear_checkpoints(self, job_id: str) -> None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM portfolio_job_checkpoints WHERE job_id = %s",
                    (job_id,),
                )
            conn.commit()

    def claim_next_queued_job(
        self,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> PortfolioJobStatusResponse | None:
        now_dt = now or datetime.now(UTC)
        with self._lock:
            queued = self.list_jobs(status="QUEUED")
            if not queued:
                return None
            job = queued[0]
            now_iso = now_dt.isoformat()
            claimed = job.model_copy(
                update={
                    "status": "RUNNING",
                    "worker_id": worker_id,
                    "heartbeat_at": now_iso,
                    "lease_expires_at": (
                        now_dt + timedelta(seconds=max(0.01, lease_seconds))
                    ).isoformat(),
                    "started_at": job.started_at or now_iso,
                    "attempt_count": job.attempt_count + 1,
                }
            )
            self.save(claimed)
            return claimed

    def claim_job_by_id(
        self,
        job_id: str,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> PortfolioJobStatusResponse | None:
        now_dt = now or datetime.now(UTC)
        with self._lock:
            job = self.get(job_id)
            if job is None or job.status != "QUEUED":
                return None
            now_iso = now_dt.isoformat()
            claimed = job.model_copy(
                update={
                    "status": "RUNNING",
                    "worker_id": worker_id,
                    "heartbeat_at": now_iso,
                    "lease_expires_at": (
                        now_dt + timedelta(seconds=max(0.01, lease_seconds))
                    ).isoformat(),
                    "started_at": job.started_at or now_iso,
                    "attempt_count": job.attempt_count + 1,
                }
            )
            self.save(claimed)
            return claimed

    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_seconds: float,
        *,
        now: datetime | None = None,
    ) -> bool:
        now_dt = now or datetime.now(UTC)
        with self._lock:
            job = self.get(job_id)
            if job is None or job.status != "RUNNING" or job.worker_id != worker_id:
                return False
            nxt = job.model_copy(
                update={
                    "heartbeat_at": now_dt.isoformat(),
                    "lease_expires_at": (
                        now_dt + timedelta(seconds=max(0.01, lease_seconds))
                    ).isoformat(),
                }
            )
            self.save(nxt)
            return True

    def reap_stale_leases(
        self, *, now: datetime | None = None
    ) -> list[PortfolioJobStatusResponse]:
        now_dt = now or datetime.now(UTC)
        reaped: list[PortfolioJobStatusResponse] = []
        with self._lock:
            for job in self.list_jobs(status="RUNNING"):
                exp_dt = _parse_iso_dt(job.lease_expires_at)
                if exp_dt is None or exp_dt > now_dt:
                    continue
                if job.attempt_count >= job.max_attempts:
                    nxt = job.model_copy(
                        update={
                            "status": "DEAD_LETTER",
                            "worker_id": None,
                            "lease_expires_at": None,
                            "last_error_code": "LEASE_EXPIRED_MAX_ATTEMPTS",
                            "error": (
                                f"Worker lease expired after {job.attempt_count}/"
                                f"{job.max_attempts} attempts; moved to DEAD_LETTER."
                            ),
                            "completed_at": now_dt.isoformat(),
                        }
                    )
                else:
                    nxt = job.model_copy(
                        update={
                            "status": "QUEUED",
                            "worker_id": None,
                            "lease_expires_at": None,
                            "last_error_code": "LEASE_EXPIRED",
                            "error": (
                                f"Stale lease from worker '{job.worker_id}' expired at "
                                f"{job.lease_expires_at}; re-queued for crash recovery."
                            ),
                        }
                    )
                self.save(nxt)
                reaped.append(nxt)
        return reaped

    def close(self) -> None:
        with self._lock:
            if self._conn is not None and hasattr(self._conn, "close"):
                self._conn.close()
                self._conn = None


def build_portfolio_job_store(
    backend: str | None = None,
    *,
    db_path: str | Path | None = None,
    postgres_dsn: str | None = None,
) -> PortfolioJobStoreBackend:
    """Instantiates configured portfolio job persistence backend."""
    chosen = (backend or settings.portfolio_job_store or "memory").strip().lower()
    if chosen == "memory":
        return InMemoryPortfolioJobStore()
    if chosen == "sqlite":
        return SQLitePortfolioJobStore(db_path=db_path)
    if chosen == "postgres":
        return PostgresPortfolioJobStore(dsn=postgres_dsn)
    raise ValueError(
        f"Unsupported PORTFOLIO_JOB_STORE={chosen!r}; expected 'memory', 'sqlite', or 'postgres'."
    )


class PortfolioJobManager:
    """
    Crash-recoverable, lease-based async portfolio blast-radius queue supporting:
      - `Idempotency-Key` deduplication (scoped by `tenant_id` + SHA-256 fingerprint)
      - Atomic worker leases, heartbeats, and per-contract crash checkpoints
      - Stale-lease reaper & Dead-Letter Queue (`DEAD_LETTER`) with admin requeue
      - SSRF-validated dual-signed outbound webhooks & Clause-AST isomorphic caching
    """

    def __init__(
        self,
        *,
        store: TemporalGraphStore | None = None,
        job_store: PortfolioJobStoreBackend | None = None,
        clause_cache: ClauseASTCache | None = None,
        webhook_transport: httpx.BaseTransport | None = None,
        dns_resolver: DNSResolver | None = None,
        signer: AttestationSigner | None = None,
        hmac_secret: str | None = None,
        webhook_max_attempts: int | None = None,
        webhook_backoff_base_seconds: float | None = None,
        lease_seconds: float | None = None,
        max_attempts: int | None = None,
        worker_mode: str | None = None,
        contract_evaluator: Callable[
            ..., tuple[PortfolioContractImpact, list[str], list[str], bool]
        ]
        | None = None,
    ) -> None:
        self._store = store
        self._lock = threading.RLock()
        self._job_store: PortfolioJobStoreBackend = (
            job_store if job_store is not None else build_portfolio_job_store()
        )
        self._clause_cache: ClauseASTCache | None = (
            clause_cache if clause_cache is not None else default_clause_cache
        )
        self._webhook_transport = webhook_transport
        self._dns_resolver = dns_resolver
        self._signer = signer or default_attestation_ledger.signer
        self._hmac_secret = hmac_secret
        self._webhook_max_attempts = webhook_max_attempts
        self._webhook_backoff_base_seconds = webhook_backoff_base_seconds
        self._lease_seconds = float(
            lease_seconds
            if lease_seconds is not None
            else settings.portfolio_job_lease_seconds
        )
        self._max_attempts = max(
            1,
            int(
                max_attempts
                if max_attempts is not None
                else settings.portfolio_job_max_attempts
            ),
        )
        self._worker_mode = (
            (worker_mode or settings.portfolio_worker_mode or "embedded")
            .strip()
            .lower()
        )
        self._contract_evaluator = (
            contract_evaluator or _evaluate_single_portfolio_contract_with_cache
        )
        self._futures: dict[str, Future[None]] = {}

    def _get_store(self) -> TemporalGraphStore:
        if self._store is None:
            from lexgraph_lah.graph.temporal_store import get_default_temporal_store

            self._store = get_default_temporal_store()
        return self._store

    def _deliver_webhook_if_configured(
        self,
        *,
        job_id: str,
        req: PortfolioAsyncJobRequest,
        final_job: PortfolioJobStatusResponse,
    ) -> None:
        if not req.webhook_url:
            return
        result_summary: dict[str, Any] | None = None
        if final_job.result is not None:
            result_summary = {
                "total_contracts_scanned": final_job.result.total_contracts_scanned,
                "impacted_contracts_count": final_job.result.impacted_contracts_count,
                "newly_non_compliant_count": final_job.result.newly_non_compliant_count,
                "newly_commenced_gazettes": final_job.result.newly_commenced_gazettes,
            }
        webhook_payload = {
            "event": (
                "portfolio_job.completed"
                if final_job.status == "COMPLETED"
                else "portfolio_job.failed"
            ),
            "job_id": final_job.job_id,
            "tenant_id": final_job.tenant_id,
            "status": final_job.status,
            "total_contracts": final_job.total_contracts,
            "processed_contracts": final_job.processed_contracts,
            "cache_hits": final_job.cache_hits,
            "cache_misses": final_job.cache_misses,
            "completed_at": final_job.completed_at,
            "error": final_job.error,
            "last_error_code": final_job.last_error_code,
            "summary": result_summary,
        }
        delivery = deliver_signed_webhook(
            webhook_url=req.webhook_url,
            payload=webhook_payload,
            hmac_secret=self._hmac_secret,
            signer=self._signer,
            dns_resolver=self._dns_resolver,
            transport=self._webhook_transport,
            max_attempts=self._webhook_max_attempts,
            backoff_base_seconds=self._webhook_backoff_base_seconds,
        )
        with self._lock:
            cur = self._job_store.get(job_id) or final_job
            self._job_store.save(cur.model_copy(update={"webhook_delivery": delivery}))

    def process_claimed_job(
        self,
        claimed_job: PortfolioJobStatusResponse,
        *,
        worker_id: str,
        store: TemporalGraphStore | None = None,
        lease_seconds: float | None = None,
    ) -> PortfolioJobStatusResponse:
        """
        Executes a claimed `RUNNING` job resuming from any persisted per-contract
        checkpoints without re-evaluating already completed contracts.
        """
        job_id = claimed_job.job_id
        tenant_id = claimed_job.tenant_id
        eff_lease = float(
            lease_seconds if lease_seconds is not None else self._lease_seconds
        )
        req = self._job_store.get_request(job_id)
        if req is None:
            dead = claimed_job.model_copy(
                update={
                    "status": "DEAD_LETTER",
                    "worker_id": None,
                    "lease_expires_at": None,
                    "last_error_code": "MISSING_JOB_REQUEST",
                    "error": f"Request payload missing for portfolio job '{job_id}'.",
                    "completed_at": datetime.now(UTC).isoformat(),
                }
            )
            self._job_store.save(dead)
            return dead

        active_store = store or self._get_store()
        existing_checkpoints = self._job_store.list_checkpoints(job_id)

        impacts: list[PortfolioContractImpact] = []
        all_gazettes: set[str] = set()
        all_statutes: set[str] = set()
        cache_hits = 0
        cache_misses = 0
        remaining_contracts: list[PortfolioContractInput] = []

        for contract in req.contracts:
            cid = contract.contract_id or contract.document_id
            ckpt = existing_checkpoints.get(cid)
            if ckpt is not None:
                imp, gz, st, is_hit = ckpt
                impacts.append(imp)
                all_gazettes.update(gz)
                all_statutes.update(st)
                if is_hit:
                    cache_hits += 1
                else:
                    cache_misses += 1
            else:
                remaining_contracts.append(contract)

        processed = len(impacts)

        def _update_job(**updates: Any) -> PortfolioJobStatusResponse:
            with self._lock:
                cur = self._job_store.get(job_id) or claimed_job
                nxt = cur.model_copy(update=updates)
                self._job_store.save(nxt)
                return nxt

        try:
            with measure_latency_ms() as elapsed_holder:
                if remaining_contracts:
                    window_cache = _build_window_cache(
                        contracts=remaining_contracts,
                        from_date=req.from_date,
                        to_date=req.to_date,
                        default_regimes=req.regimes,
                        default_territorial_scope=req.default_territorial_scope,
                        store=active_store,
                    )
                    worker_count = min(
                        req.max_workers, max(1, len(remaining_contracts))
                    )
                    with ThreadPoolExecutor(max_workers=worker_count) as pool:
                        fut_to_cid: dict[Future[Any], str] = {}
                        for contract in remaining_contracts:
                            cid = contract.contract_id or contract.document_id
                            reg_key, eff_scope, _ = _window_cache_key(
                                contract, req.regimes, req.default_territorial_scope
                            )
                            fut = pool.submit(
                                self._contract_evaluator,
                                contract=contract,
                                from_date=req.from_date,
                                to_date=req.to_date,
                                default_regimes=req.regimes,
                                default_territorial_scope=req.default_territorial_scope,
                                persona=req.persona,
                                store=active_store,
                                precomputed_window=window_cache[(reg_key, eff_scope)],
                                clause_cache=self._clause_cache,
                                cache_bypass=req.cache_bypass,
                                tenant_id=tenant_id,
                            )
                            fut_to_cid[fut] = cid

                        for fut in as_completed(fut_to_cid):
                            cid = fut_to_cid[fut]
                            impact, ckpt_gz, ckpt_st, is_hit = fut.result()
                            self._job_store.save_checkpoint(
                                job_id=job_id,
                                contract_id=cid,
                                impact=impact,
                                gazettes=sorted(ckpt_gz),
                                statutes=sorted(ckpt_st),
                                is_hit=is_hit,
                            )
                            impacts.append(impact)
                            all_gazettes.update(ckpt_gz)
                            all_statutes.update(ckpt_st)
                            processed += 1
                            if is_hit:
                                cache_hits += 1
                            else:
                                cache_misses += 1
                            self._job_store.renew_lease(job_id, worker_id, eff_lease)
                            if processed % 10 == 0 or processed == len(req.contracts):
                                _update_job(
                                    processed_contracts=processed,
                                    cache_hits=cache_hits,
                                    cache_misses=cache_misses,
                                )

            resp = _assemble_portfolio_response(
                from_date=req.from_date,
                to_date=req.to_date,
                impacts=impacts,
                all_gazettes=all_gazettes,
                all_statutes=all_statutes,
                elapsed_ms=elapsed_holder[0],
            )
            emit_otel_attributes(
                {
                    "lexgraph.portfolio.job_id": job_id,
                    "lexgraph.cache_hits": cache_hits,
                    "lexgraph.cache_misses": cache_misses,
                    "lexgraph.cache_hit": cache_hits > 0,
                    "lexgraph.tenant_id": tenant_id,
                }
            )
            final_job = _update_job(
                status="COMPLETED",
                processed_contracts=processed,
                cache_hits=cache_hits,
                cache_misses=cache_misses,
                worker_id=None,
                lease_expires_at=None,
                last_error_code=None,
                error=None,
                completed_at=datetime.now(UTC).isoformat(),
                result=resp,
            )
            self._deliver_webhook_if_configured(
                job_id=job_id, req=req, final_job=final_job
            )
            return self._job_store.get(job_id) or final_job
        except (ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
            cur_job = self._job_store.get(job_id) or claimed_job
            err_code = type(exc).__name__
            if cur_job.attempt_count >= cur_job.max_attempts:
                dead_job = _update_job(
                    status="DEAD_LETTER",
                    processed_contracts=processed,
                    cache_hits=cache_hits,
                    cache_misses=cache_misses,
                    worker_id=None,
                    lease_expires_at=None,
                    last_error_code=err_code,
                    error=str(exc),
                    completed_at=datetime.now(UTC).isoformat(),
                )
                self._deliver_webhook_if_configured(
                    job_id=job_id, req=req, final_job=dead_job
                )
                return self._job_store.get(job_id) or dead_job

            requeued_job = _update_job(
                status="QUEUED",
                processed_contracts=processed,
                cache_hits=cache_hits,
                cache_misses=cache_misses,
                worker_id=None,
                lease_expires_at=None,
                last_error_code=err_code,
                error=str(exc),
            )
            return requeued_job

    def _dispatch_background_job(
        self,
        job_id: str,
        *,
        store: TemporalGraphStore | None = None,
    ) -> None:
        worker_id = f"embedded-{uuid.uuid4().hex[:8]}"

        def _run_job() -> None:
            claimed = self._job_store.claim_job_by_id(
                job_id, worker_id, self._lease_seconds
            )
            if claimed is None:
                return
            self.process_claimed_job(
                claimed,
                worker_id=worker_id,
                store=store,
                lease_seconds=self._lease_seconds,
            )

        runner_pool = ThreadPoolExecutor(max_workers=1)
        runner_fut = runner_pool.submit(_run_job)
        runner_pool.shutdown(wait=False)
        with self._lock:
            self._futures[job_id] = runner_fut

    def submit_job_with_meta(
        self,
        req: PortfolioAsyncJobRequest,
        *,
        tenant_id: str = "default-tenant",
        store: TemporalGraphStore | None = None,
        idempotency_key: str | None = None,
        auto_dispatch: bool | None = None,
    ) -> tuple[PortfolioJobStatusResponse, bool]:
        """
        Submits an async portfolio job with optional `Idempotency-Key` deduplication.
        Returns `(job, is_duplicate)`. Raises `IdempotencyConflictError` if the same key
        is reused with a differing payload within the same tenant.
        """
        if req.from_date > req.to_date:
            raise ValueError(
                f"from_date ({req.from_date.isoformat()}) must be on or before to_date ({req.to_date.isoformat()})."
            )

        if req.webhook_url:
            validate_webhook_url_ssrf(req.webhook_url, dns_resolver=self._dns_resolver)

        clean_key = idempotency_key.strip() if idempotency_key else None
        if clean_key == "":
            clean_key = None
        fingerprint = compute_job_payload_fingerprint(req)

        with self._lock:
            if clean_key is not None:
                existing = self._job_store.lookup_idempotency(
                    tenant_id=tenant_id, idempotency_key=clean_key
                )
                if existing is not None:
                    existing_job_id, existing_fp = existing
                    if existing_fp != fingerprint:
                        raise IdempotencyConflictError(
                            f"Idempotency-Key '{clean_key}' already bound to a different payload "
                            f"for tenant '{tenant_id}'."
                        )
                    existing_job = self._job_store.get(
                        existing_job_id, tenant_id=tenant_id
                    )
                    if existing_job is not None:
                        return existing_job, True

            job_id = f"PJOB-{uuid.uuid4().hex[:10].upper()}"
            now_iso = datetime.now(UTC).isoformat()
            initial_delivery = (
                WebhookDeliveryStatus(webhook_url=req.webhook_url, status="PENDING")
                if req.webhook_url
                else None
            )
            initial = PortfolioJobStatusResponse(
                job_id=job_id,
                tenant_id=tenant_id,
                status="QUEUED",
                total_contracts=len(req.contracts),
                processed_contracts=0,
                max_workers=req.max_workers,
                created_at=now_iso,
                webhook_url=req.webhook_url,
                webhook_delivery=initial_delivery,
                cache_hits=0,
                cache_misses=0,
                idempotency_key=clean_key,
                payload_fingerprint=fingerprint,
                attempt_count=0,
                max_attempts=self._max_attempts,
            )
            self._job_store.save(initial)
            self._job_store.save_request(job_id, req)
            if clean_key is not None:
                self._job_store.register_idempotency(
                    tenant_id=tenant_id,
                    idempotency_key=clean_key,
                    job_id=job_id,
                    payload_fingerprint=fingerprint,
                )

        should_dispatch = (
            auto_dispatch
            if auto_dispatch is not None
            else (self._worker_mode != "external")
        )
        if should_dispatch:
            self._dispatch_background_job(job_id, store=store)
        return initial, False

    def submit_job(
        self,
        req: PortfolioAsyncJobRequest,
        *,
        tenant_id: str = "default-tenant",
        store: TemporalGraphStore | None = None,
        idempotency_key: str | None = None,
        auto_dispatch: bool | None = None,
    ) -> PortfolioJobStatusResponse:
        job, _is_dup = self.submit_job_with_meta(
            req,
            tenant_id=tenant_id,
            store=store,
            idempotency_key=idempotency_key,
            auto_dispatch=auto_dispatch,
        )
        return job

    def get_job(
        self, job_id: str, *, tenant_id: str | None = None
    ) -> PortfolioJobStatusResponse | None:
        return self._job_store.get(job_id, tenant_id=tenant_id)

    def reap_stale_leases(
        self, *, now: datetime | None = None
    ) -> list[PortfolioJobStatusResponse]:
        return self._job_store.reap_stale_leases(now=now)

    def list_dlq(self, *, tenant_id: str) -> list[PortfolioJobStatusResponse]:
        return self._job_store.list_jobs(tenant_id=tenant_id, status="DEAD_LETTER")

    def requeue_job(
        self,
        job_id: str,
        *,
        tenant_id: str,
        reset_checkpoints: bool = False,
        auto_dispatch: bool | None = None,
    ) -> PortfolioJobStatusResponse | None:
        with self._lock:
            job = self._job_store.get(job_id, tenant_id=tenant_id)
            if job is None:
                return None
            if job.status not in {"DEAD_LETTER", "FAILED"}:
                raise PortfolioJobStateError(
                    f"Job '{job_id}' in status '{job.status}' cannot be requeued; "
                    f"only DEAD_LETTER or FAILED jobs may be requeued."
                )
            if reset_checkpoints:
                self._job_store.clear_checkpoints(job_id)
            now_iso = datetime.now(UTC).isoformat()
            requeued = job.model_copy(
                update={
                    "status": "QUEUED",
                    "attempt_count": 0,
                    "worker_id": None,
                    "lease_expires_at": None,
                    "heartbeat_at": None,
                    "completed_at": None,
                    "last_error_code": None,
                    "error": None,
                    "requeued_at": now_iso,
                }
            )
            self._job_store.save(requeued)

        should_dispatch = (
            auto_dispatch
            if auto_dispatch is not None
            else (self._worker_mode != "external")
        )
        if should_dispatch:
            self._dispatch_background_job(job_id)
        return requeued

    def run_worker_once(
        self,
        *,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
        now: datetime | None = None,
        store: TemporalGraphStore | None = None,
    ) -> PortfolioJobStatusResponse | None:
        """Reaps expired leases and processes at most one queued job synchronously."""
        eff_worker = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        eff_lease = float(
            lease_seconds if lease_seconds is not None else self._lease_seconds
        )
        self.reap_stale_leases(now=now)
        claimed = self._job_store.claim_next_queued_job(eff_worker, eff_lease, now=now)
        if claimed is None:
            return None
        return self.process_claimed_job(
            claimed,
            worker_id=eff_worker,
            store=store,
            lease_seconds=eff_lease,
        )

    def wait_for_job(
        self, job_id: str, *, timeout: float = 30.0
    ) -> PortfolioJobStatusResponse | None:
        with self._lock:
            fut = self._futures.get(job_id)
        if fut is not None:
            fut.result(timeout=timeout)
        return self.get_job(job_id)


default_portfolio_job_manager = PortfolioJobManager()
