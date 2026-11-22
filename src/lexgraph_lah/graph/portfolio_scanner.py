"""
Zero-token Portfolio Gazette Blast-Radius Engine (`scan_portfolio_blast_radius` & Async Jobs).

Evaluates synchronous batches of up to 50 contracts OR asynchronous bounded-concurrency
enterprise jobs of 500–2,000+ contracts (including `.zip` archives of `.docx`/`.pdf`/`.txt`)
across bi-temporal statutory/P.U. gazette windows (`from_date` -> `to_date`), ranking
exposure by severity, newly broken clauses, strictest territorial deontic bounds, and
PII-safe delta remediation summaries.
"""

from __future__ import annotations

import io
import threading
import uuid
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lexgraph_lah.config import settings
from lexgraph_lah.graph.deontic_solver import normalize_regimes
from lexgraph_lah.graph.diff_engine import (
    compute_statutory_window_context,
    evaluate_contract_delta_impact,
)
from lexgraph_lah.ingestion.contract_ast import extract_contract_paragraphs
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
)
from lexgraph_lah.security.doc_firewall import (
    scan_document_security,
    validate_zip_archive_safety,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import measure_latency_ms

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
            cache[key] = compute_statutory_window_context(
                from_date=from_date,
                to_date=to_date,
                regimes=eff_regimes,
                territorial_scope=eff_scope,
                store=store,
            )
    return cache


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
        rem_pract = (
            f"[{contract.document_id}] Scope={eff_scope.value}; "
            f"Risk={delta.from_overall_risk.value}->{delta.to_overall_risk.value}; "
            f"Broken rules={', '.join(broken_rule_ids) or 'THRESHOLD_SHIFT'}. "
            f"Tighten clauses to satisfy [{bounds_hint}]."
        )
        rem_rakyat = (
            f"Contract '{contract.title or contract.document_id}' ({eff_scope.value}) "
            f"needs updates for {broken_count} new rule(s) taking effect by "
            f"{to_date.isoformat()}."
        )
    else:
        rem_pract = (
            f"[{contract.document_id}] Scope={eff_scope.value}; no new statutory "
            f"delta regressions between {from_date.isoformat()} and {to_date.isoformat()}."
        )
        rem_rakyat = (
            f"Contract '{contract.title or contract.document_id}' remained unaffected by "
            f"new rules between {from_date.isoformat()} and {to_date.isoformat()}."
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


class PortfolioJobManager:
    """
    Bounded-concurrency async portfolio blast-radius job runner for 500–2,000+ contracts
    and uploaded `.zip` contract archives.
    """

    def __init__(self, *, store: TemporalGraphStore | None = None) -> None:
        self._store = store
        self._lock = threading.RLock()
        self._jobs: dict[str, PortfolioJobStatusResponse] = {}
        self._futures: dict[str, Future[None]] = {}

    def _get_store(self) -> TemporalGraphStore:
        if self._store is None:
            from lexgraph_lah.graph.temporal_store import get_default_temporal_store

            self._store = get_default_temporal_store()
        return self._store

    def submit_job(
        self,
        req: PortfolioAsyncJobRequest,
        *,
        tenant_id: str = "default-tenant",
        store: TemporalGraphStore | None = None,
    ) -> PortfolioJobStatusResponse:
        if req.from_date > req.to_date:
            raise ValueError(
                f"from_date ({req.from_date.isoformat()}) must be on or before to_date ({req.to_date.isoformat()})."
            )

        job_id = f"PJOB-{uuid.uuid4().hex[:10].upper()}"
        now_iso = datetime.now(UTC).isoformat()
        initial = PortfolioJobStatusResponse(
            job_id=job_id,
            tenant_id=tenant_id,
            status="QUEUED",
            total_contracts=len(req.contracts),
            processed_contracts=0,
            max_workers=req.max_workers,
            created_at=now_iso,
        )
        with self._lock:
            self._jobs[job_id] = initial

        active_store = store or self._get_store()

        def _run_job() -> None:
            with self._lock:
                cur = self._jobs[job_id]
                self._jobs[job_id] = cur.model_copy(
                    update={
                        "status": "RUNNING",
                        "started_at": datetime.now(UTC).isoformat(),
                    }
                )
            try:
                with measure_latency_ms() as elapsed_holder:
                    window_cache = _build_window_cache(
                        contracts=req.contracts,
                        from_date=req.from_date,
                        to_date=req.to_date,
                        default_regimes=req.regimes,
                        default_territorial_scope=req.default_territorial_scope,
                        store=active_store,
                    )
                    impacts: list[PortfolioContractImpact] = []
                    all_gazettes: set[str] = set()
                    all_statutes: set[str] = set()
                    worker_count = min(req.max_workers, max(1, len(req.contracts)))

                    with ThreadPoolExecutor(max_workers=worker_count) as pool:
                        futs = []
                        for contract in req.contracts:
                            reg_key, eff_scope, _ = _window_cache_key(
                                contract, req.regimes, req.default_territorial_scope
                            )
                            futs.append(
                                pool.submit(
                                    _evaluate_single_portfolio_contract,
                                    contract=contract,
                                    from_date=req.from_date,
                                    to_date=req.to_date,
                                    default_regimes=req.regimes,
                                    default_territorial_scope=req.default_territorial_scope,
                                    persona=req.persona,
                                    store=active_store,
                                    precomputed_window=window_cache[
                                        (reg_key, eff_scope)
                                    ],
                                )
                            )
                        for fut in as_completed(futs):
                            impact, gz, st = fut.result()
                            impacts.append(impact)
                            all_gazettes.update(gz)
                            all_statutes.update(st)
                            with self._lock:
                                cur = self._jobs[job_id]
                                self._jobs[job_id] = cur.model_copy(
                                    update={
                                        "processed_contracts": cur.processed_contracts
                                        + 1
                                    }
                                )

                resp = _assemble_portfolio_response(
                    from_date=req.from_date,
                    to_date=req.to_date,
                    impacts=impacts,
                    all_gazettes=all_gazettes,
                    all_statutes=all_statutes,
                    elapsed_ms=elapsed_holder[0],
                )
                with self._lock:
                    cur = self._jobs[job_id]
                    self._jobs[job_id] = cur.model_copy(
                        update={
                            "status": "COMPLETED",
                            "completed_at": datetime.now(UTC).isoformat(),
                            "result": resp,
                        }
                    )
            except (ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
                with self._lock:
                    cur = self._jobs[job_id]
                    self._jobs[job_id] = cur.model_copy(
                        update={
                            "status": "FAILED",
                            "completed_at": datetime.now(UTC).isoformat(),
                            "error": str(exc),
                        }
                    )

        # Single coordinator background thread owns the bounded worker pool and status transitions
        runner_pool = ThreadPoolExecutor(max_workers=1)
        runner_fut = runner_pool.submit(_run_job)
        runner_pool.shutdown(wait=False)
        with self._lock:
            self._futures[job_id] = runner_fut
        return initial

    def get_job(
        self, job_id: str, *, tenant_id: str | None = None
    ) -> PortfolioJobStatusResponse | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if tenant_id is not None and job.tenant_id != tenant_id:
                return None
            return job

    def wait_for_job(
        self, job_id: str, *, timeout: float = 30.0
    ) -> PortfolioJobStatusResponse | None:
        with self._lock:
            fut = self._futures.get(job_id)
        if fut is not None:
            fut.result(timeout=timeout)
        return self.get_job(job_id)


default_portfolio_job_manager = PortfolioJobManager()
