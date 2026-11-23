"""
Zero-token Portfolio Gazette Blast-Radius Engine (`scan_portfolio_blast_radius` & Async Jobs).

Evaluates synchronous batches of up to 50 contracts OR asynchronous bounded-concurrency
enterprise jobs of 500–2,000+ contracts (including `.zip` archives of `.docx`/`.pdf`/`.txt`)
across bi-temporal statutory/P.U. gazette windows (`from_date` -> `to_date`), ranking
exposure by severity, newly broken clauses, strictest territorial deontic bounds, and
PII-safe delta remediation summaries.
"""

from __future__ import annotations

import importlib
import io
import sqlite3
import threading
import uuid
import zipfile
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import UTC, date, datetime
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


class PortfolioJobStoreBackend(Protocol):
    """Durable job storage backend protocol (`memory`, `sqlite`, `postgres`)."""

    def save(self, job: PortfolioJobStatusResponse) -> None: ...

    def get(
        self, job_id: str, *, tenant_id: str | None = None
    ) -> PortfolioJobStatusResponse | None: ...


class InMemoryPortfolioJobStore:
    """Thread-safe zero-config in-memory portfolio job store."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, PortfolioJobStatusResponse] = {}

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


class SQLitePortfolioJobStore:
    """SQLite WAL-backed durable portfolio job metadata and result store."""

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
    Bounded-concurrency async portfolio blast-radius job runner for 500–2,000+ contracts
    and uploaded `.zip` contract archives, with durable job persistence, Clause-AST
    isomorphic caching, and SSRF-validated dual-signed outbound webhooks.
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

        if req.webhook_url:
            validate_webhook_url_ssrf(req.webhook_url, dns_resolver=self._dns_resolver)

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
        )
        self._job_store.save(initial)

        active_store = store or self._get_store()

        def _update_job(**updates: Any) -> PortfolioJobStatusResponse:
            with self._lock:
                cur = self._job_store.get(job_id) or initial
                nxt = cur.model_copy(update=updates)
                self._job_store.save(nxt)
                return nxt

        def _deliver_webhook_if_configured(
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
                "event": "portfolio_job.completed"
                if final_job.status == "COMPLETED"
                else "portfolio_job.failed",
                "job_id": final_job.job_id,
                "tenant_id": final_job.tenant_id,
                "status": final_job.status,
                "total_contracts": final_job.total_contracts,
                "processed_contracts": final_job.processed_contracts,
                "cache_hits": final_job.cache_hits,
                "cache_misses": final_job.cache_misses,
                "completed_at": final_job.completed_at,
                "error": final_job.error,
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
            _update_job(webhook_delivery=delivery)

        def _run_job() -> None:
            _update_job(
                status="RUNNING",
                started_at=datetime.now(UTC).isoformat(),
            )
            cache_hits = 0
            cache_misses = 0
            processed = 0
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
                                    _evaluate_single_portfolio_contract_with_cache,
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
                                    clause_cache=self._clause_cache,
                                    cache_bypass=req.cache_bypass,
                                    tenant_id=tenant_id,
                                )
                            )
                        for fut in as_completed(futs):
                            impact, gz, st, is_hit = fut.result()
                            impacts.append(impact)
                            all_gazettes.update(gz)
                            all_statutes.update(st)
                            processed += 1
                            if is_hit:
                                cache_hits += 1
                            else:
                                cache_misses += 1
                            if processed % 25 == 0 or processed == len(req.contracts):
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
                    completed_at=datetime.now(UTC).isoformat(),
                    result=resp,
                )
                _deliver_webhook_if_configured(final_job)
            except (ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
                failed_job = _update_job(
                    status="FAILED",
                    processed_contracts=processed,
                    cache_hits=cache_hits,
                    cache_misses=cache_misses,
                    completed_at=datetime.now(UTC).isoformat(),
                    error=str(exc),
                )
                _deliver_webhook_if_configured(failed_job)

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
        return self._job_store.get(job_id, tenant_id=tenant_id)

    def wait_for_job(
        self, job_id: str, *, timeout: float = 30.0
    ) -> PortfolioJobStatusResponse | None:
        with self._lock:
            fut = self._futures.get(job_id)
        if fut is not None:
            fut.result(timeout=timeout)
        return self.get_job(job_id)


default_portfolio_job_manager = PortfolioJobManager()
