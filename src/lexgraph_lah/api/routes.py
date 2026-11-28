import asyncio
import base64
import binascii
import hashlib
import json
import threading
import time
import uuid
from collections import OrderedDict
from datetime import date
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from pydantic import BaseModel, Field, ValidationError

from lexgraph_lah.agents.graph import _DEFAULT_TEMPORAL_STORE, build_compliance_graph
from lexgraph_lah.attestation.bundle import build_lexpack_bundle
from lexgraph_lah.compliance.clause_cache import (
    compute_clause_ast_digest,
    compute_regime_set_hash,
    compute_statutory_graph_digest,
    default_clause_cache,
    record_cache_otel_event,
)
from lexgraph_lah.compliance.pdpa_scanner import scan_pdpa_compliance
from lexgraph_lah.compliance.sla_cascade import compile_incident_playbook
from lexgraph_lah.config import settings
from lexgraph_lah.graph.bilingual_critic import (
    audit_bilingual_divergence,
    audit_bilingual_pair,
)
from lexgraph_lah.graph.deontic_solver import DeonticEnvelopeResolver, normalize_regimes
from lexgraph_lah.graph.diff_engine import (
    diff_statute_lineage,
    evaluate_contract_delta_impact,
)
from lexgraph_lah.graph.portfolio_scanner import (
    IdempotencyConflictError,
    PortfolioJobStateError,
    default_portfolio_job_manager,
    extract_contracts_from_zip_archive,
    scan_portfolio_blast_radius,
)
from lexgraph_lah.graph.reranker import filter_by_territorial_scope
from lexgraph_lah.graph.temporal_store import build_point_in_time_cypher
from lexgraph_lah.hitl.precedent_playbook import (
    StatutoryFloorViolationError,
    default_precedent_playbook_store,
)
from lexgraph_lah.hitl.review_store import default_hitl_review_ledger
from lexgraph_lah.ingestion.contract_ast import build_contract_ast
from lexgraph_lah.ingestion.ooxml_redliner import compile_track_changes_docx
from lexgraph_lah.mcp.jsonrpc import handle_jsonrpc_message
from lexgraph_lah.mcp.tools import MCP_TOOL_DEFINITIONS, dispatch_mcp_tool_async
from lexgraph_lah.middleware.pii_scrubber import (
    ReversiblePIIVault,
    default_pii_session_store,
    scrub_malaysian_pii,
)
from lexgraph_lah.negotiation.counter_docx_compiler import (
    compile_counter_redline_docx,
)
from lexgraph_lah.negotiation.docx_redline_critic import (
    analyze_counterparty_docx_redlines,
)
from lexgraph_lah.retrieval.hybrid_retriever import default_hybrid_retriever
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    AttestationLedgerRecord,
    AttestationPublicKeyResponse,
    AttestationVerifyRequest,
    AttestationVerifyResponse,
    BilingualClausePair,
    BilingualDivergenceReport,
    BilingualDivergenceRequest,
    ClauseAudit,
    ComplianceAttestationManifest,
    ComplianceCheckRequest,
    CompositeDeonticEnvelope,
    ContractASTGraph,
    ContractAuditResponse,
    ContractDeltaAuditRequest,
    ContractDeltaAuditResponse,
    CounterpartyRedlineDiff,
    CounterpartyRedlineJsonRequest,
    CounterRedlineCompileRequest,
    CounterRedlineCompileResult,
    DocumentSecurityFinding,
    DocumentSecurityReport,
    GraphTopologyResponse,
    HITLReviewRecord,
    HITLReviewRequest,
    IncidentPlaybookRequest,
    IncidentPlaybookResponse,
    IRACAnalysis,
    OutputPersona,
    PDPAComplianceScanRequest,
    PDPAComplianceScanResponse,
    PIIScrubSummary,
    PlaybookListResponse,
    PlaybookPromoteRequest,
    PointInTimeResearchRequest,
    PointInTimeResearchResponse,
    PortfolioAsyncJobRequest,
    PortfolioBlastRadiusRequest,
    PortfolioBlastRadiusResponse,
    PortfolioDLQListResponse,
    PortfolioJobStatusResponse,
    PrecedentPlaybookRule,
    ProvisionLineageResponse,
    RakyatGuidance,
    RetrievalExplainRequest,
    RetrievalExplainResponse,
    RetrievalSearchResponse,
    RiskSeverity,
    SecurityScanRequest,
    StatutoryDiffRequest,
    StatutoryVersionDiff,
    TelemetryMetricsResponse,
    TenantFinOpsUsageResponse,
    TerritorialScope,
)
from lexgraph_lah.schemas.state import AgentState
from lexgraph_lah.security.attestation_ledger import (
    compute_manifest_sha256,
    default_attestation_ledger,
)
from lexgraph_lah.security.auth import get_request_tenant_id
from lexgraph_lah.security.doc_firewall import ZipBombError, scan_document_security
from lexgraph_lah.telemetry.cost_tracker import (
    compute_telemetry_summary,
    default_bnm_fx_provider,
    default_tenant_budget_tracker,
)
from lexgraph_lah.telemetry.tracer import (
    ComplianceSpanRecord,
    measure_latency_ms,
    telemetry_registry,
)
from lexgraph_lah.ui.render import render_workbench_html

router = APIRouter()


class PIIScrubRequest(BaseModel):
    text: str = Field(..., min_length=1)


class MCPToolCallRequest(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ExportDocxRequest(BaseModel):
    document_id: str = Field(default="MY-REDLINE-DOC", min_length=1)
    raw_text: str = Field(..., min_length=1)
    reference_date: date | None = None
    as_of_date: date | None = None
    act_filter: str | None = None
    regimes: list[str] | None = None
    territorial_scope: TerritorialScope | None = None
    persona: OutputPersona = OutputPersona.PRACTITIONER
    language: str = "bilingual"
    rehydrate_pii: bool = True
    audit_session_id: str | None = None
    findings: list[ClauseAudit] | None = None


_DEFAULT_DUAL_LAYER_CONTRACT = (
    'Clause 1 Definitions: "Security Incident" means confirmed unlawful disclosure causing downtime exceeding 48 hours. '
    "SEC-5.1 Breach Notification: Vendor shall notify Client of any personal data or NCII cyber security incident "
    "within 10 days. "
    "Clause 14 Liability Carve-Out: Notwithstanding Clause 5.1, the Vendor shall bear zero statutory liability "
    "and waives regulatory audit access."
)


def _resolve_fixtures_dir() -> Path:
    repo_root_candidate = Path(__file__).resolve().parents[3] / "examples" / "fixtures"
    if repo_root_candidate.is_dir():
        return repo_root_candidate
    return Path.cwd() / "examples" / "fixtures"


def _load_all_fixtures() -> list[dict[str, Any]]:
    fixtures_dir = _resolve_fixtures_dir()
    if not fixtures_dir.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for path in sorted(fixtures_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        data.setdefault("fixture_id", path.stem)
        data.setdefault("filename", path.name)
        items.append(data)
    return items


class _SyncedComplianceCache(dict[str, ContractAuditResponse]):
    """Keeps legacy `_COMPLIANCE_CACHE.clear()` synchronized with `default_clause_cache`."""

    def clear(self) -> None:
        super().clear()
        default_clause_cache.clear()


# Semantic/exact-match response cache to avoid redundant LLM billing on identical (text, reference_date, act_filter)
_COMPLIANCE_CACHE: dict[str, ContractAuditResponse] = _SyncedComplianceCache()

# Tenant-isolated LRU caches for `.lexpack.zip` `include_docx=true` hydration.
_SESSION_ARTIFACT_LOCK = threading.RLock()
_SESSION_DOCX_CACHE: OrderedDict[tuple[str, str], bytes] = OrderedDict()
_SESSION_AUDIT_SNAPSHOTS: OrderedDict[
    tuple[str, str], tuple[str, ContractAuditResponse]
] = OrderedDict()
_SESSION_NEGOTIATION_CACHE: OrderedDict[
    tuple[str, str], tuple[bytes | None, CounterpartyRedlineDiff]
] = OrderedDict()
_MAX_SESSION_ARTIFACTS = 256


def _store_session_docx(tenant_id: str, audit_session_id: str, data: bytes) -> None:
    if not audit_session_id:
        return
    with _SESSION_ARTIFACT_LOCK:
        key = (tenant_id, audit_session_id)
        _SESSION_DOCX_CACHE[key] = data
        _SESSION_DOCX_CACHE.move_to_end(key)
        while len(_SESSION_DOCX_CACHE) > _MAX_SESSION_ARTIFACTS:
            _SESSION_DOCX_CACHE.popitem(last=False)


def _get_session_docx(tenant_id: str, audit_session_id: str) -> bytes | None:
    with _SESSION_ARTIFACT_LOCK:
        return _SESSION_DOCX_CACHE.get((tenant_id, audit_session_id))


def _store_session_audit_snapshot(
    tenant_id: str, audit_session_id: str, raw_text: str, resp: ContractAuditResponse
) -> None:
    if not audit_session_id:
        return
    with _SESSION_ARTIFACT_LOCK:
        key = (tenant_id, audit_session_id)
        _SESSION_AUDIT_SNAPSHOTS[key] = (raw_text, resp)
        _SESSION_AUDIT_SNAPSHOTS.move_to_end(key)
        while len(_SESSION_AUDIT_SNAPSHOTS) > _MAX_SESSION_ARTIFACTS:
            _SESSION_AUDIT_SNAPSHOTS.popitem(last=False)


def _get_session_audit_snapshot(
    tenant_id: str, audit_session_id: str
) -> tuple[str, ContractAuditResponse] | None:
    with _SESSION_ARTIFACT_LOCK:
        return _SESSION_AUDIT_SNAPSHOTS.get((tenant_id, audit_session_id))


def _store_session_negotiation(
    tenant_id: str,
    audit_session_id: str,
    docx_bytes: bytes | None,
    diff: CounterpartyRedlineDiff,
) -> None:
    if not audit_session_id:
        return
    with _SESSION_ARTIFACT_LOCK:
        key = (tenant_id, audit_session_id)
        _SESSION_NEGOTIATION_CACHE[key] = (docx_bytes, diff)
        _SESSION_NEGOTIATION_CACHE.move_to_end(key)
        while len(_SESSION_NEGOTIATION_CACHE) > _MAX_SESSION_ARTIFACTS:
            _SESSION_NEGOTIATION_CACHE.popitem(last=False)


def _get_session_negotiation(
    tenant_id: str, audit_session_id: str
) -> tuple[bytes | None, CounterpartyRedlineDiff] | None:
    with _SESSION_ARTIFACT_LOCK:
        return _SESSION_NEGOTIATION_CACHE.get((tenant_id, audit_session_id))


_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
    RiskSeverity.CRITICAL: 4,
}


def _compute_overall_risk(clauses: list[ClauseAudit]) -> RiskSeverity:
    if not clauses:
        return RiskSeverity.LOW
    return max(clauses, key=lambda c: _SEVERITY_RANK[c.severity]).severity


def _cache_key(
    req: ComplianceCheckRequest,
    *,
    tenant_id: str = "default-tenant",
    playbook_digest: str = "",
) -> str:
    scope_val = (
        req.territorial_scope.value
        if req.territorial_scope
        else TerritorialScope.ALL_MALAYSIA.value
    )
    ref_d = req.as_of_date or req.reference_date or "TODAY"
    regimes_str = ",".join(normalize_regimes(req.regimes)) if req.regimes else "DEFAULT"
    payload = (
        f"{tenant_id}|{playbook_digest}|{req.raw_text.strip()}|{ref_d}|"
        f"{req.act_filter or 'ALL'}|{regimes_str}|{scope_val}|{req.persona.value}|{req.language}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _build_audit_persona_blocks(
    document_id: str,
    effective_date: date,
    clauses: list[ClauseAudit],
    overall_risk: RiskSeverity,
) -> tuple[IRACAnalysis, RakyatGuidance]:
    violated = sorted({sid for c in clauses for sid in c.violated_statute_ids})
    stat_str = ", ".join(violated) if violated else "Act 709 (PDPA) Part II Principles"
    high_risk_clauses = [
        c
        for c in clauses
        if c.severity in {RiskSeverity.MEDIUM, RiskSeverity.HIGH, RiskSeverity.CRITICAL}
    ]

    if not high_risk_clauses:
        irac = IRACAnalysis(
            issue=f"Whether {document_id} complies with Malaysian statutory provisions effective on {effective_date.isoformat()}.",
            rule=f"Applicable Malaysian provisions ({stat_str}) active as of {effective_date.isoformat()}.",
            application="All reviewed clauses satisfy baseline statutory safeguards without exclusionary waivers or delayed breach SLAs.",
            conclusion=f"Overall Risk: {overall_risk.value}. Clauses align with active Malaysian statutory mandates.",
        )
        rakyat = RakyatGuidance(
            plain_summary_en="This agreement meets Malaysia's personal data security and breach reporting timelines as of the selected date.",
            plain_summary_bm="Perjanjian ini mematuhi piawaian keselamatan data peribadi dan tempoh pemberitahuan kebocoran data Malaysia bagi tarikh ini.",
            gov_my_checklist=[
                "Keep your bilingual Bahasa Melayu and English privacy notice updated.",
                "Verify your Data Protection Officer (DPO) contact details at https://portal.pdp.gov.my.",
                "Retain signed compliance records for inspection by JPDP (https://www.pdp.gov.my).",
            ],
            official_portals=[
                "https://www.pdp.gov.my",
                "https://portal.pdp.gov.my",
                "https://lom.agc.gov.my",
            ],
        )
        return irac, rakyat

    cats = ", ".join(c.category for c in high_risk_clauses)
    irac = IRACAnalysis(
        issue=f"Whether {document_id} breaches statutory duties under {stat_str} as of {effective_date.isoformat()}.",
        rule=f"Malaysian statutory mandates ({stat_str}) governing data processor security liability and 72-hour breach notification.",
        application=f"Identified {len(high_risk_clauses)} exposed clause(s) across {cats}.",
        conclusion=f"Overall Risk: {overall_risk.value}. Adopt the recommended redlines prior to contract execution.",
    )
    rakyat = RakyatGuidance(
        plain_summary_en=(
            f"Attention ({overall_risk.value} Risk): This contract has {len(high_risk_clauses)} clause(s) "
            "that do not protect your personal data properly under Malaysian law (for example, shifting blame away from the vendor or delaying data leak alerts past 72 hours)."
        ),
        plain_summary_bm=(
            f"Perhatian (Risiko {overall_risk.value}): Kontrak ini mengandungi {len(high_risk_clauses)} klausa "
            "berisiko di bawah undang-undang Malaysia, seperti mengecualikan liabiliti pemproses data atau melambatkan notis kebocoran data."
        ),
        gov_my_checklist=[
            "Ask the vendor to remove any clause saying they have 'zero liability' if your data leaks.",
            "Ensure confirmed personal data breaches must be escalated in <= 24h so JPDP can be notified within 72h at https://portal.pdp.gov.my.",
            "Check official Malaysian PDPA guidance or file a public complaint at https://www.pdp.gov.my.",
        ],
        official_portals=[
            "https://www.pdp.gov.my",
            "https://portal.pdp.gov.my",
            "https://lom.agc.gov.my",
        ],
    )
    return irac, rakyat


def _build_initial_agent_state(
    payload: ComplianceCheckRequest,
    effective_date: date,
    scope: TerritorialScope,
    *,
    tenant_id: str | None = None,
) -> AgentState:
    return {
        "document_id": payload.document_id,
        "raw_text": payload.raw_text,
        "reference_date": effective_date.isoformat(),
        "act_filter": payload.act_filter,
        "regimes": normalize_regimes(payload.regimes) if payload.regimes else None,
        "territorial_scope": scope.value,
        "persona": payload.persona.value,
        "language": payload.language,
        "tenant_id": tenant_id,
        "abstention_threshold": payload.abstention_threshold
        or settings.abstention_threshold,
        "extracted_clauses": [],
        "auditor_feedback": "",
        "is_grounded": False,
        "retry_count": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }


def _finalize_audit_response(
    payload: ComplianceCheckRequest,
    final_state: dict[str, Any],
    effective_date: date,
    scope: TerritorialScope,
    elapsed_ms: float,
    record_span: bool = True,
    audit_session_id: str | None = None,
) -> ContractAuditResponse:
    clauses: list[ClauseAudit] = final_state.get("extracted_clauses", [])
    active_statutes = final_state.get("retrieved_statutes", [])
    pii_dict = final_state.get("pii_scrub")
    pii_scrub = PIIScrubSummary(**pii_dict) if isinstance(pii_dict, dict) else None
    overall_risk = _compute_overall_risk(clauses)

    bilingual_pairs: list[BilingualClausePair] = []
    divergence_warnings: list[BilingualDivergenceReport] = []
    seen_pairs: set[str] = set()
    for stat in active_statutes:
        pair = _DEFAULT_TEMPORAL_STORE.get_bilingual_pair(
            stat.node_id, include_divergence=True, as_of_date=effective_date
        )
        if pair:
            pair_key = f"{pair.act_number}:{pair.section_code}"
            if pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                bilingual_pairs.append(pair)
                if pair.divergence_report and pair.divergence_report.has_divergence:
                    divergence_warnings.append(pair.divergence_report)

    irac_summary, rakyat_summary = _build_audit_persona_blocks(
        document_id=payload.document_id,
        effective_date=effective_date,
        clauses=clauses,
        overall_risk=overall_risk,
    )

    span_id = final_state.get("trace_id") or f"span-{uuid.uuid4().hex[:8]}"
    is_abstained = bool(final_state.get("is_abstained", False))
    selected_model = final_state.get("selected_model")
    telemetry = compute_telemetry_summary(
        prompt_tokens=int(final_state.get("prompt_tokens", 0)),
        completion_tokens=int(final_state.get("completion_tokens", 0)),
        latency_ms=elapsed_ms,
        retry_count=int(final_state.get("retry_count", 0)),
        is_verified_grounded=bool(
            final_state.get("is_grounded", False) or is_abstained
        ),
        trace_id=span_id,
        model_name=selected_model,
    )

    if record_span:
        telemetry_registry.record_span(
            ComplianceSpanRecord(
                span_id=span_id,
                document_id=payload.document_id,
                reference_date=effective_date.isoformat(),
                active_statute_count=len(active_statutes),
                model_tier=selected_model,
                model_routing_reason=final_state.get("model_routing_reason"),
                telemetry=telemetry,
                timestamp_epoch=time.time(),
            )
        )

    env_dict = final_state.get("deontic_envelope")
    deontic_envelope = (
        CompositeDeonticEnvelope(**env_dict) if isinstance(env_dict, dict) else None
    )
    ast_dict = final_state.get("contract_ast")
    contract_ast = ContractASTGraph(**ast_dict) if isinstance(ast_dict, dict) else None
    sec_report_dict = final_state.get("security_report")
    security_report = (
        DocumentSecurityReport(**sec_report_dict)
        if isinstance(sec_report_dict, dict)
        else None
    )
    sec_findings_raw = final_state.get("security_findings") or []
    security_findings = [
        DocumentSecurityFinding(**f) if isinstance(f, dict) else f
        for f in sec_findings_raw
    ]
    manifest_dict = final_state.get("attestation_manifest")
    manifest: ComplianceAttestationManifest | None = None
    if isinstance(manifest_dict, dict):
        manifest = ComplianceAttestationManifest(**manifest_dict).model_copy(
            update={
                "estimated_cost_usd": telemetry.estimated_cost_usd,
                "estimated_cost_myr": telemetry.estimated_cost_myr,
                "total_tokens": telemetry.total_tokens,
                "model_used": selected_model,
                "trace_id": span_id,
            }
        )
        manifest.manifest_sha256 = compute_manifest_sha256(manifest)
        default_attestation_ledger.record(manifest, telemetry=telemetry)

    regimes_out = (
        normalize_regimes(payload.regimes)
        if payload.regimes
        else (deontic_envelope.regimes_evaluated if deontic_envelope else ["ACT_709"])
    )

    return ContractAuditResponse(
        document_id=payload.document_id,
        reference_date=effective_date,
        overall_risk=overall_risk,
        findings=clauses,
        active_statutes=active_statutes,
        telemetry=telemetry,
        is_abstained=is_abstained,
        abstention_reason=final_state.get("abstention_reason"),
        persona=payload.persona,
        territorial_scope=scope,
        regimes=regimes_out,
        language=payload.language,
        executive_summary=str(final_state.get("executive_summary", "")),
        pii_scrub=pii_scrub,
        bilingual_provisions=bilingual_pairs,
        bilingual_divergence_warnings=divergence_warnings,
        irac_summary=irac_summary,
        rakyat_summary=rakyat_summary,
        deontic_envelope=deontic_envelope,
        contract_ast=contract_ast,
        attestation_manifest=manifest,
        security_findings=security_findings,
        security_report=security_report,
        audit_session_id=audit_session_id,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )


async def _execute_compliance_check(
    payload: ComplianceCheckRequest,
    *,
    tenant_id: str,
    use_cache: bool = True,
) -> ContractAuditResponse:
    session_id = payload.audit_session_id or f"sess-{uuid.uuid4().hex[:12]}"
    effective_date = payload.as_of_date or payload.reference_date or date.today()
    scope = payload.territorial_scope or TerritorialScope.ALL_MALAYSIA
    cache_enabled = bool(use_cache and not payload.cache_bypass)
    playbook_digest = default_precedent_playbook_store.get_tenant_playbook_digest(
        tenant_id
    )
    key = _cache_key(payload, tenant_id=tenant_id, playbook_digest=playbook_digest)

    regimes_norm = normalize_regimes(payload.regimes) if payload.regimes else None
    reg_hash = compute_regime_set_hash(regimes_norm)
    stat_digest = compute_statutory_graph_digest(
        _DEFAULT_TEMPORAL_STORE,
        as_of_date=effective_date,
        territorial_scope=scope,
        regimes=regimes_norm,
    )
    ast_graph, _ = build_contract_ast(
        document_id=payload.document_id,
        raw_text=payload.raw_text,
        token_style="vault",
    )
    clause_digest = compute_clause_ast_digest(
        ast_graph,
        as_of_date=effective_date,
        territorial_scope=scope,
        regime_set_hash=reg_hash,
        statutory_graph_digest=stat_digest,
        persona=payload.persona.value,
        language=payload.language,
        act_filter=payload.act_filter,
        abstention_threshold=payload.abstention_threshold,
        playbook_digest=playbook_digest,
        cache_namespace="compliance",
    )

    if cache_enabled:
        cached_resp: ContractAuditResponse | None = None
        ast_hit = default_clause_cache.get(clause_digest)
        if isinstance(ast_hit, dict):
            cached_resp = ContractAuditResponse.model_validate(ast_hit)
        elif key in _COMPLIANCE_CACHE:
            cached_resp = _COMPLIANCE_CACHE[key]

        if cached_resp is not None:
            cur_pii = scrub_malaysian_pii(payload.raw_text)
            if cur_pii.placeholders:
                default_pii_session_store.save_session(
                    tenant_id, session_id, cur_pii.placeholders
                )
            zero_cost_telemetry = compute_telemetry_summary(
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=0.1,
                retry_count=0,
                is_verified_grounded=cached_resp.telemetry.is_verified_grounded,
                trace_id=cached_resp.telemetry.trace_id or "span-cached",
                cache_hit=True,
            )
            record_cache_otel_event(
                cache_hit=True,
                digest=clause_digest,
                surface="compliance",
                tenant_id=tenant_id,
            )
            default_tenant_budget_tracker.record_usage(
                tenant_id=tenant_id,
                telemetry=zero_cost_telemetry,
                cache_hit=True,
            )
            hit_resp = cached_resp.model_copy(
                update={
                    "document_id": payload.document_id,
                    "audit_session_id": session_id,
                    "pii_scrub": cur_pii,
                    "telemetry": zero_cost_telemetry,
                }
            )
            _store_session_audit_snapshot(
                tenant_id, session_id, payload.raw_text, hit_resp
            )
            return hit_resp

    exceeded, budget_policy, usage_snap = default_tenant_budget_tracker.check_budget(
        tenant_id
    )
    if exceeded and budget_policy == "reject_429":
        raise HTTPException(
            status_code=429,
            detail=(
                f"Tenant '{tenant_id}' exceeded monthly FinOps budget "
                f"(RM {usage_snap.cumulative_cost_myr:.4f} / "
                f"RM {usage_snap.monthly_budget_myr:.4f})."
            ),
        )

    graph = build_compliance_graph()
    initial_state = _build_initial_agent_state(
        payload, effective_date, scope, tenant_id=tenant_id
    )
    if exceeded and budget_policy == "deterministic_fallback":
        initial_state["force_deterministic_fallback"] = True

    with measure_latency_ms() as elapsed_holder:
        final_state = await graph.ainvoke(initial_state)

    response = _finalize_audit_response(
        payload=payload,
        final_state=final_state,
        effective_date=effective_date,
        scope=scope,
        elapsed_ms=elapsed_holder[0],
        record_span=True,
        audit_session_id=session_id,
    )
    fx_rate, fx_source = await default_bnm_fx_provider.get_usd_to_myr_rate()
    default_tenant_budget_tracker.record_usage(
        tenant_id=tenant_id,
        telemetry=response.telemetry,
        cache_hit=False,
        deterministic_fallback=bool(initial_state.get("force_deterministic_fallback")),
        fx_rate_used=fx_rate,
        fx_rate_source=fx_source,
    )
    record_cache_otel_event(
        cache_hit=False,
        digest=clause_digest,
        surface="compliance",
        tenant_id=tenant_id,
    )

    vault_map = final_state.get("pii_vault_map") or (
        response.pii_scrub.placeholders if response.pii_scrub else {}
    )
    if isinstance(vault_map, dict) and vault_map:
        default_pii_session_store.save_session(tenant_id, session_id, vault_map)
    if cache_enabled:
        _COMPLIANCE_CACHE[key] = response
        sanitized_for_ast_cache = response.model_dump(mode="json")
        if isinstance(sanitized_for_ast_cache.get("pii_scrub"), dict):
            # Never persist raw PII placeholders in shared ClauseASTCache.
            sanitized_for_ast_cache["pii_scrub"]["placeholders"] = {}
        default_clause_cache.set(clause_digest, sanitized_for_ast_cache)
    _store_session_audit_snapshot(tenant_id, session_id, payload.raw_text, response)
    return response


@router.post("/compliance/check", response_model=ContractAuditResponse)
async def check_compliance(
    payload: ComplianceCheckRequest,
    request: Request,
    use_cache: Annotated[
        bool, Query(description="Enable deterministic FinOps cache lookup")
    ] = True,
) -> ContractAuditResponse:
    """
    Executes the 5-node multi-regime temporal Graph-RAG & counterfactual compliance pipeline:
    1. Builds Intra-Contract Dependency AST + Reversible PII Vault (`contract_ast_ingestor`).
    2. Resolves active statutes, 0.78 Abstention Gate & Strictest Composite Deontic Envelope.
    3. Evaluates cross-clause traps & counterfactual redlines with FinOps USD/MYR telemetry.
    """
    tenant_id = get_request_tenant_id(request)
    return await _execute_compliance_check(
        payload, tenant_id=tenant_id, use_cache=use_cache
    )


def _sse_frame(event_name: str, data: dict[str, Any]) -> str:
    return f"event: {event_name}\ndata: {json.dumps(data, default=str)}\n\n"


@router.post("/compliance/stream")
async def stream_compliance(
    payload: ComplianceCheckRequest, request: Request
) -> StreamingResponse:
    """
    Real-time Server-Sent Events (`text/event-stream`) endpoint streaming live 5-node
    LangGraph state transitions, PII scrub counts, 0.78 Abstention Gate telemetry,
    counterfactual retry diffs, and real-time USD + MYR FinOps burn ticker.
    """
    tenant_id = get_request_tenant_id(request)
    effective_date = payload.as_of_date or payload.reference_date or date.today()
    scope = payload.territorial_scope or TerritorialScope.ALL_MALAYSIA
    graph = build_compliance_graph()
    initial_state = _build_initial_agent_state(
        payload, effective_date, scope, tenant_id=tenant_id
    )

    async def _event_generator():
        accumulated_state: dict[str, Any] = dict(initial_state)
        cumulative_prompt = 0
        cumulative_completion = 0
        start_time = time.perf_counter()
        step_idx = 0

        async for update in graph.astream(initial_state, stream_mode="updates"):
            for node_name, node_payload in update.items():
                step_idx += 1
                if not isinstance(node_payload, dict):
                    continue
                for k, v in node_payload.items():
                    if k == "prompt_tokens":
                        cumulative_prompt += int(v or 0)
                        accumulated_state[k] = cumulative_prompt
                    elif k == "completion_tokens":
                        cumulative_completion += int(v or 0)
                        accumulated_state[k] = cumulative_completion
                    else:
                        accumulated_state[k] = v

                elapsed_so_far = (time.perf_counter() - start_time) * 1000.0
                burn = compute_telemetry_summary(
                    prompt_tokens=cumulative_prompt,
                    completion_tokens=cumulative_completion,
                    latency_ms=elapsed_so_far,
                    retry_count=int(accumulated_state.get("retry_count", 0)),
                    is_verified_grounded=bool(
                        accumulated_state.get("is_grounded", False)
                    ),
                )

                node_event: dict[str, Any] = {
                    "step_index": step_idx,
                    "node": node_name,
                    "status": "completed",
                    "retry_count": int(accumulated_state.get("retry_count", 0)),
                    "is_abstained": bool(accumulated_state.get("is_abstained", False)),
                }
                if isinstance(accumulated_state.get("pii_scrub"), dict):
                    node_event["pii_redaction_count"] = accumulated_state[
                        "pii_scrub"
                    ].get("redaction_count", 0)
                if "max_relevance_score" in node_payload:
                    node_event["max_relevance_score"] = node_payload[
                        "max_relevance_score"
                    ]
                    node_event["abstention_threshold"] = initial_state[
                        "abstention_threshold"
                    ]

                yield _sse_frame("node_update", node_event)

                if node_name == "deontic_temporal_retriever":
                    yield _sse_frame(
                        "abstention_gate",
                        {
                            "threshold": initial_state["abstention_threshold"],
                            "max_relevance_score": accumulated_state.get(
                                "max_relevance_score", 1.0
                            ),
                            "is_abstained": bool(
                                accumulated_state.get("is_abstained", False)
                            ),
                            "abstention_reason": accumulated_state.get(
                                "abstention_reason"
                            ),
                            "active_statute_count": len(
                                accumulated_state.get("retrieved_statutes") or []
                            ),
                        },
                    )

                if node_name == "counterfactual_auditor":
                    cf_log = accumulated_state.get("counterfactual_log") or []
                    latest_cf = cf_log[-1] if cf_log else {}
                    yield _sse_frame(
                        "counterfactual_diff",
                        {
                            "attempt": latest_cf.get("attempt", 1),
                            "passed": bool(accumulated_state.get("is_grounded", False)),
                            "failures": latest_cf.get("failures", []),
                            "auditor_feedback": accumulated_state.get(
                                "auditor_feedback", ""
                            ),
                        },
                    )

                yield _sse_frame(
                    "finops_tick",
                    {
                        "node": node_name,
                        "prompt_tokens": cumulative_prompt,
                        "completion_tokens": cumulative_completion,
                        "total_tokens": burn.total_tokens,
                        "estimated_cost_usd": burn.estimated_cost_usd,
                        "estimated_cost_myr": burn.estimated_cost_myr,
                        "latency_ms": burn.latency_ms,
                    },
                )
                await asyncio.sleep(0)

        total_elapsed = (time.perf_counter() - start_time) * 1000.0
        final_response = _finalize_audit_response(
            payload=payload,
            final_state=accumulated_state,
            effective_date=effective_date,
            scope=scope,
            elapsed_ms=total_elapsed,
            record_span=True,
        )
        yield _sse_frame("complete", final_response.model_dump(mode="json"))

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


async def _parse_multipart_upload(
    request: Request,
) -> tuple[dict[str, str], bytes | None, str | None]:
    content_type = request.headers.get("content-type", "")
    body = await request.body()
    if "application/json" in content_type.lower():
        data = json.loads(body.decode("utf-8"))
        fields = {
            k: (",".join(v) if isinstance(v, list) else str(v))
            for k, v in data.items()
            if v is not None
        }
        return fields, None, None

    msg = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1") + b"\r\n\r\n" + body
    )
    fields = {}
    file_bytes: bytes | None = None
    filename: str | None = None
    if msg.is_multipart():
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            fname = part.get_filename()
            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes):
                continue
            if fname is not None or name == "file":
                file_bytes = payload
                filename = fname or "uploaded_contract.txt"
            elif name:
                val = payload.decode("utf-8", errors="replace")
                if name in fields and name == "regimes":
                    fields[name] = f"{fields[name]},{val}"
                else:
                    fields[name] = val
    return fields, file_bytes, filename


def _parse_regimes_field(raw_regimes: str | None) -> list[str]:
    if not raw_regimes or not raw_regimes.strip():
        return ["ACT_709"]
    trimmed = raw_regimes.strip()
    if trimmed.startswith("["):
        try:
            loaded = json.loads(trimmed)
            if isinstance(loaded, list):
                return normalize_regimes([str(x) for x in loaded])
        except json.JSONDecodeError:
            pass
    parts = [p.strip() for p in trimmed.split(",") if p.strip()]
    return normalize_regimes(parts)


def _normalize_lang_literal(raw: str) -> Literal["bm", "ms", "en", "bilingual"]:
    low = raw.strip().lower()
    if low == "bm":
        return "bm"
    if low == "ms":
        return "ms"
    if low == "en":
        return "en"
    return "bilingual"


@router.post("/compliance/upload", response_model=ContractAuditResponse)
async def upload_compliance_contract(request: Request) -> ContractAuditResponse:
    """
    Multipart `.docx` / `.pdf` / `.txt` multi-regime contract audit endpoint supporting
    pre-AST IPI firewall scanning, `regimes`, `as_of_date`, `territorial_scope`, `persona`,
    and `language`.
    """
    fields, file_bytes, filename = await _parse_multipart_upload(request)
    raw_text_field = fields.get("raw_text", "")
    if not raw_text_field and file_bytes is None:
        raise HTTPException(
            status_code=422,
            detail="Provide either a multipart 'file' (.docx/.pdf/.txt) or 'raw_text'.",
        )

    doc_id = fields.get("document_id") or filename or f"UPLOAD-{uuid.uuid4().hex[:6]}"
    date_str = fields.get("as_of_date") or fields.get("reference_date")
    effective_date = date.fromisoformat(date_str) if date_str else date.today()
    regimes = _parse_regimes_field(fields.get("regimes"))
    scope = TerritorialScope(
        fields.get("territorial_scope") or TerritorialScope.ALL_MALAYSIA.value
    )
    persona = OutputPersona(fields.get("persona") or OutputPersona.PRACTITIONER.value)
    lang = fields.get("language") or "bilingual"

    try:
        sec_report = scan_document_security(
            document_id=doc_id,
            raw_text=raw_text_field or None,
            file_bytes=file_bytes,
            filename=filename,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    extracted_text = sec_report.sanitized_text
    if not extracted_text.strip():
        if sec_report.findings:
            return ContractAuditResponse(
                document_id=doc_id,
                reference_date=effective_date,
                overall_risk=sec_report.risk_level,
                findings=[],
                active_statutes=[],
                telemetry=sec_report.telemetry,
                is_abstained=True,
                abstention_reason="Uploaded document contained only quarantined adversarial payloads.",
                persona=persona,
                territorial_scope=scope,
                regimes=regimes or ["ACT_709"],
                language=_normalize_lang_literal(lang),
                executive_summary=(
                    f"SECURITY FIREWALL ABSTAINED: Blocked {sec_report.blocked_injection_count} "
                    "adversarial payload(s) with zero benign clauses remaining."
                ),
                pii_scrub=scrub_malaysian_pii(""),
                security_findings=sec_report.findings,
                security_report=sec_report,
                disclaimer=DEFAULT_LEGAL_DISCLAIMER,
            )
        raise HTTPException(
            status_code=422, detail="Uploaded document contained no readable text."
        )

    payload = ComplianceCheckRequest(
        document_id=doc_id,
        raw_text=extracted_text,
        reference_date=effective_date,
        as_of_date=effective_date,
        regimes=regimes,
        territorial_scope=scope,
        persona=persona,
        language=_normalize_lang_literal(lang),
    )
    resp = await _execute_compliance_check(
        payload, tenant_id=get_request_tenant_id(request), use_cache=False
    )
    return resp.model_copy(
        update={
            "security_report": sec_report,
            "security_findings": sec_report.findings or resp.security_findings,
        }
    )


@router.post("/compliance/export-docx")
async def export_redline_docx(payload: ExportDocxRequest) -> Response:
    """
    Compiles and streams a genuine Microsoft Word Track-Changes `.docx` containing native
    `<w:del>` deletions, `<w:ins>` insertions (author `lexgraph-lah`), `<w:comment>` statutory
    lineage callouts, optional local PII re-hydration, and cryptographic attestation headers.
    """
    tenant_id = get_request_tenant_id()
    effective_date = payload.as_of_date or payload.reference_date or date.today()
    scope = payload.territorial_scope or TerritorialScope.ALL_MALAYSIA
    regimes = normalize_regimes(payload.regimes) if payload.regimes else ["ACT_709"]

    check_req = ComplianceCheckRequest(
        document_id=payload.document_id,
        raw_text=payload.raw_text,
        reference_date=effective_date,
        as_of_date=effective_date,
        act_filter=payload.act_filter,
        regimes=regimes,
        territorial_scope=scope,
        persona=payload.persona,
        language=_normalize_lang_literal(payload.language),
        audit_session_id=payload.audit_session_id,
    )

    graph = build_compliance_graph()
    initial_state = _build_initial_agent_state(check_req, effective_date, scope)
    with measure_latency_ms() as elapsed_holder:
        final_state = await graph.ainvoke(initial_state)

    audit_resp = _finalize_audit_response(
        payload=check_req,
        final_state=final_state,
        effective_date=effective_date,
        scope=scope,
        elapsed_ms=elapsed_holder[0],
        record_span=True,
        audit_session_id=payload.audit_session_id,
    )
    findings = payload.findings if payload.findings is not None else audit_resp.findings
    vault_map: dict[str, str] = dict(final_state.get("pii_vault_map") or {})
    persisted_map: dict[str, str] | None = None
    if payload.audit_session_id:
        persisted_map = default_pii_session_store.load_session(
            tenant_id=tenant_id, audit_session_id=payload.audit_session_id
        )
    merged_vault_map: dict[str, str] = {
        **(audit_resp.pii_scrub.placeholders if audit_resp.pii_scrub else {}),
        **vault_map,
        **(persisted_map or {}),
    }
    vault = ReversiblePIIVault(initial_mapping=merged_vault_map)

    docx_bytes = compile_track_changes_docx(
        document_id=payload.document_id,
        raw_text=payload.raw_text,
        findings=findings,
        active_statutes=audit_resp.active_statutes,
        deontic_envelope=audit_resp.deontic_envelope,
        contract_ast=audit_resp.contract_ast,
        manifest=audit_resp.attestation_manifest,
        rehydrate_pii=payload.rehydrate_pii,
        pii_vault=vault,
        pii_placeholders=merged_vault_map,
    )
    if payload.audit_session_id:
        _store_session_docx(tenant_id, payload.audit_session_id, docx_bytes)
        _store_session_audit_snapshot(
            tenant_id, payload.audit_session_id, payload.raw_text, audit_resp
        )

    manifest = audit_resp.attestation_manifest
    safe_name = "".join(
        c if c.isalnum() or c in "-_" else "_" for c in payload.document_id
    )
    headers = {
        "Content-Disposition": f'attachment; filename="{safe_name}_redlined.docx"',
        "X-LexGraph-Attestation-SHA256": manifest.manifest_sha256 if manifest else "",
        "X-LexGraph-Attestation-Signature": manifest.signature_b64 if manifest else "",
        "X-LexGraph-Signing-Key-Id": manifest.signing_key_id if manifest else "",
        "X-LexGraph-Audit-Session-Id": payload.audit_session_id or "",
        "X-LexGraph-Graph-Hash": manifest.graph_state_hash if manifest else "",
        "X-LexGraph-As-Of-Date": effective_date.isoformat(),
        "X-LexGraph-FinOps-USD": f"{audit_resp.telemetry.estimated_cost_usd:.6f}",
        "X-LexGraph-FinOps-MYR": f"{audit_resp.telemetry.estimated_cost_myr:.6f}",
        "X-LexGraph-Trace-Id": audit_resp.telemetry.trace_id or "",
    }
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers=headers,
    )


@router.get("/api/v1/deontic/envelope", response_model=CompositeDeonticEnvelope)
async def api_v1_deontic_envelope(
    regimes: Annotated[
        str, Query(description="Comma-separated regimes, e.g. ACT_709,ACT_854,BNM_RMIT")
    ] = "ACT_709,ACT_854,BNM_RMIT",
    as_of_date: Annotated[
        date | None, Query(description="Point-in-time evaluation date (YYYY-MM-DD)")
    ] = None,
    territorial_scope: Annotated[
        str | None, Query(description="Malaysian territorial scope filter")
    ] = None,
) -> CompositeDeonticEnvelope:
    """Zero-token Multi-Regime Deontic Conflict Envelope resolver endpoint."""
    resolver = DeonticEnvelopeResolver(_DEFAULT_TEMPORAL_STORE)
    return resolver.resolve(
        regimes=_parse_regimes_field(regimes),
        as_of_date=as_of_date or date.today(),
        territorial_scope=territorial_scope,
    )


@router.post("/api/v1/compliance/scan", response_model=PDPAComplianceScanResponse)
async def api_v1_compliance_scan(
    payload: PDPAComplianceScanRequest,
) -> PDPAComplianceScanResponse:
    """
    Pre-flight PII-scrubbed Act 709 (PDPA) Compliance Gap Scanner returning strict
    Pydantic/JSON gap analysis mapped to Act 709 principles, 5-tier authority weights,
    bilingual EN/BM provisions, and verifiable SourceSpan IDs.
    """
    return scan_pdpa_compliance(payload, store=_DEFAULT_TEMPORAL_STORE)


@router.post("/api/v1/pii/scrub", response_model=PIIScrubSummary)
async def api_v1_pii_scrub(payload: PIIScrubRequest) -> PIIScrubSummary:
    """Masks Malaysian NRIC, Passport, Phone, Email, and SSM numbers in <50ms."""
    return scrub_malaysian_pii(payload.text)


@router.get("/api/v1/retrieval/search", response_model=RetrievalSearchResponse)
async def api_v1_retrieval_search(
    q: Annotated[
        str,
        Query(..., min_length=1, description="BM, EN, or code-switched legal query"),
    ],
    as_of_date: Annotated[
        date | None, Query(description="Point-in-time date (YYYY-MM-DD)")
    ] = None,
    territorial_scope: Annotated[
        str | None,
        Query(
            description="Peninsular Malaysia | Sabah | Sarawak | Federal Territories | All Malaysia"
        ),
    ] = None,
    threshold: Annotated[
        float | None,
        Query(
            ge=0.0, le=1.0, description="Abstention relevance threshold (default 0.78)"
        ),
    ] = None,
) -> RetrievalSearchResponse:
    """
    Hybrid bilingual statutory search with 5-tier Malaysian authority reranking,
    territorial scope filtering, and deterministic 0.78 Abstention Gate.
    """
    effective_threshold = (
        threshold if threshold is not None else settings.abstention_threshold
    )
    return _DEFAULT_TEMPORAL_STORE.search_with_abstention(
        query=q,
        as_of_date=as_of_date or date.today(),
        territorial_scope=territorial_scope,
        abstention_threshold=effective_threshold,
    )


@router.post("/api/v1/retrieval/explain", response_model=RetrievalExplainResponse)
async def api_v1_retrieval_explain(
    payload: RetrievalExplainRequest,
) -> RetrievalExplainResponse:
    """
    Bilingual Hybrid Statutory Retrieval explainability endpoint returning per-candidate
    `bm25_score`, `vector_score`, `graph_boost_score`, `rrf_score`, `calibrated_score`,
    `temporal_valid`, and `territorial_tier` breakdown (`viewer`/`auditor`/`admin`).
    """
    return default_hybrid_retriever.explain(
        query=payload.query,
        as_of_date=payload.as_of_date or date.today(),
        territorial_scope=payload.territorial_scope,
        top_k=payload.top_k,
        abstention_threshold=payload.abstention_threshold,
        regimes=payload.regimes,
        store=_DEFAULT_TEMPORAL_STORE,
    )


@router.get("/api/v1/statutes/{node_id}/bilingual", response_model=BilingualClausePair)
async def api_v1_bilingual_statute(
    node_id: str,
    include_divergence: Annotated[bool, Query()] = True,
    as_of_date: Annotated[date | None, Query()] = None,
) -> BilingualClausePair:
    """Returns synchronized English (Section) & Bahasa Melayu (Seksyen) statutory pair + SourceSpans."""
    pair = _DEFAULT_TEMPORAL_STORE.get_bilingual_pair(
        node_id,
        include_divergence=include_divergence,
        as_of_date=as_of_date,
    )
    if not pair:
        raise HTTPException(
            status_code=404, detail=f"Statutory node '{node_id}' not found."
        )
    return pair


@router.get("/api/v1/lineage/diff", response_model=StatutoryVersionDiff)
async def api_v1_lineage_diff_get(
    provision_id: Annotated[
        str, Query(..., min_length=1, description="Target statutory provision node ID")
    ],
    from_date: Annotated[
        date, Query(..., description="Baseline comparison date (YYYY-MM-DD)")
    ],
    to_date: Annotated[
        date, Query(..., description="Target comparison date (YYYY-MM-DD)")
    ],
) -> StatutoryVersionDiff:
    """Zero-token bi-temporal statutory redline diff across AMENDED_BY / REPEALED_BY chains."""
    try:
        return diff_statute_lineage(
            provision_id=provision_id,
            from_date=from_date,
            to_date=to_date,
            store=_DEFAULT_TEMPORAL_STORE,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/api/v1/lineage/diff", response_model=StatutoryVersionDiff)
async def api_v1_lineage_diff_post(
    payload: StatutoryDiffRequest,
) -> StatutoryVersionDiff:
    """Zero-token bi-temporal statutory redline diff endpoint."""
    try:
        return diff_statute_lineage(
            provision_id=payload.provision_id,
            from_date=payload.from_date,
            to_date=payload.to_date,
            store=_DEFAULT_TEMPORAL_STORE,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/api/v1/lineage/delta-audit", response_model=ContractDeltaAuditResponse)
async def api_v1_lineage_delta_audit(
    payload: ContractDeltaAuditRequest,
    request: Request,
) -> ContractDeltaAuditResponse:
    """
    Zero-token Contract Delta-Audit evaluating whether a contract compliant at `from_date`
    becomes non-compliant at `to_date` due to intervening statutory/P.U. amendments,
    with pre-flight Malaysian PII scrubbing.
    """
    try:
        result = evaluate_contract_delta_impact(payload, store=_DEFAULT_TEMPORAL_STORE)
        request.state.pii_scrub_latency_ms = result.pii_scrub.scrub_latency_ms
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/api/v1/crosswalk/{node_id}/divergence",
    response_model=BilingualDivergenceReport,
)
async def api_v1_crosswalk_divergence_get(
    node_id: str,
    as_of_date: Annotated[
        date | None, Query(description="Point-in-time date (YYYY-MM-DD)")
    ] = None,
) -> BilingualDivergenceReport:
    """Act 388 s. 63 Bilingual Divergence Critic inspecting paired BM/EN statutory nodes."""
    try:
        return audit_bilingual_divergence(
            node_id=node_id,
            as_of_date=as_of_date,
            store=_DEFAULT_TEMPORAL_STORE,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/v1/crosswalk/divergence", response_model=BilingualDivergenceReport)
async def api_v1_crosswalk_divergence_post(
    payload: BilingualDivergenceRequest,
    request: Request,
) -> BilingualDivergenceReport:
    """
    Act 388 s. 63 Bilingual Divergence Critic supporting stored `node_id` lookup or
    PII-scrubbed inline `en_text` vs `bm_text` comparison.
    """
    try:
        if payload.en_text or payload.bm_text:
            en_scrub = scrub_malaysian_pii(payload.en_text or "")
            bm_scrub = scrub_malaysian_pii(payload.bm_text or "")
            request.state.pii_scrub_latency_ms = round(
                en_scrub.scrub_latency_ms + bm_scrub.scrub_latency_ms, 4
            )
            return audit_bilingual_pair(
                en_node=None,
                bm_node=None,
                authoritative_language=payload.authoritative_language,
                as_of_date=payload.as_of_date or date.today(),
                provision_id=payload.node_id,
                act_name=payload.act_name,
                act_number=payload.act_number,
                section_code=payload.section_code,
                en_text=en_scrub.masked_text if payload.en_text is not None else None,
                bm_text=bm_scrub.masked_text if payload.bm_text is not None else None,
            )
        return audit_bilingual_divergence(
            node_id=payload.node_id,
            as_of_date=payload.as_of_date,
            store=_DEFAULT_TEMPORAL_STORE,
            authoritative_language=payload.authoritative_language,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/api/v1/research/point-in-time", response_model=PointInTimeResearchResponse
)
async def api_v1_research_point_in_time(
    payload: PointInTimeResearchRequest,
) -> PointInTimeResearchResponse:
    """
    Executes Point-in-Time Statutory Lineage & Bilingual (BM <-> EN) Crosswalk research,
    returning grounded claims with verbatim SourceSpans, 7-tier Malaysian authority breakdown,
    chronological amendment_timeline, bilingual crosswalk, and subgraph data.
    """
    return _DEFAULT_TEMPORAL_STORE.execute_point_in_time_research(payload)


@router.get(
    "/api/v1/provisions/{provision_id}/lineage", response_model=ProvisionLineageResponse
)
async def api_v1_provision_lineage(
    provision_id: str,
    as_of_date: Annotated[
        date | None, Query(description="Point-in-time evaluation date (YYYY-MM-DD)")
    ] = None,
    include_repealed_lineage: Annotated[
        bool, Query(description="Include superseded/repealed versions")
    ] = True,
) -> ProvisionLineageResponse:
    """
    Returns full chronological amendment history, linked BM/EN counterpart text,
    and judicial treatments for a Malaysian statutory provision.
    """
    try:
        return _DEFAULT_TEMPORAL_STORE.get_provision_lineage(
            provision_id=provision_id,
            as_of_date=as_of_date,
            include_repealed_lineage=include_repealed_lineage,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/v1/mcp/tools")
async def api_v1_mcp_tools() -> dict[str, Any]:
    """Lists MCP-compatible tools exposed by lexgraph-lah."""
    return {"tools": MCP_TOOL_DEFINITIONS}


@router.post("/api/v1/mcp/call")
async def api_v1_mcp_call(payload: MCPToolCallRequest) -> dict[str, Any]:
    """Invokes an MCP tool wrapper cleanly via HTTP."""
    try:
        result = await dispatch_mcp_tool_async(payload.name, payload.arguments)
        return {"tool": payload.name, "result": result}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/v1/security/scan", response_model=DocumentSecurityReport)
async def api_v1_security_scan(request: Request) -> DocumentSecurityReport:
    """
    Zero-token Adversarial Document Sanitizer & Indirect Prompt Injection (IPI) Firewall.
    Accepts either JSON (`SecurityScanRequest`) or multipart `.docx`/`.pdf`/`.txt` upload.
    """
    content_type = request.headers.get("content-type", "").lower()
    if "multipart/form-data" in content_type:
        fields, file_bytes, filename = await _parse_multipart_upload(request)
        raw_text_val = fields.get("raw_text") or None
        if raw_text_val is None and file_bytes is None:
            raise HTTPException(
                status_code=422,
                detail="Provide either multipart 'file' (.docx/.pdf/.txt) or 'raw_text'.",
            )
        doc_id = fields.get("document_id") or filename or "SEC-SCAN-001"
        try:
            return scan_document_security(
                document_id=doc_id,
                raw_text=raw_text_val,
                file_bytes=file_bytes,
                filename=filename,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        raw_body = await request.json()
        parsed_req = SecurityScanRequest(**raw_body)
    except (json.JSONDecodeError, TypeError, ValidationError, ValueError) as exc:
        raise HTTPException(
            status_code=422, detail=f"Invalid request body: {exc}"
        ) from exc

    return scan_document_security(
        document_id=parsed_req.document_id,
        raw_text=parsed_req.raw_text,
    )


@router.post(
    "/api/v1/portfolio/blast-radius", response_model=PortfolioBlastRadiusResponse
)
async def api_v1_portfolio_blast_radius(
    payload: PortfolioBlastRadiusRequest,
) -> PortfolioBlastRadiusResponse:
    """
    Zero-token Batch Gazette Blast-Radius Scanner evaluating up to 50 contracts across
    bi-temporal statutory commencements and East/West Malaysian territorial bounds.
    """
    try:
        return scan_portfolio_blast_radius(payload, store=_DEFAULT_TEMPORAL_STORE)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/api/v1/portfolio/jobs",
    status_code=202,
    response_model=PortfolioJobStatusResponse,
)
async def api_v1_submit_portfolio_job(
    request: Request, response: Response
) -> PortfolioJobStatusResponse:
    """
    Asynchronous Portfolio Blast-Radius Job submission supporting 500-2,000+ contracts
    via JSON (`PortfolioAsyncJobRequest`) OR multipart `.zip` archives of `.docx`/`.pdf`/`.txt` files
    with `Idempotency-Key` deduplication (`200` replay / `409 Conflict` on mismatch) and
    crash-recoverable worker leases.
    """
    tenant_id = get_request_tenant_id(request)
    idempotency_key = request.headers.get("idempotency-key")
    content_type = request.headers.get("content-type", "").lower()

    if "multipart/form-data" in content_type:
        fields, file_bytes, _filename = await _parse_multipart_upload(request)
        if not file_bytes:
            raise HTTPException(
                status_code=422,
                detail="Multipart portfolio job requires a non-empty '.zip' archive under 'file'.",
            )
        from_raw = fields.get("from_date")
        to_raw = fields.get("to_date")
        if not from_raw or not to_raw:
            raise HTTPException(
                status_code=422,
                detail="Multipart portfolio job requires 'from_date' and 'to_date' (YYYY-MM-DD).",
            )
        try:
            from_d = date.fromisoformat(from_raw)
            to_d = date.fromisoformat(to_raw)
            scope = TerritorialScope(
                fields.get("default_territorial_scope")
                or TerritorialScope.ALL_MALAYSIA.value
            )
            persona = OutputPersona(
                fields.get("persona") or OutputPersona.PRACTITIONER.value
            )
            raw_workers = fields.get("max_workers")
            max_workers = int(raw_workers) if raw_workers else 4
            regimes = (
                _parse_regimes_field(fields.get("regimes"))
                if fields.get("regimes")
                else None
            )
            contracts = extract_contracts_from_zip_archive(file_bytes)
            cache_bypass_flag = str(fields.get("cache_bypass", "")).strip().lower() in {
                "1",
                "true",
                "yes",
            }
            webhook_url_val = (fields.get("webhook_url") or "").strip() or None
            job_req = PortfolioAsyncJobRequest(
                from_date=from_d,
                to_date=to_d,
                contracts=contracts,
                regimes=regimes,
                default_territorial_scope=scope,
                persona=persona,
                max_workers=max_workers,
                webhook_url=webhook_url_val,
                cache_bypass=cache_bypass_flag,
            )
        except (ZipBombError, ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    else:
        raw_body = await request.body()
        try:
            job_req = PortfolioAsyncJobRequest.model_validate_json(raw_body)
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        job_res, is_duplicate = default_portfolio_job_manager.submit_job_with_meta(
            job_req,
            tenant_id=tenant_id,
            store=_DEFAULT_TEMPORAL_STORE,
            idempotency_key=idempotency_key,
        )
        if is_duplicate:
            response.status_code = 200
        return job_res
    except IdempotencyConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/v1/portfolio/dlq", response_model=PortfolioDLQListResponse)
async def api_v1_list_portfolio_dlq(request: Request) -> PortfolioDLQListResponse:
    """Lists tenant-scoped `DEAD_LETTER` portfolio jobs (`admin` role only)."""
    tenant_id = get_request_tenant_id(request)
    dlq_jobs = default_portfolio_job_manager.list_dlq(tenant_id=tenant_id)
    return PortfolioDLQListResponse(
        tenant_id=tenant_id, total=len(dlq_jobs), jobs=dlq_jobs
    )


@router.post(
    "/api/v1/portfolio/jobs/{job_id}/requeue",
    response_model=PortfolioJobStatusResponse,
)
async def api_v1_requeue_portfolio_job(
    job_id: str,
    request: Request,
    reset_checkpoints: Annotated[bool, Query()] = False,
) -> PortfolioJobStatusResponse:
    """Requeues a `DEAD_LETTER` or `FAILED` portfolio job (`admin` or `auditor`)."""
    tenant_id = get_request_tenant_id(request)
    try:
        requeued = default_portfolio_job_manager.requeue_job(
            job_id,
            tenant_id=tenant_id,
            reset_checkpoints=reset_checkpoints,
        )
    except PortfolioJobStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if requeued is None:
        raise HTTPException(
            status_code=404,
            detail=f"Portfolio job '{job_id}' not found for tenant '{tenant_id}'.",
        )
    return requeued


@router.get(
    "/api/v1/portfolio/jobs/{job_id}", response_model=PortfolioJobStatusResponse
)
async def api_v1_get_portfolio_job(
    job_id: str, request: Request
) -> PortfolioJobStatusResponse:
    """Polls an asynchronous portfolio blast-radius job status and ranked results."""
    tenant_id = get_request_tenant_id(request)
    job = default_portfolio_job_manager.get_job(job_id, tenant_id=tenant_id)
    if job is None:
        raise HTTPException(
            status_code=404,
            detail=f"Portfolio job '{job_id}' not found for tenant '{tenant_id}'.",
        )
    return job


@router.post("/api/v1/hitl/reviews", response_model=HITLReviewRecord)
async def api_v1_record_hitl_review(
    payload: HITLReviewRequest, request: Request
) -> HITLReviewRecord:
    """
    Records a counsel Human-in-the-Loop (HITL) clause adjudication (`ACCEPT_REDLINE`,
    `MODIFY_REDLINE`, `REJECT_FALSE_POSITIVE`, `ESCALATE_TO_COUNSEL`) after mandatory
    Malaysian PII scrubbing and signs it into the Ed25519 `AttestationLedger` (`auditor`/`admin`).
    """
    tenant_id = get_request_tenant_id(request)
    state = getattr(request, "state", None)
    ctx = getattr(state, "tenant_context", None) if state is not None else None
    reviewer_subject = getattr(ctx, "subject", None) or "counsel"
    try:
        return default_hitl_review_ledger.record_review(
            payload,
            tenant_id=tenant_id,
            reviewer_subject=str(reviewer_subject),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/v1/hitl/export-jsonl")
async def api_v1_export_hitl_jsonl(request: Request) -> PlainTextResponse:
    """
    Exports tenant-scoped PII-scrubbed counsel adjudications as deterministic JSONL
    golden regression test cases directly loadable by `evals/run_benchmark.py --extra-jsonl` (`admin`).
    """
    tenant_id = get_request_tenant_id(request)
    jsonl_body = default_hitl_review_ledger.export_golden_jsonl(tenant_id=tenant_id)
    return PlainTextResponse(
        content=jsonl_body,
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": f'attachment; filename="hitl_golden_{tenant_id}.jsonl"',
            "X-Tenant-ID": tenant_id,
        },
    )


@router.get("/api/v1/hitl/playbook", response_model=PlaybookListResponse)
async def api_v1_list_playbook(request: Request) -> PlaybookListResponse:
    """Lists active tenant-scoped 3-Tier Counsel Precedent Playbook rules (`viewer`/`auditor`/`admin`)."""
    tenant_id = get_request_tenant_id(request)
    return default_precedent_playbook_store.list_rules(tenant_id=tenant_id)


@router.post("/api/v1/hitl/playbook/promote", response_model=PrecedentPlaybookRule)
async def api_v1_promote_playbook_rule(
    payload: PlaybookPromoteRequest, request: Request
) -> PrecedentPlaybookRule:
    """
    Promotes an adjudicated HITL review or custom fallback into the tenant-isolated
    3-tier Precedent Playbook while enforcing mandatory IN_FORCE DeonticEnvelopeResolver
    statutory floors (`422 STATUTORY_FLOOR_VIOLATION` unless `admin` supplies
    `statutory_risk_waiver=true` + rationale, recorded in Ed25519 AttestationLedger).
    """
    tenant_id = get_request_tenant_id(request)
    state = getattr(request, "state", None)
    ctx = getattr(state, "tenant_context", None) if state is not None else None
    actor_id = str(getattr(ctx, "subject", None) or "counsel")
    actor_role = str(getattr(ctx, "role", None) or "auditor").strip().lower()
    try:
        return default_precedent_playbook_store.promote_rule(
            tenant_id=tenant_id,
            request=payload,
            actor_id=actor_id,
            actor_role=actor_role,
        )
    except StatutoryFloorViolationError as exc:
        raise HTTPException(status_code=422, detail=exc.to_detail_dict()) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/api/v1/negotiation/diff-docx",
    response_model=CounterpartyRedlineDiff,
)
async def api_v1_negotiation_diff_docx(request: Request) -> CounterpartyRedlineDiff:
    """
    Zero-token Counterparty OOXML Track-Changes (<w:ins>, <w:del>, <w:moveFrom>, <w:moveTo>)
    & Comment-Thread Negotiation Critic supporting multipart `.docx` uploads or JSON payloads.
    """
    tenant_id = get_request_tenant_id(request)
    content_type = request.headers.get("content-type", "").lower()

    if "multipart/form-data" in content_type:
        fields, file_bytes, filename = await _parse_multipart_upload(request)
        if not file_bytes and not (
            fields.get("baseline_text") or fields.get("proposed_text")
        ):
            raise HTTPException(
                status_code=422,
                detail="Provide a multipart '.docx' file under 'file' or baseline_text/proposed_text.",
            )
        doc_id = fields.get("document_id") or filename or f"NEG-{uuid.uuid4().hex[:6]}"
        as_of_raw = fields.get("as_of_date")
        try:
            as_of = date.fromisoformat(as_of_raw) if as_of_raw else None
            regimes = (
                _parse_regimes_field(fields.get("regimes"))
                if fields.get("regimes")
                else None
            )
            scope = fields.get("territorial_scope") or TerritorialScope.ALL_MALAYSIA
            diff_res = analyze_counterparty_docx_redlines(
                document_id=doc_id,
                docx_bytes=file_bytes,
                filename=filename,
                baseline_text=fields.get("baseline_text"),
                proposed_text=fields.get("proposed_text"),
                as_of_date=as_of,
                regimes=regimes,
                territorial_scope=scope,
                tenant_id=tenant_id,
                audit_session_id=fields.get("audit_session_id"),
                store=_DEFAULT_TEMPORAL_STORE,
                ledger=default_attestation_ledger,
                pii_store=default_pii_session_store,
            )
            if diff_res.audit_session_id:
                _store_session_negotiation(
                    tenant_id, diff_res.audit_session_id, file_bytes, diff_res
                )
            return diff_res
        except (ZipBombError, ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    raw_body = await request.body()
    try:
        json_req = CounterpartyRedlineJsonRequest.model_validate_json(raw_body)
        docx_bytes = (
            base64.b64decode(json_req.docx_base64, validate=True)
            if json_req.docx_base64
            else None
        )
        diff_res = analyze_counterparty_docx_redlines(
            document_id=json_req.document_id,
            docx_bytes=docx_bytes,
            filename=json_req.filename,
            revisions=json_req.revisions,
            baseline_text=json_req.baseline_text,
            proposed_text=json_req.proposed_text,
            comments=json_req.comments,
            as_of_date=json_req.as_of_date,
            regimes=json_req.regimes,
            territorial_scope=json_req.territorial_scope,
            tenant_id=tenant_id,
            audit_session_id=json_req.audit_session_id,
            store=_DEFAULT_TEMPORAL_STORE,
            ledger=default_attestation_ledger,
            pii_store=default_pii_session_store,
        )
        if diff_res.audit_session_id:
            _store_session_negotiation(
                tenant_id, diff_res.audit_session_id, docx_bytes, diff_res
            )
        return diff_res
    except (ZipBombError, ValidationError, ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/api/v1/negotiation/compile-counter-docx", response_model=None)
async def api_v1_compile_counter_docx(
    request: Request,
    response_format: Annotated[
        Literal["json", "docx"],
        Query(
            description="Return structured CounterRedlineCompileResult JSON or raw '.docx' binary stream"
        ),
    ] = "json",
) -> CounterRedlineCompileResult | Response:
    """
    Zero-Token Closed-Loop Counter-Redline `.docx` Compiler (`$0.00 USD / 0 tokens`):
    mutates counterparty `.docx` revisions or synthesizes valid `<w:del>`/`<w:ins>` +
    `word/comments.xml` counter-markup with bilingual statutory / tenant playbook fallbacks
    and strict tenant-scoped PII re-hydration (`auditor`/`admin`).
    """
    tenant_id = get_request_tenant_id(request)
    content_type = request.headers.get("content-type", "").lower()

    if "multipart/form-data" in content_type:
        fields, file_bytes, filename = await _parse_multipart_upload(request)
        try:
            disp_raw = fields.get("dispositions")
            dispositions_obj = json.loads(disp_raw) if disp_raw else {}
            req_model = CounterRedlineCompileRequest.model_validate(
                {
                    "document_id": fields.get("document_id")
                    or filename
                    or f"COUNTER-{uuid.uuid4().hex[:6]}",
                    "audit_session_id": fields.get("audit_session_id"),
                    "filename": filename,
                    "baseline_text": fields.get("baseline_text"),
                    "proposed_text": fields.get("proposed_text"),
                    "dispositions": dispositions_obj,
                    "counsel_author": fields.get("counsel_author")
                    or settings.counter_redline_default_author,
                    "counsel_initials": fields.get("counsel_initials")
                    or settings.counter_redline_default_initials,
                    "as_of_date": (
                        date.fromisoformat(fields["as_of_date"])
                        if fields.get("as_of_date")
                        else None
                    ),
                    "regimes": (
                        _parse_regimes_field(fields.get("regimes"))
                        if fields.get("regimes")
                        else None
                    ),
                    "territorial_scope": fields.get("territorial_scope")
                    or TerritorialScope.ALL_MALAYSIA.value,
                    "rehydrate_pii": fields.get("rehydrate_pii", "true").lower()
                    in {"true", "1", "yes"},
                    "use_tenant_playbook": fields.get(
                        "use_tenant_playbook", "true"
                    ).lower()
                    in {"true", "1", "yes"},
                    "preferred_playbook_tier": fields.get("preferred_playbook_tier")
                    or "TIER_2_FALLBACK",
                }
            )
            docx_bytes = file_bytes
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    else:
        raw_body = await request.body()
        try:
            req_model = CounterRedlineCompileRequest.model_validate_json(raw_body)
            docx_bytes = (
                base64.b64decode(req_model.docx_base64, validate=True)
                if req_model.docx_base64
                else None
            )
        except (ValidationError, ValueError, binascii.Error) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    diff_obj = req_model.diff
    if (
        docx_bytes is None
        and diff_obj is None
        and not req_model.baseline_text
        and not req_model.proposed_text
        and not req_model.revisions
    ):
        if req_model.audit_session_id:
            cached_neg = _get_session_negotiation(tenant_id, req_model.audit_session_id)
            if cached_neg is None:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        f"Negotiation session '{req_model.audit_session_id}' not found "
                        f"for tenant '{tenant_id}'."
                    ),
                )
            cached_bytes, cached_diff = cached_neg
            docx_bytes = cached_bytes
            diff_obj = cached_diff
        else:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Provide a counterparty '.docx', 'audit_session_id', 'diff', or "
                    "baseline_text/proposed_text payload."
                ),
            )

    try:
        out_bytes, compile_res = compile_counter_redline_docx(
            document_id=req_model.document_id,
            docx_bytes=docx_bytes,
            filename=req_model.filename,
            diff=diff_obj,
            baseline_text=req_model.baseline_text,
            proposed_text=req_model.proposed_text,
            revisions=req_model.revisions,
            comments=req_model.comments,
            dispositions=req_model.dispositions,
            counsel_author=req_model.counsel_author,
            counsel_initials=req_model.counsel_initials,
            as_of_date=req_model.as_of_date,
            regimes=req_model.regimes,
            territorial_scope=req_model.territorial_scope,
            tenant_id=tenant_id,
            audit_session_id=req_model.audit_session_id,
            rehydrate_pii=req_model.rehydrate_pii,
            use_tenant_playbook=req_model.use_tenant_playbook,
            preferred_playbook_tier=req_model.preferred_playbook_tier,
            store=_DEFAULT_TEMPORAL_STORE,
            ledger=default_attestation_ledger,
            pii_store=default_pii_session_store,
            playbook_store=default_precedent_playbook_store,
        )
    except (ZipBombError, ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if response_format == "docx":
        manifest_id = (
            compile_res.attestation_manifest.manifest_id
            if compile_res.attestation_manifest
            else ""
        )
        return Response(
            content=out_bytes,
            media_type=(
                "application/vnd.openxmlformats-officedocument."
                "wordprocessingml.document"
            ),
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{compile_res.filename}"'
                ),
                "X-Tenant-ID": tenant_id,
                "X-Output-Docx-SHA256": compile_res.output_docx_sha256,
                "X-Attestation-Manifest-ID": manifest_id,
                "X-Rehydrated-PII-Count": str(compile_res.rehydrated_pii_count),
                "X-Total-Tokens": "0",
            },
        )
    return compile_res


@router.post(
    "/api/v1/deontic/incident-playbook",
    response_model=IncidentPlaybookResponse,
)
async def api_v1_incident_playbook(
    payload: IncidentPlaybookRequest, request: Request
) -> IncidentPlaybookResponse:
    """
    Zero-token Multi-Regulator Incident Timeline Compiler (UTC + Asia/Kuala_Lumpur +
    Act 388 s. 54 computation-of-time) & Sub-Processor SLA Cascade Verifier.
    """
    tenant_id = get_request_tenant_id(request)
    try:
        return compile_incident_playbook(
            payload,
            store=_DEFAULT_TEMPORAL_STORE,
            ledger=default_attestation_ledger,
            tenant_id=tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/v1/attestation/{manifest_id}/bundle")
async def api_v1_attestation_bundle(
    manifest_id: str,
    request: Request,
    include_docx: Annotated[
        bool,
        Query(
            description="Include tenant-scoped redlined_contract.docx inside .lexpack.zip"
        ),
    ] = False,
    audit_session_id: Annotated[
        str | None,
        Query(description="Tenant-scoped audit_session_id for DOCX bundle hydration"),
    ] = None,
) -> Response:
    """
    Streams a deterministic, offline-verifiable `.lexpack.zip` air-gapped evidence bundle
    (`manifest.json`, `signature.ed25519`, `public_key.pem`, `statutory_snapshot.json`,
    `verification_instructions.txt`, and optional `redlined_contract.docx`).
    """
    rec = default_attestation_ledger.get(manifest_id)
    if rec is None:
        raise HTTPException(
            status_code=404,
            detail=f"Attestation manifest '{manifest_id}' not found in ledger.",
        )

    tenant_id = get_request_tenant_id(request)
    docx_bytes: bytes | None = None
    if include_docx:
        if not audit_session_id:
            raise HTTPException(
                status_code=422,
                detail="Query parameter 'audit_session_id' is required when include_docx=true.",
            )
        docx_bytes = _get_session_docx(tenant_id, audit_session_id)
        if docx_bytes is None:
            snapshot = _get_session_audit_snapshot(tenant_id, audit_session_id)
            if snapshot is None:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        f"No exportable session artifact found for tenant '{tenant_id}' "
                        f"and audit_session_id '{audit_session_id}'."
                    ),
                )
            snap_raw_text, snap_resp = snapshot
            persisted_map = default_pii_session_store.load_session(
                tenant_id=tenant_id, audit_session_id=audit_session_id
            )
            merged_map: dict[str, str] = {
                **(snap_resp.pii_scrub.placeholders if snap_resp.pii_scrub else {}),
                **(persisted_map or {}),
            }
            vault = ReversiblePIIVault(initial_mapping=merged_map)
            docx_bytes = compile_track_changes_docx(
                document_id=snap_resp.document_id,
                raw_text=snap_raw_text,
                findings=snap_resp.findings,
                active_statutes=snap_resp.active_statutes,
                deontic_envelope=snap_resp.deontic_envelope,
                contract_ast=snap_resp.contract_ast,
                manifest=snap_resp.attestation_manifest,
                rehydrate_pii=True,
                pii_vault=vault,
                pii_placeholders=merged_map,
            )
            _store_session_docx(tenant_id, audit_session_id, docx_bytes)

    bundle_bytes = build_lexpack_bundle(
        manifest_id,
        ledger=default_attestation_ledger,
        store=_DEFAULT_TEMPORAL_STORE,
        docx_bytes=docx_bytes,
        tenant_id=tenant_id,
    )
    safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in manifest_id)
    return Response(
        content=bundle_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_id}.lexpack.zip"',
            "X-LexGraph-Manifest-Id": manifest_id,
        },
    )


@router.get(
    "/api/v1/finops/tenant-usage",
    response_model=TenantFinOpsUsageResponse,
)
async def api_v1_finops_tenant_usage(
    request: Request,
    tenant_id: Annotated[
        str | None,
        Query(
            description="Optional tenant_id (must match verified X-Tenant-ID identity)"
        ),
    ] = None,
    billing_month: Annotated[
        str | None,
        Query(description="Optional YYYY-MM billing month filter"),
    ] = None,
) -> TenantFinOpsUsageResponse:
    """
    Returns real-time per-tenant cumulative USD/MYR FinOps usage, cache hits,
    deterministic fallback count, and configured monthly budget guardrail state.
    """
    verified_tenant = get_request_tenant_id(request)
    if (
        tenant_id is not None
        and tenant_id.strip()
        and tenant_id.strip() != verified_tenant
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Tenant spoofing blocked: requested tenant_id '{tenant_id}' does not "
                f"match verified tenant '{verified_tenant}'."
            ),
        )
    return default_tenant_budget_tracker.get_usage(
        verified_tenant, billing_month=billing_month
    )


@router.get(
    "/api/v1/attestation/public-key", response_model=AttestationPublicKeyResponse
)
async def api_v1_attestation_public_key() -> AttestationPublicKeyResponse:
    """Returns the Ed25519 public verification key and SHA-256 fingerprint for independent attestation verification."""
    return default_attestation_ledger.get_public_key_info()


@router.get("/api/v1/attestation/{manifest_id}", response_model=AttestationLedgerRecord)
async def api_v1_get_attestation(manifest_id: str) -> AttestationLedgerRecord:
    """Retrieves an immutable hash-chained ComplianceAttestationManifest record."""
    rec = default_attestation_ledger.get(manifest_id)
    if rec is None:
        raise HTTPException(
            status_code=404,
            detail=f"Attestation manifest '{manifest_id}' not found in ledger.",
        )
    return rec


@router.post("/api/v1/attestation/verify", response_model=AttestationVerifyResponse)
async def api_v1_verify_attestation(
    payload: AttestationVerifyRequest,
) -> AttestationVerifyResponse:
    """
    Cryptographically verifies a contract's SHA-256 digest, `as_of_date` snapshot,
    SourceSpan citations, and append-only SQLite WAL hash chain.
    """
    return default_attestation_ledger.verify(
        manifest_id=payload.manifest_id,
        raw_text=payload.raw_text,
        expected_doc_sha256=payload.expected_doc_sha256,
        manifest=payload.manifest,
    )


@router.post("/mcp")
async def mcp_jsonrpc_http(request: Request) -> Response:
    """Native Streamable HTTP JSON-RPC 2.0 MCP transport endpoint."""
    raw_bytes = await request.body()
    try:
        body = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        err_payload = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": f"Parse error: {exc}"},
        }
        return Response(
            content=json.dumps(err_payload),
            status_code=200,
            media_type="application/json",
        )

    rpc_response = await handle_jsonrpc_message(body)
    if rpc_response is None:
        return Response(status_code=204)
    return Response(
        content=json.dumps(rpc_response, ensure_ascii=False),
        status_code=200,
        media_type="application/json",
    )


@router.get("/graph/nodes", response_model=GraphTopologyResponse)
async def get_graph_nodes(
    as_of_date: Annotated[
        date | None,
        Query(
            description="Optional point-in-time filter (YYYY-MM-DD). Returns all versions if omitted."
        ),
    ] = None,
    act_name: Annotated[
        str | None, Query(description="Optional canonical act name filter")
    ] = None,
    territorial_scope: Annotated[
        str | None,
        Query(description="Optional Malaysian territorial jurisdiction filter"),
    ] = None,
    language: Annotated[
        str | None, Query(description="Optional language filter ('en' or 'bm')")
    ] = None,
    include_contract_ast: Annotated[
        bool,
        Query(description="Include Dual-Layer Contract AST & Deontic Envelope links"),
    ] = False,
    regimes: Annotated[
        str | None,
        Query(description="Comma-separated regimes for Dual-Layer Deontic Envelope"),
    ] = None,
    raw_text: Annotated[
        str | None,
        Query(description="Optional contract text for Dual-Layer AST overlay"),
    ] = None,
    document_id: Annotated[str, Query()] = "DEMO-AST",
) -> GraphTopologyResponse:
    """
    Returns statutory graph nodes, temporal/citation edges (`AMENDED_BY`, `REPEALED_BY`, `CITES`,
    `HAS_TRANSLATION`), parameterized Cypher query, and optional Dual-Layer Contract AST
    (`DEFINES_TERM`, `OVERRIDES_NOTWITHSTANDING`) linked to colliding statutory regimes.
    """
    if as_of_date is not None:
        nodes = _DEFAULT_TEMPORAL_STORE.query_point_in_time(
            as_of_date=as_of_date,
            act_name=act_name,
            include_citations=True,
            language=language,
            territorial_scope=territorial_scope,
        )
        cypher_bundle = build_point_in_time_cypher(
            as_of_date=as_of_date,
            act_name=act_name,
            territorial_scope=territorial_scope,
        )
    else:
        all_nodes = list(_DEFAULT_TEMPORAL_STORE.nodes.values())
        nodes = [
            n
            for n in all_nodes
            if (act_name is None or n.act_name == act_name)
            and (language is None or n.language == language)
        ]
        nodes = filter_by_territorial_scope(nodes, territorial_scope)
        cypher_bundle = build_point_in_time_cypher(
            as_of_date=date.today(),
            act_name=act_name,
            territorial_scope=territorial_scope,
        )

    node_id_set = {n.node_id for n in nodes}
    edges = [
        e
        for e in _DEFAULT_TEMPORAL_STORE.edges
        if e.source_id in node_id_set or e.target_id in node_id_set
    ]

    contract_nodes: list[dict[str, Any]] = []
    contract_edges: list[dict[str, Any]] = []
    envelope: CompositeDeonticEnvelope | None = None

    if include_contract_ast:
        eff_date = as_of_date or date.today()
        target_regimes = (
            _parse_regimes_field(regimes)
            if regimes
            else ["ACT_709", "ACT_854", "BNM_RMIT"]
        )
        resolver = DeonticEnvelopeResolver(_DEFAULT_TEMPORAL_STORE)
        envelope = resolver.resolve(
            regimes=target_regimes,
            as_of_date=eff_date,
            territorial_scope=territorial_scope,
        )
        ast_graph, _ = build_contract_ast(
            document_id=document_id,
            raw_text=raw_text or _DEFAULT_DUAL_LAYER_CONTRACT,
            token_style="vault",
        )
        trap_clause_ids = {
            t.overriding_clause_id for t in ast_graph.shadow_override_traps
        } | {t.definition_clause_id for t in ast_graph.narrow_definition_traps}
        winning_node_ids = [
            b.dominating_node_id for b in envelope.resolved_bounds.values()
        ]
        for cn in ast_graph.clauses:
            contract_nodes.append(
                {
                    "id": f"AST::{cn.clause_id}",
                    "clause_id": cn.clause_id,
                    "label": f"{cn.clause_id}\n[{cn.section_type}]",
                    "section_type": cn.section_type,
                    "is_trap": cn.clause_id in trap_clause_ids,
                }
            )
            if cn.extracted_metrics or cn.clause_id in trap_clause_ids:
                for w_nid in winning_node_ids[:2]:
                    if w_nid in node_id_set:
                        contract_edges.append(
                            {
                                "id": f"AST::{cn.clause_id}->STAT::{w_nid}",
                                "source": f"AST::{cn.clause_id}",
                                "target": w_nid,
                                "edge_type": "CONFLICTS_WITH_ENVELOPE",
                                "label": "STRICT_ENVELOPE_TARGET",
                                "is_hostile_trap": cn.clause_id in trap_clause_ids,
                            }
                        )
        for ce in ast_graph.edges:
            contract_edges.append(
                {
                    "id": f"AST::{ce.source_clause_id}-{ce.edge_type.value}-{ce.target_clause_id}",
                    "source": f"AST::{ce.source_clause_id}",
                    "target": f"AST::{ce.target_clause_id}",
                    "edge_type": ce.edge_type.value,
                    "label": ce.edge_type.value,
                    "is_hostile_trap": ce.is_hostile_trap,
                }
            )

    return GraphTopologyResponse(
        as_of_date=as_of_date,
        nodes=nodes,
        edges=edges,
        cypher_query=cypher_bundle.query,
        contract_nodes=contract_nodes,
        contract_edges=contract_edges,
        deontic_envelope=envelope,
    )


@router.get("/telemetry/metrics", response_model=TelemetryMetricsResponse)
async def get_telemetry_metrics() -> TelemetryMetricsResponse:
    """
    Returns aggregated FinOps and OpenTelemetry span metrics across compliance runs.
    """
    spans = telemetry_registry.list_spans()
    total_runs = len(spans)
    if total_runs == 0:
        return TelemetryMetricsResponse(
            total_runs=0,
            total_tokens=0,
            total_cost_usd=0.0,
            total_cost_myr=0.0,
            average_latency_ms=0.0,
            grounded_rate=1.0,
            spans=[],
        )

    total_tokens = sum(s.telemetry.total_tokens for s in spans)
    total_usd = round(sum(s.telemetry.estimated_cost_usd for s in spans), 6)
    total_myr = round(sum(s.telemetry.estimated_cost_myr for s in spans), 6)
    avg_latency = round(sum(s.telemetry.latency_ms for s in spans) / total_runs, 2)
    grounded_count = sum(1 for s in spans if s.telemetry.is_verified_grounded)
    grounded_rate = round(grounded_count / total_runs, 4)

    return TelemetryMetricsResponse(
        total_runs=total_runs,
        total_tokens=total_tokens,
        total_cost_usd=total_usd,
        total_cost_myr=total_myr,
        average_latency_ms=avg_latency,
        grounded_rate=grounded_rate,
        spans=[s.model_dump() for s in reversed(spans)],
    )


DASHBOARD_HTML = render_workbench_html("graph")


@router.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard() -> HTMLResponse:
    """Serves the interactive Cytoscape.js statutory graph & FinOps telemetry dashboard."""
    return HTMLResponse(content=DASHBOARD_HTML)


@router.get("/health")
async def get_health() -> dict[str, Any]:
    """Liveness and readiness probe for Docker Compose and CI orchestration."""
    return {
        "status": "ok",
        "service": "lexgraph-lah",
        "version": "0.1.0",
        "model_name": settings.model_name,
        "usd_to_myr_rate": settings.usd_to_myr_rate,
        "phoenix_collector_endpoint": settings.phoenix_collector_endpoint,
    }


@router.get("/fixtures")
async def list_fixtures() -> dict[str, Any]:
    """Returns the Malaysian regulatory compliance test fixtures from examples/fixtures/."""
    fixtures = _load_all_fixtures()
    return {"count": len(fixtures), "fixtures": fixtures}


@router.get("/fixtures/{fixture_id}")
async def get_fixture(fixture_id: str) -> dict[str, Any]:
    """Returns a single compliance fixture by its fixture_id or filename stem."""
    normalized = fixture_id.removesuffix(".json")
    for item in _load_all_fixtures():
        if item.get("fixture_id") == normalized or item.get("filename") == fixture_id:
            return item
    raise HTTPException(status_code=404, detail=f"Fixture '{fixture_id}' not found.")


DEMO_HTML = render_workbench_html("audit")


@router.get("/", response_class=HTMLResponse)
@router.get("/demo", response_class=HTMLResponse)
async def get_demo_ui() -> HTMLResponse:
    """Serves the interactive Judge-Friendly Compliance & FinOps Demo UI at `/` and `/demo`."""
    return HTMLResponse(content=DEMO_HTML)
