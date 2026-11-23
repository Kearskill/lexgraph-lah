"""
Zero-token Sub-Processor SLA Cascade Verifier & Multi-Regulator Incident Timeline Playbook.

Implements:
  1. `verify_sla_cascade(...)`: extracts vendor/sub-processor breach notification windows
     (EN & BM, including hours, minutes, calendar days, and `hari bekerja` / working days)
     and mathematically compares them against every applicable `recipient_obligation` from
     `DeonticEnvelopeResolver`, flagging `SLA_CASCADE_BREACH` whenever
     `vendor_notice_hours >= regulator_deadline_hours` or `< 25%` operational triage buffer remains.
  2. `compile_incident_playbook(...)`: normalizes incident discovery timestamp to UTC and
     `Asia/Kuala_Lumpur`, generates chronological statutory notification milestones across
     all triggered regulators/recipients (applying `Act 388 s. 54` computation-of-time
     metadata for day-based statutory periods), attaches SLA cascade warnings, and records
     an Ed25519-signed `AttestationLedgerRecord` in `0` LLM tokens.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from typing import TYPE_CHECKING, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from lexgraph_lah.graph.deontic_solver import (
    DeonticEnvelopeResolver,
    normalize_regimes,
)
from lexgraph_lah.graph.temporal_store import get_default_temporal_store
from lexgraph_lah.ingestion.contract_ast import (
    build_contract_ast,
    extract_numeric_sla_from_text,
)
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    ComplianceAttestationManifest,
    IncidentPlaybookRequest,
    IncidentPlaybookResponse,
    IncidentTimelineMilestone,
    PartyRole,
    RecipientNoticeObligation,
    RiskSeverity,
    SLACascadeCheckItem,
    SLACascadeReport,
    TerritorialScope,
)
from lexgraph_lah.security.attestation_ledger import (
    AttestationLedger,
    compute_manifest_sha256,
    default_attestation_ledger,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import (
    ComplianceSpanRecord,
    measure_latency_ms,
    telemetry_registry,
)

if TYPE_CHECKING:
    from lexgraph_lah.graph.temporal_store import TemporalGraphStore

PARTY_ROLE_DEFAULT_REGIMES: dict[PartyRole, list[str]] = {
    "DATA_USER_CONTROLLER": ["ACT_709"],
    "NCII_ENTITY": ["ACT_854", "ACT_709"],
    "BNM_FINANCIAL_INSTITUTION": ["BNM_RMIT", "ACT_854", "ACT_709"],
    "PUBLIC_SECTOR_AGENCY_ACT_864": ["ACT_864", "ACT_854", "ACT_709"],
}

_MINUTES_RE = re.compile(
    r"\b(\d+(?:\.\d+)?)\s*(?:minutes?|mins?|minit)\b",
    re.IGNORECASE,
)
_BUSINESS_DAYS_RE = re.compile(
    r"\b(\d+(?:\.\d+)?)\s*(?:business\s+days?|working\s+days?|hari\s+bekerja)\b",
    re.IGNORECASE,
)

_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
    RiskSeverity.CRITICAL: 4,
}


def get_kuala_lumpur_tz() -> tzinfo:
    """Returns `Asia/Kuala_Lumpur` ZoneInfo with deterministic UTC+08:00 fallback when tzdata is absent."""
    try:
        return ZoneInfo("Asia/Kuala_Lumpur")
    except ZoneInfoNotFoundError:
        return timezone(timedelta(hours=8), name="Asia/Kuala_Lumpur")


def _parse_discovery_timestamp(raw_ts: str) -> tuple[datetime, datetime]:
    cleaned = raw_ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    kl_tz = get_kuala_lumpur_tz()
    if dt.tzinfo is None:
        dt_myt = dt.replace(tzinfo=kl_tz)
    else:
        dt_myt = dt.astimezone(kl_tz)
    dt_utc = dt_myt.astimezone(UTC)
    return dt_utc, dt_myt


def _extract_vendor_windows(text: str) -> tuple[float | None, float | None, bool]:
    """
    Extracts `(vendor_notice_hours, vendor_report_days, is_business_days)` from contract text.
    """
    low = text.lower()
    is_business = bool(_BUSINESS_DAYS_RE.search(low))
    notice_h, report_d = extract_numeric_sla_from_text(text)

    # Check explicit minutes (e.g. "within 30 minutes" / "dalam tempoh 30 minit")
    min_matches = [float(m.group(1)) / 60.0 for m in _MINUTES_RE.finditer(low)]
    if min_matches:
        min_h = min(min_matches)
        notice_h = min_h if notice_h is None else min(notice_h, min_h)

    return notice_h, report_d, is_business


def _format_hours_readable(hours: float) -> str:
    if hours < 1.0:
        mins = round(hours * 60.0)
        return f"{mins} minutes ({hours:g} hours)"
    if hours.is_integer():
        return f"{int(hours)} hour" if int(hours) == 1 else f"{int(hours)} hours"
    return f"{hours:g} hours"


def _format_hours_bm(hours: float) -> str:
    if hours < 1.0:
        mins = round(hours * 60.0)
        return f"{mins} minit"
    if hours.is_integer():
        return f"{int(hours)} jam"
    return f"{hours:g} jam"


def _obligation_deadline_hours(ob: RecipientNoticeObligation) -> float | None:
    if not isinstance(ob.threshold_value, (int, float)) or isinstance(
        ob.threshold_value, bool
    ):
        return None
    val = float(ob.threshold_value)
    unit = ob.unit.strip().lower()
    if unit in {"hour", "hours", "jam"}:
        return val
    if unit in {"day", "days", "hari"}:
        return val * 24.0
    return None


def _build_bilingual_cascade_redlines(
    *,
    checks: list[SLACascadeCheckItem],
    party_role: PartyRole,
) -> tuple[str, str]:
    breaches = [c for c in checks if c.status == "SLA_CASCADE_BREACH"]
    if not breaches:
        return (
            "No SLA cascade redline required — vendor notification timeline preserves a >= 25% regulatory triage buffer.",
            "Tiada pindaan SLA diperlukan — tempoh notis vendor mengekalkan penampan triaj >= 25%.",
        )

    strictest = min(checks, key=lambda c: c.regulator_deadline_hours)
    rec_h = strictest.recommended_max_vendor_hours
    h_en = _format_hours_readable(rec_h)
    h_bm = _format_hours_bm(rec_h)
    reg_Summary = ", ".join(
        f"{b.recipient} ({_format_hours_readable(b.regulator_deadline_hours)} via {b.citation})"
        for b in sorted(breaches, key=lambda x: x.regulator_deadline_hours)
    )
    redline_en = (
        f"Sub-Processor Incident Notification SLA ({party_role}): Sub-Processor shall notify "
        f"Client of any suspected or confirmed security, personal data, or cyber incident within "
        f"{h_en} of detection (preserving at least a 25% operational triage buffer prior to "
        f"downstream regulatory deadlines: {reg_Summary})."
    )
    redline_bm = (
        f"SLA Pemberitahuan Insiden Sub-Pemproses ({party_role}): Sub-Pemproses hendaklah memaklumkan "
        f"Pelanggan mengenai sebarang insiden keselamatan siber atau pelanggaran data peribadi dalam "
        f"tempoh {h_bm} selepas pengesanan bagi mengekalkan penampan triaj sekurang-kurangnya 25% "
        f"sebelum had masa berkanun ({strictest.citation})."
    )
    return redline_en, redline_bm


def verify_sla_cascade(
    *,
    party_role: PartyRole = "DATA_USER_CONTROLLER",
    contract_text: str | None = None,
    clauses: list[str] | None = None,
    document_id: str = "SLA-CASCADE-001",
    as_of_date: date | None = None,
    regimes: list[str] | None = None,
    territorial_scope: TerritorialScope | str | None = None,
    store: TemporalGraphStore | None = None,
    record_telemetry: bool = True,
) -> SLACascadeReport:
    """
    Zero-token upstream-vs-downstream SLA Cascade Verifier comparing vendor/sub-processor
    contractual incident notice windows against every distinct `recipient_obligation`
    from `DeonticEnvelopeResolver`.
    """
    graph_store = store or get_default_temporal_store()
    eff_date = as_of_date or date.today()
    eff_regimes = (
        normalize_regimes(regimes)
        if regimes
        else list(PARTY_ROLE_DEFAULT_REGIMES[party_role])
    )
    scope_enum = (
        territorial_scope
        if isinstance(territorial_scope, TerritorialScope)
        else TerritorialScope(territorial_scope)
        if territorial_scope
        else TerritorialScope.ALL_MALAYSIA
    )

    combined_raw = contract_text or ""
    if clauses:
        extra = "\n".join(c.strip() for c in clauses if c.strip())
        combined_raw = f"{combined_raw}\n{extra}".strip() if combined_raw else extra

    with measure_latency_ms() as elapsed_holder:
        pii_scrub = scrub_malaysian_pii(combined_raw)
        safe_text = pii_scrub.masked_text

        ast_graph, _ = build_contract_ast(
            document_id=document_id,
            raw_text=safe_text or "[EMPTY_CONTRACT]",
            token_style="vault",
        )
        resolver = DeonticEnvelopeResolver(graph_store)
        envelope = resolver.resolve(
            regimes=eff_regimes,
            as_of_date=eff_date,
            territorial_scope=scope_enum,
        )

        # Locate best contractual notice window across clauses
        extracted_notice_h: float | None = None
        extracted_report_d: float | None = None
        is_business_days = False
        source_clause_id = "SEC-1.0"
        source_excerpt = safe_text[:240]

        for cnode in ast_graph.clauses:
            low_c = cnode.text.lower()
            if not any(
                kw in low_c
                for kw in (
                    "breach",
                    "incident",
                    "notify",
                    "notification",
                    "report",
                    "kebocoran",
                    "insiden",
                    "notis",
                    "pemberitahuan",
                    "sla",
                )
            ):
                continue
            ch, cd, c_biz = _extract_vendor_windows(cnode.text)
            if ch is not None and (
                extracted_notice_h is None or ch < extracted_notice_h
            ):
                extracted_notice_h = ch
                is_business_days = is_business_days or c_biz
                source_clause_id = cnode.clause_id
                source_excerpt = cnode.text[:240]
            if cd is not None and (
                extracted_report_d is None or cd > extracted_report_d
            ):
                extracted_report_d = cd

        if extracted_notice_h is None and safe_text.strip():
            extracted_notice_h, extracted_report_d, is_business_days = (
                _extract_vendor_windows(safe_text)
            )

        checks: list[SLACascadeCheckItem] = []
        if extracted_notice_h is not None:
            for ob in sorted(
                envelope.recipient_obligations.values(),
                key=lambda item: (
                    _obligation_deadline_hours(item) or 1e9,
                    item.recipient,
                ),
            ):
                reg_hours = _obligation_deadline_hours(ob)
                if reg_hours is None:
                    continue
                # Skip unrelated fiscal / non-incident windows unless explicitly triggered
                if ob.metric_key in {
                    "stamp_duty_payment_max_days",
                    "myinvois_cancellation_rejection_max_hours",
                }:
                    continue

                vendor_h = (
                    extracted_report_d * 24.0
                    if ob.notice_stage == "FULL_REPORT"
                    and extracted_report_d is not None
                    else extracted_notice_h
                )
                slack = round(reg_hours - vendor_h, 4)
                deficit = round(max(0.0, vendor_h - reg_hours), 4)
                ratio = round(slack / reg_hours, 4) if reg_hours > 0 else 0.0
                min_buffer = round(0.25 * reg_hours, 4)
                rec_max_h = (
                    round(0.5 * reg_hours, 2)
                    if reg_hours <= 2.0
                    else round(0.75 * reg_hours, 2)
                )

                if vendor_h >= reg_hours:
                    status: Literal["COMPLIANT", "SLA_CASCADE_BREACH"] = (
                        "SLA_CASCADE_BREACH"
                    )
                    reason: Literal[
                        "NONE", "IMPOSSIBLE_TIMELINE", "INSUFFICIENT_TRIAGE_BUFFER"
                    ] = "IMPOSSIBLE_TIMELINE"
                    sev = RiskSeverity.CRITICAL
                elif ratio < 0.25:
                    status = "SLA_CASCADE_BREACH"
                    reason = "INSUFFICIENT_TRIAGE_BUFFER"
                    sev = RiskSeverity.HIGH
                else:
                    status = "COMPLIANT"
                    reason = "NONE"
                    sev = RiskSeverity.LOW

                checks.append(
                    SLACascadeCheckItem(
                        recipient=ob.recipient,
                        notice_stage=ob.notice_stage,
                        regime_id=ob.regime_id,
                        citation=ob.citation,
                        node_id=ob.node_id,
                        vendor_notice_hours=vendor_h,
                        regulator_deadline_hours=reg_hours,
                        slack_hours=slack,
                        deficit_hours=deficit,
                        triage_buffer_ratio=ratio,
                        min_required_buffer_hours=min_buffer,
                        recommended_max_vendor_hours=rec_max_h,
                        status=status,
                        breach_reason=reason,
                        severity=sev,
                        clause_id=source_clause_id,
                        clause_excerpt=source_excerpt,
                    )
                )

        breach_detected = any(c.status == "SLA_CASCADE_BREACH" for c in checks)
        overall_risk = (
            max(checks, key=lambda c: _SEVERITY_RANK[c.severity]).severity
            if checks
            else RiskSeverity.LOW
        )
        redline_en, redline_bm = _build_bilingual_cascade_redlines(
            checks=checks, party_role=party_role
        )

    trace_id = f"sla-{uuid.uuid4().hex[:8]}"
    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_holder[0],
        retry_count=0,
        is_verified_grounded=True,
        trace_id=trace_id,
    )
    if record_telemetry:
        telemetry_registry.record_span(
            ComplianceSpanRecord(
                span_id=trace_id,
                document_id=document_id,
                reference_date=eff_date.isoformat(),
                active_statute_count=len(envelope.active_node_ids),
                extra_attributes={
                    "sla_cascade.party_role": party_role,
                    "sla_cascade.breach_detected": breach_detected,
                },
                telemetry=telemetry,
                timestamp_epoch=time.time(),
            )
        )

    return SLACascadeReport(
        document_id=document_id,
        party_role=party_role,
        as_of_date=eff_date,
        territorial_scope=scope_enum,
        regimes=eff_regimes,
        extracted_vendor_notice_hours=extracted_notice_h,
        is_business_days_window=is_business_days,
        cascade_breach_detected=breach_detected,
        overall_risk=overall_risk,
        checks=checks,
        recommended_redline_en=redline_en,
        recommended_redline_bm=redline_bm,
        pii_scrub=pii_scrub,
        telemetry=telemetry,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )


def compile_incident_playbook(
    req: IncidentPlaybookRequest,
    *,
    store: TemporalGraphStore | None = None,
    ledger: AttestationLedger | None = None,
    tenant_id: str = "default-tenant",
) -> IncidentPlaybookResponse:
    """
    Zero-token Multi-Regulator Incident Playbook Simulator normalizing `discovery_timestamp`
    to UTC + `Asia/Kuala_Lumpur`, generating chronological statutory deadline milestones with
    `Act 388 s. 54` computation-of-time metadata, checking vendor SLA cascades, and recording
    an Ed25519-signed `AttestationLedgerRecord`.
    """
    graph_store = store or get_default_temporal_store()
    att_ledger = ledger or default_attestation_ledger
    kl_tz = get_kuala_lumpur_tz()
    disc_utc, disc_myt = _parse_discovery_timestamp(req.discovery_timestamp)
    eff_date = req.as_of_date or disc_myt.date()
    eff_regimes = (
        normalize_regimes(req.triggered_regimes)
        if req.triggered_regimes
        else list(PARTY_ROLE_DEFAULT_REGIMES[req.party_role])
    )

    with measure_latency_ms() as elapsed_holder:
        resolver = DeonticEnvelopeResolver(graph_store)
        envelope = resolver.resolve(
            regimes=eff_regimes,
            as_of_date=eff_date,
            territorial_scope=req.territorial_scope,
        )

        act388_node = graph_store.nodes.get("ACT-388-SEC-54-V1")
        act388_spans = (
            [sp.span_id for sp in act388_node.source_spans] if act388_node else []
        )

        raw_milestones: list[tuple[float, IncidentTimelineMilestone]] = []
        for ob in envelope.recipient_obligations.values():
            if not isinstance(ob.threshold_value, (int, float)) or isinstance(
                ob.threshold_value, bool
            ):
                continue
            val = float(ob.threshold_value)
            unit = ob.unit.strip().lower()
            if unit not in {"hour", "hours", "jam", "day", "days", "hari"}:
                continue

            ob_node = graph_store.nodes.get(ob.node_id)
            span_ids = [sp.span_id for sp in ob_node.source_spans] if ob_node else []

            if unit in {"day", "days", "hari"}:
                # Apply Act 388 s. 54: discovery day excluded + roll Saturday/Sunday expiry to Monday
                raw_target_date = disc_myt.date() + timedelta(days=round(val))
                adjusted_date = raw_target_date
                rolled_weekend = False
                if raw_target_date.weekday() == 5:  # Saturday -> Monday
                    adjusted_date = raw_target_date + timedelta(days=2)
                    rolled_weekend = True
                elif raw_target_date.weekday() == 6:  # Sunday -> Monday
                    adjusted_date = raw_target_date + timedelta(days=1)
                    rolled_weekend = True
                deadline_myt = datetime(
                    adjusted_date.year,
                    adjusted_date.month,
                    adjusted_date.day,
                    disc_myt.hour,
                    disc_myt.minute,
                    disc_myt.second,
                    tzinfo=kl_tz,
                )
                deadline_utc = deadline_myt.astimezone(UTC)
                hours_delta = round(
                    (deadline_utc - disc_utc).total_seconds() / 3600.0, 2
                )
                s54_applied = True
                s54_meta: dict[str, Any] | None = {
                    "statute": "Interpretation Acts 1948 and 1967 [Act 388] s. 54",
                    "node_id": "ACT-388-SEC-54-V1",
                    "discovery_day_excluded": disc_myt.date().isoformat(),
                    "unadjusted_expiry_date": raw_target_date.isoformat(),
                    "effective_expiry_date": adjusted_date.isoformat(),
                    "rolled_from_weekly_holiday": rolled_weekend,
                }
                for sid in act388_spans:
                    if sid not in span_ids:
                        span_ids.append(sid)
            else:
                deadline_utc = disc_utc + timedelta(hours=val)
                deadline_myt = deadline_utc.astimezone(kl_tz)
                hours_delta = round(val, 2)
                s54_applied = False
                s54_meta = None

            raw_milestones.append(
                (
                    hours_delta,
                    IncidentTimelineMilestone(
                        milestone_order=0,
                        recipient=ob.recipient,
                        notice_stage=ob.notice_stage,
                        regime_id=ob.regime_id,
                        node_id=ob.node_id,
                        citation=ob.citation,
                        statutory_window_value=val,
                        statutory_window_unit=ob.unit
                        or ("hours" if not s54_applied else "days"),
                        deadline_utc=deadline_utc.isoformat(),
                        deadline_myt=deadline_myt.isoformat(),
                        hours_from_discovery=hours_delta,
                        act_388_s54_applied=s54_applied,
                        act_388_s54_metadata=s54_meta,
                        description=ob.description,
                        source_span_ids=span_ids,
                    ),
                )
            )

        raw_milestones.sort(key=lambda item: (item[0], item[1].recipient))
        milestones = [
            m.model_copy(update={"milestone_order": idx})
            for idx, (_, m) in enumerate(raw_milestones, start=1)
        ]

        cascade_report: SLACascadeReport | None = None
        cascade_warnings: list[SLACascadeCheckItem] = []
        red_en = ""
        red_bm = ""
        if req.contract_text or req.clauses:
            cascade_report = verify_sla_cascade(
                party_role=req.party_role,
                contract_text=req.contract_text,
                clauses=req.clauses,
                document_id=req.document_id,
                as_of_date=eff_date,
                regimes=eff_regimes,
                territorial_scope=req.territorial_scope,
                store=graph_store,
                record_telemetry=False,
            )
            cascade_warnings = [
                chk
                for chk in cascade_report.checks
                if chk.status == "SLA_CASCADE_BREACH"
            ]
            red_en = cascade_report.recommended_redline_en
            red_bm = cascade_report.recommended_redline_bm

    trace_id = f"play-{uuid.uuid4().hex[:8]}"
    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_holder[0],
        retry_count=0,
        is_verified_grounded=True,
        trace_id=trace_id,
    )

    doc_basis = json.dumps(
        {
            "document_id": req.document_id,
            "discovery_timestamp_utc": disc_utc.isoformat(),
            "party_role": req.party_role,
            "triggered_regimes": eff_regimes,
            "contract_text_sha256": hashlib.sha256(
                (
                    (req.contract_text or "") + "\n" + "\n".join(req.clauses or [])
                ).encode("utf-8")
            ).hexdigest(),
        },
        sort_keys=True,
    )
    input_sha = hashlib.sha256(doc_basis.encode("utf-8")).hexdigest()
    graph_state_hash = hashlib.sha256(
        json.dumps(
            {
                "active_node_ids": sorted(envelope.active_node_ids),
                "envelope_hash": envelope.envelope_hash,
                "as_of_date": eff_date.isoformat(),
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    all_span_ids = sorted(
        {sid for ms in milestones for sid in ms.source_span_ids}
        | {
            sp.span_id
            for nid in envelope.active_node_ids
            if nid in graph_store.nodes
            for sp in graph_store.nodes[nid].source_spans
        }
    )

    manifest = ComplianceAttestationManifest(
        document_id=req.document_id,
        input_doc_sha256=input_sha,
        graph_state_hash=graph_state_hash,
        as_of_date=eff_date,
        regimes=eff_regimes,
        territorial_scope=req.territorial_scope.value,
        is_verified_grounded=True,
        retry_count=0,
        estimated_cost_usd=0.0,
        estimated_cost_myr=0.0,
        total_tokens=0,
        model_used=None,
        trace_id=trace_id,
        citation_span_ids=all_span_ids,
    )
    manifest.manifest_sha256 = compute_manifest_sha256(manifest)
    att_record = att_ledger.record(manifest, telemetry=telemetry)

    telemetry_registry.record_span(
        ComplianceSpanRecord(
            span_id=trace_id,
            document_id=req.document_id,
            reference_date=eff_date.isoformat(),
            active_statute_count=len(envelope.active_node_ids),
            tenant_id=tenant_id,
            extra_attributes={
                "incident_playbook.party_role": req.party_role,
                "incident_playbook.milestone_count": len(milestones),
                "incident_playbook.cascade_warnings": len(cascade_warnings),
            },
            telemetry=telemetry,
            timestamp_epoch=time.time(),
        )
    )

    return IncidentPlaybookResponse(
        document_id=req.document_id,
        party_role=req.party_role,
        discovery_timestamp_utc=disc_utc.isoformat(),
        discovery_timestamp_myt=disc_myt.isoformat(),
        as_of_date=eff_date,
        territorial_scope=req.territorial_scope,
        triggered_regimes=eff_regimes,
        milestones=milestones,
        sla_cascade_report=cascade_report,
        sla_cascade_warnings=cascade_warnings,
        recommended_redline_en=red_en,
        recommended_redline_bm=red_bm,
        attestation_manifest=manifest,
        attestation_record=att_record,
        telemetry=telemetry,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )
