"""
Zero-token Counterparty OOXML Track-Changes & Comment-Thread Negotiation Critic.

Parses counterparty redlined `.docx` files (`<w:ins>`, `<w:del>`, `<w:moveFrom>`,
`<w:moveTo>`, `<w:commentRangeStart>`, `word/comments.xml`, `word/commentsExtended.xml`)
or structured JSON revision payloads, scrubs Malaysian PII via `ReversiblePIIVault` /
`EncryptedPIISessionStore`, runs `DeonticEnvelopeResolver` + `ContractASTGraph` against
both reconstructed baseline and proposed clauses, classifies every counterparty delta
(`COMPLIANT_ACCEPT`, `DEONTIC_REGRESSION`, `COMMENT_CONFLICT`, `NEUTRAL_EDIT`), and
records an Ed25519-signed `ComplianceAttestationManifest` in `0` LLM tokens.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import date
from typing import TYPE_CHECKING, Literal
from xml.etree import ElementTree as ET

from lexgraph_lah.compliance.fiscal_aige_scanner import evaluate_fiscal_aige_clauses
from lexgraph_lah.graph.deontic_solver import (
    DeonticEnvelopeResolver,
    normalize_regimes,
)
from lexgraph_lah.graph.temporal_store import get_default_temporal_store
from lexgraph_lah.ingestion.contract_ast import (
    build_contract_ast,
    extract_numeric_sla_from_text,
)
from lexgraph_lah.middleware.pii_scrubber import (
    EncryptedPIISessionStore,
    ReversiblePIIVault,
    default_pii_session_store,
)
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    ClauseRedlineDelta,
    CommentAnnotation,
    ComplianceAttestationManifest,
    CompositeDeonticEnvelope,
    ContractASTGraph,
    CounterpartyRedlineDiff,
    RedlineClassification,
    RedlineRevisionInput,
    RedlineRevisionItem,
    RiskSeverity,
    TerritorialScope,
)
from lexgraph_lah.security.attestation_ledger import (
    AttestationLedger,
    compute_manifest_sha256,
    default_attestation_ledger,
)
from lexgraph_lah.security.doc_firewall import (
    ZipBombError,
    sanitize_docx_bytes,
    scan_document_security,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import (
    ComplianceSpanRecord,
    measure_latency_ms,
    telemetry_registry,
)

if TYPE_CHECKING:
    from lexgraph_lah.graph.temporal_store import TemporalGraphStore

_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_W15_NS = "{http://schemas.microsoft.com/office/word/2012/wordml}"

_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
    RiskSeverity.CRITICAL: 4,
}


@dataclass(slots=True)
class _ParsedParagraphDelta:
    clause_hint: str
    baseline_text: str
    proposed_text: str
    revisions: list[RedlineRevisionItem] = field(default_factory=list)
    comment_ids: list[str] = field(default_factory=list)


def _attr(elem: ET.Element, local_name: str, ns: str = _W_NS) -> str:
    return (
        elem.attrib.get(f"{ns}{local_name}") or elem.attrib.get(local_name) or ""
    ).strip()


def _parse_comments_parts(
    zf: zipfile.ZipFile,
) -> tuple[dict[str, CommentAnnotation], dict[str, list[CommentAnnotation]]]:
    """
    Parses `word/comments.xml` and `word/commentsExtended.xml` (reply threading via
    `w15:paraId` / `w15:paraIdParent` and resolution status `w15:done`).
    """
    names = set(zf.namelist())
    if "word/comments.xml" not in names:
        return {}, {}

    ext_by_para: dict[str, tuple[str, bool]] = {}
    if "word/commentsExtended.xml" in names:
        try:
            ext_root = ET.fromstring(zf.read("word/commentsExtended.xml"))
            for item in ext_root.iter():
                if item.tag.endswith("commentEx"):
                    pid = _attr(item, "paraId", _W15_NS) or _attr(item, "paraId", _W_NS)
                    parent_pid = _attr(item, "paraIdParent", _W15_NS) or _attr(
                        item, "paraIdParent", _W_NS
                    )
                    done_raw = _attr(item, "done", _W15_NS) or _attr(
                        item, "done", _W_NS
                    )
                    if pid:
                        ext_by_para[pid] = (parent_pid, done_raw in {"1", "true"})
        except ET.ParseError:
            pass

    comments_by_id: dict[str, CommentAnnotation] = {}
    para_to_comment_id: dict[str, str] = {}

    try:
        c_root = ET.fromstring(zf.read("word/comments.xml"))
    except ET.ParseError:
        return {}, {}

    for com in c_root.iter(f"{_W_NS}comment"):
        cid = _attr(com, "id")
        if not cid:
            continue
        author = _attr(com, "author") or "counterparty"
        c_date = _attr(com, "date")
        c_text = "".join(
            t.text
            for t in com.iter()
            if t.tag in {f"{_W_NS}t", f"{_W_NS}delText"} and t.text
        ).strip()
        para_id = ""
        for p_el in com.iter(f"{_W_NS}p"):
            cand_pid = (
                p_el.attrib.get(
                    "{http://schemas.microsoft.com/office/word/2010/wordml}paraId"
                )
                or p_el.attrib.get(f"{_W15_NS}paraId")
                or _attr(p_el, "paraId")
            )
            if cand_pid:
                para_id = cand_pid.strip()
                break
        parent_para, done = ext_by_para.get(para_id, ("", False))
        if para_id:
            para_to_comment_id[para_id] = cid
        comments_by_id[cid] = CommentAnnotation(
            comment_id=cid,
            author=author,
            date=c_date,
            text=c_text,
            para_id=para_id or None,
            parent_para_id=parent_para or None,
            resolved=done,
        )

    replies_by_root: dict[str, list[CommentAnnotation]] = {}
    for cid, ann in list(comments_by_id.items()):
        if ann.parent_para_id and ann.parent_para_id in para_to_comment_id:
            parent_cid = para_to_comment_id[ann.parent_para_id]
            updated = ann.model_copy(update={"parent_comment_id": parent_cid})
            comments_by_id[cid] = updated
            # Resolve top-level parent root for thread attachment
            root_cid = parent_cid
            seen_chain = {cid}
            while (
                root_cid in comments_by_id
                and comments_by_id[root_cid].parent_comment_id
                and comments_by_id[root_cid].parent_comment_id not in seen_chain
            ):
                seen_chain.add(root_cid)
                root_cid = str(comments_by_id[root_cid].parent_comment_id)
            replies_by_root.setdefault(root_cid, []).append(updated)

    return comments_by_id, replies_by_root


def _walk_paragraph_revisions(
    para: ET.Element,
    *,
    active_comment_ids: set[str],
) -> tuple[str, str, list[RedlineRevisionItem], list[str]]:
    """
    Reconstructs `(baseline_text, proposed_text, revisions, touched_comment_ids)` from a
    single `<w:p>` element containing `<w:ins>`, `<w:del>`, `<w:moveFrom>`, `<w:moveTo>`,
    `<w:commentRangeStart>`, `<w:commentRangeEnd>`, and `<w:commentReference>`.
    """
    base_parts: list[str] = []
    prop_parts: list[str] = []
    revisions: list[RedlineRevisionItem] = []
    touched_comments: list[str] = sorted(active_comment_ids)

    def _note_comment(cid: str) -> None:
        if cid and cid not in touched_comments:
            touched_comments.append(cid)

    def _collect_text(node: ET.Element, *, include_del_text: bool) -> str:
        buf: list[str] = []
        for sub in node.iter():
            if (
                sub.tag == f"{_W_NS}t"
                and sub.text
                or include_del_text
                and sub.tag == f"{_W_NS}delText"
                and sub.text
            ):
                buf.append(sub.text)
        return "".join(buf)

    def _visit(elem: ET.Element) -> None:
        tag = elem.tag
        if tag == f"{_W_NS}commentRangeStart":
            cid = _attr(elem, "id")
            if cid:
                active_comment_ids.add(cid)
                _note_comment(cid)
            return
        if tag == f"{_W_NS}commentRangeEnd":
            cid = _attr(elem, "id")
            if cid:
                _note_comment(cid)
                active_comment_ids.discard(cid)
            return
        if tag == f"{_W_NS}commentReference":
            cid = _attr(elem, "id")
            if cid:
                _note_comment(cid)
            return

        if tag in {f"{_W_NS}ins", f"{_W_NS}moveTo"}:
            rev_type: Literal["INS", "MOVE_TO"] = (
                "MOVE_TO" if tag == f"{_W_NS}moveTo" else "INS"
            )
            txt = _collect_text(elem, include_del_text=False)
            if txt:
                prop_parts.append(txt)
                revisions.append(
                    RedlineRevisionItem(
                        revision_id=_attr(elem, "id"),
                        revision_type=rev_type,
                        author=_attr(elem, "author") or "counterparty",
                        date=_attr(elem, "date"),
                        text=txt,
                    )
                )
            for sub in elem.iter():
                if sub.tag == f"{_W_NS}commentRangeStart":
                    cid = _attr(sub, "id")
                    if cid:
                        active_comment_ids.add(cid)
                        _note_comment(cid)
                elif sub.tag == f"{_W_NS}commentRangeEnd":
                    cid = _attr(sub, "id")
                    if cid:
                        _note_comment(cid)
                        active_comment_ids.discard(cid)
                elif sub.tag == f"{_W_NS}commentReference":
                    cid = _attr(sub, "id")
                    if cid:
                        _note_comment(cid)
            return

        if tag in {f"{_W_NS}del", f"{_W_NS}moveFrom"}:
            del_type: Literal["DEL", "MOVE_FROM"] = (
                "MOVE_FROM" if tag == f"{_W_NS}moveFrom" else "DEL"
            )
            txt = _collect_text(elem, include_del_text=True)
            if txt:
                base_parts.append(txt)
                revisions.append(
                    RedlineRevisionItem(
                        revision_id=_attr(elem, "id"),
                        revision_type=del_type,
                        author=_attr(elem, "author") or "counterparty",
                        date=_attr(elem, "date"),
                        text=txt,
                    )
                )
            for sub in elem.iter():
                if sub.tag == f"{_W_NS}commentRangeStart":
                    cid = _attr(sub, "id")
                    if cid:
                        active_comment_ids.add(cid)
                        _note_comment(cid)
                elif sub.tag == f"{_W_NS}commentRangeEnd":
                    cid = _attr(sub, "id")
                    if cid:
                        _note_comment(cid)
                        active_comment_ids.discard(cid)
                elif sub.tag == f"{_W_NS}commentReference":
                    cid = _attr(sub, "id")
                    if cid:
                        _note_comment(cid)
            return

        if tag == f"{_W_NS}r":
            for child in elem:
                if child.tag in {f"{_W_NS}t", f"{_W_NS}delText"} and child.text:
                    base_parts.append(child.text)
                    prop_parts.append(child.text)
                elif child.tag == f"{_W_NS}commentReference":
                    cid = _attr(child, "id")
                    if cid:
                        _note_comment(cid)
            return

        for child in elem:
            _visit(child)

    for child in para:
        _visit(child)

    baseline = re.sub(r"\s{2,}", " ", "".join(base_parts)).strip()
    proposed = re.sub(r"\s{2,}", " ", "".join(prop_parts)).strip()
    return baseline, proposed, revisions, touched_comments


def _extract_clause_id_hint(text: str, fallback_idx: int) -> str:
    m = re.search(
        r"\b(?:SEC-|Clause\s+|Section\s+|Klausa\s+|Seksyen\s+)(\d+(?:\.\d+)*)\b",
        text,
        re.IGNORECASE,
    )
    if m:
        return f"SEC-{m.group(1)}"
    return f"PARA-{fallback_idx}"


def _parse_docx_revisions(
    clean_docx_bytes: bytes,
) -> tuple[
    list[_ParsedParagraphDelta],
    dict[str, CommentAnnotation],
    dict[str, list[CommentAnnotation]],
]:
    with zipfile.ZipFile(io.BytesIO(clean_docx_bytes), "r") as zf:
        if "word/document.xml" not in zf.namelist():
            raise ValueError("Invalid .docx archive: missing word/document.xml")
        doc_root = ET.fromstring(zf.read("word/document.xml"))
        comments_by_id, replies_by_root = _parse_comments_parts(zf)

    paragraphs: list[_ParsedParagraphDelta] = []
    active_comments: set[str] = set()
    body = doc_root.find(f"{_W_NS}body")
    root_children = list(body) if body is not None else list(doc_root)

    para_elements: list[ET.Element] = []
    for child in root_children:
        if child.tag == f"{_W_NS}p":
            para_elements.append(child)
        elif child.tag == f"{_W_NS}tbl":
            para_elements.extend(child.findall(f".//{_W_NS}p"))

    for idx, p_el in enumerate(para_elements, start=1):
        base_txt, prop_txt, revs, cids = _walk_paragraph_revisions(
            p_el, active_comment_ids=active_comments
        )
        if not base_txt and not prop_txt and not revs:
            continue
        hint = _extract_clause_id_hint(prop_txt or base_txt, idx)
        paragraphs.append(
            _ParsedParagraphDelta(
                clause_hint=hint,
                baseline_text=base_txt,
                proposed_text=prop_txt,
                revisions=revs,
                comment_ids=cids,
            )
        )

    return paragraphs, comments_by_id, replies_by_root


def _detect_comment_conflict(
    *,
    comment_text: str,
    envelope: CompositeDeonticEnvelope,
    as_of_date: date,
) -> str | None:
    low = comment_text.lower()

    # Check if comment claims a statutory regime does not apply or proposes liability waiver
    if any(
        kw in low
        for kw in (
            "does not apply",
            "exempt from pdpa",
            "exempt from act 709",
            "exempt from act 854",
            "waive statutory liability",
            "zero statutory liability",
            "no audit access",
            "reject bnm audit",
            "reject nacsa audit",
            "no dpo required",
            "need not notify",
            "tidak perlu melaporkan",
            "kecualikan liabiliti berkanun",
            "tolak hak audit",
        )
    ):
        return (
            "Counterparty comment proposes non-compliant exclusion or statutory exemption "
            "conflicting with active Malaysian regulatory bounds."
        )

    # Check if comment proposes numeric SLA slower than active envelope bound
    c_hours, c_days = extract_numeric_sla_from_text(comment_text)
    if c_hours is not None and "incident_notice_max_hours" in envelope.resolved_bounds:
        bound = envelope.resolved_bounds["incident_notice_max_hours"]
        limit = float(bound.strictest_value)
        if c_hours > limit:
            return (
                f"Counterparty comment proposes {c_hours:g}h incident notice, violating "
                f"strictest envelope <= {limit:g}h ({bound.dominating_regime} {bound.dominating_citation})."
            )
    if c_days is not None and "full_report_max_days" in envelope.resolved_bounds:
        bound_d = envelope.resolved_bounds["full_report_max_days"]
        limit_d = float(bound_d.strictest_value)
        if c_days > limit_d:
            return (
                f"Counterparty comment proposes {c_days:g}d report window, violating "
                f"<= {limit_d:g}d ({bound_d.dominating_citation})."
            )

    # Check fiscal / MyInvois / Stamp Act misinterpretations inside comments
    if (
        "ACT_53" in envelope.regimes_evaluated
        and as_of_date >= date(2026, 1, 1)
        and any(
            kw in low
            for kw in (
                "consolidated e-invoice",
                "consolidated billing",
                "e-invois disatukan",
            )
        )
        and any(
            kw in low
            for kw in (
                "above rm10",
                "above rm 10",
                "over rm10",
                "over rm 10",
                "regardless of amount",
                "even over 10,000",
            )
        )
    ):
        return (
            "Counterparty comment asserts consolidated e-invoicing above RM 10,000, "
            "contravening Act 53 s. 82C (effective 2026-01-01)."
        )

    if (
        "ACT_378" in envelope.regimes_evaluated
        and as_of_date >= date(2026, 1, 1)
        and re.search(r"\brm\s*300\b", low)
        and any(kw in low for kw in ("stamp", "exempt", "setem", "employment"))
    ):
        return (
            "Counterparty comment cites legacy RM 300 employment stamp duty exemption; "
            "effective 2026-01-01 threshold is RM 3,000/month under Stamp Act 1949 [Act 378]."
        )

    return None


def _evaluate_text_deontic_breaches(
    *,
    clause_id: str,
    text: str,
    ast_graph: ContractASTGraph,
    envelope: CompositeDeonticEnvelope,
    as_of_date: date,
    store: TemporalGraphStore,
) -> tuple[list[str], list[str], list[str], str]:
    """
    Returns `(breached_bounds, violated_statute_ids, source_span_ids, suggested_redline)`
    for a single reconstructed baseline or proposed clause string.
    """
    low = text.lower()
    breached: list[str] = []
    violated_nodes: list[str] = []
    suggested_parts: list[str] = []

    notice_h, report_d = extract_numeric_sla_from_text(text)
    if (
        notice_h is not None
        and "incident_notice_max_hours" in envelope.resolved_bounds
        and any(
            kw in low
            for kw in (
                "breach",
                "incident",
                "notify",
                "notification",
                "report",
                "kebocoran",
                "insiden",
                "notis",
            )
        )
    ):
        b = envelope.resolved_bounds["incident_notice_max_hours"]
        limit_h = float(b.strictest_value)
        if notice_h > limit_h:
            breached.append(
                f"incident_notice_max_hours ({notice_h:g}h > <= {limit_h:g}h)"
            )
            violated_nodes.append(b.dominating_node_id)
            suggested_parts.append(
                f"notify Client and regulators within {int(limit_h) if limit_h.is_integer() else limit_h:g} hours"
            )

    if report_d is not None and "full_report_max_days" in envelope.resolved_bounds:
        bd = envelope.resolved_bounds["full_report_max_days"]
        limit_d = float(bd.strictest_value)
        if report_d > limit_d:
            breached.append(f"full_report_max_days ({report_d:g}d > <= {limit_d:g}d)")
            violated_nodes.append(bd.dominating_node_id)
            suggested_parts.append(f"deliver full report within {int(limit_d)} days")

    if any(
        kw in low
        for kw in (
            "zero statutory liability",
            "bear no statutory liability",
            "waives all statutory",
            "capped at rm 1",
            "excludes statutory liability",
            "tiada liabiliti berkanun",
            "mengecualikan liabiliti berkanun",
        )
    ):
        if "processor_direct_liability" in envelope.resolved_bounds:
            bp = envelope.resolved_bounds["processor_direct_liability"]
            violated_nodes.append(bp.dominating_node_id)
        else:
            violated_nodes.append("PDPA-2010-SEC-9-V2")
        breached.append("processor_direct_liability (liability waiver/cap)")
        suggested_parts.append(
            "assume full direct statutory obligations without liability caps"
        )

    if any(
        kw in low
        for kw in (
            "waives all rights to inspect",
            "waives regulatory audit",
            "no audit",
            "prohibits regulatory audit",
            "menolak hak audit",
        )
    ):
        if "regulator_audit_access" in envelope.resolved_bounds:
            ba = envelope.resolved_bounds["regulator_audit_access"]
            violated_nodes.append(ba.dominating_node_id)
        breached.append("regulator_audit_access (audit right removed)")
        suggested_parts.append(
            "preserve unrestricted regulator (BNM/NACSA/JPDP) audit rights"
        )

    if any(
        kw in low
        for kw in ("no dpo", "without a dpo", "not appoint a dpo", "waive dpo")
    ):
        breached.append("mandatory_dpo_appointment (s. 12A)")
        violated_nodes.append("PDPA-2010-SEC-12A-V1")
        suggested_parts.append("appoint and register a Data Protection Officer (DPO)")

    if any(
        kw in low
        for kw in (
            "need not notify affected data subjects",
            "no notice to affected data subjects",
            "waives data subject breach notification",
        )
    ):
        breached.append("data_subject_breach_notice_max_days (7d)")
        violated_nodes.append("PDPD-DBN-2025-02")
        suggested_parts.append("notify affected data subjects within 7 days")

    # Hostile Notwithstanding / Walau apa pun shadow traps or narrow definition traps
    if re.search(
        r"\b(?:notwithstanding|walau\s+apa\s+pun)\b",
        low,
    ) and any(
        kw in low
        for kw in (
            "limit",
            "cap",
            "waive",
            "exclude",
            "no liability",
            "zero liability",
            "maximum aggregate",
            "sole discretion",
            "had liabiliti",
            "pengecualian",
            "mengatasi",
        )
    ):
        breached.append(
            "shadow_override_trap ('Notwithstanding' carve-out overriding compliance duties)"
        )
        violated_nodes.append(
            envelope.resolved_bounds["incident_notice_max_hours"].dominating_node_id
            if "incident_notice_max_hours" in envelope.resolved_bounds
            else "PDPA-2010-SEC-9-V2"
        )
        suggested_parts.append(
            "expressly preserve mandatory statutory compliance duties notwithstanding any limitation or cap"
        )

    for strap in ast_graph.shadow_override_traps:
        if strap.overriding_clause_id == clause_id or (
            strap.overriding_quote and strap.overriding_quote in text
        ):
            breached.append(
                f"shadow_override_trap ({strap.trigger_phrase} -> {strap.target_clause_id})"
            )
            violated_nodes.append(
                envelope.resolved_bounds["incident_notice_max_hours"].dominating_node_id
                if "incident_notice_max_hours" in envelope.resolved_bounds
                else "PDPA-2010-SEC-9-V2"
            )
            suggested_parts.append(
                "remove overriding 'Notwithstanding' carve-out over statutory compliance clauses"
            )
    for ntrap in ast_graph.narrow_definition_traps:
        if ntrap.definition_clause_id == clause_id or (
            ntrap.contract_definition and ntrap.contract_definition in text
        ):
            breached.append(f"narrow_definition_trap ('{ntrap.term_name}')")
            violated_nodes.append("PDPA-2010-SEC-12B-V1")
            suggested_parts.append(
                f"align '{ntrap.term_name}' definition with statutory scope"
            )

    # Also run Deliverable 2 fiscal / AIGE / BNM Outsourcing evaluator on this reconstructed AST
    fiscal_findings = evaluate_fiscal_aige_clauses(
        ast_graph=ast_graph,
        envelope=envelope,
        as_of_date=as_of_date,
        store=store,
        active_statute_ids=set(envelope.active_node_ids),
    )
    for ff in fiscal_findings:
        breached.append(f"{ff.category}")
        violated_nodes.extend(ff.violated_statute_ids)
        suggested_parts.append(ff.recommended_redline)

    dedup_nodes = list(dict.fromkeys(violated_nodes))
    span_ids: list[str] = []
    for nid in dedup_nodes:
        snode = store.nodes.get(nid)
        if snode:
            for sp in snode.source_spans:
                if sp.span_id not in span_ids:
                    span_ids.append(sp.span_id)

    redline_text = "; ".join(dict.fromkeys(suggested_parts)) if suggested_parts else ""
    return list(dict.fromkeys(breached)), dedup_nodes, span_ids, redline_text


def analyze_counterparty_docx_redlines(
    *,
    document_id: str = "NEG-REDLINE-001",
    docx_bytes: bytes | None = None,
    filename: str | None = None,
    revisions: list[RedlineRevisionInput] | None = None,
    baseline_text: str | None = None,
    proposed_text: str | None = None,
    comments: list[CommentAnnotation] | None = None,
    as_of_date: date | None = None,
    regimes: list[str] | None = None,
    territorial_scope: TerritorialScope | str | None = None,
    tenant_id: str = "default-tenant",
    audit_session_id: str | None = None,
    store: TemporalGraphStore | None = None,
    ledger: AttestationLedger | None = None,
    pii_store: EncryptedPIISessionStore | None = None,
) -> CounterpartyRedlineDiff:
    """
    Zero-token Counterparty OOXML Track-Changes & Comment-Thread Negotiation Critic.
    Runs `doc_firewall` pre-AST, parses `<w:ins>`/`<w:del>`/`<w:moveFrom>`/`<w:moveTo>`
    and comment threads, scrubs Malaysian PII, evaluates both baseline and proposed
    clauses via `DeonticEnvelopeResolver` + `ContractASTGraph`, and records an Ed25519
    signed `ComplianceAttestationManifest`.
    """
    graph_store = store or get_default_temporal_store()
    att_ledger = ledger or default_attestation_ledger
    vault_store = pii_store or default_pii_session_store
    eff_date = as_of_date or date.today()
    eff_regimes = normalize_regimes(regimes) if regimes else ["ACT_709", "ACT_854"]
    scope_enum = (
        territorial_scope
        if isinstance(territorial_scope, TerritorialScope)
        else TerritorialScope(territorial_scope)
        if territorial_scope
        else TerritorialScope.ALL_MALAYSIA
    )
    session_id = audit_session_id or f"neg-{uuid.uuid4().hex[:12]}"

    with measure_latency_ms() as elapsed_holder:
        # 1. Pre-AST Security Firewall Inspection
        if docx_bytes is not None:
            sec_report = scan_document_security(
                document_id=document_id,
                file_bytes=docx_bytes,
                filename=filename or "counterparty_redline.docx",
            )
            if any(
                f.category == "ZIP_BOMB_OR_MALFORMED_ARCHIVE"
                for f in sec_report.findings
            ):
                raise ZipBombError(
                    sec_report.findings[0].rationale
                    if sec_report.findings
                    else "Archive failed ZIP safety validation."
                )
            working_docx, _ = sanitize_docx_bytes(docx_bytes, document_id=document_id)
            parsed_paras, parsed_comments, replies_by_root = _parse_docx_revisions(
                working_docx
            )
            input_digest = hashlib.sha256(docx_bytes).hexdigest()
        else:
            raw_joined = "\n".join(
                [baseline_text or "", proposed_text or ""]
                + [f"{r.baseline_text}\n{r.proposed_text}" for r in (revisions or [])]
                + [c.text for c in (comments or [])]
            )
            sec_report = scan_document_security(
                document_id=document_id,
                raw_text=raw_joined,
            )
            parsed_paras = []
            parsed_comments = {c.comment_id: c for c in (comments or [])}
            replies_by_root = {}
            if revisions:
                for idx, rev in enumerate(revisions, start=1):
                    cids: list[str] = []
                    for c in rev.comments:
                        parsed_comments[c.comment_id] = c
                        cids.append(c.comment_id)
                    rev_items: list[RedlineRevisionItem] = []
                    if rev.baseline_text != rev.proposed_text:
                        rev_items.append(
                            RedlineRevisionItem(
                                revision_id=rev.revision_id or str(idx),
                                revision_type=rev.revision_type,
                                author=rev.author,
                                date=rev.date,
                                text=rev.proposed_text or rev.baseline_text,
                            )
                        )
                    parsed_paras.append(
                        _ParsedParagraphDelta(
                            clause_hint=rev.clause_id,
                            baseline_text=rev.baseline_text,
                            proposed_text=rev.proposed_text,
                            revisions=rev_items,
                            comment_ids=cids,
                        )
                    )
            elif baseline_text is not None or proposed_text is not None:
                base_lines = [
                    ln.strip()
                    for ln in (baseline_text or "").splitlines()
                    if ln.strip()
                ]
                prop_lines = [
                    ln.strip()
                    for ln in (proposed_text or "").splitlines()
                    if ln.strip()
                ]
                max_n = max(len(base_lines), len(prop_lines), 1)
                for idx in range(max_n):
                    b_ln = base_lines[idx] if idx < len(base_lines) else ""
                    p_ln = prop_lines[idx] if idx < len(prop_lines) else ""
                    cids = (
                        list(parsed_comments.keys())
                        if idx == 0 and parsed_comments
                        else []
                    )
                    revs = (
                        [
                            RedlineRevisionItem(
                                revision_id=str(idx + 1),
                                revision_type="REPLACE",
                                author="counterparty",
                                text=p_ln or b_ln,
                            )
                        ]
                        if b_ln != p_ln
                        else []
                    )
                    parsed_paras.append(
                        _ParsedParagraphDelta(
                            clause_hint=_extract_clause_id_hint(p_ln or b_ln, idx + 1),
                            baseline_text=b_ln,
                            proposed_text=p_ln,
                            revisions=revs,
                            comment_ids=cids,
                        )
                    )
            else:
                raise ValueError(
                    "Provide either a '.docx' upload, 'docx_base64', 'revisions', or 'baseline_text'/'proposed_text'."
                )
            input_digest = hashlib.sha256(raw_joined.encode("utf-8")).hexdigest()

        # 2. Scrub Malaysian PII across reconstructed surfaces & comments
        vault = ReversiblePIIVault(token_style="vault")
        scrubbed_baseline_parts: list[str] = []
        scrubbed_proposed_parts: list[str] = []
        for p in parsed_paras:
            if p.baseline_text:
                scrubbed_baseline_parts.append(vault.scrub(p.baseline_text)[0])
            if p.proposed_text:
                scrubbed_proposed_parts.append(vault.scrub(p.proposed_text)[0])

        baseline_full = "\n".join(scrubbed_baseline_parts)
        proposed_full = "\n".join(scrubbed_proposed_parts)
        full_surface_scrub = vault.scrub(baseline_full + "\n" + proposed_full)[1]

        if vault.token_map:
            vault.persist_session(
                tenant_id=tenant_id,
                audit_session_id=session_id,
                store=vault_store,
            )

        # 3. Build baseline & proposed ContractASTGraphs + DeonticEnvelopeResolver
        baseline_ast, _ = build_contract_ast(
            document_id=f"{document_id}-BASELINE",
            raw_text=baseline_full or "[EMPTY_BASELINE]",
            token_style="vault",
        )
        proposed_ast, _ = build_contract_ast(
            document_id=f"{document_id}-PROPOSED",
            raw_text=proposed_full or "[EMPTY_PROPOSED]",
            token_style="vault",
        )
        resolver = DeonticEnvelopeResolver(graph_store)
        envelope = resolver.resolve(
            regimes=eff_regimes,
            as_of_date=eff_date,
            territorial_scope=scope_enum,
        )

        # 4. Evaluate each delta deterministically against baseline & proposed envelopes
        clause_deltas: list[ClauseRedlineDelta] = []
        attached_comment_ids: set[str] = set()

        for p_idx, p in enumerate(parsed_paras, start=1):
            b_scrub = vault.scrub(p.baseline_text)[0] if p.baseline_text else ""
            p_scrub = vault.scrub(p.proposed_text)[0] if p.proposed_text else ""
            revs_scrubbed = [
                r.model_copy(update={"text": vault.scrub(r.text)[0]})
                for r in p.revisions
            ]

            thread_comments: list[CommentAnnotation] = []
            seen_cids: set[str] = set()
            for cid in p.comment_ids:
                if cid in parsed_comments and cid not in seen_cids:
                    seen_cids.add(cid)
                    attached_comment_ids.add(cid)
                    root_c = parsed_comments[cid]
                    thread_comments.append(root_c)
                    for rep in replies_by_root.get(cid, []):
                        if rep.comment_id not in seen_cids:
                            seen_cids.add(rep.comment_id)
                            attached_comment_ids.add(rep.comment_id)
                            thread_comments.append(rep)

            # Evaluate comment conflicts
            evaluated_comments: list[CommentAnnotation] = []
            comment_conflicts: list[str] = []
            for c_ann in thread_comments:
                c_txt_scrub = vault.scrub(c_ann.text)[0]
                c_conflict = _detect_comment_conflict(
                    comment_text=c_txt_scrub,
                    envelope=envelope,
                    as_of_date=eff_date,
                )
                if c_conflict:
                    comment_conflicts.append(c_conflict)
                evaluated_comments.append(
                    c_ann.model_copy(
                        update={
                            "text": c_txt_scrub,
                            "has_conflict": c_conflict is not None,
                            "conflict_reason": c_conflict,
                        }
                    )
                )

            # Build per-clause mini ASTs so intra-clause traps (e.g. Notwithstanding) are scoped cleanly
            b_clause_ast, _ = build_contract_ast(
                document_id=f"{document_id}-B-{p_idx}",
                raw_text=b_scrub or "[EMPTY]",
                token_style="vault",
            )
            p_clause_ast, _ = build_contract_ast(
                document_id=f"{document_id}-P-{p_idx}",
                raw_text=p_scrub or "[EMPTY]",
                token_style="vault",
            )

            b_breaches, _, _, _ = (
                _evaluate_text_deontic_breaches(
                    clause_id=p.clause_hint,
                    text=b_scrub,
                    ast_graph=b_clause_ast,
                    envelope=envelope,
                    as_of_date=eff_date,
                    store=graph_store,
                )
                if b_scrub
                else ([], [], [], "")
            )
            p_breaches, p_statutes, p_spans, p_redline = (
                _evaluate_text_deontic_breaches(
                    clause_id=p.clause_hint,
                    text=p_scrub,
                    ast_graph=p_clause_ast,
                    envelope=envelope,
                    as_of_date=eff_date,
                    store=graph_store,
                )
                if p_scrub
                else ([], [], [], "")
            )

            # Also detect numeric SLA regression relative to baseline even if both > 0
            b_h, b_d = extract_numeric_sla_from_text(b_scrub)
            p_h, p_d = extract_numeric_sla_from_text(p_scrub)
            sla_weakened = False
            if (
                b_h is not None
                and p_h is not None
                and p_h > b_h
                and "incident_notice_max_hours" in envelope.resolved_bounds
            ):
                lim = float(
                    envelope.resolved_bounds[
                        "incident_notice_max_hours"
                    ].strictest_value
                )
                if p_h > lim:
                    sla_weakened = True
            if (
                b_d is not None
                and p_d is not None
                and p_d > b_d
                and "full_report_max_days" in envelope.resolved_bounds
            ):
                lim_d = float(
                    envelope.resolved_bounds["full_report_max_days"].strictest_value
                )
                if p_d > lim_d:
                    sla_weakened = True

            # Check document-level shadow override traps targeting this clause
            doc_shadow_for_clause = [
                t
                for t in proposed_ast.shadow_override_traps
                if t.overriding_clause_id == p.clause_hint
                or (t.overriding_quote and t.overriding_quote in p_scrub)
            ]
            for st in doc_shadow_for_clause:
                msg = f"shadow_override_trap ({st.trigger_phrase} -> {st.target_clause_id})"
                if msg not in p_breaches:
                    p_breaches.append(msg)

            new_or_worsened_breach = bool(set(p_breaches) - set(b_breaches)) or (
                sla_weakened and bool(p_breaches)
            )
            has_text_mutation = b_scrub.strip() != p_scrub.strip()

            classification: RedlineClassification
            severity = RiskSeverity.LOW
            rationale = ""
            counter_redline = ""

            if new_or_worsened_breach or (
                bool(p_breaches)
                and has_text_mutation
                and len(p_breaches) >= len(b_breaches)
            ):
                classification = "DEONTIC_REGRESSION"
                severity = (
                    RiskSeverity.CRITICAL
                    if any(
                        "liability" in br.lower()
                        or "shadow_override" in br.lower()
                        or "crypto" in br.lower()
                        for br in p_breaches
                    )
                    else RiskSeverity.HIGH
                )
                rationale = (
                    f"Counterparty revision in {p.clause_hint} introduces/retains statutory regression(s): "
                    + "; ".join(p_breaches)
                    + "."
                )
                counter_redline = (
                    p_redline
                    or b_scrub
                    or "Restore baseline compliance clause satisfying strictest Malaysian statutory envelope."
                )
            elif comment_conflicts:
                classification = "COMMENT_CONFLICT"
                severity = RiskSeverity.HIGH
                rationale = " | ".join(comment_conflicts)
                counter_redline = (
                    f"Reject counterparty comment position and confirm adherence to active "
                    f"Malaysian statutory bounds as of {eff_date.isoformat()}."
                )
            elif (
                has_text_mutation
                and (not p_breaches)
                and (
                    bool(b_breaches)
                    or any(
                        kw in p_scrub.lower()
                        for kw in (
                            "act 709",
                            "act 854",
                            "bnm",
                            "nacsa",
                            "dpo",
                            "audit",
                            "encrypt",
                            "24 hours",
                            "6 hours",
                            "1 hour",
                            "72 hours",
                            "myinvois",
                            "stamp",
                        )
                    )
                )
            ):
                classification = "COMPLIANT_ACCEPT"
                severity = RiskSeverity.LOW
                rationale = (
                    f"Revision in {p.clause_hint} preserves or strengthens statutory compliance "
                    f"under {', '.join(eff_regimes)}."
                )
                counter_redline = (
                    "Accept counterparty revision — compliant with statutory floor."
                )
            else:
                classification = "NEUTRAL_EDIT"
                severity = RiskSeverity.LOW
                rationale = (
                    f"Editorial or non-statutory modification in {p.clause_hint} with no "
                    "deontic regression or comment conflict."
                )
                counter_redline = "No compliance counter-redline required."

            clause_deltas.append(
                ClauseRedlineDelta(
                    clause_id=p.clause_hint,
                    classification=classification,
                    severity=severity,
                    baseline_text=b_scrub,
                    proposed_text=p_scrub,
                    revisions=revs_scrubbed,
                    comments=evaluated_comments,
                    breached_bounds=p_breaches,
                    violated_statute_ids=p_statutes,
                    source_span_ids=p_spans,
                    rationale=rationale,
                    recommended_counter_redline=counter_redline,
                )
            )

        # Include any unanchored comments (in word/comments.xml without range markers)
        for cid, c_ann in sorted(parsed_comments.items()):
            if cid in attached_comment_ids:
                continue
            c_txt_scrub = vault.scrub(c_ann.text)[0]
            c_conflict = _detect_comment_conflict(
                comment_text=c_txt_scrub,
                envelope=envelope,
                as_of_date=eff_date,
            )
            ann_out = c_ann.model_copy(
                update={
                    "text": c_txt_scrub,
                    "has_conflict": c_conflict is not None,
                    "conflict_reason": c_conflict,
                }
            )
            clause_deltas.append(
                ClauseRedlineDelta(
                    clause_id=f"COMMENT-{cid}",
                    classification="COMMENT_CONFLICT" if c_conflict else "NEUTRAL_EDIT",
                    severity=RiskSeverity.HIGH if c_conflict else RiskSeverity.LOW,
                    baseline_text="",
                    proposed_text="",
                    revisions=[],
                    comments=[ann_out],
                    breached_bounds=[c_conflict] if c_conflict else [],
                    violated_statute_ids=[],
                    source_span_ids=[],
                    rationale=c_conflict
                    or "Unanchored counterparty comment annotation.",
                    recommended_counter_redline=(
                        "Reject non-compliant comment proposal."
                        if c_conflict
                        else "No counter-redline required."
                    ),
                )
            )

        reg_cnt = sum(
            1 for d in clause_deltas if d.classification == "DEONTIC_REGRESSION"
        )
        com_cnt = sum(
            1 for d in clause_deltas if d.classification == "COMMENT_CONFLICT"
        )
        acc_cnt = sum(
            1 for d in clause_deltas if d.classification == "COMPLIANT_ACCEPT"
        )
        neu_cnt = sum(1 for d in clause_deltas if d.classification == "NEUTRAL_EDIT")

        overall_risk = (
            max(clause_deltas, key=lambda d: _SEVERITY_RANK[d.severity]).severity
            if clause_deltas
            else RiskSeverity.LOW
        )
        if (
            sec_report.findings
            and _SEVERITY_RANK[sec_report.risk_level] > _SEVERITY_RANK[overall_risk]
        ):
            overall_risk = sec_report.risk_level

    trace_id = f"neg-{uuid.uuid4().hex[:8]}"
    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_holder[0],
        retry_count=0,
        is_verified_grounded=True,
        trace_id=trace_id,
    )

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
    citation_span_ids = sorted(
        {sid for d in clause_deltas for sid in d.source_span_ids}
        | {
            sp.span_id
            for nid in envelope.active_node_ids
            if nid in graph_store.nodes
            for sp in graph_store.nodes[nid].source_spans
        }
    )
    manifest = ComplianceAttestationManifest(
        document_id=document_id,
        input_doc_sha256=input_digest,
        graph_state_hash=graph_state_hash,
        as_of_date=eff_date,
        regimes=eff_regimes,
        territorial_scope=scope_enum.value,
        is_verified_grounded=True,
        retry_count=0,
        estimated_cost_usd=0.0,
        estimated_cost_myr=0.0,
        total_tokens=0,
        model_used=None,
        trace_id=trace_id,
        citation_span_ids=citation_span_ids,
    )
    manifest.manifest_sha256 = compute_manifest_sha256(manifest)
    att_ledger.record(manifest, telemetry=telemetry)

    telemetry_registry.record_span(
        ComplianceSpanRecord(
            span_id=trace_id,
            document_id=document_id,
            reference_date=eff_date.isoformat(),
            active_statute_count=len(envelope.active_node_ids),
            tenant_id=tenant_id,
            extra_attributes={
                "negotiation.regression_count": reg_cnt,
                "negotiation.comment_conflict_count": com_cnt,
            },
            telemetry=telemetry,
            timestamp_epoch=time.time(),
        )
    )

    return CounterpartyRedlineDiff(
        document_id=document_id,
        as_of_date=eff_date,
        territorial_scope=scope_enum,
        regimes=eff_regimes,
        overall_risk=overall_risk,
        baseline_clauses=baseline_ast.clauses,
        proposed_clauses=proposed_ast.clauses,
        clause_deltas=clause_deltas,
        regression_count=reg_cnt,
        comment_conflict_count=com_cnt,
        compliant_accept_count=acc_cnt,
        neutral_edit_count=neu_cnt,
        deontic_envelope=envelope,
        security_report=sec_report,
        pii_scrub=full_surface_scrub,
        audit_session_id=session_id,
        attestation_manifest=manifest,
        telemetry=telemetry,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )
