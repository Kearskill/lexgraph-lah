"""
Zero-Token Closed-Loop Counterparty .docx Compiler.

Compiles a CounterpartyRedlineDiff (and optional original counterparty `.docx`
bytes + counsel disposition overrides) into a ready-to-send Microsoft Word
`.docx` counter-markup response at $0.00 USD / 0 LLM tokens:
- Cleanly accepts COMPLIANT_ACCEPT / NEUTRAL_EDIT revisions into plain `<w:r><w:t>`
- Rejects DEONTIC_REGRESSION / COMMENT_CONFLICT edits via `<w:del>` + `<w:ins>`
  authored under configurable counsel identity (`LexGraph Counsel`)
- Inserts bilingual EN/BM statutory remediation or Tenant Precedent Playbook
  fallback wording (`TIER_1_PREFERRED` / `TIER_2_FALLBACK` / `TIER_3_STATUTORY_FLOOR`)
- Appends structured margin comments (`word/comments.xml` + `<w:commentRangeStart>`,
  `<w:commentRangeEnd>`, `<w:commentReference>`) citing exact Malaysian statutes,
  as_of_date, and composite deontic bounds
- Strictly re-hydrates vaulted PII tokens inside the `(tenant_id, audit_session_id)`
  AES-256-GCM AAD boundary and signs the compiled turn in Ed25519 AttestationLedger.
"""

from __future__ import annotations

import base64
import hashlib
import io
import re
import time
import uuid
import zipfile
from datetime import UTC, date, datetime
from typing import Any
from xml.etree import ElementTree as ET

from lexgraph_lah.config import settings
from lexgraph_lah.graph.deontic_solver import (
    DeonticEnvelopeResolver,
    normalize_regimes,
)
from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    get_default_temporal_store,
)
from lexgraph_lah.hitl.precedent_playbook import (
    PrecedentPlaybookStore,
    default_precedent_playbook_store,
)
from lexgraph_lah.middleware.pii_scrubber import (
    EncryptedPIISessionStore,
    default_pii_session_store,
)
from lexgraph_lah.negotiation.docx_redline_critic import (
    analyze_counterparty_docx_redlines,
)
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    ClauseDispositionOverride,
    ClauseRedlineDelta,
    CommentAnnotation,
    CompiledClauseAction,
    ComplianceAttestationManifest,
    CompositeDeonticEnvelope,
    CounselDisposition,
    CounterpartyRedlineDiff,
    CounterRedlineCompileResult,
    PlaybookTier,
    PrecedentPlaybookRule,
    RedlineRevisionInput,
    TerritorialScope,
)
from lexgraph_lah.security.attestation_ledger import (
    AttestationLedger,
    compute_manifest_sha256,
    default_attestation_ledger,
)
from lexgraph_lah.security.doc_firewall import (
    sanitize_docx_bytes,
    scan_document_security,
    validate_zip_archive_safety,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import (
    ComplianceSpanRecord,
    measure_latency_ms,
    telemetry_registry,
)

W_URI = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_URI = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
XML_URI = "http://www.w3.org/XML/1998/namespace"
CT_URI = "http://schemas.openxmlformats.org/package/2006/content-types"
REL_URI = "http://schemas.openxmlformats.org/package/2006/relationships"

ET.register_namespace("w", W_URI)
ET.register_namespace("r", R_URI)
ET.register_namespace("xml", XML_URI)

_W = f"{{{W_URI}}}"
_XML_SPACE = f"{{{XML_URI}}}space"

_MINIMAL_CONTENT_TYPES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>'
    '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
    "</Types>"
)

_MINIMAL_ROOT_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    "</Relationships>"
)

_MINIMAL_DOC_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>'
    "</Relationships>"
)

_MINIMAL_SETTINGS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:settings xmlns:w="{W_URI}">'
    "<w:trackRevisions/>"
    "</w:settings>"
)


def _w_el(
    local_name: str, attrib: dict[str, str] | None = None, text: str | None = None
) -> ET.Element:
    el = ET.Element(f"{_W}{local_name}", attrib or {})
    if text is not None:
        el.text = text
    return el


def _rehydrate_with_count(text: str, placeholders: dict[str, str]) -> tuple[str, int]:
    if not text or not placeholders:
        return text, 0
    out = text
    count = 0
    for token, raw_val in placeholders.items():
        if token and token in out:
            hits = out.count(token)
            out = out.replace(token, raw_val)
            count += hits
    return out, count


def _normalize_match_key(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _extract_paragraph_surface(p_el: ET.Element) -> str:
    parts: list[str] = []
    for node in p_el.iter():
        if node.tag in {f"{_W}t", f"{_W}delText"} and node.text:
            parts.append(node.text)
    return "".join(parts)


def _resolve_bilingual_remediation(
    *,
    delta: ClauseRedlineDelta,
    store: TemporalGraphStore,
) -> tuple[str, list[str]]:
    en_base = (delta.recommended_counter_redline or delta.baseline_text or "").strip()
    citations: list[str] = []
    bm_snippets: list[str] = []

    for sid in delta.violated_statute_ids:
        node = store.nodes.get(sid)
        if node is None:
            citations.append(sid)
            continue
        gaz = f" [{node.gazette_ref}]" if node.gazette_ref else ""
        citations.append(f"{node.act_number} {node.section_code}{gaz}".strip())
        if node.translation_node_id and node.translation_node_id in store.nodes:
            bm_node = store.nodes[node.translation_node_id]
            bm_first = bm_node.text.strip()
            if len(bm_first) > 180:
                bm_first = bm_first[:177].rstrip() + "..."
            bm_snippets.append(
                f"{bm_node.act_number} {bm_node.section_code}: {bm_first}"
            )

    if not citations and delta.breached_bounds:
        citations.extend(delta.breached_bounds[:3])

    if bm_snippets and "BM:" not in en_base and "Bahasa Melayu" not in en_base:
        composed = f"{en_base} | BM: {bm_snippets[0]}"
    else:
        composed = en_base
    return composed, citations


def _select_playbook_text(
    rule: PrecedentPlaybookRule,
    preferred_tier: PlaybookTier,
) -> tuple[str, PlaybookTier]:
    if preferred_tier == "TIER_1_PREFERRED":
        return rule.tier_1_preferred, "TIER_1_PREFERRED"
    if preferred_tier == "TIER_3_STATUTORY_FLOOR":
        return rule.tier_3_statutory_floor, "TIER_3_STATUTORY_FLOOR"
    if rule.tier_2_fallback:
        return rule.tier_2_fallback, "TIER_2_FALLBACK"
    return rule.tier_1_preferred, "TIER_1_PREFERRED"


def _format_margin_comment(
    *,
    delta: ClauseRedlineDelta,
    disposition: CounselDisposition,
    citations: list[str],
    as_of_date: date,
    envelope: CompositeDeonticEnvelope | None,
    playbook_rule: PrecedentPlaybookRule | None,
    playbook_tier: PlaybookTier | None,
    custom_comment: str | None = None,
) -> str:
    bound_notes: list[str] = []
    if envelope is not None:
        for mk, bound in sorted(envelope.resolved_bounds.items()):
            note = f"{bound.dominating_citation} ({bound.dominating_regime}): {mk} {bound.operator} {bound.strictest_value}"
            if bound.unit:
                note += f" {bound.unit}"
            bound_notes.append(note)

    parts = [
        f"[LexGraph Counter-Redline | {delta.clause_id} | {delta.classification} -> {disposition} | as_of={as_of_date.isoformat()}]"
    ]
    if citations:
        parts.append("Provisions: " + "; ".join(citations))
    elif delta.violated_statute_ids:
        parts.append("Provisions: " + ", ".join(delta.violated_statute_ids))

    if bound_notes:
        parts.append("Deontic Bound: " + "; ".join(bound_notes[:3]))
    elif delta.breached_bounds:
        parts.append("Breached Bounds: " + "; ".join(delta.breached_bounds))

    if playbook_rule is not None:
        parts.append(
            f"Tenant Playbook: {playbook_rule.rule_id} ({playbook_tier or 'TIER_2_FALLBACK'})"
        )
    if custom_comment:
        parts.append(f"Counsel Note: {custom_comment.strip()}")
    elif delta.rationale:
        parts.append(f"Rationale: {delta.rationale.strip()}")
    return " | ".join(parts)


def _populate_paragraph_children(
    p_el: ET.Element,
    *,
    disposition: CounselDisposition,
    old_text: str,
    counter_text: str,
    accepted_text: str,
    author: str,
    rev_date: str,
    rev_counter: list[int],
    comment_id: int | None,
) -> tuple[bool, bool]:
    """Mutates a `<w:p>` element's children in-place while preserving `<w:pPr>`."""
    preserved_ppr = p_el.find(f"{_W}pPr")
    for child in list(p_el):
        p_el.remove(child)
    if preserved_ppr is not None:
        p_el.append(preserved_ppr)

    def _next_id() -> str:
        val = rev_counter[0]
        rev_counter[0] += 1
        return str(val)

    emitted_del = False
    emitted_ins = False

    if comment_id is not None:
        p_el.append(_w_el("commentRangeStart", {f"{_W}id": str(comment_id)}))

    if disposition == "ACCEPT_COUNTERPARTY":
        run = _w_el("r")
        run.append(_w_el("t", {_XML_SPACE: "preserve"}, accepted_text))
        p_el.append(run)
    elif disposition == "ESCALATE_COMMENT_ONLY":
        run = _w_el("r")
        run.append(_w_el("t", {_XML_SPACE: "preserve"}, old_text))
        p_el.append(run)
    else:
        # COUNTER_PROPOSE_FALLBACK or REJECT_REVERT_BASELINE
        if old_text:
            del_el = _w_el(
                "del",
                {
                    f"{_W}id": _next_id(),
                    f"{_W}author": author,
                    f"{_W}date": rev_date,
                },
            )
            del_run = _w_el("r")
            del_run.append(_w_el("delText", {_XML_SPACE: "preserve"}, old_text))
            del_el.append(del_run)
            p_el.append(del_el)
            emitted_del = True

            spacer = _w_el("r")
            spacer.append(_w_el("t", {_XML_SPACE: "preserve"}, " "))
            p_el.append(spacer)

        if counter_text:
            ins_el = _w_el(
                "ins",
                {
                    f"{_W}id": _next_id(),
                    f"{_W}author": author,
                    f"{_W}date": rev_date,
                },
            )
            ins_run = _w_el("r")
            ins_run.append(_w_el("t", {_XML_SPACE: "preserve"}, counter_text))
            ins_el.append(ins_run)
            p_el.append(ins_el)
            emitted_ins = True

    if comment_id is not None:
        p_el.append(_w_el("commentRangeEnd", {f"{_W}id": str(comment_id)}))
        ref_run = _w_el("r")
        ref_run.append(_w_el("commentReference", {f"{_W}id": str(comment_id)}))
        p_el.append(ref_run)

    return emitted_del, emitted_ins


def _ensure_content_types(raw_xml: bytes) -> bytes:
    text = raw_xml.decode("utf-8", errors="replace")
    if "/word/comments.xml" in text and "/word/settings.xml" in text:
        return raw_xml
    additions: list[str] = []
    if "/word/comments.xml" not in text:
        additions.append(
            '<Override PartName="/word/comments.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>'
        )
    if "/word/settings.xml" not in text:
        additions.append(
            '<Override PartName="/word/settings.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
        )
    idx = text.rfind("</Types>")
    if idx == -1:
        return _MINIMAL_CONTENT_TYPES_XML.encode("utf-8")
    updated = text[:idx] + "".join(additions) + text[idx:]
    return updated.encode("utf-8")


def _ensure_doc_rels(raw_xml: bytes | None) -> bytes:
    if raw_xml is None:
        return _MINIMAL_DOC_RELS_XML.encode("utf-8")
    text = raw_xml.decode("utf-8", errors="replace")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return _MINIMAL_DOC_RELS_XML.encode("utf-8")

    existing_targets = {
        str(el.attrib.get("Target") or "").lower()
        for el in root.iter()
        if el.tag.endswith("Relationship")
    }
    existing_ids = {
        str(el.attrib.get("Id") or "")
        for el in root.iter()
        if el.tag.endswith("Relationship")
    }
    rid_idx = 1
    while f"rId{rid_idx}" in existing_ids:
        rid_idx += 1

    inserts: list[str] = []
    if "comments.xml" not in existing_targets:
        inserts.append(
            f'<Relationship Id="rId{rid_idx}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" '
            'Target="comments.xml"/>'
        )
        rid_idx += 1
        while f"rId{rid_idx}" in existing_ids:
            rid_idx += 1
    if "settings.xml" not in existing_targets:
        inserts.append(
            f'<Relationship Id="rId{rid_idx}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" '
            'Target="settings.xml"/>'
        )

    if not inserts:
        return raw_xml
    idx = text.rfind("</Relationships>")
    if idx == -1:
        return _MINIMAL_DOC_RELS_XML.encode("utf-8")
    return (text[:idx] + "".join(inserts) + text[idx:]).encode("utf-8")


def _ensure_settings(raw_xml: bytes | None) -> bytes:
    if raw_xml is None:
        return _MINIMAL_SETTINGS_XML.encode("utf-8")
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return _MINIMAL_SETTINGS_XML.encode("utf-8")
    if root.find(f"{_W}trackRevisions") is None:
        root.append(_w_el("trackRevisions"))
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _merge_comments_xml(
    existing_raw: bytes | None,
    new_comments: list[tuple[int, str, str, str, str]],
) -> bytes:
    if existing_raw is not None:
        try:
            root = ET.fromstring(existing_raw)
        except ET.ParseError:
            root = ET.Element(f"{_W}comments")
    else:
        root = ET.Element(f"{_W}comments")

    for cid, author, initials, rev_date, body_text in new_comments:
        com = _w_el(
            "comment",
            {
                f"{_W}id": str(cid),
                f"{_W}author": author,
                f"{_W}date": rev_date,
                f"{_W}initials": initials,
            },
        )
        p_el = _w_el("p")
        run = _w_el("r")
        run.append(_w_el("t", {_XML_SPACE: "preserve"}, body_text))
        p_el.append(run)
        com.append(p_el)
        root.append(com)

    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _max_existing_ids(
    doc_root: ET.Element, comments_raw: bytes | None
) -> tuple[int, int]:
    max_rev = 0
    for tag in (f"{_W}ins", f"{_W}del", f"{_W}moveFrom", f"{_W}moveTo"):
        for el in doc_root.iter(tag):
            raw_id = el.attrib.get(f"{_W}id") or el.attrib.get("id") or ""
            if raw_id.isdigit():
                max_rev = max(max_rev, int(raw_id))

    max_com = 0
    for el in doc_root.iter():
        if el.tag in {
            f"{_W}commentRangeStart",
            f"{_W}commentRangeEnd",
            f"{_W}commentReference",
        }:
            raw_id = el.attrib.get(f"{_W}id") or el.attrib.get("id") or ""
            if raw_id.isdigit():
                max_com = max(max_com, int(raw_id))

    if comments_raw is not None:
        try:
            c_root = ET.fromstring(comments_raw)
            for com in c_root.iter(f"{_W}comment"):
                raw_id = com.attrib.get(f"{_W}id") or com.attrib.get("id") or ""
                if raw_id.isdigit():
                    max_com = max(max_com, int(raw_id))
        except ET.ParseError:
            pass
    return max_rev, max_com


def compile_counter_redline_docx(
    *,
    document_id: str = "COUNTER-REDLINE-001",
    docx_bytes: bytes | None = None,
    filename: str | None = None,
    diff: CounterpartyRedlineDiff | None = None,
    baseline_text: str | None = None,
    proposed_text: str | None = None,
    revisions: list[RedlineRevisionInput] | None = None,
    comments: list[CommentAnnotation] | None = None,
    dispositions: dict[str, CounselDisposition | ClauseDispositionOverride]
    | None = None,
    counsel_author: str | None = None,
    counsel_initials: str | None = None,
    as_of_date: date | None = None,
    regimes: list[str] | None = None,
    territorial_scope: TerritorialScope | str = TerritorialScope.ALL_MALAYSIA,
    tenant_id: str = "default-tenant",
    audit_session_id: str | None = None,
    rehydrate_pii: bool = True,
    use_tenant_playbook: bool = True,
    preferred_playbook_tier: PlaybookTier = "TIER_2_FALLBACK",
    store: TemporalGraphStore | None = None,
    ledger: AttestationLedger | None = None,
    pii_store: EncryptedPIISessionStore | None = None,
    playbook_store: PrecedentPlaybookStore | None = None,
    timestamp_iso: str | None = None,
) -> tuple[bytes, CounterRedlineCompileResult]:
    """
    Compiles a zero-token Microsoft Word counter-redline `.docx` response turn from
    an uploaded `.docx` and/or `CounterpartyRedlineDiff` + counsel dispositions.
    """
    graph_store = store or get_default_temporal_store()
    att_ledger = ledger or default_attestation_ledger
    vault_store = pii_store or default_pii_session_store
    pb_store = playbook_store or default_precedent_playbook_store

    author = (
        counsel_author or settings.counter_redline_default_author
    ).strip() or "LexGraph Counsel"
    initials = (
        counsel_initials or settings.counter_redline_default_initials
    ).strip() or "LGC"
    rev_date = timestamp_iso or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    safe_docx_bytes: bytes | None = None
    in_place_mode = False
    if docx_bytes is not None:
        validate_zip_archive_safety(docx_bytes)
        scan_document_security(
            document_id=document_id,
            file_bytes=docx_bytes,
            filename=filename or f"{document_id}.docx",
        )
        safe_docx_bytes, _ = sanitize_docx_bytes(docx_bytes, document_id)
        in_place_mode = True

    with measure_latency_ms() as elapsed_holder:
        eff_session_id = (
            audit_session_id
            or (diff.audit_session_id if diff else None)
            or f"neg-{uuid.uuid4().hex[:12]}"
        )
        if diff is None:
            diff = analyze_counterparty_docx_redlines(
                document_id=document_id,
                docx_bytes=safe_docx_bytes,
                filename=filename,
                revisions=revisions,
                baseline_text=baseline_text,
                proposed_text=proposed_text,
                comments=comments,
                as_of_date=as_of_date,
                regimes=regimes,
                territorial_scope=territorial_scope,
                tenant_id=tenant_id,
                audit_session_id=eff_session_id,
                store=graph_store,
                ledger=att_ledger,
                pii_store=vault_store,
            )

        eff_date = as_of_date or diff.as_of_date
        eff_scope = (
            territorial_scope
            if isinstance(territorial_scope, TerritorialScope)
            else TerritorialScope(str(territorial_scope))
        )
        eff_regimes = normalize_regimes(regimes or diff.regimes or ["ACT_709"])
        envelope = diff.deontic_envelope
        if envelope is None:
            envelope = DeonticEnvelopeResolver(graph_store).resolve(
                regimes=eff_regimes,
                as_of_date=eff_date,
                territorial_scope=eff_scope,
            )

        # Strictly tenant + session bound AES-256-GCM PII unsealing.
        pii_map: dict[str, str] = {}
        if rehydrate_pii and eff_session_id:
            loaded_map = vault_store.load_session(tenant_id, eff_session_id)
            if isinstance(loaded_map, dict):
                pii_map = dict(loaded_map)

        override_map = dispositions or {}
        actions: list[CompiledClauseAction] = []
        accepted_count = 0
        counter_proposed_count = 0
        reverted_count = 0
        escalated_count = 0
        rehydrated_pii_count = 0

        # Prepare resolved counter-edits & comment payloads
        prepared: list[
            tuple[
                ClauseRedlineDelta,
                CounselDisposition,
                str,
                str,
                str,
                str | None,
                PrecedentPlaybookRule | None,
                PlaybookTier | None,
                list[str],
            ]
        ] = []

        for delta in diff.clause_deltas:
            raw_ov = override_map.get(delta.clause_id)
            ov_obj: ClauseDispositionOverride | None = None
            if isinstance(raw_ov, ClauseDispositionOverride):
                ov_obj = raw_ov
                disp: CounselDisposition = raw_ov.disposition
            elif isinstance(raw_ov, str):
                disp = raw_ov  # type: ignore[assignment]
            else:
                disp = (
                    "ACCEPT_COUNTERPARTY"
                    if delta.classification in {"COMPLIANT_ACCEPT", "NEUTRAL_EDIT"}
                    else "COUNTER_PROPOSE_FALLBACK"
                )

            tier_choice = ov_obj.playbook_tier if ov_obj else preferred_playbook_tier
            matched_pb: PrecedentPlaybookRule | None = None
            pb_tier_used: PlaybookTier | None = None
            stat_remed, citations = _resolve_bilingual_remediation(
                delta=delta, store=graph_store
            )

            old_raw = (delta.proposed_text or delta.baseline_text or "").strip()
            accepted_raw = (delta.proposed_text or delta.baseline_text or "").strip()
            counter_raw = stat_remed

            if disp == "ACCEPT_COUNTERPARTY":
                source: Any = "COUNTERPARTY_ACCEPTED"
                accepted_count += 1
            elif disp == "REJECT_REVERT_BASELINE":
                source = "BASELINE_REVERT"
                counter_raw = (delta.baseline_text or old_raw).strip()
                reverted_count += 1
            elif disp == "ESCALATE_COMMENT_ONLY":
                source = "COMMENT_ONLY"
                counter_raw = old_raw
                escalated_count += 1
            else:
                # COUNTER_PROPOSE_FALLBACK
                counter_proposed_count += 1
                if ov_obj and ov_obj.custom_text and ov_obj.custom_text.strip():
                    counter_raw = ov_obj.custom_text.strip()
                    source = "COUNSEL_OVERRIDE"
                else:
                    if use_tenant_playbook:
                        matched_pb = pb_store.match_clause(
                            tenant_id=tenant_id,
                            clause_text=delta.proposed_text or delta.baseline_text,
                            regimes=eff_regimes,
                            territorial_scope=eff_scope.value,
                            preferred_tier=tier_choice,
                        )
                    if matched_pb is not None:
                        counter_raw, pb_tier_used = _select_playbook_text(
                            matched_pb, tier_choice
                        )
                        source = "TENANT_PLAYBOOK"
                    else:
                        counter_raw = stat_remed
                        source = "STATUTORY_REMEDIATION"

            old_out, c1 = _rehydrate_with_count(old_raw, pii_map)
            counter_out, c2 = _rehydrate_with_count(counter_raw, pii_map)
            accepted_out, c3 = _rehydrate_with_count(accepted_raw, pii_map)
            rehydrated_pii_count += c1 + c2 + c3

            need_comment = (
                disp != "ACCEPT_COUNTERPARTY"
                or bool(ov_obj and ov_obj.custom_comment)
                or bool(delta.violated_statute_ids)
                or bool(delta.breached_bounds)
            )
            comment_body: str | None = None
            if need_comment:
                raw_comment = _format_margin_comment(
                    delta=delta,
                    disposition=disp,
                    citations=citations,
                    as_of_date=eff_date,
                    envelope=envelope,
                    playbook_rule=matched_pb,
                    playbook_tier=pb_tier_used,
                    custom_comment=ov_obj.custom_comment if ov_obj else None,
                )
                comment_body, c4 = _rehydrate_with_count(raw_comment, pii_map)
                rehydrated_pii_count += c4

            prepared.append(
                (
                    delta,
                    disp,
                    source,
                    old_out,
                    counter_out,
                    comment_body,
                    matched_pb,
                    pb_tier_used,
                    citations,
                )
            )

        # Build or mutate the .docx ZIP archive
        new_comments_payload: list[tuple[int, str, str, str, str]] = []
        comments_appended = 0

        if in_place_mode and safe_docx_bytes is not None:
            with zipfile.ZipFile(io.BytesIO(safe_docx_bytes), "r") as zin:
                zip_items: dict[str, bytes] = {
                    name: zin.read(name) for name in zin.namelist()
                }
            doc_xml_raw = zip_items.get("word/document.xml")
            if doc_xml_raw is None:
                in_place_mode = False

        if in_place_mode and safe_docx_bytes is not None:
            doc_root = ET.fromstring(zip_items["word/document.xml"])
            comments_raw = zip_items.get("word/comments.xml")
            max_rev, max_com = _max_existing_ids(doc_root, comments_raw)
            rev_counter = [max_rev + 1]
            comment_counter = max_com + 1

            body_el = doc_root.find(f"{_W}body")
            if body_el is None:
                body_el = _w_el("body")
                doc_root.append(body_el)

            para_elements = [p for p in body_el.findall(f"{_W}p")]
            used_para_indices: set[int] = set()

            def _match_paragraph_index(
                delta: ClauseRedlineDelta, old_out: str
            ) -> int | None:
                # 1. Exact text/clause match against paragraph surface
                cid_low = delta.clause_id.lower()
                base_rehyd, _ = _rehydrate_with_count(delta.baseline_text, pii_map)
                keys = [
                    _normalize_match_key(old_out),
                    _normalize_match_key(base_rehyd),
                    _normalize_match_key(delta.proposed_text),
                    _normalize_match_key(delta.baseline_text),
                ]
                for idx, p_el in enumerate(para_elements):
                    if idx in used_para_indices:
                        continue
                    surf = _normalize_match_key(_extract_paragraph_surface(p_el))
                    if not surf:
                        continue
                    if any(k and (k in surf or surf in k) for k in keys):
                        return idx
                    if cid_low and cid_low in surf:
                        return idx
                # 2. Fallback to next unmatched paragraph index
                for idx, p_el in enumerate(para_elements):
                    if (
                        idx not in used_para_indices
                        and _extract_paragraph_surface(p_el).strip()
                    ):
                        return idx
                return None

            for (
                delta,
                disp,
                source,
                old_out,
                counter_out,
                comment_body,
                matched_pb,
                pb_tier_used,
                citations,
            ) in prepared:
                cid_str: str | None = None
                cid_int: int | None = None
                if comment_body is not None:
                    cid_int = comment_counter
                    comment_counter += 1
                    cid_str = str(cid_int)
                    new_comments_payload.append(
                        (cid_int, author, initials, rev_date, comment_body)
                    )
                    comments_appended += 1

                p_idx = _match_paragraph_index(delta, old_out)
                if p_idx is not None:
                    target_p = para_elements[p_idx]
                    used_para_indices.add(p_idx)
                else:
                    target_p = _w_el("p")
                    sect_pr = body_el.find(f"{_W}sectPr")
                    if sect_pr is not None:
                        insert_at = list(body_el).index(sect_pr)
                        body_el.insert(insert_at, target_p)
                    else:
                        body_el.append(target_p)

                accepted_out = (
                    _rehydrate_with_count(
                        delta.proposed_text or delta.baseline_text, pii_map
                    )[0]
                ).strip()
                emitted_del, emitted_ins = _populate_paragraph_children(
                    target_p,
                    disposition=disp,
                    old_text=old_out,
                    counter_text=counter_out,
                    accepted_text=accepted_out,
                    author=author,
                    rev_date=rev_date,
                    rev_counter=rev_counter,
                    comment_id=cid_int,
                )
                actions.append(
                    CompiledClauseAction(
                        clause_id=delta.clause_id,
                        classification=delta.classification,
                        disposition=disp,
                        counter_text_source=source,
                        playbook_rule_id=matched_pb.rule_id if matched_pb else None,
                        playbook_tier=pb_tier_used,
                        comment_id=cid_str,
                        cited_provisions=citations or list(delta.violated_statute_ids),
                        emitted_del=emitted_del,
                        emitted_ins=emitted_ins,
                    )
                )

            # Rehydrate vaulted PII tokens on any remaining untouched paragraphs if enabled
            if rehydrate_pii and pii_map:
                for idx, p_el in enumerate(para_elements):
                    if idx in used_para_indices:
                        continue
                    for t_el in p_el.iter():
                        if t_el.tag in {f"{_W}t", f"{_W}delText"} and t_el.text:
                            upd, cnt = _rehydrate_with_count(t_el.text, pii_map)
                            if cnt:
                                t_el.text = upd
                                rehydrated_pii_count += cnt

            zip_items["word/document.xml"] = ET.tostring(
                doc_root, encoding="utf-8", xml_declaration=True
            )
            if "[Content_Types].xml" in zip_items:
                zip_items["[Content_Types].xml"] = _ensure_content_types(
                    zip_items["[Content_Types].xml"]
                )
            else:
                zip_items["[Content_Types].xml"] = _MINIMAL_CONTENT_TYPES_XML.encode(
                    "utf-8"
                )
            zip_items["word/_rels/document.xml.rels"] = _ensure_doc_rels(
                zip_items.get("word/_rels/document.xml.rels")
            )
            zip_items["word/settings.xml"] = _ensure_settings(
                zip_items.get("word/settings.xml")
            )
            if new_comments_payload or "word/comments.xml" in zip_items:
                zip_items["word/comments.xml"] = _merge_comments_xml(
                    zip_items.get("word/comments.xml"), new_comments_payload
                )

            out_buf = io.BytesIO()
            with zipfile.ZipFile(
                out_buf, "w", compression=zipfile.ZIP_DEFLATED
            ) as zout:
                for entry_name, entry_bytes in zip_items.items():
                    zout.writestr(entry_name, entry_bytes)
            out_docx_bytes = out_buf.getvalue()
        else:
            # Synthesized valid OOXML package from diff / baseline+proposed text
            doc_root = ET.Element(f"{_W}document")
            body_el = _w_el("body")
            doc_root.append(body_el)

            hdr_p = _w_el("p")
            hdr_r = _w_el("r")
            hdr_r.append(
                _w_el(
                    "t",
                    {_XML_SPACE: "preserve"},
                    (
                        f"LEXGRAPH COUNTER-REDLINE TURN | Document: {document_id} | "
                        f"Counsel: {author} | As-Of: {eff_date.isoformat()} | "
                        f"Regimes: {', '.join(eff_regimes)}"
                    ),
                )
            )
            hdr_p.append(hdr_r)
            body_el.append(hdr_p)

            rev_counter = [1]
            comment_counter = 1
            for (
                delta,
                disp,
                source,
                old_out,
                counter_out,
                comment_body,
                matched_pb,
                pb_tier_used,
                citations,
            ) in prepared:
                cid_str = None
                cid_int = None
                if comment_body is not None:
                    cid_int = comment_counter
                    comment_counter += 1
                    cid_str = str(cid_int)
                    new_comments_payload.append(
                        (cid_int, author, initials, rev_date, comment_body)
                    )
                    comments_appended += 1

                p_el = _w_el("p")
                accepted_out = (
                    _rehydrate_with_count(
                        delta.proposed_text or delta.baseline_text, pii_map
                    )[0]
                ).strip()
                emitted_del, emitted_ins = _populate_paragraph_children(
                    p_el,
                    disposition=disp,
                    old_text=old_out,
                    counter_text=counter_out,
                    accepted_text=accepted_out,
                    author=author,
                    rev_date=rev_date,
                    rev_counter=rev_counter,
                    comment_id=cid_int,
                )
                body_el.append(p_el)
                actions.append(
                    CompiledClauseAction(
                        clause_id=delta.clause_id,
                        classification=delta.classification,
                        disposition=disp,
                        counter_text_source=source,
                        playbook_rule_id=matched_pb.rule_id if matched_pb else None,
                        playbook_tier=pb_tier_used,
                        comment_id=cid_str,
                        cited_provisions=citations or list(delta.violated_statute_ids),
                        emitted_del=emitted_del,
                        emitted_ins=emitted_ins,
                    )
                )

            body_el.append(_w_el("sectPr"))
            doc_xml_bytes = ET.tostring(
                doc_root, encoding="utf-8", xml_declaration=True
            )
            comments_xml_bytes = _merge_comments_xml(None, new_comments_payload)
            out_buf = io.BytesIO()
            with zipfile.ZipFile(
                out_buf, "w", compression=zipfile.ZIP_DEFLATED
            ) as zout:
                zout.writestr(
                    "[Content_Types].xml", _MINIMAL_CONTENT_TYPES_XML.encode("utf-8")
                )
                zout.writestr("_rels/.rels", _MINIMAL_ROOT_RELS_XML.encode("utf-8"))
                zout.writestr(
                    "word/_rels/document.xml.rels",
                    _MINIMAL_DOC_RELS_XML.encode("utf-8"),
                )
                zout.writestr(
                    "word/settings.xml", _MINIMAL_SETTINGS_XML.encode("utf-8")
                )
                zout.writestr("word/comments.xml", comments_xml_bytes)
                zout.writestr("word/document.xml", doc_xml_bytes)
            out_docx_bytes = out_buf.getvalue()

        output_sha256 = hashlib.sha256(out_docx_bytes).hexdigest()

        # Ed25519 Attestation (strictly $0.00 USD / 0 LLM tokens)
        citation_spans: list[str] = []
        seen_spans: set[str] = set()
        for delta in diff.clause_deltas:
            for sp in delta.source_span_ids or delta.violated_statute_ids:
                if sp not in seen_spans:
                    seen_spans.add(sp)
                    citation_spans.append(sp)

        manifest = ComplianceAttestationManifest(
            manifest_id=f"CRD-{uuid.uuid4().hex[:12].upper()}",
            document_id=document_id,
            input_doc_sha256=output_sha256,
            graph_state_hash=envelope.envelope_hash,
            as_of_date=eff_date,
            regimes=eff_regimes,
            territorial_scope=eff_scope.value,
            is_verified_grounded=True,
            retry_count=0,
            estimated_cost_usd=0.0,
            estimated_cost_myr=0.0,
            total_tokens=0,
            model_used="deterministic-counter-redline-compiler",
            trace_id=f"counter-docx-{uuid.uuid4().hex[:10]}",
            citation_span_ids=citation_spans,
        )
        manifest.manifest_sha256 = compute_manifest_sha256(manifest)

    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_holder[0],
        retry_count=0,
        is_verified_grounded=True,
        trace_id=manifest.trace_id or "counter-docx",
        cache_hit=False,
    )
    led_rec = att_ledger.record(manifest, telemetry)
    manifest = manifest.model_copy(
        update={
            "prev_chain_hash": led_rec.prev_chain_hash,
            "chain_hash": led_rec.chain_hash,
            "signature_b64": led_rec.signature_b64,
            "signing_key_id": led_rec.signing_key_id,
            "signature_algorithm": led_rec.signature_algorithm,
        }
    )

    telemetry_registry.record_span(
        ComplianceSpanRecord(
            span_id=manifest.trace_id or f"counter-docx-{document_id}",
            document_id=document_id,
            reference_date=eff_date.isoformat(),
            active_statute_count=len(envelope.active_node_ids),
            tenant_id=tenant_id,
            extra_attributes={
                "counter_docx.accepted_count": accepted_count,
                "counter_docx.counter_proposed_count": counter_proposed_count,
                "counter_docx.reverted_count": reverted_count,
                "counter_docx.comments_appended": comments_appended,
                "counter_docx.rehydrated_pii_count": rehydrated_pii_count,
            },
            telemetry=telemetry,
            timestamp_epoch=time.time(),
        )
    )

    out_filename = (
        f"{(filename or document_id).removesuffix('.docx')}_counter_redline.docx"
    )
    result = CounterRedlineCompileResult(
        document_id=document_id,
        filename=out_filename,
        audit_session_id=eff_session_id,
        as_of_date=eff_date,
        regimes=eff_regimes,
        territorial_scope=eff_scope,
        counsel_author=author,
        in_place_ooxml_mutation=in_place_mode,
        accepted_count=accepted_count,
        counter_proposed_count=counter_proposed_count,
        reverted_count=reverted_count,
        escalated_count=escalated_count,
        comments_appended=comments_appended,
        rehydrated_pii_count=rehydrated_pii_count,
        output_docx_sha256=output_sha256,
        docx_base64=base64.b64encode(out_docx_bytes).decode("ascii"),
        clause_actions=actions,
        attestation_manifest=manifest,
        telemetry=telemetry,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )
    return out_docx_bytes, result


__all__ = ["compile_counter_redline_docx"]
