import io
import zipfile
from datetime import UTC, datetime
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from lexgraph_lah.middleware.pii_scrubber import ReversiblePIIVault
from lexgraph_lah.schemas.domain import (
    ClauseAudit,
    ComplianceAttestationManifest,
    CompositeDeonticEnvelope,
    ContractASTGraph,
    StatutoryNode,
)

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
XML_NS = "http://www.w3.org/XML/1998/namespace"

_CONTENT_TYPES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>
  <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
</Types>
"""

_ROOT_RELS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""

_DOCUMENT_RELS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
</Relationships>
"""

_SETTINGS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:trackRevisions/>
</w:settings>
"""


def _rehydrate_text(
    text: str,
    rehydrate_pii: bool,
    pii_vault: ReversiblePIIVault | None,
    pii_placeholders: dict[str, str] | None,
) -> str:
    if not rehydrate_pii:
        return text
    out = text
    if pii_vault is not None:
        out = pii_vault.rehydrate(out)
    if pii_placeholders:
        for token, raw_val in pii_placeholders.items():
            out = out.replace(token, raw_val)
    return out


def _format_comment_body(
    finding: ClauseAudit,
    active_statutes_by_id: dict[str, StatutoryNode],
    deontic_envelope: CompositeDeonticEnvelope | None,
    manifest: ComplianceAttestationManifest | None,
) -> str:
    citations: list[str] = []
    for sid in finding.violated_statute_ids:
        snode = active_statutes_by_id.get(sid)
        if snode:
            gaz = f" [{snode.gazette_ref}]" if snode.gazette_ref else ""
            citations.append(
                f"{sid}: {snode.act_name} ({snode.act_number} {snode.section_code}){gaz}"
            )
        else:
            citations.append(sid)

    envelope_notes: list[str] = []
    if deontic_envelope and deontic_envelope.resolved_bounds:
        for metric_key, bound in deontic_envelope.resolved_bounds.items():
            envelope_notes.append(
                f"{metric_key} {bound.operator} {bound.strictest_value} ({bound.dominating_regime} / {bound.dominating_citation})"
            )

    parts = [
        f"[lexgraph-lah {finding.severity.value} | {finding.clause_id} — {finding.category}]",
        f"Rationale: {finding.rationale}",
    ]
    if finding.overriding_clause_id:
        parts.append(
            f"Shadow Override Trap: Linked to {finding.overriding_clause_id} (neutralized={finding.addresses_shadow_override})."
        )
    if citations:
        parts.append("Statutory & P.U. Lineage: " + " | ".join(citations))
    if envelope_notes:
        parts.append("Strictest Envelope: " + "; ".join(envelope_notes[:3]))
    if manifest:
        parts.append(
            f"Attestation SHA-256: {manifest.manifest_sha256[:16]}... | "
            f"FinOps: ${manifest.estimated_cost_usd:.6f} USD / RM {manifest.estimated_cost_myr:.6f} MYR"
        )
    return " ".join(parts)


def compile_track_changes_docx(
    document_id: str,
    raw_text: str,
    findings: list[ClauseAudit],
    active_statutes: list[StatutoryNode] | None = None,
    deontic_envelope: CompositeDeonticEnvelope | None = None,
    contract_ast: ContractASTGraph | None = None,
    manifest: ComplianceAttestationManifest | None = None,
    rehydrate_pii: bool = True,
    pii_vault: ReversiblePIIVault | None = None,
    pii_placeholders: dict[str, str] | None = None,
    author: str = "lexgraph-lah",
    timestamp_iso: str | None = None,
) -> bytes:
    """
    Compiles a genuine Microsoft Word Track Changes `.docx` file containing native
    `<w:del>` strikethrough deletions, `<w:ins>` insertions (author `lexgraph-lah`),
    `<w:trackRevisions/>`, and `<w:comment>` statutory/gazette/FinOps callouts.
    """
    rev_date = timestamp_iso or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    statutes_by_id = {s.node_id: s for s in (active_statutes or [])}

    findings_by_quote: list[ClauseAudit] = list(findings)
    rev_id = 1
    comment_id = 0
    comment_entries: list[tuple[int, str]] = []
    paragraph_xml_blocks: list[str] = []

    def _next_rev_id() -> int:
        nonlocal rev_id
        val = rev_id
        rev_id += 1
        return val

    # Header summary paragraph
    reg_label = (
        ", ".join(deontic_envelope.regimes_evaluated)
        if deontic_envelope and deontic_envelope.regimes_evaluated
        else "ACT_709"
    )
    as_of_label = (
        manifest.as_of_date.isoformat()
        if manifest
        else (deontic_envelope.as_of_date.isoformat() if deontic_envelope else "CURRENT")
    )
    header_text = (
        f"LEXGRAPH-LAH TRACK CHANGES COMPLIANCE REDLINE | Document: {document_id} | "
        f"As-Of Date: {as_of_label} | Regimes: {reg_label}"
    )
    paragraph_xml_blocks.append(
        "<w:p><w:r><w:rPr><w:b/></w:rPr>"
        f'<w:t xml:space="preserve">{escape(header_text)}</w:t>'
        "</w:r></w:p>"
    )

    if contract_ast and (
        contract_ast.shadow_override_traps or contract_ast.narrow_definition_traps
    ):
        trap_summary = (
            f"AST Trap Summary: {len(contract_ast.shadow_override_traps)} Shadow Override Trap(s), "
            f"{len(contract_ast.narrow_definition_traps)} Narrow Definition Trap(s) detected."
        )
        paragraph_xml_blocks.append(
            "<w:p><w:r><w:rPr><w:color w:val=\"B45309\"/><w:b/></w:rPr>"
            f'<w:t xml:space="preserve">{escape(trap_summary)}</w:t>'
            "</w:r></w:p>"
        )

    # Render redlined contract text preserving unmatched segments verbatim
    source_text = contract_ast.scrubbed_text if contract_ast else raw_text
    remaining_cursor = 0
    matched_spans: list[tuple[int, int, ClauseAudit]] = []
    for finding in findings_by_quote:
        q = finding.exact_quote
        if not q:
            continue
        pos = source_text.find(q)
        if pos != -1:
            matched_spans.append((pos, pos + len(q), finding))

    matched_spans.sort(key=lambda item: item[0])

    # Remove overlapping spans cleanly
    non_overlapping: list[tuple[int, int, ClauseAudit]] = []
    for s_pos, e_pos, finding in matched_spans:
        if not non_overlapping or s_pos >= non_overlapping[-1][1]:
            non_overlapping.append((s_pos, e_pos, finding))

    def _emit_plain_paragraph(txt: str) -> None:
        cleaned = _rehydrate_text(txt, rehydrate_pii, pii_vault, pii_placeholders).strip()
        if not cleaned:
            return
        paragraph_xml_blocks.append(
            f'<w:p><w:r><w:t xml:space="preserve">{escape(cleaned)}</w:t></w:r></w:p>'
        )

    for s_pos, e_pos, finding in non_overlapping:
        if s_pos > remaining_cursor:
            _emit_plain_paragraph(source_text[remaining_cursor:s_pos])

        old_txt = _rehydrate_text(
            finding.exact_quote, rehydrate_pii, pii_vault, pii_placeholders
        )
        new_txt = _rehydrate_text(
            finding.recommended_redline, rehydrate_pii, pii_vault, pii_placeholders
        )

        needs_change = bool(new_txt.strip()) and not new_txt.lower().startswith(
            "no redline required"
        ) and new_txt.strip() != old_txt.strip()

        cid = comment_id
        comment_id += 1
        comment_body = _format_comment_body(
            finding=finding,
            active_statutes_by_id=statutes_by_id,
            deontic_envelope=deontic_envelope,
            manifest=manifest,
        )
        comment_entries.append((cid, comment_body))

        if needs_change:
            del_id = _next_rev_id()
            ins_id = _next_rev_id()
            p_xml = (
                "<w:p>"
                f'<w:commentRangeStart w:id="{cid}"/>'
                f'<w:del w:id="{del_id}" w:author="{escape(author)}" w:date="{escape(rev_date)}">'
                "<w:r><w:delText xml:space=\"preserve\">"
                f"{escape(old_txt)}"
                "</w:delText></w:r>"
                "</w:del>"
                '<w:r><w:t xml:space="preserve"> </w:t></w:r>'
                f'<w:ins w:id="{ins_id}" w:author="{escape(author)}" w:date="{escape(rev_date)}">'
                "<w:r><w:t xml:space=\"preserve\">"
                f"{escape(new_txt)}"
                "</w:t></w:r>"
                "</w:ins>"
                f'<w:commentRangeEnd w:id="{cid}"/>'
                f'<w:r><w:commentReference w:id="{cid}"/></w:r>'
                "</w:p>"
            )
            paragraph_xml_blocks.append(p_xml)
        else:
            p_xml = (
                "<w:p>"
                f'<w:commentRangeStart w:id="{cid}"/>'
                f'<w:r><w:t xml:space="preserve">{escape(old_txt)}</w:t></w:r>'
                f'<w:commentRangeEnd w:id="{cid}"/>'
                f'<w:r><w:commentReference w:id="{cid}"/></w:r>'
                "</w:p>"
            )
            paragraph_xml_blocks.append(p_xml)

        remaining_cursor = e_pos

    if remaining_cursor < len(source_text):
        _emit_plain_paragraph(source_text[remaining_cursor:])

    # If findings did not match offsets (e.g., synthetic multi-clause), append redlines explicitly
    if not non_overlapping and findings_by_quote:
        for finding in findings_by_quote:
            old_txt = _rehydrate_text(
                finding.exact_quote, rehydrate_pii, pii_vault, pii_placeholders
            )
            new_txt = _rehydrate_text(
                finding.recommended_redline, rehydrate_pii, pii_vault, pii_placeholders
            )
            cid = comment_id
            comment_id += 1
            comment_entries.append(
                (
                    cid,
                    _format_comment_body(
                        finding, statutes_by_id, deontic_envelope, manifest
                    ),
                )
            )
            del_id = _next_rev_id()
            ins_id = _next_rev_id()
            paragraph_xml_blocks.append(
                "<w:p>"
                f'<w:commentRangeStart w:id="{cid}"/>'
                f'<w:del w:id="{del_id}" w:author="{escape(author)}" w:date="{escape(rev_date)}">'
                f'<w:r><w:delText xml:space="preserve">{escape(old_txt)}</w:delText></w:r>'
                "</w:del>"
                '<w:r><w:t xml:space="preserve"> </w:t></w:r>'
                f'<w:ins w:id="{ins_id}" w:author="{escape(author)}" w:date="{escape(rev_date)}">'
                f'<w:r><w:t xml:space="preserve">{escape(new_txt)}</w:t></w:r>'
                "</w:ins>"
                f'<w:commentRangeEnd w:id="{cid}"/>'
                f'<w:r><w:commentReference w:id="{cid}"/></w:r>'
                "</w:p>"
            )

    if manifest:
        att_txt = (
            f"Compliance Attestation Manifest | Doc SHA-256: {manifest.input_doc_sha256} | "
            f"Graph Hash: {manifest.graph_state_hash} | Manifest SHA-256: {manifest.manifest_sha256} | "
            f"FinOps: ${manifest.estimated_cost_usd:.6f} USD / RM {manifest.estimated_cost_myr:.6f} MYR"
        )
        paragraph_xml_blocks.append(
            f'<w:p><w:r><w:t xml:space="preserve">{escape(att_txt)}</w:t></w:r></w:p>'
        )

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        "<w:body>"
        + "".join(paragraph_xml_blocks)
        + "<w:sectPr/></w:body></w:document>"
    )

    comment_xml_nodes: list[str] = []
    for cid, cbody in comment_entries:
        comment_xml_nodes.append(
            f'<w:comment w:id="{cid}" w:author="{escape(author)}" '
            f'w:date="{escape(rev_date)}" w:initials="LG">'
            f'<w:p><w:r><w:t xml:space="preserve">{escape(cbody)}</w:t></w:r></w:p>'
            "</w:comment>"
        )
    comments_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        + "".join(comment_xml_nodes)
        + "</w:comments>"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES_XML)
        zf.writestr("_rels/.rels", _ROOT_RELS_XML)
        zf.writestr("word/_rels/document.xml.rels", _DOCUMENT_RELS_XML)
        zf.writestr("word/settings.xml", _SETTINGS_XML)
        zf.writestr("word/comments.xml", comments_xml)
        zf.writestr("word/document.xml", document_xml)
    return buf.getvalue()


def inspect_ooxml_docx(docx_bytes: bytes) -> dict[str, Any]:
    """Parses a Track-Changes `.docx` archive and summarizes `<w:del>`, `<w:ins>`, and `<w:comment>` entries."""
    with zipfile.ZipFile(io.BytesIO(docx_bytes), "r") as zf:
        doc_root = ET.fromstring(zf.read("word/document.xml"))
        comments_root = (
            ET.fromstring(zf.read("word/comments.xml"))
            if "word/comments.xml" in zf.namelist()
            else None
        )
        settings_xml = (
            zf.read("word/settings.xml").decode("utf-8", errors="ignore")
            if "word/settings.xml" in zf.namelist()
            else ""
        )

    deletions: list[dict[str, str]] = []
    for del_el in doc_root.iter(f"{{{W_NS}}}del"):
        txt = "".join(t.text or "" for t in del_el.iter(f"{{{W_NS}}}delText"))
        deletions.append(
            {
                "author": del_el.attrib.get(f"{{{W_NS}}}author", ""),
                "text": txt,
            }
        )

    insertions: list[dict[str, str]] = []
    for ins_el in doc_root.iter(f"{{{W_NS}}}ins"):
        txt = "".join(t.text or "" for t in ins_el.iter(f"{{{W_NS}}}t"))
        insertions.append(
            {
                "author": ins_el.attrib.get(f"{{{W_NS}}}author", ""),
                "text": txt,
            }
        )

    comments: list[dict[str, str]] = []
    if comments_root is not None:
        for com_el in comments_root.iter(f"{{{W_NS}}}comment"):
            txt = "".join(t.text or "" for t in com_el.iter(f"{{{W_NS}}}t"))
            comments.append(
                {
                    "id": com_el.attrib.get(f"{{{W_NS}}}id", ""),
                    "author": com_el.attrib.get(f"{{{W_NS}}}author", ""),
                    "text": txt,
                }
            )

    return {
        "track_revisions_enabled": "trackRevisions" in settings_xml,
        "deletions": deletions,
        "insertions": insertions,
        "comments": comments,
    }
