import hashlib
import io
import re
import zipfile
import zlib
from typing import Literal
from xml.etree import ElementTree as ET

from lexgraph_lah.middleware.pii_scrubber import ReversiblePIIVault
from lexgraph_lah.schemas.domain import (
    ContractASTGraph,
    ContractClauseNode,
    ContractDependencyEdge,
    ContractEdgeType,
    NarrowDefinitionTrap,
    RiskSeverity,
    ShadowOverrideTrap,
    SourceSpan,
)

_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

_CLAUSE_BOUNDARY_RE = re.compile(
    r"(?:^|(?<=\s)|(?<=\.\s))"
    r"(?P<header>"
    r"(?:SEC-\d+(?:\.\d+)*)"
    r"|(?:(?:Clause|Section|Seksyen|Klausa)\s+\d+(?:\.\d+)*(?:\([a-zA-Z0-9]+\))?(?:\s+[^:\n]{0,60})?:)"
    r"|(?:^\d+(?:\.\d+)+\s+[A-Z][A-Za-z0-9\s\-/&]+:)"
    r")",
    re.MULTILINE,
)

_INLINE_REF_PREFIX_RE = re.compile(
    r"(?:\b(?:notwithstanding|subject\s+to|under|in|to|of|see|pursuant\s+to|dalam|kepada|bawah)\s+)$",
    re.IGNORECASE,
)

_CLAUSE_REF_RE = re.compile(
    r"\b(?:SEC-|Clause\s+|Section\s+|Klausa\s+|Seksyen\s+)(\d+(?:\.\d+)*)\b",
    re.IGNORECASE,
)

_DEFINITION_RE = re.compile(
    r'["\u201c](?P<term>[A-Za-z][A-Za-z0-9\s\-]{2,45})["\u201d]\s+'
    r"(?:means|shall\s+mean|refers\s+to|bermaksud|adalah\s+ditakrifkan\s+sebagai)",
    re.IGNORECASE,
)

_OVERRIDE_TRIGGER_RE = re.compile(
    r"(?P<phrase>"
    r"notwithstanding\s+anything\s+to\s+the\s+contrary(?:\s+in\s+(?:clause|section|this\s+agreement)[^.,;]*)?"
    r"|notwithstanding\s+(?:clause|section|sec-|klausa|seksyen)\s+[\d.]+"
    r"|subject\s+to\s+(?:clause|section|sec-|klausa|seksyen)\s+[\d.]+"
    r"|walau\s+apa\s+pun\s+yang\s+terkandung\s+dalam\s+(?:klausa|seksyen|perjanjian)\s*[\d.]*"
    r"|walau\s+apa\s+pun\s+peruntukan\s+lain"
    r"|tertakluk\s+kepada\s+(?:klausa|seksyen)\s+[\d.]+"
    r")",
    re.IGNORECASE,
)

_HOURS_RE = re.compile(
    r"\b(\d+(?:\.\d+)?)\s*(?:hour|hours|hr|hrs|jam)\b",
    re.IGNORECASE,
)
_DAYS_RE = re.compile(
    r"\b(\d+(?:\.\d+)?)\s*(?:business\s+days?|calendar\s+days?|working\s+days?|days?|hari\s+bekerja|hari)\b",
    re.IGNORECASE,
)


def extract_numeric_sla_from_text(text: str) -> tuple[float | None, float | None]:
    """
    Extracts `(incident_notice_hours, full_report_days)` from contract or redline text.
    Supports both English (hours/days) and Bahasa Melayu (jam/hari).
    Returns `None` for any metric not explicitly expressed.
    """
    low = text.lower()
    hours_matches = [float(m.group(1)) for m in _HOURS_RE.finditer(low)]
    days_matches = [float(m.group(1)) for m in _DAYS_RE.finditer(low)]

    notice_hours: float | None = min(hours_matches) if hours_matches else None
    report_days: float | None = None

    # Differentiate initial breach notice expressed in days (e.g., "notify within 10 days")
    # vs post-incident full report timelines (e.g., "full report within 14 days").
    if days_matches:
        for m in _DAYS_RE.finditer(low):
            val = float(m.group(1))
            window = low[max(0, m.start() - 48) : min(len(low), m.end() + 24)]
            if any(
                kw in window
                for kw in (
                    "full report",
                    "comprehensive report",
                    "post-incident",
                    "laporan penuh",
                )
            ):
                report_days = val if report_days is None else min(report_days, val)
            elif notice_hours is None:
                notice_hours = val * 24.0
        if (
            report_days is None
            and len(days_matches) > 0
            and any(
                kw in low for kw in ("full report", "laporan penuh", "written report")
            )
        ):
            report_days = min(days_matches)

    if notice_hours is None and any(
        kw in low for kw in ("immediately", "dengan segera")
    ):
        notice_hours = 0.5

    return notice_hours, report_days


def extract_text_from_docx_bytes(data: bytes) -> list[tuple[int, str]]:
    """
    Extracts `(page_number, paragraph_text)` tuples from a `.docx` OpenXML archive
    using Python stdlib `zipfile` and `xml.etree.ElementTree`.
    """
    paragraphs: list[tuple[int, str]] = []
    page_num = 1
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        if "word/document.xml" not in zf.namelist():
            raise ValueError("Invalid .docx archive: missing word/document.xml")
        xml_bytes = zf.read("word/document.xml")
    root = ET.fromstring(xml_bytes)

    for para in root.iter(f"{_W_NS}p"):
        if (
            para.find(f".//{_W_NS}br[@{_W_NS}type='page']") is not None
            or para.find(f".//{_W_NS}lastRenderedPageBreak") is not None
        ):
            page_num += 1

        texts: list[str] = []
        for elem in para.iter():
            if elem.tag in {f"{_W_NS}t", f"{_W_NS}delText"} and elem.text:
                texts.append(elem.text)
        joined = "".join(texts).strip()
        if joined:
            paragraphs.append((page_num, joined))
    return paragraphs


def _decode_pdf_literal(raw_lit: str) -> str:
    return (
        raw_lit.replace(r"\(", "(")
        .replace(r"\)", ")")
        .replace(r"\\", "\\")
        .replace(r"\n", "\n")
        .replace(r"\r", " ")
        .replace(r"\t", " ")
    )


def extract_text_from_pdf_bytes(data: bytes) -> list[tuple[int, str]]:
    """
    Extracts `(page_number, text)` lines from PDF bytes using pure Python stream
    decompression (`zlib`) and PDF text operator parsing (`Tj`/`TJ`), with clean
    UTF-8/Latin-1 fallback for text-embedded synthetic PDFs.
    """
    streams: list[bytes] = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.DOTALL):
        chunk = match.group(1)
        try:
            streams.append(zlib.decompress(chunk))
        except zlib.error:
            streams.append(chunk)

    extracted: list[tuple[int, str]] = []
    page_idx = 0
    for stream_bytes in streams:
        text_str = stream_bytes.decode("latin-1", errors="ignore")
        tj_parts = [
            _decode_pdf_literal(m.group(1))
            for m in re.finditer(r"\(([^()\\]*(?:\\.[^()\\]*)*)\)\s*Tj", text_str)
        ]
        tj_array_parts: list[str] = []
        for arr in re.finditer(r"\[(.*?)\]\s*TJ", text_str, re.DOTALL):
            inner = "".join(
                _decode_pdf_literal(m.group(1))
                for m in re.finditer(r"\(([^()\\]*(?:\\.[^()\\]*)*)\)", arr.group(1))
            )
            if inner:
                tj_array_parts.append(inner)
        combined = " ".join(p.strip() for p in (tj_parts + tj_array_parts) if p.strip())
        if combined:
            page_idx += 1
            extracted.append((page_idx, combined))

    if extracted:
        return extracted

    # Fallback: readable plain-text lines inside minimal or text-only PDFs
    decoded = data.decode("utf-8", errors="ignore")
    lines = [
        ln.strip()
        for ln in decoded.splitlines()
        if ln.strip()
        and not ln.startswith(("%PDF", "obj", "endobj", "xref", "trailer", "startxref"))
    ]
    if lines:
        return [(1, "\n".join(lines))]
    return [(1, "")]


def extract_contract_paragraphs(
    raw_text: str | None = None,
    file_bytes: bytes | None = None,
    filename: str | None = None,
) -> tuple[Literal["text", "docx", "pdf"], list[tuple[int, str]], str]:
    """Normalizes `.docx`, `.pdf`, or raw text into `(source_format, page_paragraphs, full_text)`."""
    if file_bytes is not None:
        fname = (filename or "").lower()
        if fname.endswith(".docx") or file_bytes[:2] == b"PK":
            paras = extract_text_from_docx_bytes(file_bytes)
            full_text = "\n".join(p for _, p in paras)
            return "docx", paras, full_text
        if fname.endswith(".pdf") or file_bytes.startswith(b"%PDF"):
            paras = extract_text_from_pdf_bytes(file_bytes)
            full_text = "\n".join(p for _, p in paras)
            return "pdf", paras, full_text
        decoded = file_bytes.decode("utf-8", errors="replace")
        paras = [(1, line.strip()) for line in decoded.splitlines() if line.strip()]
        return "text", paras, decoded

    text = raw_text or ""
    paras = [(1, line.strip()) for line in text.splitlines() if line.strip()]
    return "text", paras, text


def _normalize_clause_id(raw_header: str, fallback_idx: int) -> str:
    cleaned = raw_header.strip().rstrip(":")
    sec_m = re.search(
        r"(?:SEC-|Clause\s+|Section\s+|Klausa\s+|Seksyen\s+)(\d+(?:\.\d+)*)",
        cleaned,
        re.IGNORECASE,
    )
    if sec_m:
        return f"SEC-{sec_m.group(1)}"
    num_m = re.match(r"^(\d+(?:\.\d+)+)", cleaned)
    if num_m:
        return f"SEC-{num_m.group(1)}"
    return f"SEC-{fallback_idx}.0"


def _segment_scrubbed_text(
    scrubbed_text: str,
    page_paragraphs: list[tuple[int, str]],
    vault: ReversiblePIIVault,
) -> list[tuple[str, str, int, int, int, int]]:
    """
    Segments `scrubbed_text` into `(clause_id, text, page, paragraph_idx, start_char, end_char)`
    tuples with exact character offsets into `scrubbed_text`.
    """
    # Map paragraph character ranges to page numbers
    page_ranges: list[tuple[int, int, int]] = []
    cursor = 0
    for page_no, raw_para in page_paragraphs:
        scrubbed_para = raw_para
        # Find exact or sequential window
        idx = scrubbed_text.find(scrubbed_para[:40], cursor)
        if idx != -1:
            end_pos = min(len(scrubbed_text), idx + len(scrubbed_para))
            page_ranges.append((idx, end_pos, page_no))
            cursor = end_pos

    def _page_for_offset(offset: int) -> int:
        for s_off, e_off, pno in page_ranges:
            if s_off <= offset <= e_off:
                return pno
        return 1

    matches = [
        m
        for m in _CLAUSE_BOUNDARY_RE.finditer(scrubbed_text)
        if not _INLINE_REF_PREFIX_RE.search(
            scrubbed_text[max(0, m.start() - 25) : m.start()]
        )
    ]
    segments: list[tuple[str, str, int, int, int, int]] = []

    if not matches:
        stripped = scrubbed_text.strip()
        if not stripped:
            return []
        start = scrubbed_text.find(stripped)
        end = start + len(stripped)
        return [("SEC-1.0", stripped, 1, 0, start, end)]

    if matches[0].start() > 0:
        preamble = scrubbed_text[: matches[0].start()].strip()
        if preamble and len(preamble) > 10:
            s_off = scrubbed_text.find(preamble)
            segments.append(
                (
                    "SEC-0.0",
                    preamble,
                    _page_for_offset(s_off),
                    0,
                    s_off,
                    s_off + len(preamble),
                )
            )

    seen_ids: dict[str, int] = {}
    for idx, match in enumerate(matches):
        seg_start = match.start()
        seg_end = (
            matches[idx + 1].start() if idx + 1 < len(matches) else len(scrubbed_text)
        )
        raw_seg = scrubbed_text[seg_start:seg_end]
        lead_ws = len(raw_seg) - len(raw_seg.lstrip())
        start_char = seg_start + lead_ws
        trimmed = scrubbed_text[start_char:seg_end].rstrip()
        end_char = start_char + len(trimmed)
        if not trimmed:
            continue

        base_id = _normalize_clause_id(match.group("header"), idx + 1)
        count = seen_ids.get(base_id, 0) + 1
        seen_ids[base_id] = count
        clause_id = base_id if count == 1 else f"{base_id}-{count}"

        segments.append(
            (
                clause_id,
                trimmed,
                _page_for_offset(start_char),
                len(segments),
                start_char,
                end_char,
            )
        )

    return segments


def _extract_clause_metrics(clause_text: str) -> dict[str, float | str | bool]:
    metrics: dict[str, float | str | bool] = {}
    low = clause_text.lower()
    notice_h, report_d = extract_numeric_sla_from_text(clause_text)
    if notice_h is not None and any(
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
            "pemberitahuan",
        )
    ):
        metrics["incident_notice_max_hours"] = notice_h
    if report_d is not None:
        metrics["full_report_max_days"] = report_d

    if any(
        kw in low
        for kw in (
            "zero statutory liability",
            "bear no statutory liability",
            "waives all statutory",
            "tiada liabiliti berkanun",
            "mengecualikan liabiliti berkanun",
        )
    ):
        metrics["processor_direct_liability"] = "zero_statutory_liability_waiver"

    if any(
        kw in low
        for kw in (
            "waives all rights to inspect",
            "no audit",
            "prohibits regulatory audit",
            "menolak hak audit",
        )
    ):
        metrics["regulator_audit_access"] = False
    elif any(
        kw in low for kw in ("audit access", "bnm audit", "nacsa audit", "hak audit")
    ):
        metrics["regulator_audit_access"] = True

    return metrics


def _detect_narrow_definition_trap(term_name: str, clause_text: str) -> str | None:
    low_term = term_name.lower()
    low_txt = clause_text.lower()

    if any(
        k in low_term for k in ("security incident", "insiden keselamatan", "breach")
    ) and any(
        trap in low_txt
        for trap in (
            "excluding",
            "shall not include",
            "only if confirmed",
            "proven malice",
            "tidak termasuk",
            "kecuali",
            "exceeding 48 hours",
            "confirmed exfiltration",
            "without unauthorized",
        )
    ):
        return (
            f"Narrow definition of '{term_name}' excludes statutory breach/incident triggers "
            "mandated by Act 709 s. 12B and Act 854 s. 23."
        )

    if any(k in low_term for k in ("personal data", "data peribadi")) and any(
        trap in low_txt
        for trap in (
            "excluding business",
            "excluding ip",
            "excluding metadata",
            "shall not include nric",
            "tidak termasuk",
        )
    ):
        return (
            f"Narrow definition of '{term_name}' carves out personal data categories "
            "protected under Act 709 Section 4."
        )

    if any(
        k in low_term for k in ("sub-processor", "subprocessor", "sub-pemproses")
    ) and any(
        trap in low_txt
        for trap in ("excluding affiliates", "excluding cloud", "tidak termasuk")
    ):
        return (
            f"Narrow definition of '{term_name}' exempts cloud/affiliate processors from "
            "Act 709 s. 9(1A) and BNM RMiT vendor accountability."
        )
    return None


def _is_hostile_override_clause(clause_text: str) -> bool:
    low = clause_text.lower()
    return any(
        kw in low
        for kw in (
            "zero",
            "no liability",
            "capped at rm 1",
            "aggregate liability",
            "limit of liability",
            "sole discretion",
            "14 days",
            "10 days",
            "30 days",
            "waive",
            "exclude",
            "tiada liabiliti",
            "had liabiliti",
            "dikecualikan",
            "mengecualikan",
            "budi bicara mutlak",
        )
    )


def build_contract_ast(
    document_id: str,
    raw_text: str | None = None,
    file_bytes: bytes | None = None,
    filename: str | None = None,
    token_style: Literal["vault", "legacy"] = "vault",
) -> tuple[ContractASTGraph, ReversiblePIIVault]:
    """
    Ingests `.docx`, `.pdf`, or raw text (BM, EN, or mixed), scrubs Malaysian PII into
    a per-request ReversiblePIIVault, segments clauses with hierarchical SourceSpans,
    and builds the Intra-Contract Dependency Graph (`DEFINES_TERM`, `OVERRIDES_NOTWITHSTANDING`,
    `CROSS_REFERENCES`) with Narrow Definition and Shadow Override trap detection.
    """
    source_format, page_paragraphs, full_text = extract_contract_paragraphs(
        raw_text=raw_text,
        file_bytes=file_bytes,
        filename=filename,
    )
    raw_sha256 = hashlib.sha256(full_text.encode("utf-8")).hexdigest()

    vault = ReversiblePIIVault(token_style=token_style)
    scrubbed_text, _ = vault.scrub(full_text)

    raw_segments = _segment_scrubbed_text(scrubbed_text, page_paragraphs, vault)
    clauses: list[ContractClauseNode] = []

    for clause_id, seg_txt, page_no, para_idx, start_char, end_char in raw_segments:
        first_line = (
            seg_txt.split(":", 1)[0].strip() if ":" in seg_txt else seg_txt[:60]
        )
        section_type: Literal[
            "DEFINITION", "OPERATIVE", "PRIORITY_OVERRIDE", "GENERAL"
        ] = "OPERATIVE"
        low_seg = seg_txt.lower()
        if (
            _DEFINITION_RE.search(seg_txt)
            or "definition" in first_line.lower()
            or "definisi" in first_line.lower()
        ):
            section_type = "DEFINITION"
        elif _OVERRIDE_TRIGGER_RE.search(seg_txt):
            section_type = "PRIORITY_OVERRIDE"
        elif "preamble" in first_line.lower():
            section_type = "GENERAL"

        defined_terms = [
            m.group("term").strip() for m in _DEFINITION_RE.finditer(seg_txt)
        ]
        refs = [f"SEC-{m.group(1)}" for m in _CLAUSE_REF_RE.finditer(seg_txt)]
        # Deduplicate preserving order
        seen_refs: list[str] = []
        for r in refs:
            if r != clause_id and r not in seen_refs:
                seen_refs.append(r)

        seg_hash = hashlib.sha256(seg_txt.encode("utf-8")).hexdigest()
        span = SourceSpan(
            span_id=f"AST-{document_id}-{clause_id}",
            doc_id=document_id,
            source_uri=f"contract://{document_id}/{clause_id}",
            act_number=document_id,
            section_id=clause_id,
            canonical_citation=f"{document_id} {clause_id} (p.{page_no}, para {para_idx})",
            language="en" if "section" in low_seg or "clause" in low_seg else "ms",
            pdf_page=max(1, page_no),
            start_char=max(0, start_char),
            end_char=max(1, end_char),
            content_sha256=seg_hash,
            text=seg_txt,
        )

        clauses.append(
            ContractClauseNode(
                clause_id=clause_id,
                heading=first_line[:80],
                section_type=section_type,
                text=seg_txt,
                paragraph_idx=para_idx,
                pdf_page=max(1, page_no),
                start_char=max(0, start_char),
                end_char=max(1, end_char),
                source_span=span,
                defined_terms=defined_terms,
                referenced_clauses=seen_refs,
                extracted_metrics=_extract_clause_metrics(seg_txt),
            )
        )

    clause_by_id = {c.clause_id: c for c in clauses}
    edges: list[ContractDependencyEdge] = []
    narrow_traps: list[NarrowDefinitionTrap] = []
    shadow_traps: list[ShadowOverrideTrap] = []

    # 1. DEFINES_TERM edges + Narrow Definition Trap detection
    for def_clause in clauses:
        for term in def_clause.defined_terms:
            term_lower = term.lower()
            target_ids: list[str] = []
            for op_clause in clauses:
                if op_clause.clause_id == def_clause.clause_id:
                    continue
                if re.search(rf"\b{re.escape(term_lower)}\b", op_clause.text.lower()):
                    target_ids.append(op_clause.clause_id)
                    conflict_desc = _detect_narrow_definition_trap(
                        term, def_clause.text
                    )
                    edges.append(
                        ContractDependencyEdge(
                            source_clause_id=def_clause.clause_id,
                            target_clause_id=op_clause.clause_id,
                            edge_type=ContractEdgeType.DEFINES_TERM,
                            term_name=term,
                            trigger_phrase=f'"{term}"',
                            is_hostile_trap=conflict_desc is not None,
                            rationale=conflict_desc
                            or f"Defined term '{term}' governs {op_clause.clause_id}.",
                        )
                    )
            conflict_desc = _detect_narrow_definition_trap(term, def_clause.text)
            if conflict_desc:
                narrow_traps.append(
                    NarrowDefinitionTrap(
                        term_name=term,
                        definition_clause_id=def_clause.clause_id,
                        target_clause_ids=target_ids,
                        contract_definition=def_clause.text,
                        statutory_conflict=conflict_desc,
                        severity=RiskSeverity.HIGH,
                    )
                )

    # 2. OVERRIDES_NOTWITHSTANDING edges + Shadow Override Trap detection
    for src_clause in clauses:
        override_match = _OVERRIDE_TRIGGER_RE.search(src_clause.text)
        if not override_match:
            continue
        trigger_phrase = override_match.group("phrase").strip()
        explicit_targets = [
            ref
            for ref in src_clause.referenced_clauses
            if ref in clause_by_id and ref != src_clause.clause_id
        ]
        # Match numeric prefix refs e.g., Clause 5 -> SEC-5 or SEC-5.1
        if not explicit_targets:
            for ref_m in _CLAUSE_REF_RE.finditer(src_clause.text):
                ref_num = ref_m.group(1)
                for cid in clause_by_id:
                    if cid != src_clause.clause_id and (
                        cid == f"SEC-{ref_num}" or cid.startswith(f"SEC-{ref_num}.")
                    ):
                        explicit_targets.append(cid)

        # Blanket "anything to the contrary" overrides security/breach/protection clauses
        if not explicit_targets and any(
            k in trigger_phrase.lower()
            for k in ("anything to the contrary", "peruntukan lain", "perjanjian")
        ):
            for op_c in clauses:
                if op_c.clause_id != src_clause.clause_id and any(
                    kw in op_c.text.lower()
                    for kw in (
                        "security",
                        "breach",
                        "personal data",
                        "incident",
                        "audit",
                        "keselamatan",
                        "kebocoran",
                        "data peribadi",
                    )
                ):
                    explicit_targets.append(op_c.clause_id)

        is_hostile = _is_hostile_override_clause(src_clause.text)
        seen_t: set[str] = set()
        for tid in explicit_targets:
            if tid in seen_t or tid not in clause_by_id:
                continue
            seen_t.add(tid)
            target_c = clause_by_id[tid]
            edges.append(
                ContractDependencyEdge(
                    source_clause_id=src_clause.clause_id,
                    target_clause_id=tid,
                    edge_type=ContractEdgeType.OVERRIDES_NOTWITHSTANDING,
                    trigger_phrase=trigger_phrase,
                    is_hostile_trap=is_hostile,
                    rationale=(
                        f"{src_clause.clause_id} uses '{trigger_phrase}' to override {tid}."
                    ),
                )
            )
            if is_hostile:
                shadow_traps.append(
                    ShadowOverrideTrap(
                        overriding_clause_id=src_clause.clause_id,
                        target_clause_id=tid,
                        trigger_phrase=trigger_phrase,
                        overriding_quote=src_clause.text,
                        target_quote=target_c.text,
                        trap_description=(
                            f"Shadow override trap: {src_clause.clause_id} ('{trigger_phrase}') "
                            f"subordinates/hollows out compliance protections in {tid}."
                        ),
                        severity=RiskSeverity.CRITICAL,
                    )
                )

    # 3. CROSS_REFERENCES edges
    existing_override_pairs = {
        (e.source_clause_id, e.target_clause_id)
        for e in edges
        if e.edge_type == ContractEdgeType.OVERRIDES_NOTWITHSTANDING
    }
    for src_clause in clauses:
        for ref in src_clause.referenced_clauses:
            resolved_targets = [
                cid
                for cid in clause_by_id
                if cid != src_clause.clause_id
                and (cid == ref or cid.startswith(f"{ref}."))
            ]
            for tid in resolved_targets:
                if (src_clause.clause_id, tid) in existing_override_pairs:
                    continue
                edges.append(
                    ContractDependencyEdge(
                        source_clause_id=src_clause.clause_id,
                        target_clause_id=tid,
                        edge_type=ContractEdgeType.CROSS_REFERENCES,
                        trigger_phrase=ref,
                        is_hostile_trap=False,
                        rationale=f"{src_clause.clause_id} cross-references {tid}.",
                    )
                )

    ast_graph = ContractASTGraph(
        document_id=document_id,
        source_format=source_format,
        scrubbed_text=scrubbed_text,
        raw_sha256=raw_sha256,
        clauses=clauses,
        edges=edges,
        narrow_definition_traps=narrow_traps,
        shadow_override_traps=shadow_traps,
    )
    return ast_graph, vault
