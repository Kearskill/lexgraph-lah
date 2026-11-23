"""
Zero-token adversarial Document Security & Indirect Prompt Injection (IPI) Firewall.

Inspects `.docx` (OOXML XML layers, hidden runs, tiny/near-white fonts, macros,
customXml, comments), `.pdf` (invisible `3 Tr` rendering mode, micro/zero font sizes,
near-white fill colors, off-canvas text), and plain text BEFORE `ContractASTGraph`
ingestion, quarantining hostile payloads without mutating benign visible clauses.
"""

from __future__ import annotations

import io
import re
import time
import xml.etree.ElementTree as ET
import zipfile
import zlib
from typing import Any, Literal

from lexgraph_lah.config import settings
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import (
    DocumentSecurityFinding,
    DocumentSecurityReport,
    RiskSeverity,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary

SecurityFinding = DocumentSecurityFinding

_W_URI = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_R_URI = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_W_NS = f"{{{_W_URI}}}"

SecurityCategory = Literal[
    "HIDDEN_OOXML_TEXT",
    "HIDDEN_FONT_SIZE",
    "NEAR_WHITE_TEXT",
    "SUSPICIOUS_CUSTOM_XML",
    "MACRO_OR_EMBEDDED",
    "HIDDEN_PDF_LAYER",
    "INDIRECT_PROMPT_INJECTION",
    "STATUTORY_SPOOF_OVERRIDE",
    "UNICODE_BIDI_OVERRIDE",
    "ZERO_WIDTH_STEGANOGRAPHY",
    "UNICODE_HOMOGLYPH_SPOOFING",
]

_SEVERITY_ORDER: dict[RiskSeverity, int] = {
    RiskSeverity.LOW: 0,
    RiskSeverity.MEDIUM: 1,
    RiskSeverity.HIGH: 2,
    RiskSeverity.CRITICAL: 3,
}

# Bilingual (EN + BM) Indirect Prompt Injection and Statutory Spoofing patterns.
# Scoped specifically to adversarial control directives so genuine slow-SLA
# non-compliant contract clauses remain intact for downstream legal auditing.
_IPI_RULES: tuple[tuple[str, SecurityCategory, RiskSeverity, str], ...] = (
    (
        r"(?is)\[\s*(?:system|admin|developer|assistant|hidden|prompt)\b[^\]]*\]",
        "INDIRECT_PROMPT_INJECTION",
        RiskSeverity.CRITICAL,
        "Bracketed system/developer control directive detected in document payload.",
    ),
    (
        r"(?is)(?:<\|im_start\|>|<\|system\|>|###\s*(?:system|instruction|override)\b[^\n]*)",
        "INDIRECT_PROMPT_INJECTION",
        RiskSeverity.CRITICAL,
        "Prompt-delimiter control injection marker detected.",
    ),
    (
        r"(?i)\b(?:ignore|disregard|forget|override|bypass|suspend)\b.{0,45}\b(?:(?:all|previous|prior|above|system|developer|compliance|audit|statutory|existing)\s+)*(?:instructions?|prompts?|rules?|provisions?|checks?|constraints?|verdicts?|directives?|act\s*(?:709|854|658|265|136)|pdpa|rmit)\b",
        "INDIRECT_PROMPT_INJECTION",
        RiskSeverity.CRITICAL,
        "Instruction-override Indirect Prompt Injection directive detected.",
    ),
    (
        r"(?i)\b(?:force|return|output|mark|classify|set)\b.{0,40}\b(?:overall_risk|verdict|status|compliance|contract)?\s*[:=]?\s*(?:COMPLIANT|PATUH|NO\s+VIOLATION|LOW\s+RISK|ZERO\s+FINDINGS)\b",
        "INDIRECT_PROMPT_INJECTION",
        RiskSeverity.CRITICAL,
        "Verdict-forcing adversarial directive attempting to coerce a COMPLIANT result.",
    ),
    (
        r"(?i)\b(?:do\s+not\s+flag|suppress\s+all\s+findings|skip\s+(?:pdpa|act\s*709|act\s*854|act\s*658|bnm|rmit|citation)\s*(?:check|audit|scan)?)\b",
        "INDIRECT_PROMPT_INJECTION",
        RiskSeverity.HIGH,
        "Suppression directive attempting to disable statutory audit checks.",
    ),
    (
        r"(?i)\b(?:abaikan|ketepikan|lupakan|pintas)\b.{0,45}\b(?:semua\s+)?(?:arahan|peraturan|panduan|semakan|sekatan|peruntukan|undang-undang|akta\s*(?:709|854|658|265|136)|pdpa|rmit)(?:\s+(?:terdahulu|sebelumnya|sistem|berkanun|akta\s*(?:709|854|658|265|136)))?\b",
        "INDIRECT_PROMPT_INJECTION",
        RiskSeverity.CRITICAL,
        "Bahasa Malaysia instruction-override prompt injection detected.",
    ),
    (
        r"(?i)\b(?:tukar|tetapkan|keluarkan|isytiharkan)\b.{0,40}\b(?:keputusan|status|verdict|kontrak)?\s*(?:kepada|sebagai|:|=)?\s*(?:PATUH|COMPLIANT|TIADA\s+PELANGGARAN|RISIKO\s+RENDAH)\b",
        "INDIRECT_PROMPT_INJECTION",
        RiskSeverity.CRITICAL,
        "Bahasa Malaysia verdict-forcing directive detected.",
    ),
    (
        r"(?i)\b(?:arahan\s+sistem(?:\s+rahsia)?|pintas\s+akta\s*(?:709|854|658))\b",
        "INDIRECT_PROMPT_INJECTION",
        RiskSeverity.CRITICAL,
        "Bahasa Malaysia hidden system directive detected.",
    ),
    (
        r"(?i)\b(?:act\s*709|pdpa|act\s*854|p\.?u\.?\s*\(a\)\s*220/2024|bnm\s*rmit|sabah\s*cap\.?\s*67|sarawak\s*cap\.?\s*76|akta\s*(?:709|854)|seksyen\s*12b|section\s*12b|act\s*378|stamp\s*act|act\s*53|myinvois|act\s*(?:864|866|873))\b.{0,65}\b(?:(?:is\s+hereby|is|has\s+been)\s+repealed|does\s+not\s+apply\s+to\s+this\s+(?:ai|vendor|contract)|exempts?\s+this\s+audit|exempts?\s+.*?\bconsolidated|telah\s+dimansuhkan|permits?\s+(?:30|60|90)\s*[- ]?days?\s+(?:breach|notification|notice)|allows\s+(?:30|60|90)\s+days|allows?\s+consolidated\s+e-?invoices?\s+over\s+rm\s*10,?000)\b",
        "STATUTORY_SPOOF_OVERRIDE",
        RiskSeverity.HIGH,
        "Adversarial statutory-spoofing override attempting to misrepresent Malaysian statutory bounds.",
    ),
    (
        r"(?i)\b(?:spoof|fabricate|invent)\b.{0,35}\b(?:citation|statute|section|gazette|sourcespan)\b",
        "STATUTORY_SPOOF_OVERRIDE",
        RiskSeverity.HIGH,
        "Citation-spoofing directive detected.",
    ),
)

_COMPILED_IPI_RULES = [
    (re.compile(pat), cat, sev, rationale) for pat, cat, sev, rationale in _IPI_RULES
]

# Sentence splitter used to isolate inline adversarial directives without deleting
# genuine visible contract obligations residing in the same paragraph.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?;])\s+")

# Unicode Trojan-Source bidi controls, zero-width steganography, and Cyrillic/Greek
# confusables in Latin text (expressed purely via ASCII \uXXXX escapes).
_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
_BIDI_OVERRIDE_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")
_CONFUSABLE_MAP: dict[str, str] = {
    "\u0410": "A",
    "\u0430": "a",
    "\u0415": "E",
    "\u0435": "e",
    "\u041e": "O",
    "\u043e": "o",
    "\u0420": "P",
    "\u0440": "p",
    "\u0421": "C",
    "\u0441": "c",
    "\u0422": "T",
    "\u0442": "t",
    "\u0425": "X",
    "\u0445": "x",
    "\u0406": "I",
    "\u0456": "i",
    "\u041a": "K",
    "\u043a": "k",
    "\u041c": "M",
    "\u043c": "m",
    "\u041d": "H",
    "\u043d": "h",
    "\u0412": "B",
    "\u0432": "b",
    "\u0405": "S",
    "\u0455": "s",
    "\u0408": "J",
    "\u0458": "j",
    "\u0423": "Y",
    "\u0443": "y",
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0396": "Z",
    "\u0397": "H",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a5": "Y",
    "\u03a7": "X",
    "\u03b1": "a",
    "\u03b5": "e",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03bd": "v",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c4": "t",
    "\u03c5": "u",
    "\u03c7": "x",
}
_CONFUSABLE_TRANS = str.maketrans(_CONFUSABLE_MAP)
_HOMOGLYPH_TRIGGER_RE = re.compile(
    r"(?i)\b(?:act|akta|pdpa|bnm|rmit|section|seksyen|ignore|override|bypass|compliant|patuh|instructions?)\b"
)


def _format_unicode_excerpt(raw: str, *, strip_controls: bool = True) -> str:
    cleaned = raw
    if strip_controls:
        cleaned = _BIDI_OVERRIDE_RE.sub("[BIDI]", cleaned)
        cleaned = _ZERO_WIDTH_RE.sub("[ZW]", cleaned)
    return _safe_excerpt(cleaned)


def normalize_and_scan_unicode(
    text: str,
    *,
    source_format: Literal["docx", "pdf", "text"],
    location: str,
    findings: list[DocumentSecurityFinding],
    quarantined: list[str],
) -> str:
    """
    Detects and neutralizes:
      1. Trojan-Source Bidirectional (Bidi) override controls (`U+202A`..`U+202E`, `U+2066`..`U+2069`)
      2. Zero-width steganographic joiners/marks (`U+200B`..`U+200F`, `U+2060`, `U+FEFF`)
      3. Mixed-script Cyrillic/Greek-in-Latin homoglyph spoofing
    Returns canonical ASCII-skeleton-normalized text for downstream IPI and AST evaluation.
    """
    working = text

    if _BIDI_OVERRIDE_RE.search(working):
        excerpt = _format_unicode_excerpt(working)
        findings.append(
            DocumentSecurityFinding(
                finding_id=f"SEC-{len(findings) + 1:03d}",
                category="UNICODE_BIDI_OVERRIDE",
                severity=RiskSeverity.CRITICAL,
                source_format=source_format,
                location=location,
                excerpt=excerpt,
                rationale=(
                    "Trojan-Source bidirectional override/isolate control characters detected "
                    "and stripped to prevent visual text reordering attacks."
                ),
                quarantined=True,
            )
        )
        quarantined.append(excerpt)
        working = _BIDI_OVERRIDE_RE.sub("", working)

    if _ZERO_WIDTH_RE.search(working):
        excerpt = _format_unicode_excerpt(working)
        findings.append(
            DocumentSecurityFinding(
                finding_id=f"SEC-{len(findings) + 1:03d}",
                category="ZERO_WIDTH_STEGANOGRAPHY",
                severity=RiskSeverity.HIGH,
                source_format=source_format,
                location=location,
                excerpt=excerpt,
                rationale=(
                    "Zero-width steganographic characters detected and stripped to defeat "
                    "token-splitting evasion."
                ),
                quarantined=True,
            )
        )
        quarantined.append(excerpt)
        working = _ZERO_WIDTH_RE.sub("", working)

    if any(ch in _CONFUSABLE_MAP for ch in working):
        despoofed = working.translate(_CONFUSABLE_TRANS)
        has_ascii_alnum = bool(re.search(r"[A-Za-z0-9]", working))
        ipi_after_skeleton = _extract_matching_ipi(despoofed)
        if (
            has_ascii_alnum
            or ipi_after_skeleton is not None
            or _HOMOGLYPH_TRIGGER_RE.search(despoofed)
        ):
            excerpt = _safe_excerpt(working)
            findings.append(
                DocumentSecurityFinding(
                    finding_id=f"SEC-{len(findings) + 1:03d}",
                    category="UNICODE_HOMOGLYPH_SPOOFING",
                    severity=(
                        RiskSeverity.CRITICAL
                        if ipi_after_skeleton is not None
                        else RiskSeverity.HIGH
                    ),
                    source_format=source_format,
                    location=location,
                    excerpt=excerpt,
                    rationale=(
                        "Mixed-script Cyrillic/Greek homoglyph spoofing detected and normalized "
                        "to ASCII skeleton prior to IPI and statutory inspection."
                    ),
                    quarantined=True,
                )
            )
            quarantined.append(excerpt)
            working = despoofed

    return working


def _safe_excerpt(raw: str, max_len: int = 240) -> str:
    scrubbed = scrub_malaysian_pii(raw).masked_text.strip()
    if len(scrubbed) > max_len:
        return scrubbed[: max_len - 3].rstrip() + "..."
    return scrubbed


def _is_near_white_hex(raw_color: str | None) -> bool:
    if not raw_color:
        return False
    cleaned = raw_color.strip().lstrip("#").lower()
    if cleaned in {"auto", ""}:
        return False
    if cleaned == "white":
        return True
    if len(cleaned) != 6 or not all(c in "0123456789abcdef" for c in cleaned):
        return False
    r = int(cleaned[0:2], 16)
    g = int(cleaned[2:4], 16)
    b = int(cleaned[4:6], 16)
    return r >= 240 and g >= 240 and b >= 240


def _highest_severity(findings: list[DocumentSecurityFinding]) -> RiskSeverity:
    if not findings:
        return RiskSeverity.LOW
    return max(findings, key=lambda f: _SEVERITY_ORDER[f.severity]).severity


def _extract_matching_ipi(
    text: str,
) -> tuple[SecurityCategory, RiskSeverity, str] | None:
    for pattern, cat, sev, rationale in _COMPILED_IPI_RULES:
        if pattern.search(text):
            return cat, sev, rationale
    return None


def _filter_visible_line_for_ipi(
    line: str,
    *,
    source_format: Literal["docx", "pdf", "text"],
    location: str,
    findings: list[DocumentSecurityFinding],
    quarantined: list[str],
) -> str:
    """
    Removes adversarial IPI / statutory-spoofing spans from a visible line while
    retaining benign (or genuinely auditable non-compliant) contractual clauses.
    """
    working = normalize_and_scan_unicode(
        line,
        source_format=source_format,
        location=location,
        findings=findings,
        quarantined=quarantined,
    )
    finding_idx_base = len(findings) + 1

    # Step 1: Strip bracketed system tags inline first (e.g., "[SYSTEM: ...]")
    bracket_pattern, bracket_cat, bracket_sev, bracket_rat = _COMPILED_IPI_RULES[0]
    for m in list(bracket_pattern.finditer(working)):
        matched_text = m.group(0).strip()
        if matched_text and (
            _extract_matching_ipi(matched_text) is not None
            or re.search(
                r"(?i)(?:ignore|override|compliant|patuh|bypass|abaikan|statut|pdpa|act\s*709)",
                matched_text,
            )
        ):
            findings.append(
                DocumentSecurityFinding(
                    finding_id=f"SEC-{len(findings) + 1:03d}",
                    category=bracket_cat,
                    severity=bracket_sev,
                    source_format=source_format,
                    location=location,
                    excerpt=_safe_excerpt(matched_text),
                    rationale=bracket_rat,
                    quarantined=True,
                )
            )
            quarantined.append(_safe_excerpt(matched_text))
            working = working.replace(m.group(0), " ")

    working = re.sub(r"\s{2,}", " ", working).strip()
    if not working:
        return ""

    # Step 2: Check sentence by sentence so an injected trailing sentence does not
    # destroy a valid legal sentence in the same paragraph.
    sentences = _SENTENCE_SPLIT_RE.split(working)
    clean_sentences: list[str] = []
    for s_idx, sentence in enumerate(sentences, start=1):
        s_clean = sentence.strip()
        if not s_clean:
            continue
        hit = _extract_matching_ipi(s_clean)
        if hit is not None:
            cat, sev, rationale = hit
            findings.append(
                DocumentSecurityFinding(
                    finding_id=f"SEC-{max(finding_idx_base, len(findings) + 1):03d}",
                    category=cat,
                    severity=sev,
                    source_format=source_format,
                    location=f"{location}:sent[{s_idx}]"
                    if len(sentences) > 1
                    else location,
                    excerpt=_safe_excerpt(s_clean),
                    rationale=rationale,
                    quarantined=True,
                )
            )
            quarantined.append(_safe_excerpt(s_clean))
        else:
            clean_sentences.append(s_clean)

    return " ".join(clean_sentences).strip()


def _detect_run_hidden_reason(
    rpr: ET.Element | None,
) -> tuple[SecurityCategory, RiskSeverity, str] | None:
    if rpr is None:
        return None

    vanish = rpr.find(f"{_W_NS}vanish")
    if vanish is not None:
        val = (vanish.attrib.get(f"{_W_NS}val") or "true").strip().lower()
        if val not in {"0", "false", "off"}:
            return (
                "HIDDEN_OOXML_TEXT",
                RiskSeverity.CRITICAL,
                "OOXML <w:vanish/> property hides text from human reviewers while exposing it to naive LLM parsers.",
            )

    web_hidden = rpr.find(f"{_W_NS}webHidden")
    if web_hidden is not None:
        val = (web_hidden.attrib.get(f"{_W_NS}val") or "true").strip().lower()
        if val not in {"0", "false", "off"}:
            return (
                "HIDDEN_OOXML_TEXT",
                RiskSeverity.CRITICAL,
                "OOXML <w:webHidden/> property hides text run from rendered document views.",
            )

    for sz_tag in (f"{_W_NS}sz", f"{_W_NS}szCs"):
        sz_elem = rpr.find(sz_tag)
        if sz_elem is not None:
            raw_sz = sz_elem.attrib.get(f"{_W_NS}val")
            if raw_sz is not None:
                try:
                    if float(raw_sz) <= 2.0:
                        return (
                            "HIDDEN_FONT_SIZE",
                            RiskSeverity.HIGH,
                            f"Microscopic OOXML font size (sz={raw_sz} half-points <= 1pt) obscures hidden text.",
                        )
                except ValueError:
                    pass

    color_elem = rpr.find(f"{_W_NS}color")
    if color_elem is not None:
        color_val = color_elem.attrib.get(f"{_W_NS}val")
        if _is_near_white_hex(color_val):
            return (
                "NEAR_WHITE_TEXT",
                RiskSeverity.HIGH,
                f"Near-white OOXML text color (#{color_val}) conceals text against white pages.",
            )

    return None


class ZipBombError(ValueError):
    """Raised when an uploaded OOXML/ZIP archive violates zip-bomb or traversal safety guards."""


def validate_zip_archive_safety(
    data: bytes,
    *,
    max_uncompressed_bytes: int | None = None,
    max_compression_ratio: float | None = None,
    max_entries: int | None = None,
) -> dict[str, Any]:
    """
    Validates a ZIP/OOXML archive BEFORE full XML unpacking to neutralize zip-bombs
    (decompression bombs, spoofed central-directory sizes, excessive entry counts)
    and archive path-traversal entries (`../`, leading `/`, or backslashes).
    """
    byte_limit = (
        max_uncompressed_bytes
        if max_uncompressed_bytes is not None
        else settings.docx_max_uncompressed_bytes
    )
    ratio_limit = (
        max_compression_ratio
        if max_compression_ratio is not None
        else settings.docx_max_compression_ratio
    )
    entry_limit = max_entries if max_entries is not None else settings.docx_max_entries

    try:
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
    except zipfile.BadZipFile as exc:
        raise ZipBombError("Malformed or invalid ZIP/OOXML archive.") from exc

    total_actual_bytes = 0
    total_declared_bytes = 0
    entry_count = 0

    with zf:
        infos = zf.infolist()
        entry_count = len(infos)
        if entry_count > entry_limit:
            raise ZipBombError(
                f"Archive entry count ({entry_count}) exceeds ceiling ({entry_limit})."
            )

        for info in infos:
            fname = info.filename
            if (
                fname.startswith(("/", "\\"))
                or ".." in fname.replace("\\", "/").split("/")
                or (len(fname) >= 2 and fname[1] == ":")
            ):
                raise ZipBombError(f"Unsafe ZIP path traversal entry '{fname}'.")

            total_declared_bytes += max(0, info.file_size)
            if total_declared_bytes > byte_limit:
                raise ZipBombError(
                    f"Archive declared uncompressed size exceeds ceiling ({byte_limit} bytes)."
                )
            if (
                info.file_size > 65536
                and info.compress_size > 0
                and (info.file_size / info.compress_size) > ratio_limit
            ):
                raise ZipBombError(
                    f"Archive entry '{fname}' exceeds max compression ratio ({ratio_limit}x)."
                )

            # Stream entry in bounded 64 KB chunks to catch spoofed header file_size values
            entry_actual = 0
            with zf.open(info, "r") as stream:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    entry_actual += len(chunk)
                    total_actual_bytes += len(chunk)
                    if total_actual_bytes > byte_limit:
                        raise ZipBombError(
                            f"Archive decompressed payload exceeds ceiling ({byte_limit} bytes)."
                        )
                    if (
                        entry_actual > 65536
                        and info.compress_size > 0
                        and (entry_actual / info.compress_size) > ratio_limit
                    ):
                        raise ZipBombError(
                            f"Archive entry '{fname}' runtime ratio exceeds {ratio_limit}x."
                        )

    return {
        "entry_count": entry_count,
        "total_uncompressed_bytes": total_actual_bytes,
    }


def _inspect_docx_security(
    data: bytes,
) -> tuple[str, list[DocumentSecurityFinding], list[str]]:
    findings: list[DocumentSecurityFinding] = []
    quarantined: list[str] = []
    clean_paragraphs: list[str] = []

    try:
        validate_zip_archive_safety(data)
    except ZipBombError as exc:
        findings.append(
            DocumentSecurityFinding(
                finding_id="SEC-001",
                category="ZIP_BOMB_OR_MALFORMED_ARCHIVE",
                severity=RiskSeverity.CRITICAL,
                source_format="docx",
                location="archive.zip",
                excerpt="[Quarantined OOXML/ZIP bomb or path-traversal archive]",
                rationale=str(exc),
                quarantined=True,
            )
        )
        quarantined.append(f"[ZIP safety violation: {exc}]")
        return "", findings, quarantined

    try:
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid .docx archive") from exc

    with zf:
        names = zf.namelist()
        if "word/document.xml" not in names:
            raise ValueError("Invalid .docx archive: missing word/document.xml")

        # 1. Inspect macros / ActiveX / embedded binaries
        for name in names:
            low = name.lower()
            if (
                "vbaproject" in low
                or low.endswith(".bin")
                or low.startswith("word/activex/")
            ):
                findings.append(
                    DocumentSecurityFinding(
                        finding_id=f"SEC-{len(findings) + 1:03d}",
                        category="MACRO_OR_EMBEDDED",
                        severity=RiskSeverity.CRITICAL,
                        source_format="docx",
                        location=name,
                        excerpt=f"[Quarantined macro/embedded binary part: {name}]",
                        rationale="Embedded VBA macro or binary ActiveX payload detected inside .docx package.",
                        quarantined=True,
                    )
                )
                quarantined.append(f"[Binary part quarantined: {name}]")

        # 2. Inspect customXml/*.xml, word/comments.xml, and word/commentsExtended.xml
        for name in sorted(names):
            low = name.lower()
            is_custom_xml = low.startswith("customxml/") and low.endswith(".xml")
            is_comments = low == "word/comments.xml"
            is_comments_ext = low == "word/commentsextended.xml"
            if not (is_custom_xml or is_comments or is_comments_ext):
                continue

            raw_part = zf.read(name)
            if len(raw_part) > settings.docx_max_xml_part_bytes:
                findings.append(
                    DocumentSecurityFinding(
                        finding_id=f"SEC-{len(findings) + 1:03d}",
                        category="ZIP_BOMB_OR_MALFORMED_ARCHIVE",
                        severity=RiskSeverity.CRITICAL,
                        source_format="docx",
                        location=name,
                        excerpt=f"[Oversized OOXML part quarantined: {len(raw_part)} bytes]",
                        rationale=(
                            f"OOXML supplementary part '{name}' ({len(raw_part)} bytes) exceeds "
                            f"DOCX_MAX_XML_PART_BYTES ({settings.docx_max_xml_part_bytes})."
                        ),
                        quarantined=True,
                    )
                )
                quarantined.append(f"[Oversized XML part quarantined: {name}]")
                continue

            try:
                part_root = ET.fromstring(raw_part)
            except ET.ParseError:
                findings.append(
                    DocumentSecurityFinding(
                        finding_id=f"SEC-{len(findings) + 1:03d}",
                        category="SUSPICIOUS_CUSTOM_XML",
                        severity=RiskSeverity.HIGH,
                        source_format="docx",
                        location=name,
                        excerpt="[Malformed XML payload in supplementary OOXML part]",
                        rationale="Malformed supplementary XML part quarantined.",
                        quarantined=True,
                    )
                )
                continue

            if is_comments:
                for c_idx, comment in enumerate(
                    part_root.iter(f"{_W_NS}comment"), start=1
                ):
                    c_text = "".join(
                        t.text
                        for t in comment.iter()
                        if t.tag in {f"{_W_NS}t", f"{_W_NS}delText"} and t.text
                    ).strip()
                    if not c_text:
                        continue
                    c_text = normalize_and_scan_unicode(
                        c_text,
                        source_format="docx",
                        location=f"{name}:comment[{c_idx}]",
                        findings=findings,
                        quarantined=quarantined,
                    )
                    ipi_hit = _extract_matching_ipi(c_text)
                    hidden_reason = next(
                        (
                            hr
                            for hr in (
                                _detect_run_hidden_reason(
                                    p.find(f"{_W_NS}pPr/{_W_NS}rPr")
                                )
                                for p in comment.iter(f"{_W_NS}p")
                            )
                            if hr is not None
                        ),
                        None,
                    ) or next(
                        (
                            hr
                            for hr in (
                                _detect_run_hidden_reason(r.find(f"{_W_NS}rPr"))
                                for r in comment.iter(f"{_W_NS}r")
                            )
                            if hr is not None
                        ),
                        None,
                    )
                    if ipi_hit is not None or hidden_reason is not None:
                        cat = (
                            ipi_hit[0] if ipi_hit is not None else hidden_reason[0]  # type: ignore[index]
                        )
                        sev = (
                            ipi_hit[1] if ipi_hit is not None else hidden_reason[1]  # type: ignore[index]
                        )
                        findings.append(
                            DocumentSecurityFinding(
                                finding_id=f"SEC-{len(findings) + 1:03d}",
                                category=cat,
                                severity=sev,
                                source_format="docx",
                                location=f"{name}:comment[{c_idx}]",
                                excerpt=_safe_excerpt(c_text),
                                rationale=(
                                    ipi_hit[2]
                                    if ipi_hit is not None
                                    else f"Hidden run inside OOXML comment: {hidden_reason[2]}"  # type: ignore[index]
                                ),
                                quarantined=True,
                            )
                        )
                        quarantined.append(_safe_excerpt(c_text))
            elif is_comments_ext:
                xml_comments = [
                    c.strip()
                    for c in re.findall(
                        r"<!--(.*?)-->",
                        raw_part.decode("utf-8", errors="ignore"),
                        flags=re.DOTALL,
                    )
                    if c.strip()
                ]
                ext_texts = [
                    elem.text.strip()
                    for elem in part_root.iter()
                    if elem.text and elem.text.strip()
                ]
                ext_attr_vals = [
                    str(v).strip()
                    for elem in part_root.iter()
                    for v in elem.attrib.values()
                    if str(v).strip()
                ]
                joined_ext = " ".join(ext_texts + ext_attr_vals + xml_comments).strip()
                if joined_ext:
                    joined_ext = normalize_and_scan_unicode(
                        joined_ext,
                        source_format="docx",
                        location=name,
                        findings=findings,
                        quarantined=quarantined,
                    )
                tag_signal = any(
                    kw in elem.tag.lower()
                    for elem in part_root.iter()
                    for kw in ("prompt", "instruction", "system", "override", "inject")
                )
                ipi_hit = _extract_matching_ipi(joined_ext) if joined_ext else None
                hidden_in_ext = any(
                    _detect_run_hidden_reason(r.find(f"{_W_NS}rPr")) is not None
                    for r in part_root.iter(f"{_W_NS}r")
                )
                if tag_signal or ipi_hit is not None or hidden_in_ext:
                    cat = (
                        ipi_hit[0]
                        if ipi_hit is not None
                        else (
                            "HIDDEN_OOXML_TEXT"
                            if hidden_in_ext
                            else "SUSPICIOUS_CUSTOM_XML"
                        )
                    )
                    sev = ipi_hit[1] if ipi_hit is not None else RiskSeverity.CRITICAL
                    findings.append(
                        DocumentSecurityFinding(
                            finding_id=f"SEC-{len(findings) + 1:03d}",
                            category=cat,
                            severity=sev,
                            source_format="docx",
                            location=name,
                            excerpt=_safe_excerpt(joined_ext or f"<{part_root.tag}>"),
                            rationale="Suspicious instruction or hidden payload inside word/commentsExtended.xml quarantined.",
                            quarantined=True,
                        )
                    )
                    if joined_ext:
                        quarantined.append(_safe_excerpt(joined_ext))
            else:
                # customXml part: inspect tag names and text content
                custom_texts = [
                    elem.text.strip()
                    for elem in part_root.iter()
                    if elem.text and elem.text.strip()
                ]
                joined_custom = " ".join(custom_texts).strip()
                if joined_custom:
                    joined_custom = normalize_and_scan_unicode(
                        joined_custom,
                        source_format="docx",
                        location=name,
                        findings=findings,
                        quarantined=quarantined,
                    )
                tag_signal = any(
                    kw in elem.tag.lower()
                    for elem in part_root.iter()
                    for kw in ("prompt", "instruction", "system", "override", "inject")
                )
                ipi_hit = (
                    _extract_matching_ipi(joined_custom) if joined_custom else None
                )
                if tag_signal or ipi_hit is not None:
                    findings.append(
                        DocumentSecurityFinding(
                            finding_id=f"SEC-{len(findings) + 1:03d}",
                            category="SUSPICIOUS_CUSTOM_XML",
                            severity=RiskSeverity.CRITICAL
                            if ipi_hit
                            else RiskSeverity.HIGH,
                            source_format="docx",
                            location=name,
                            excerpt=_safe_excerpt(
                                joined_custom or f"<{part_root.tag}>"
                            ),
                            rationale="Suspicious customXml instruction payload quarantined outside visible body.",
                            quarantined=True,
                        )
                    )
                    if joined_custom:
                        quarantined.append(_safe_excerpt(joined_custom))

        # 3. Inspect primary word/document.xml (+ headers/footers/footnotes/endnotes)
        body_parts = ["word/document.xml"] + sorted(
            n
            for n in names
            if (
                n.startswith(("word/header", "word/footer"))
                or n in {"word/footnotes.xml", "word/endnotes.xml"}
            )
            and n.endswith(".xml")
        )
        for part_name in body_parts:
            raw_body_part = zf.read(part_name)
            if len(raw_body_part) > settings.docx_max_xml_part_bytes:
                findings.append(
                    DocumentSecurityFinding(
                        finding_id=f"SEC-{len(findings) + 1:03d}",
                        category="ZIP_BOMB_OR_MALFORMED_ARCHIVE",
                        severity=RiskSeverity.CRITICAL,
                        source_format="docx",
                        location=part_name,
                        excerpt=f"[Oversized OOXML XML part quarantined: {len(raw_body_part)} bytes]",
                        rationale=(
                            f"OOXML part '{part_name}' ({len(raw_body_part)} bytes) exceeds "
                            f"DOCX_MAX_XML_PART_BYTES ({settings.docx_max_xml_part_bytes})."
                        ),
                        quarantined=True,
                    )
                )
                quarantined.append(f"[Oversized XML part quarantined: {part_name}]")
                continue
            try:
                root = ET.fromstring(raw_body_part)
            except ET.ParseError:
                findings.append(
                    DocumentSecurityFinding(
                        finding_id=f"SEC-{len(findings) + 1:03d}",
                        category="SUSPICIOUS_CUSTOM_XML",
                        severity=RiskSeverity.HIGH,
                        source_format="docx",
                        location=part_name,
                        excerpt=f"[Malformed XML payload in {part_name}]",
                        rationale=f"Malformed OOXML part '{part_name}' quarantined.",
                        quarantined=True,
                    )
                )
                continue

            for p_idx, para in enumerate(root.iter(f"{_W_NS}p"), start=1):
                p_rpr = para.find(f"{_W_NS}pPr/{_W_NS}rPr")
                para_hidden = _detect_run_hidden_reason(p_rpr)

                visible_chunks: list[str] = []
                # Walk direct runs and tracked-change children (<w:ins>, <w:del>, <w:hyperlink>)
                runs = list(para.findall(f".//{_W_NS}r"))
                for r_idx, run in enumerate(runs, start=1):
                    run_texts = [
                        t.text
                        for t in run.iter()
                        if t.tag in {f"{_W_NS}t", f"{_W_NS}delText"} and t.text
                    ]
                    run_str = "".join(run_texts)
                    if not run_str.strip():
                        if run_str:
                            visible_chunks.append(run_str)
                        continue

                    hidden_reason = para_hidden or _detect_run_hidden_reason(
                        run.find(f"{_W_NS}rPr")
                    )
                    if hidden_reason is not None:
                        cat, sev, rationale = hidden_reason
                        excerpt = _safe_excerpt(run_str)
                        findings.append(
                            DocumentSecurityFinding(
                                finding_id=f"SEC-{len(findings) + 1:03d}",
                                category=cat,
                                severity=sev,
                                source_format="docx",
                                location=f"{part_name}:p[{p_idx}]:r[{r_idx}]",
                                excerpt=excerpt,
                                rationale=rationale,
                                quarantined=True,
                            )
                        )
                        quarantined.append(excerpt)
                    else:
                        visible_chunks.append(run_str)

                para_visible = "".join(visible_chunks).strip()
                if para_visible:
                    cleaned_para = _filter_visible_line_for_ipi(
                        para_visible,
                        source_format="docx",
                        location=f"{part_name}:p[{p_idx}]",
                        findings=findings,
                        quarantined=quarantined,
                    )
                    if cleaned_para:
                        clean_paragraphs.append(cleaned_para)

    return "\n".join(clean_paragraphs), findings, quarantined


def _decode_pdf_literal(raw_lit: str) -> str:
    return (
        raw_lit.replace(r"\(", "(")
        .replace(r"\)", ")")
        .replace(r"\\", "\\")
        .replace(r"\n", "\n")
        .replace(r"\r", " ")
        .replace(r"\t", " ")
    )


def _decode_pdf_hex(raw_hex: str) -> str:
    cleaned = re.sub(r"\s+", "", raw_hex)
    if len(cleaned) % 2 == 1:
        cleaned += "0"
    try:
        raw_bytes = bytes.fromhex(cleaned)
    except ValueError:
        return ""
    if raw_bytes.startswith(b"\xfe\xff"):
        return raw_bytes[2:].decode("utf-16-be", errors="ignore")
    if raw_bytes.startswith(b"\xff\xfe"):
        return raw_bytes[2:].decode("utf-16-le", errors="ignore")
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return raw_bytes.decode("latin-1", errors="ignore")


_PDF_OP_TOKEN_RE = re.compile(
    r"(?P<bt>\bBT\b)|"
    r"(?P<et>\bET\b)|"
    r"(?P<push>\bq\b)|"
    r"(?P<pop>\bQ\b)|"
    r"(?P<tm>(?P<tma>[+-]?\d*\.?\d+)\s+(?P<tmb>[+-]?\d*\.?\d+)\s+(?P<tmc>[+-]?\d*\.?\d+)\s+(?P<tmd>[+-]?\d*\.?\d+)\s+(?P<tmx>[+-]?\d*\.?\d+)\s+(?P<tmy>[+-]?\d*\.?\d+)\s+Tm\b)|"
    r"(?P<td>(?P<tdx>[+-]?\d*\.?\d+)\s+(?P<tdy>[+-]?\d*\.?\d+)\s+(?:Td|TD)\b)|"
    r"(?P<tf>/\S+\s+(?P<fsize>[+-]?\d*\.?\d+)\s+Tf)|"
    r"(?P<tr>(?P<rmode>\d+)\s+Tr)|"
    r"(?P<rgb>(?P<r>[+-]?\d*\.?\d+)\s+(?P<g>[+-]?\d*\.?\d+)\s+(?P<b>[+-]?\d*\.?\d+)\s+rg\b)|"
    r"(?P<gray>(?P<gr>[+-]?\d*\.?\d+)\s+g\b)|"
    r"(?P<tj_arr>\[(?P<arr_body>.*?)\]\s*TJ)|"
    r"(?P<tj_hex><(?P<hex>[0-9A-Fa-f\s]+)>\s*Tj)|"
    r"(?P<tj>\((?P<lit>(?:\\.|[^()\\])*)\)\s*Tj)",
    re.DOTALL,
)


def _inspect_pdf_security(
    data: bytes,
) -> tuple[str, list[DocumentSecurityFinding], list[str]]:
    findings: list[DocumentSecurityFinding] = []
    quarantined: list[str] = []
    clean_lines: list[str] = []

    streams: list[bytes] = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.DOTALL):
        chunk = match.group(1)
        try:
            streams.append(zlib.decompress(chunk))
        except zlib.error:
            streams.append(chunk)

    had_pdf_text_ops = False
    for s_idx, stream_bytes in enumerate(streams, start=1):
        try:
            text_str = stream_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text_str = stream_bytes.decode("latin-1", errors="ignore")
        state_stack: list[tuple[int, float, bool, float, float, bool]] = []
        render_mode = 0
        font_size = 12.0
        is_near_white = False
        cur_x = 0.0
        cur_y = 0.0
        off_page = False

        visible_stream_chunks: list[str] = []
        for m in _PDF_OP_TOKEN_RE.finditer(text_str):
            if m.group("bt") or m.group("et"):
                cur_x = 0.0
                cur_y = 0.0
                off_page = False
            elif m.group("push"):
                state_stack.append(
                    (render_mode, font_size, is_near_white, cur_x, cur_y, off_page)
                )
            elif m.group("pop"):
                if state_stack:
                    (
                        render_mode,
                        font_size,
                        is_near_white,
                        cur_x,
                        cur_y,
                        off_page,
                    ) = state_stack.pop()
            elif m.group("tm"):
                try:
                    cur_x = float(m.group("tmx"))
                    cur_y = float(m.group("tmy"))
                    off_page = (
                        cur_x < -50.0
                        or cur_y < -50.0
                        or cur_x > 2000.0
                        or cur_y > 2000.0
                    )
                except ValueError:
                    pass
            elif m.group("td"):
                try:
                    tx = float(m.group("tdx"))
                    ty = float(m.group("tdy"))
                    cur_x += tx
                    cur_y += ty
                    off_page = (
                        abs(tx) > 2000.0
                        or abs(ty) > 2000.0
                        or cur_x < -200.0
                        or cur_y < -200.0
                        or cur_x > 2000.0
                        or cur_y > 2000.0
                    )
                except ValueError:
                    pass
            elif m.group("tf"):
                try:
                    font_size = float(m.group("fsize"))
                except ValueError:
                    pass
            elif m.group("tr"):
                try:
                    render_mode = int(m.group("rmode"))
                except ValueError:
                    pass
            elif m.group("rgb"):
                try:
                    r = float(m.group("r"))
                    g = float(m.group("g"))
                    b = float(m.group("b"))
                    is_near_white = r >= 0.94 and g >= 0.94 and b >= 0.94
                except ValueError:
                    pass
            elif m.group("gray"):
                try:
                    gr = float(m.group("gr"))
                    is_near_white = gr >= 0.94
                except ValueError:
                    pass
            elif m.group("tj") or m.group("tj_hex") or m.group("tj_arr"):
                had_pdf_text_ops = True
                if m.group("tj"):
                    piece = _decode_pdf_literal(m.group("lit"))
                elif m.group("tj_hex"):
                    piece = _decode_pdf_hex(m.group("hex"))
                else:
                    parts: list[str] = []
                    for item_m in re.finditer(
                        r"\((?P<l>(?:\\.|[^()\\])*)\)|<(?P<h>[0-9A-Fa-f\s]+)>",
                        m.group("arr_body"),
                    ):
                        if item_m.group("l") is not None:
                            parts.append(_decode_pdf_literal(item_m.group("l")))
                        elif item_m.group("h") is not None:
                            parts.append(_decode_pdf_hex(item_m.group("h")))
                    piece = "".join(parts)
                if not piece.strip():
                    continue

                hidden_reasons: list[str] = []
                if render_mode == 3:
                    hidden_reasons.append("PDF invisible text rendering mode (`3 Tr`)")
                if font_size <= 2.0:
                    hidden_reasons.append(
                        f"PDF micro/zero font size (`{font_size} Tf`)"
                    )
                if is_near_white:
                    hidden_reasons.append("PDF white/near-white fill color")
                if off_page:
                    hidden_reasons.append(
                        f"PDF off-page text positioning (`{cur_x:g}, {cur_y:g}`)"
                    )

                if hidden_reasons:
                    excerpt = _safe_excerpt(piece)
                    findings.append(
                        DocumentSecurityFinding(
                            finding_id=f"SEC-{len(findings) + 1:03d}",
                            category="HIDDEN_PDF_LAYER",
                            severity=RiskSeverity.CRITICAL
                            if render_mode == 3
                            else RiskSeverity.HIGH,
                            source_format="pdf",
                            location=f"pdf:stream[{s_idx}]",
                            excerpt=excerpt,
                            rationale="; ".join(hidden_reasons)
                            + " conceals hidden PDF text layer.",
                            quarantined=True,
                        )
                    )
                    quarantined.append(excerpt)
                else:
                    visible_stream_chunks.append(piece.strip())

        if visible_stream_chunks:
            joined = " ".join(visible_stream_chunks).strip()
            cleaned = _filter_visible_line_for_ipi(
                joined,
                source_format="pdf",
                location=f"pdf:stream[{s_idx}]",
                findings=findings,
                quarantined=quarantined,
            )
            if cleaned:
                clean_lines.append(cleaned)

    if not had_pdf_text_ops and not findings:
        decoded = data.decode("utf-8", errors="ignore")
        for ln_idx, ln in enumerate(decoded.splitlines(), start=1):
            stripped = ln.strip()
            if not stripped or stripped.startswith(
                ("%PDF", "obj", "endobj", "xref", "trailer", "startxref")
            ):
                continue
            cleaned = _filter_visible_line_for_ipi(
                stripped,
                source_format="pdf",
                location=f"pdf:line[{ln_idx}]",
                findings=findings,
                quarantined=quarantined,
            )
            if cleaned:
                clean_lines.append(cleaned)

    return "\n".join(clean_lines), findings, quarantined


def _inspect_text_security(
    raw_text: str,
) -> tuple[str, list[DocumentSecurityFinding], list[str]]:
    findings: list[DocumentSecurityFinding] = []
    quarantined: list[str] = []
    clean_lines: list[str] = []

    for ln_idx, line in enumerate(raw_text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            clean_lines.append("")
            continue
        cleaned = _filter_visible_line_for_ipi(
            stripped,
            source_format="text",
            location=f"text:line[{ln_idx}]",
            findings=findings,
            quarantined=quarantined,
        )
        if cleaned:
            clean_lines.append(cleaned)

    sanitized = "\n".join(clean_lines).strip()
    return sanitized, findings, quarantined


def _strip_hidden_runs_from_elem(elem: ET.Element, parent_hidden: bool = False) -> None:
    """Recursively removes hidden OOXML `<w:r>` runs while preserving paragraph indices."""
    for child in list(elem):
        if child.tag == f"{_W_NS}p":
            p_rpr = child.find(f"{_W_NS}pPr/{_W_NS}rPr")
            para_hidden = _detect_run_hidden_reason(p_rpr) is not None
            _strip_hidden_runs_from_elem(
                child, parent_hidden=parent_hidden or para_hidden
            )
        elif child.tag == f"{_W_NS}r":
            is_hidden = parent_hidden or (
                _detect_run_hidden_reason(child.find(f"{_W_NS}rPr")) is not None
            )
            if is_hidden:
                elem.remove(child)
            else:
                # Neutralize inline IPI tokens and Unicode steganography/homoglyphs in visible runs
                for t_elem in child.iter():
                    if t_elem.tag in {f"{_W_NS}t", f"{_W_NS}delText"} and t_elem.text:
                        tmp_findings: list[DocumentSecurityFinding] = []
                        tmp_quar: list[str] = []
                        cleaned_txt = _filter_visible_line_for_ipi(
                            t_elem.text,
                            source_format="docx",
                            location="sanitize",
                            findings=tmp_findings,
                            quarantined=tmp_quar,
                        )
                        if tmp_findings or cleaned_txt != t_elem.text:
                            t_elem.text = cleaned_txt
        else:
            _strip_hidden_runs_from_elem(child, parent_hidden=parent_hidden)


def sanitize_docx_bytes(
    data: bytes,
    document_id: str = "SEC-DOCX-001",
) -> tuple[bytes, DocumentSecurityReport]:
    """
    Rewrites a `.docx` archive removing macros/binary parts, suspicious `customXml`,
    suspicious comments, and hidden OOXML runs (`<w:vanish/>`, `<w:webHidden/>`,
    tiny/near-white fonts) while preserving valid visible paragraphs and `<w:trackRevisions/>`.
    """
    validate_zip_archive_safety(data)
    report = scan_document_security(
        document_id=document_id,
        file_bytes=data,
        filename="upload.docx",
    )

    ET.register_namespace("w", _W_URI)
    ET.register_namespace("r", _R_URI)

    suspicious_parts = {
        f.location
        for f in report.findings
        if f.category
        in {
            "MACRO_OR_EMBEDDED",
            "SUSPICIOUS_CUSTOM_XML",
            "INDIRECT_PROMPT_INJECTION",
            "STATUTORY_SPOOF_OVERRIDE",
            "HIDDEN_OOXML_TEXT",
            "ZIP_BOMB_OR_MALFORMED_ARCHIVE",
        }
        and ":" not in f.location
    }
    suspicious_comment_indices = {
        int(m.group(1))
        for f in report.findings
        if f.location.startswith("word/comments.xml:comment[")
        for m in [re.search(r"comment\[(\d+)\]$", f.location)]
        if m is not None
    }

    in_buf = io.BytesIO(data)
    out_buf = io.BytesIO()
    with (
        zipfile.ZipFile(in_buf, "r") as zin,
        zipfile.ZipFile(out_buf, "w", compression=zipfile.ZIP_DEFLATED) as zout,
    ):
        for info in zin.infolist():
            name = info.filename
            low = name.lower()
            if (
                "vbaproject" in low
                or low.endswith(".bin")
                or low.startswith("word/activex/")
                or name in suspicious_parts
            ):
                continue

            raw_part = zin.read(name)
            is_body_xml = name == "word/document.xml" or (
                (
                    name.startswith(("word/header", "word/footer"))
                    or name in {"word/footnotes.xml", "word/endnotes.xml"}
                )
                and name.endswith(".xml")
            )
            if is_body_xml:
                try:
                    root = ET.fromstring(raw_part)
                    _strip_hidden_runs_from_elem(root)
                    raw_part = ET.tostring(root, encoding="utf-8", xml_declaration=True)
                except ET.ParseError:
                    pass
            elif low == "word/comments.xml" and suspicious_comment_indices:
                try:
                    c_root = ET.fromstring(raw_part)
                    for c_idx, comment in enumerate(
                        list(c_root.findall(f"{_W_NS}comment")), start=1
                    ):
                        if c_idx in suspicious_comment_indices:
                            c_root.remove(comment)
                    raw_part = ET.tostring(
                        c_root, encoding="utf-8", xml_declaration=True
                    )
                except ET.ParseError:
                    pass

            zout.writestr(name, raw_part)

    return out_buf.getvalue(), report


def scan_document_security(
    *,
    document_id: str = "SEC-SCAN-001",
    raw_text: str | None = None,
    file_bytes: bytes | None = None,
    filename: str | None = None,
) -> DocumentSecurityReport:
    """
    Zero-token pre-AST document security firewall inspecting OOXML `.docx`, `.pdf`,
    or raw text for hidden runs, micro/white fonts, macros/customXml, and bilingual IPI.
    """
    started = time.perf_counter()

    source_format: Literal["docx", "pdf", "text"] = "text"
    findings: list[DocumentSecurityFinding]
    if file_bytes is not None:
        fname = (filename or "").lower()
        if fname.endswith(".docx") or file_bytes[:2] == b"PK":
            source_format = "docx"
            sanitized_text, findings, quarantined = _inspect_docx_security(file_bytes)
        elif fname.endswith(".pdf") or file_bytes.startswith(b"%PDF"):
            source_format = "pdf"
            sanitized_text, findings, quarantined = _inspect_pdf_security(file_bytes)
        else:
            decoded = file_bytes.decode("utf-8", errors="replace")
            sanitized_text, findings, quarantined = _inspect_text_security(decoded)
    else:
        sanitized_text, findings, quarantined = _inspect_text_security(raw_text or "")

    latency_ms = (time.perf_counter() - started) * 1000.0
    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=latency_ms,
        retry_count=0,
        is_verified_grounded=True,
    )

    return DocumentSecurityReport(
        document_id=document_id,
        source_format=source_format,
        passed=len(findings) == 0,
        risk_level=_highest_severity(findings),
        blocked_injection_count=len(findings),
        quarantined_segments=quarantined,
        findings=findings,
        sanitized_text=sanitized_text,
        pii_scrub_applied=True,
        telemetry=telemetry,
    )
