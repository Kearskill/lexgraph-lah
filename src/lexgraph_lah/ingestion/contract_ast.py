import hashlib
import importlib
import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import zlib
from dataclasses import dataclass
from typing import Any, Literal, Protocol
from xml.etree import ElementTree as ET

from pydantic import BaseModel, Field

from lexgraph_lah.config import settings
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
    r"|walau\s+apa\s+pun\s+yang\s+terkandung\s+dalam\s+(?:klausa|seksyen|perjanjian)\s*[\d.]*"
    r"|walau\s+apa\s+pun\s+peruntukan\s+lain"
    r")",
    re.IGNORECASE,
)

_SUBJECT_TO_RE = re.compile(
    r"(?P<phrase>(?:subject\s+to|tertakluk\s+kepada)\s+"
    r"(?:Clause|Section|SEC-|Klausa|Seksyen)\s*(?P<num>\d+(?:\.\d+)*))",
    re.IGNORECASE,
)

_SCHEDULE_HEADING_RE = re.compile(
    r"\b(?P<kind>Schedule|Appendix|Annexure|Jadual|Lampiran)\s*(?P<code>[A-Z0-9]+(?:\.\d+)?)?\b",
    re.IGNORECASE,
)

_SURVIVES_TERMINATION_RE = re.compile(
    r"(?P<phrase>"
    r"survive(?:s)?\s+(?:any\s+|the\s+)?(?:termination|expiration|expiry)"
    r"|continue\s+in\s+full\s+force\s+(?:after|following)\s+termination"
    r"|kekal\s+berkuat\s+kuasa\s+(?:selepas|walaupun)\s+(?:penamatan|tamat)"
    r"|terus\s+berkuat\s+kuasa\s+(?:selepas|walaupun)\s+penamatan"
    r")",
    re.IGNORECASE,
)


@dataclass(slots=True)
class DocxTableBlock:
    """Structured OOXML `<w:tbl>` block extracted from a Word `.docx` document."""

    page_number: int
    heading: str
    schedule_code: str
    rows: list[list[str]]
    serialized_text: str


class OCRPageResult(BaseModel):
    """Per-page OCR output emitted by an `OCRAdapter`."""

    page_number: int = Field(..., ge=1)
    text: str = ""
    provider: str = "none"
    confidence: float = 0.0
    requires_ocr: bool = True


class OCRAdapter(Protocol):
    """Pluggable OCR interface for scanned / low-text PDF pages."""

    provider_name: str

    def extract_pages(
        self, pdf_bytes: bytes, page_numbers: list[int]
    ) -> list[OCRPageResult]: ...


class NullOCRAdapter:
    """Default safe OCR adapter (`OCR_PROVIDER=none`) returning empty text for abstention."""

    provider_name: str = "none"

    def extract_pages(
        self, pdf_bytes: bytes, page_numbers: list[int]
    ) -> list[OCRPageResult]:
        return [
            OCRPageResult(
                page_number=p,
                text="",
                provider="none",
                confidence=0.0,
                requires_ocr=True,
            )
            for p in page_numbers
        ]


class TesseractOCRAdapter:
    """Optional Tesseract OCR adapter (`OCR_PROVIDER=tesseract`)."""

    provider_name: str = "tesseract"

    def extract_pages(
        self, pdf_bytes: bytes, page_numbers: list[int]
    ) -> list[OCRPageResult]:
        results: list[OCRPageResult] = []
        tess_bin = shutil.which("tesseract")
        if tess_bin is None:
            return [
                OCRPageResult(
                    page_number=p,
                    text="",
                    provider="tesseract",
                    confidence=0.0,
                    requires_ocr=True,
                )
                for p in page_numbers
            ]
        try:
            pytesseract = importlib.import_module("pytesseract")
            fitz = importlib.import_module("fitz")
            pil_image = importlib.import_module("PIL.Image")
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            for pno in page_numbers:
                idx = max(0, min(len(doc) - 1, pno - 1))
                pix = doc[idx].get_pixmap(dpi=200)
                img = pil_image.open(io.BytesIO(pix.tobytes("png")))
                txt = str(pytesseract.image_to_string(img, lang="eng+msa")).strip()
                results.append(
                    OCRPageResult(
                        page_number=pno,
                        text=txt,
                        provider="tesseract",
                        confidence=0.85 if txt else 0.0,
                        requires_ocr=True,
                    )
                )
            return results
        except (
            ImportError,
            RuntimeError,
            ValueError,
            OSError,
            subprocess.SubprocessError,
        ):
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                tmp.write(pdf_bytes)
                tmp_path = tmp.name
            try:
                proc = subprocess.run(
                    [tess_bin, tmp_path, "stdout"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                txt = proc.stdout.strip() if proc.returncode == 0 else ""
            except (OSError, subprocess.SubprocessError):
                txt = ""
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            return [
                OCRPageResult(
                    page_number=p,
                    text=txt if i == 0 else "",
                    provider="tesseract",
                    confidence=0.75 if (i == 0 and txt) else 0.0,
                    requires_ocr=True,
                )
                for i, p in enumerate(page_numbers)
            ]


class GeminiVisionOCRAdapter:
    """Optional Gemini Vision OCR adapter (`OCR_PROVIDER=gemini_vision`)."""

    provider_name: str = "gemini_vision"

    def extract_pages(
        self, pdf_bytes: bytes, page_numbers: list[int]
    ) -> list[OCRPageResult]:
        api_key = settings.gemini_api_key.strip()
        if api_key in {"mock-key-for-ci", "mock-ci-key-zero-cost", "your_key_here", ""}:
            return [
                OCRPageResult(
                    page_number=p,
                    text="",
                    provider="gemini_vision",
                    confidence=0.0,
                    requires_ocr=True,
                )
                for p in page_numbers
            ]
        try:
            genai_mod = importlib.import_module("google.genai")
            types_mod = importlib.import_module("google.genai.types")
            client = genai_mod.Client(api_key=api_key)
            part = types_mod.Part.from_bytes(
                data=pdf_bytes, mime_type="application/pdf"
            )
            prompt = (
                "Transcribe all visible contractual text from pages "
                f"{page_numbers} verbatim without summarizing."
            )
            resp = client.models.generate_content(
                model=settings.model_name,
                contents=[part, prompt],
            )
            txt = str(getattr(resp, "text", "") or "").strip()
            return [
                OCRPageResult(
                    page_number=p,
                    text=txt if i == 0 else "",
                    provider="gemini_vision",
                    confidence=0.90 if (i == 0 and txt) else 0.0,
                    requires_ocr=True,
                )
                for i, p in enumerate(page_numbers)
            ]
        except (ImportError, RuntimeError, ValueError, OSError):
            return [
                OCRPageResult(
                    page_number=p,
                    text="",
                    provider="gemini_vision",
                    confidence=0.0,
                    requires_ocr=True,
                )
                for p in page_numbers
            ]


def get_ocr_adapter(provider_name: str | None = None) -> OCRAdapter:
    """Factory returning the configured OCR adapter (`none` | `tesseract` | `gemini_vision`)."""
    name = (provider_name or settings.ocr_provider or "none").strip().lower()
    if name == "tesseract":
        return TesseractOCRAdapter()
    if name == "gemini_vision":
        return GeminiVisionOCRAdapter()
    return NullOCRAdapter()


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


def _extract_paragraph_text(para: ET.Element) -> str:
    texts: list[str] = []
    for elem in para.iter():
        if elem.tag in {f"{_W_NS}t", f"{_W_NS}delText"} and elem.text:
            texts.append(elem.text)
    return "".join(texts).strip()


def extract_docx_structured(
    data: bytes,
) -> tuple[list[tuple[int, str]], list[DocxTableBlock]]:
    """
    Extracts `(page_number, paragraph_text)` tuples AND structured `<w:tbl>`
    schedule/table blocks (`DocxTableBlock`) from a `.docx` OpenXML archive.
    """
    from lexgraph_lah.security.doc_firewall import validate_zip_archive_safety

    validate_zip_archive_safety(data)
    paragraphs: list[tuple[int, str]] = []
    tables: list[DocxTableBlock] = []
    page_num = 1
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        if "word/document.xml" not in zf.namelist():
            raise ValueError("Invalid .docx archive: missing word/document.xml")
        xml_bytes = zf.read("word/document.xml")
    root = ET.fromstring(xml_bytes)
    body = root.find(f"{_W_NS}body")
    children = list(body) if body is not None else list(root)

    last_para_text = ""
    table_counter = 0

    for child in children:
        if child.tag == f"{_W_NS}p":
            if (
                child.find(f".//{_W_NS}br[@{_W_NS}type='page']") is not None
                or child.find(f".//{_W_NS}lastRenderedPageBreak") is not None
            ):
                page_num += 1
            joined = _extract_paragraph_text(child)
            if joined:
                paragraphs.append((page_num, joined))
                last_para_text = joined
        elif child.tag == f"{_W_NS}tbl":
            rows: list[list[str]] = []
            for tr in child.findall(f"{_W_NS}tr"):
                row_cells: list[str] = []
                for tc in tr.findall(f"{_W_NS}tc"):
                    cell_paras = [
                        _extract_paragraph_text(p) for p in tc.findall(f".//{_W_NS}p")
                    ]
                    cell_txt = " ".join(cp for cp in cell_paras if cp).strip()
                    row_cells.append(cell_txt)
                if any(row_cells):
                    rows.append(row_cells)
            if rows:
                table_counter += 1
                sched_match = _SCHEDULE_HEADING_RE.search(last_para_text)
                if sched_match:
                    kind_raw = sched_match.group("kind").upper()
                    code_raw = (sched_match.group("code") or str(table_counter)).upper()
                    sched_code = f"SCHED-{kind_raw}-{code_raw}"
                    heading = last_para_text[:80]
                else:
                    sched_code = f"SCHED-{table_counter}"
                    heading = f"Schedule Table {table_counter}"
                row_lines = [" | ".join(c for c in r if c) for r in rows]
                serialized = f"{heading}: " + "; ".join(row_lines)
                paragraphs.append((page_num, serialized))
                tables.append(
                    DocxTableBlock(
                        page_number=page_num,
                        heading=heading,
                        schedule_code=sched_code,
                        rows=rows,
                        serialized_text=serialized,
                    )
                )

    return paragraphs, tables


def extract_text_from_docx_bytes(data: bytes) -> list[tuple[int, str]]:
    """
    Extracts `(page_number, paragraph_text)` tuples from a `.docx` OpenXML archive
    using Python stdlib `zipfile` and `xml.etree.ElementTree`.
    """
    paragraphs, _ = extract_docx_structured(data)
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

    # Structured PDFs (with obj/stream/XObject) that yielded no Tj/TJ text operators
    # are image-only / scanned PDFs and must trigger OCR fallback rather than dumping
    # raw PDF syntax tokens as clause text.
    if re.search(rb"\b\d+\s+\d+\s+obj\b|stream\b|/Subtype\s*/Image|/XObject\b", data):
        return [(1, "")]

    # Fallback: readable plain-text lines inside minimal plain-text synthetic PDFs
    decoded = data.decode("utf-8", errors="ignore")
    lines = [
        ln.strip()
        for ln in decoded.splitlines()
        if ln.strip()
        and not ln.startswith(
            ("%PDF", "%%EOF", "obj", "endobj", "xref", "trailer", "startxref")
        )
    ]
    if lines:
        return [(1, "\n".join(lines))]
    return [(1, "")]


def detect_low_text_pdf_pages(
    data: bytes,
    extracted_pages: list[tuple[int, str]],
    min_chars_per_page: int = 25,
) -> list[int]:
    """
    Detects image-only or low-text PDF pages requiring OCR fallback.
    """
    has_image_obj = bool(re.search(rb"/Subtype\s*/Image|/XObject|Do\b", data))
    if not extracted_pages:
        return [1]
    low_pages = [
        pno for pno, txt in extracted_pages if len(txt.strip()) < min_chars_per_page
    ]
    if low_pages:
        return low_pages
    total_chars = sum(len(txt.strip()) for _, txt in extracted_pages)
    if has_image_obj and total_chars < min_chars_per_page:
        return [pno for pno, _ in extracted_pages]
    return []


def extract_contract_paragraphs(
    raw_text: str | None = None,
    file_bytes: bytes | None = None,
    filename: str | None = None,
    *,
    ocr_adapter: OCRAdapter | None = None,
) -> tuple[
    Literal["text", "docx", "pdf"],
    list[tuple[int, str]],
    str,
    list[DocxTableBlock],
    dict[str, Any] | None,
]:
    """
    Normalizes `.docx`, `.pdf`, or raw text into:
    `(source_format, page_paragraphs, full_text, docx_tables, ocr_metadata)`.
    """
    if file_bytes is not None:
        fname = (filename or "").lower()
        if fname.endswith(".docx") or file_bytes[:2] == b"PK":
            paras, tables = extract_docx_structured(file_bytes)
            full_text = "\n".join(p for _, p in paras)
            return "docx", paras, full_text, tables, None
        if fname.endswith(".pdf") or file_bytes.startswith(b"%PDF"):
            paras = extract_text_from_pdf_bytes(file_bytes)
            low_pages = detect_low_text_pdf_pages(file_bytes, paras)
            ocr_meta: dict[str, Any] | None = None
            if low_pages:
                adapter = ocr_adapter or get_ocr_adapter()
                ocr_results = adapter.extract_pages(file_bytes, low_pages)
                ocr_by_page = {
                    r.page_number: r.text.strip() for r in ocr_results if r.text.strip()
                }
                if ocr_by_page:
                    merged_paras: list[tuple[int, str]] = []
                    seen_pages: set[int] = set()
                    for pno, existing_txt in paras:
                        seen_pages.add(pno)
                        ocr_txt = ocr_by_page.get(pno, "")
                        combined = "\n".join(
                            t for t in (existing_txt.strip(), ocr_txt) if t
                        ).strip()
                        if combined:
                            merged_paras.append((pno, combined))
                    for pno, ocr_txt in sorted(ocr_by_page.items()):
                        if pno not in seen_pages and ocr_txt:
                            merged_paras.append((pno, ocr_txt))
                    paras = merged_paras or paras
                    ocr_meta = {
                        "provider": adapter.provider_name,
                        "low_text_pages": low_pages,
                        "ocr_applied": True,
                        "abstention_recommended": False,
                        "pages_recovered": sorted(ocr_by_page.keys()),
                    }
                else:
                    ocr_meta = {
                        "provider": adapter.provider_name,
                        "low_text_pages": low_pages,
                        "ocr_applied": False,
                        "abstention_recommended": True,
                        "reason": (
                            f"Low-text/scanned PDF page(s) {low_pages} detected with "
                            f"OCR_PROVIDER={adapter.provider_name}; deterministic abstention recommended."
                        ),
                    }
            full_text = "\n".join(p for _, p in paras)
            return "pdf", paras, full_text, [], ocr_meta
        decoded = file_bytes.decode("utf-8", errors="replace")
        paras = [(1, line.strip()) for line in decoded.splitlines() if line.strip()]
        return "text", paras, decoded, [], None

    text = raw_text or ""
    paras = [(1, line.strip()) for line in text.splitlines() if line.strip()]
    return "text", paras, text, [], None


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
    *,
    ocr_adapter: OCRAdapter | None = None,
) -> tuple[ContractASTGraph, ReversiblePIIVault]:
    """
    Ingests `.docx`, `.pdf`, or raw text (BM, EN, or mixed), scrubs Malaysian PII into
    a per-request ReversiblePIIVault, segments clauses with hierarchical SourceSpans,
    parses OOXML `<w:tbl>` schedules (`Jadual`/`Lampiran`), runs scanned PDF OCR fallback,
    and builds the Intra-Contract Dependency Graph (`DEFINES_TERM`,
    `OVERRIDES_NOTWITHSTANDING`, `CROSS_REFERENCES`, `SUBJECT_TO`,
    `INCORPORATES_SCHEDULE`, `SURVIVES_TERMINATION`) with trap detection.
    """
    source_format, page_paragraphs, full_text, docx_tables, ocr_meta = (
        extract_contract_paragraphs(
            raw_text=raw_text,
            file_bytes=file_bytes,
            filename=filename,
            ocr_adapter=ocr_adapter,
        )
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
            "DEFINITION", "OPERATIVE", "PRIORITY_OVERRIDE", "SCHEDULE", "GENERAL"
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
        elif _SCHEDULE_HEADING_RE.match(first_line):
            section_type = "SCHEDULE"
        elif "preamble" in first_line.lower():
            section_type = "GENERAL"

        defined_terms = [
            m.group("term").strip() for m in _DEFINITION_RE.finditer(seg_txt)
        ]
        refs = [f"SEC-{m.group(1)}" for m in _CLAUSE_REF_RE.finditer(seg_txt)]
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

    # Append structured OOXML `<w:tbl>` schedule/table AST nodes
    schedule_nodes_by_id: dict[str, ContractClauseNode] = {
        c.clause_id: c for c in clauses if c.section_type == "SCHEDULE"
    }
    for tbl_idx, tbl in enumerate(docx_tables, start=1):
        scrubbed_rows = [[vault.scrub(cell)[0] for cell in row] for row in tbl.rows]
        scrubbed_tbl_text, _ = vault.scrub(tbl.serialized_text)
        sched_id = tbl.schedule_code
        if sched_id in {c.clause_id for c in clauses}:
            sched_id = f"{tbl.schedule_code}-{tbl_idx}"
        t_start = max(0, scrubbed_text.find(scrubbed_tbl_text[:30]))
        t_end = max(t_start + 1, t_start + len(scrubbed_tbl_text))
        t_hash = hashlib.sha256(scrubbed_tbl_text.encode("utf-8")).hexdigest()
        t_span = SourceSpan(
            span_id=f"AST-{document_id}-{sched_id}",
            doc_id=document_id,
            source_uri=f"contract://{document_id}/{sched_id}",
            act_number=document_id,
            section_id=sched_id,
            canonical_citation=f"{document_id} {sched_id} (p.{tbl.page_number}, table {tbl_idx})",
            language="ms"
            if any(k in scrubbed_tbl_text.lower() for k in ("jadual", "lampiran"))
            else "en",
            pdf_page=max(1, tbl.page_number),
            start_char=t_start,
            end_char=t_end,
            content_sha256=t_hash,
            text=scrubbed_tbl_text,
        )
        sched_node = ContractClauseNode(
            clause_id=sched_id,
            heading=tbl.heading[:80],
            section_type="SCHEDULE",
            text=scrubbed_tbl_text,
            paragraph_idx=len(clauses),
            pdf_page=max(1, tbl.page_number),
            start_char=t_start,
            end_char=t_end,
            source_span=t_span,
            defined_terms=[],
            referenced_clauses=[],
            extracted_metrics=_extract_clause_metrics(scrubbed_tbl_text),
            table_rows=scrubbed_rows,
        )
        clauses.append(sched_node)
        schedule_nodes_by_id[sched_id] = sched_node

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

    # 3. SUBJECT_TO edges (EN "subject to Clause..." / BM "tertakluk kepada Klausa...")
    for src_clause in clauses:
        for subj_m in _SUBJECT_TO_RE.finditer(src_clause.text):
            ref_num = subj_m.group("num")
            phrase = subj_m.group("phrase").strip()
            targets = [
                cid
                for cid in clause_by_id
                if cid != src_clause.clause_id
                and (cid == f"SEC-{ref_num}" or cid.startswith(f"SEC-{ref_num}."))
            ]
            for tid in targets:
                edges.append(
                    ContractDependencyEdge(
                        source_clause_id=src_clause.clause_id,
                        target_clause_id=tid,
                        edge_type=ContractEdgeType.SUBJECT_TO,
                        trigger_phrase=phrase,
                        is_hostile_trap=False,
                        rationale=f"{src_clause.clause_id} is expressly '{phrase}' ({tid}).",
                    )
                )

    # 4. INCORPORATES_SCHEDULE edges (Schedule / Appendix / Jadual / Lampiran)
    for src_clause in clauses:
        if src_clause.section_type == "SCHEDULE":
            continue
        for sched_m in _SCHEDULE_HEADING_RE.finditer(src_clause.text):
            kind = sched_m.group("kind").upper()
            code = (sched_m.group("code") or "").upper()
            matched_sched_ids = [
                sid
                for sid, snode in schedule_nodes_by_id.items()
                if (code and (code in sid or code in snode.heading.upper()))
                or (not code and kind in sid)
            ]
            if not matched_sched_ids and schedule_nodes_by_id:
                matched_sched_ids = [next(iter(schedule_nodes_by_id.keys()))]
            if not matched_sched_ids:
                matched_sched_ids = [
                    f"SCHED-{kind}-{code}" if code else f"SCHED-{kind}"
                ]
            for sid in matched_sched_ids:
                edges.append(
                    ContractDependencyEdge(
                        source_clause_id=src_clause.clause_id,
                        target_clause_id=sid,
                        edge_type=ContractEdgeType.INCORPORATES_SCHEDULE,
                        trigger_phrase=sched_m.group(0).strip(),
                        is_hostile_trap=False,
                        rationale=f"{src_clause.clause_id} incorporates {sid}.",
                    )
                )

    # 5. SURVIVES_TERMINATION edges
    for src_clause in clauses:
        surv_m = _SURVIVES_TERMINATION_RE.search(src_clause.text)
        if not surv_m:
            continue
        surv_targets = [
            cid
            for ref in src_clause.referenced_clauses
            for cid in clause_by_id
            if cid != src_clause.clause_id and (cid == ref or cid.startswith(f"{ref}."))
        ] or [src_clause.clause_id]
        for tid in surv_targets:
            edges.append(
                ContractDependencyEdge(
                    source_clause_id=src_clause.clause_id,
                    target_clause_id=tid,
                    edge_type=ContractEdgeType.SURVIVES_TERMINATION,
                    trigger_phrase=surv_m.group("phrase").strip(),
                    is_hostile_trap=False,
                    rationale=f"{tid} survives termination per {src_clause.clause_id}.",
                )
            )

    # 6. CROSS_REFERENCES edges
    existing_special_pairs = {
        (e.source_clause_id, e.target_clause_id)
        for e in edges
        if e.edge_type
        in {
            ContractEdgeType.OVERRIDES_NOTWITHSTANDING,
            ContractEdgeType.SUBJECT_TO,
            ContractEdgeType.SURVIVES_TERMINATION,
        }
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
                if (src_clause.clause_id, tid) in existing_special_pairs:
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

    requires_ocr_abstention = bool(
        ocr_meta and ocr_meta.get("abstention_recommended") is True
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
        ocr_metadata=ocr_meta,
        requires_ocr_abstention=requires_ocr_abstention,
    )
    return ast_graph, vault
