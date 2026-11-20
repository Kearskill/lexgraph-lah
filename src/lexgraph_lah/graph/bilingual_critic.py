import hashlib
import re
from datetime import date
from typing import TYPE_CHECKING, Literal

from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    BilingualDivergenceIssue,
    BilingualDivergenceReport,
    RiskSeverity,
    SourceSpan,
    StatutoryNode,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import measure_latency_ms

if TYPE_CHECKING:
    from lexgraph_lah.graph.temporal_store import TemporalGraphStore

ACT_388_SECTION_63_BASIS = (
    "Interpretation Acts 1948 and 1967 [Act 388], s. 63: Where a statute or "
    "subsidiary instrument exists in both the national language (Bahasa Melayu) "
    "and English, the designated authoritative text prevails in the event of any "
    "conflict or divergence in legal meaning."
)

# Negation / prohibition patterns MUST be masked before matching permissive/mandatory modals
# so phrases like "tidak boleh", "tiada ... boleh", "may not", or "shall not" are never
# misclassified as permissive or affirmative obligations.
_EN_PROHIBITION_RE = re.compile(
    r"\b(?:shall\s+not|shall\s+be\s+no|must\s+not|may\s+not|cannot|"
    r"prohibited\s+from|no\s+(?:\w+\s+){1,4}shall)\b",
    re.IGNORECASE,
)
_EN_OBLIGATION_RE = re.compile(
    r"\b(?:shall|must|is\s+required\s+to|are\s+required\s+to|mandates?|"
    r"directly\s+bound|is\s+bound\s+to|are\s+bound\s+to)\b",
    re.IGNORECASE,
)
_EN_PERMISSION_RE = re.compile(
    r"\b(?:may|is\s+entitled\s+to|are\s+entitled\s+to|"
    r"at\s+(?:its|his|her|their)\s+discretion|permitted\s+to)\b",
    re.IGNORECASE,
)

_BM_PROHIBITION_RE = re.compile(
    r"\b(?:tidak\s+boleh|dilarang|tiada\s+(?:\w+\s+){0,5}boleh|tanpa\s+diskriminasi)\b",
    re.IGNORECASE,
)
_BM_OBLIGATION_RE = re.compile(
    r"\b(?:hendaklah|wajib|mewajibkan|mesti|terikat\s+secara\s+langsung|dikehendaki)\b",
    re.IGNORECASE,
)
_BM_PERMISSION_RE = re.compile(
    r"\b(?:boleh|berhak|mengikut\s+budi\s+bicaranya|dibenarkan)\b",
    re.IGNORECASE,
)

_WORD_NUMBERS: dict[str, float] = {
    "one": 1.0,
    "satu": 1.0,
    "two": 2.0,
    "dua": 2.0,
    "three": 3.0,
    "tiga": 3.0,
    "four": 4.0,
    "empat": 4.0,
    "five": 5.0,
    "lima": 5.0,
    "six": 6.0,
    "enam": 6.0,
    "seven": 7.0,
    "tujuh": 7.0,
    "eight": 8.0,
    "lapan": 8.0,
    "nine": 9.0,
    "sembilan": 9.0,
    "ten": 10.0,
    "sepuluh": 10.0,
    "fourteen": 14.0,
    "empat belas": 14.0,
    "thirty": 30.0,
    "tiga puluh": 30.0,
}

_UNIT_CANONICAL: dict[str, str] = {
    "hour": "hours",
    "hours": "hours",
    "jam": "hours",
    "day": "days",
    "days": "days",
    "hari": "days",
    "week": "weeks",
    "weeks": "weeks",
    "minggu": "weeks",
    "month": "months",
    "months": "months",
    "bulan": "months",
    "year": "years",
    "years": "years",
    "tahun": "years",
}

_NUM_TOKEN_PATTERN = (
    r"(?P<num>\d+(?:\.\d+)?|"
    r"empat\s+belas|tiga\s+puluh|"
    r"one|two|three|four|five|six|seven|eight|nine|ten|fourteen|thirty|"
    r"satu|dua|tiga|empat|lima|enam|tujuh|lapan|sembilan|sepuluh)"
)
_UNIT_TOKEN_PATTERN = (
    r"(?:(?:working|calendar|business|hari)\s+)?"
    r"(?P<unit>hours?|days?|weeks?|months?|years?|jam|hari|minggu|bulan|tahun)"
)
_DEADLINE_RE = re.compile(
    rf"\b{_NUM_TOKEN_PATTERN}\s+{_UNIT_TOKEN_PATTERN}\b",
    re.IGNORECASE,
)

_RM_PENALTY_RE = re.compile(r"\bRM\s*([0-9][0-9,]*(?:\.\d+)?)\b", re.IGNORECASE)

_SUBCLAUSE_NUM_RE = re.compile(r"(?<!\w)\((\d+[A-Za-z]?)\)")
_SUBCLAUSE_ALPHA_RE = re.compile(r"(?<![A-Za-z0-9.])\(([a-z])\)")
_EN_PROVISO_RE = re.compile(r"\bProvided\s+that\b", re.IGNORECASE)
_BM_PROVISO_RE = re.compile(r"\bDengan\s+syarat\s+bahawa\b", re.IGNORECASE)


def _extract_modalities(text: str, lang: Literal["en", "ms"]) -> list[str]:
    found: list[str] = []
    proh_re = _EN_PROHIBITION_RE if lang == "en" else _BM_PROHIBITION_RE
    obl_re = _EN_OBLIGATION_RE if lang == "en" else _BM_OBLIGATION_RE
    perm_re = _EN_PERMISSION_RE if lang == "en" else _BM_PERMISSION_RE

    if proh_re.search(text):
        found.append("PROHIBITION")
    masked = proh_re.sub(" __NEG__ ", text)
    if obl_re.search(masked):
        found.append("OBLIGATION")
    if perm_re.search(masked):
        found.append("PERMISSION")
    return found


def _parse_num_token(raw: str) -> float | None:
    norm = re.sub(r"\s+", " ", raw.strip().lower())
    if norm in _WORD_NUMBERS:
        return _WORD_NUMBERS[norm]
    try:
        return float(norm)
    except ValueError:
        return None


def _extract_deadlines(text: str) -> set[tuple[float, str]]:
    items: set[tuple[float, str]] = set()
    for m in _DEADLINE_RE.finditer(text):
        qty = _parse_num_token(m.group("num"))
        unit = _UNIT_CANONICAL.get(m.group("unit").lower())
        if qty is not None and unit is not None:
            items.add((qty, unit))
    return items


def _extract_rm_penalties(text: str) -> set[float]:
    amounts: set[float] = set()
    for m in _RM_PENALTY_RE.finditer(text):
        raw_num = m.group(1).replace(",", "")
        try:
            amounts.add(float(raw_num))
        except ValueError:
            continue
    return amounts


def _extract_subclauses(text: str, lang: Literal["en", "ms"]) -> set[str]:
    markers: set[str] = set()
    for m in _SUBCLAUSE_NUM_RE.finditer(text):
        markers.add(f"({m.group(1).upper()})")
    for m in _SUBCLAUSE_ALPHA_RE.finditer(text):
        markers.add(f"({m.group(1).lower()})")
    if lang == "en" and _EN_PROVISO_RE.search(text):
        markers.add("PROVISO")
    if lang == "ms" and _BM_PROVISO_RE.search(text):
        markers.add("PROVISO")
    return markers


def _make_inline_span(
    span_id: str,
    act_number: str,
    section_code: str,
    language: str,
    text: str,
) -> SourceSpan:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return SourceSpan(
        span_id=span_id,
        doc_id=f"{act_number or 'INLINE'}-{language}",
        act_number=act_number or "INLINE",
        section_id=section_code or "SEC-1",
        canonical_citation=f"{act_number or 'Inline Provision'} {section_code}".strip(),
        language=language,
        pdf_page=1,
        start_char=0,
        end_char=max(1, len(text)),
        char_offset_start=0,
        char_offset_end=max(1, len(text)),
        content_sha256=digest,
        sha256_hash=digest,
        text=text,
    )


def _format_deadlines(items: set[tuple[float, str]]) -> str:
    if not items:
        return "none"
    return ", ".join(
        f"{int(v) if v.is_integer() else v:g} {u}" for v, u in sorted(items)
    )


def _format_rm(amounts: set[float]) -> str:
    if not amounts:
        return "none"
    return ", ".join(
        f"RM {int(v):,}" if v.is_integer() else f"RM {v:,.2f}" for v in sorted(amounts)
    )


def _first_excerpt(text: str, limit: int = 220) -> str:
    clean = text.strip()
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3].rstrip() + "..."


def audit_bilingual_pair(
    en_node: StatutoryNode | None,
    bm_node: StatutoryNode | None,
    authoritative_node_id: str | None = None,
    authoritative_language: str | None = None,
    as_of_date: date | None = None,
    provision_id: str | None = None,
    act_name: str = "",
    act_number: str = "",
    section_code: str = "",
    en_text: str | None = None,
    bm_text: str | None = None,
) -> BilingualDivergenceReport:
    """
    Deterministic zero-token Act 388 s. 63 Bilingual Divergence Critic inspecting paired
    English and Bahasa Melayu provisions for deontic modality mismatches, numeric/deadline
    discrepancies, RM penalty ceiling discrepancies, and missing sub-clauses.
    """
    with measure_latency_ms() as elapsed_holder:
        eff_date = as_of_date or date.today()

        resolved_en_text = en_node.text if en_node else (en_text or "")
        resolved_bm_text = bm_node.text if bm_node else (bm_text or "")
        if en_text is not None and not en_node:
            resolved_en_text = scrub_malaysian_pii(en_text).masked_text
        if bm_text is not None and not bm_node:
            resolved_bm_text = scrub_malaysian_pii(bm_text).masked_text

        resolved_act_name = (
            (en_node.act_name if en_node else None)
            or (bm_node.act_name if bm_node else None)
            or act_name
            or "Malaysian Statutory Provision"
        )
        resolved_act_number = (
            (en_node.act_number if en_node else None)
            or (bm_node.act_number if bm_node else None)
            or act_number
            or "STATUTE"
        )
        resolved_section = (
            (en_node.section_code if en_node else None)
            or (bm_node.section_code if bm_node else None)
            or section_code
            or "SEC-1"
        )
        resolved_prov_id = (
            provision_id
            or (en_node.node_id if en_node else None)
            or (bm_node.node_id if bm_node else None)
            or f"{resolved_act_number}-{resolved_section}"
        )

        # Determine Act 388 s. 63 authoritative language
        auth_lang: Literal["ms", "en"]
        if authoritative_language is not None:
            auth_lang = "ms" if authoritative_language.lower() in {"ms", "bm"} else "en"
        elif (
            bm_node
            and bm_node.authoritative_language
            and not (en_node and en_node.authoritative_language)
        ):
            auth_lang = "ms"
        elif (
            en_node
            and en_node.authoritative_language
            and not (bm_node and bm_node.authoritative_language)
        ):
            auth_lang = "en"
        elif (
            authoritative_node_id
            and bm_node
            and authoritative_node_id == bm_node.node_id
        ):
            auth_lang = "ms"
        elif (
            authoritative_node_id
            and en_node
            and authoritative_node_id == en_node.node_id
        ):
            auth_lang = "en"
        else:
            # Post-1967 Acts default to BM authoritative unless designated EN
            auth_lang = "ms" if bm_node or resolved_bm_text else "en"

        auth_node_id = authoritative_node_id or (
            (bm_node.node_id if bm_node else "BM-TEXT")
            if auth_lang == "ms"
            else (en_node.node_id if en_node else "EN-TEXT")
        )
        auth_label = (
            "Bahasa Melayu (National Language)" if auth_lang == "ms" else "English"
        )

        en_spans: list[SourceSpan] = (
            list(en_node.source_spans)
            if en_node and en_node.source_spans
            else (
                [
                    _make_inline_span(
                        "SPAN-INLINE-EN",
                        resolved_act_number,
                        resolved_section,
                        "en",
                        resolved_en_text,
                    )
                ]
                if resolved_en_text.strip()
                else []
            )
        )
        bm_spans: list[SourceSpan] = (
            list(bm_node.source_spans)
            if bm_node and bm_node.source_spans
            else (
                [
                    _make_inline_span(
                        "SPAN-INLINE-BM",
                        resolved_act_number,
                        resolved_section,
                        "ms",
                        resolved_bm_text,
                    )
                ]
                if resolved_bm_text.strip()
                else []
            )
        )
        en_span_id = en_spans[0].span_id if en_spans else None
        bm_span_id = bm_spans[0].span_id if bm_spans else None

        if not resolved_en_text.strip() or not resolved_bm_text.strip():
            telemetry = compute_telemetry_summary(
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=elapsed_holder[0],
                retry_count=0,
                is_verified_grounded=True,
                trace_id="act388-single-lang",
            )
            return BilingualDivergenceReport(
                provision_id=resolved_prov_id,
                act_name=resolved_act_name,
                act_number=resolved_act_number,
                section_code=resolved_section,
                as_of_date=eff_date,
                authoritative_language=auth_lang,
                authoritative_node_id=auth_node_id,
                act_388_authority_basis=ACT_388_SECTION_63_BASIS,
                alignment_status="SINGLE_LANGUAGE_ONLY",
                has_divergence=False,
                en_node_id=en_node.node_id if en_node else None,
                bm_node_id=bm_node.node_id if bm_node else None,
                en_source_spans=en_spans,
                bm_source_spans=bm_spans,
                detected_en_modalities=(
                    _extract_modalities(resolved_en_text, "en")
                    if resolved_en_text.strip()
                    else []
                ),
                detected_bm_modalities=(
                    _extract_modalities(resolved_bm_text, "ms")
                    if resolved_bm_text.strip()
                    else []
                ),
                issues=[],
                summary_practitioner=(
                    f"Single-language provision ({resolved_prov_id}); no paired translation "
                    f"available for Act 388 s. 63 cross-check. Authoritative: {auth_label}."
                ),
                summary_rakyat=(
                    f"Only one language version was found for {resolved_act_number} {resolved_section}."
                ),
                telemetry=telemetry,
                disclaimer=DEFAULT_LEGAL_DISCLAIMER,
            )

        en_mods = _extract_modalities(resolved_en_text, "en")
        bm_mods = _extract_modalities(resolved_bm_text, "ms")
        en_mod_set = set(en_mods)
        bm_mod_set = set(bm_mods)

        issues: list[BilingualDivergenceIssue] = []

        # 1. Deontic Modality Mismatch (e.g. BM wajib/hendaklah vs EN may)
        has_perm_mismatch = (
            bool({"OBLIGATION", "PROHIBITION"} & en_mod_set)
            and "PERMISSION" in bm_mod_set
            and "PERMISSION" not in en_mod_set
        ) or (
            bool({"OBLIGATION", "PROHIBITION"} & bm_mod_set)
            and "PERMISSION" in en_mod_set
            and "PERMISSION" not in bm_mod_set
        )
        has_polarity_flip = bool(
            en_mod_set and bm_mod_set and en_mod_set.isdisjoint(bm_mod_set)
        )
        if has_perm_mismatch or has_polarity_flip:
            issues.append(
                BilingualDivergenceIssue(
                    issue_id=f"DIV-MODALITY-{resolved_section}",
                    divergence_type="DEONTIC_MODALITY_MISMATCH",
                    severity=RiskSeverity.HIGH,
                    en_excerpt=_first_excerpt(resolved_en_text),
                    bm_excerpt=_first_excerpt(resolved_bm_text),
                    en_span_id=en_span_id,
                    bm_span_id=bm_span_id,
                    authoritative_resolution=(
                        f"Under Act 388 s. 63, the {auth_label} text ({auth_node_id}) governs: "
                        f"apply {bm_mods if auth_lang == 'ms' else en_mods} modality."
                    ),
                    practitioner_note=(
                        f"Deontic modality conflict between EN {en_mods} and BM {bm_mods}. "
                        f"Pursuant to Act 388 s. 63, {auth_label} ({auth_node_id}) prevails."
                    ),
                    rakyat_note=(
                        f"The English and Bahasa Melayu versions disagree on whether this rule is mandatory or optional. "
                        f"Under Malaysian law (Act 388), the {auth_label} wording applies."
                    ),
                )
            )

        # 2. Numeric / Deadline Discrepancy
        en_deadlines = _extract_deadlines(resolved_en_text)
        bm_deadlines = _extract_deadlines(resolved_bm_text)
        if en_deadlines != bm_deadlines:
            issues.append(
                BilingualDivergenceIssue(
                    issue_id=f"DIV-DEADLINE-{resolved_section}",
                    divergence_type="NUMERIC_DEADLINE_DISCREPANCY",
                    severity=RiskSeverity.HIGH,
                    en_excerpt=_first_excerpt(resolved_en_text),
                    bm_excerpt=_first_excerpt(resolved_bm_text),
                    en_span_id=en_span_id,
                    bm_span_id=bm_span_id,
                    authoritative_resolution=(
                        f"Under Act 388 s. 63, {auth_label} ({auth_node_id}) governs time/numeric bounds: "
                        f"EN=[{_format_deadlines(en_deadlines)}] vs BM=[{_format_deadlines(bm_deadlines)}]."
                    ),
                    practitioner_note=(
                        f"Timeframe/numeric mismatch detected: EN specifies [{_format_deadlines(en_deadlines)}] "
                        f"while BM specifies [{_format_deadlines(bm_deadlines)}]. Follow {auth_label} ({auth_node_id})."
                    ),
                    rakyat_note=(
                        f"The English ({_format_deadlines(en_deadlines)}) and Bahasa Melayu "
                        f"({_format_deadlines(bm_deadlines)}) versions state different time limits. "
                        f"The {auth_label} rule counts."
                    ),
                )
            )

        # 3. Penalty Ceiling Discrepancy (RM amounts)
        en_rm = _extract_rm_penalties(resolved_en_text)
        bm_rm = _extract_rm_penalties(resolved_bm_text)
        if en_rm != bm_rm:
            issues.append(
                BilingualDivergenceIssue(
                    issue_id=f"DIV-PENALTY-{resolved_section}",
                    divergence_type="PENALTY_CEILING_DISCREPANCY",
                    severity=RiskSeverity.CRITICAL,
                    en_excerpt=_first_excerpt(resolved_en_text),
                    bm_excerpt=_first_excerpt(resolved_bm_text),
                    en_span_id=en_span_id,
                    bm_span_id=bm_span_id,
                    authoritative_resolution=(
                        f"Under Act 388 s. 63, {auth_label} ({auth_node_id}) governs statutory fine ceiling: "
                        f"EN=[{_format_rm(en_rm)}] vs BM=[{_format_rm(bm_rm)}]."
                    ),
                    practitioner_note=(
                        f"Monetary penalty ceiling discrepancy: EN states [{_format_rm(en_rm)}] vs BM "
                        f"[{_format_rm(bm_rm)}]. {auth_label} text prevails under Act 388 s. 63."
                    ),
                    rakyat_note=(
                        f"The maximum fine differs between English ({_format_rm(en_rm)}) and Bahasa Melayu "
                        f"({_format_rm(bm_rm)}). The {auth_label} limit applies."
                    ),
                )
            )

        # 4. Missing Sub-Clause / Proviso Discrepancy
        en_subs = _extract_subclauses(resolved_en_text, "en")
        bm_subs = _extract_subclauses(resolved_bm_text, "ms")
        if en_subs != bm_subs:
            missing_in_bm = sorted(en_subs - bm_subs)
            missing_in_en = sorted(bm_subs - en_subs)
            issues.append(
                BilingualDivergenceIssue(
                    issue_id=f"DIV-SUBCLAUSE-{resolved_section}",
                    divergence_type="MISSING_SUBCLAUSE",
                    severity=RiskSeverity.HIGH,
                    en_excerpt=_first_excerpt(resolved_en_text),
                    bm_excerpt=_first_excerpt(resolved_bm_text),
                    en_span_id=en_span_id,
                    bm_span_id=bm_span_id,
                    authoritative_resolution=(
                        f"Under Act 388 s. 63, rely on {auth_label} ({auth_node_id}); "
                        f"missing_in_bm={missing_in_bm}, missing_in_en={missing_in_en}."
                    ),
                    practitioner_note=(
                        f"Structural sub-clause mismatch between paired texts "
                        f"(EN only: {missing_in_bm or 'none'}; BM only: {missing_in_en or 'none'})."
                    ),
                    rakyat_note=(
                        "One language version contains an extra sub-section or proviso that is missing "
                        f"from the translation. Follow the {auth_label} version."
                    ),
                )
            )

        has_div = len(issues) > 0
        status: Literal["ALIGNED", "DIVERGENCE_DETECTED", "SINGLE_LANGUAGE_ONLY"] = (
            "DIVERGENCE_DETECTED" if has_div else "ALIGNED"
        )
        if has_div:
            summary_pract = (
                f"ACT 388 DIVERGENCE ({len(issues)} issue(s)) in {resolved_act_number} {resolved_section}: "
                + "; ".join(it.divergence_type for it in issues)
                + f". Authoritative precedence: {auth_label} ({auth_node_id}) under Act 388 s. 63."
            )
            summary_rak = (
                f"Warning: {len(issues)} difference(s) found between English and Bahasa Melayu for "
                f"{resolved_act_number} {resolved_section}. Under Malaysian law, the {auth_label} version governs."
            )
        else:
            summary_pract = (
                f"ACT 388 ALIGNED: EN ({en_mods or ['STATEMENT']}) and BM ({bm_mods or ['STATEMENT']}) texts "
                f"for {resolved_act_number} {resolved_section} match across deontic modality, deadlines, "
                f"penalties, and sub-clauses. Authoritative: {auth_label} ({auth_node_id})."
            )
            summary_rak = (
                f"Aligned: Both English and Bahasa Melayu versions of {resolved_act_number} {resolved_section} "
                f"say the same thing. Authoritative text: {auth_label}."
            )

    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_holder[0],
        retry_count=0,
        is_verified_grounded=True,
        trace_id=f"act388-{resolved_section.lower()}",
    )

    return BilingualDivergenceReport(
        provision_id=resolved_prov_id,
        act_name=resolved_act_name,
        act_number=resolved_act_number,
        section_code=resolved_section,
        as_of_date=eff_date,
        authoritative_language=auth_lang,
        authoritative_node_id=auth_node_id,
        act_388_authority_basis=ACT_388_SECTION_63_BASIS,
        alignment_status=status,
        has_divergence=has_div,
        en_node_id=en_node.node_id if en_node else None,
        bm_node_id=bm_node.node_id if bm_node else None,
        en_source_spans=en_spans,
        bm_source_spans=bm_spans,
        detected_en_modalities=en_mods,
        detected_bm_modalities=bm_mods,
        issues=issues,
        summary_practitioner=summary_pract,
        summary_rakyat=summary_rak,
        telemetry=telemetry,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )


def audit_bilingual_divergence(
    node_id: str | None = None,
    as_of_date: date | None = None,
    store: "TemporalGraphStore | None" = None,
    en_text: str | None = None,
    bm_text: str | None = None,
    authoritative_language: str | None = None,
    act_name: str = "",
    act_number: str = "",
    section_code: str = "",
) -> BilingualDivergenceReport:
    """
    Audits either a `TemporalGraphStore` bilingual provision pair by `node_id` (optionally
    selecting the version active on `as_of_date`) or explicit paired `en_text` / `bm_text` strings.
    Executes deterministically at 0 LLM tokens ($0.00 USD / RM 0.00 MYR).
    """
    if node_id:
        if store is None:
            from lexgraph_lah.graph.temporal_store import get_default_temporal_store

            store = get_default_temporal_store()

        target_id = node_id
        if as_of_date is not None and node_id in store.nodes:
            lineage_ids = store._collect_lineage_node_ids(node_id)
            for lid in lineage_ids:
                candidate = store.nodes[lid]
                if store._is_node_valid_on(candidate, as_of_date):
                    target_id = lid
                    break

        pair = store.get_bilingual_pair(target_id)
        if pair is None:
            raise KeyError(
                f"Statutory node '{node_id}' not found in TemporalGraphStore."
            )

        return audit_bilingual_pair(
            en_node=pair.en_node,
            bm_node=pair.bm_node,
            authoritative_node_id=pair.authoritative_node_id,
            authoritative_language=authoritative_language,
            as_of_date=as_of_date or date.today(),
            provision_id=target_id,
            act_name=pair.act_name,
            act_number=pair.act_number,
            section_code=pair.section_code,
        )

    if not en_text and not bm_text:
        raise ValueError("Provide either 'node_id' or paired 'en_text'/'bm_text'.")

    return audit_bilingual_pair(
        en_node=None,
        bm_node=None,
        authoritative_language=authoritative_language,
        as_of_date=as_of_date or date.today(),
        provision_id=f"{act_number or 'INLINE'}-{section_code or 'SEC-1'}",
        act_name=act_name or "Inline Bilingual Comparison",
        act_number=act_number or "ACT-388-CHECK",
        section_code=section_code or "SEC-1",
        en_text=en_text,
        bm_text=bm_text,
    )
