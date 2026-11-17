import hashlib
import json
import re
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from lexgraph_lah.graph.bilingual_router import resolve_cross_lingual_statute_aliases
from lexgraph_lah.graph.temporal_store import TemporalGraphStore
from lexgraph_lah.schemas.domain import (
    AuthorityTier,
    HierarchyLevel,
    SourceSpan,
    StatutoryNode,
    TemporalEdgeType,
    TerritorialScope,
)

_TOP_HEADER_RE = re.compile(
    r"(?m)^(?P<kind>PART|BAHAGIAN|CHAPTER|BAB|Section|Seksyen)\s+(?P<code>[IVXLCDM0-9]+[A-Za-z]?)\b[^\n]*"
)
_SUB_RE = re.compile(r"(?m)^[ \t]*(?P<code>\(\d+[A-Za-z]?\))")
_PROVISO_RE = re.compile(
    r"(?im)^[ \t]*(?P<marker>Provided\s+that\b|Dengan\s+syarat\s+bahawa\b)"
)
_ILLUSTRATION_RE = re.compile(r"(?im)^[ \t]*(?P<marker>Illustrations?\b|Misalan\b)\s*:?")


def _trim_span(raw_text: str, start: int, end: int) -> tuple[int, int, str]:
    """Trims leading/trailing whitespace while keeping exact offsets into `raw_text`."""
    segment = raw_text[start:end]
    lead_ws = len(segment) - len(segment.lstrip())
    start += lead_ws
    trimmed = raw_text[start:end].rstrip()
    end = start + len(trimmed)
    if end <= start:
        end = min(len(raw_text), start + 1)
    return start, end, raw_text[start:end]


def _make_source_span(
    span_id: str,
    doc_id: str,
    source_uri: str,
    act_number: str,
    section_id: str,
    canonical_citation: str,
    language: str,
    start_char: int,
    end_char: int,
    text: str,
    pdf_page: int = 1,
) -> SourceSpan:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return SourceSpan(
        span_id=span_id,
        doc_id=doc_id,
        source_uri=source_uri,
        act_number=act_number,
        section_id=section_id,
        canonical_citation=canonical_citation,
        language=language,
        pdf_page=pdf_page,
        start_char=start_char,
        end_char=end_char,
        char_offset_start=start_char,
        char_offset_end=end_char,
        content_sha256=digest,
        sha256_hash=digest,
        text=text,
    )


def ingest_structured_statute(
    store: TemporalGraphStore,
    raw_text: str,
    doc_id: str,
    source_uri: str,
    act_name: str,
    act_number: str,
    language: str,
    effective_from: date,
    version: int = 1,
    authority_tier: AuthorityTier = AuthorityTier.TIER_2_ACT_OF_PARLIAMENT,
    amendment_act_ref: str | None = None,
    territorial_scope: list[TerritorialScope] | None = None,
    id_prefix: str | None = None,
) -> list[StatutoryNode]:
    """
    Splits a Malaysian Act / Akta along structural boundaries:
      Act (Akta) -> Part (Bahagian) -> Chapter (Bab) -> Section (Seksyen)
      -> Subsection -> Proviso -> Illustration
    computing exact character-offset `SourceSpan`s and `PART_OF` structural edges.
    """
    scope = territorial_scope or [TerritorialScope.ALL_MALAYSIA]
    norm_lang = "ms" if language.lower() in {"bm", "ms"} else "en"
    lang_tag = norm_lang.upper()
    prefix = id_prefix or re.sub(r"[^A-Za-z0-9]+", "-", doc_id).strip("-").upper()
    created_nodes: list[StatutoryNode] = []

    matches = list(_TOP_HEADER_RE.finditer(raw_text))
    act_end = matches[0].start() if matches else len(raw_text)
    a_start, a_end, a_txt = _trim_span(raw_text, 0, max(1, act_end))
    if not a_txt:
        a_start, a_end, a_txt = _trim_span(raw_text, 0, len(raw_text))

    act_node_id = f"{prefix}-ACT-V{version}-{lang_tag}"
    act_node = StatutoryNode(
        node_id=act_node_id,
        act_name=act_name,
        act_number=act_number,
        section_code=act_number.upper().replace(" ", "-"),
        hierarchy_level=HierarchyLevel.ACT,
        version=version,
        language=norm_lang,
        text=a_txt,
        valid_from=effective_from,
        effective_from=effective_from,
        is_in_force=True,
        amendment_act_ref=amendment_act_ref,
        gazette_ref=amendment_act_ref or act_number,
        authority_tier=authority_tier,
        territorial_scope=scope,
        source_spans=[
            _make_source_span(
                span_id=f"SPAN-{act_node_id}",
                doc_id=doc_id,
                source_uri=source_uri,
                act_number=act_number,
                section_id="ACT",
                canonical_citation=f"{act_name} [{act_number}]",
                language=norm_lang,
                start_char=a_start,
                end_char=a_end,
                text=a_txt,
            )
        ],
    )
    store.upsert_node(act_node)
    created_nodes.append(act_node)

    current_part_id: str | None = None
    current_part_code: str | None = None
    current_chapter_id: str | None = None
    current_chapter_code: str | None = None

    for idx, m in enumerate(matches):
        kind_raw = m.group("kind").upper()
        code = m.group("code").upper()
        block_end = matches[idx + 1].start() if idx + 1 < len(matches) else len(raw_text)

        if kind_raw in {"PART", "BAHAGIAN"}:
            p_start, p_end, p_txt = _trim_span(raw_text, m.start(), block_end)
            part_code = f"PART-{code}"
            part_id = f"{prefix}-{part_code}-V{version}-{lang_tag}"
            part_node = StatutoryNode(
                node_id=part_id,
                act_name=act_name,
                act_number=act_number,
                section_code=part_code,
                part_code=part_code,
                hierarchy_level=HierarchyLevel.PART,
                parent_node_id=act_node_id,
                version=version,
                language=norm_lang,
                text=p_txt,
                valid_from=effective_from,
                effective_from=effective_from,
                is_in_force=True,
                amendment_act_ref=amendment_act_ref,
                gazette_ref=amendment_act_ref or act_number,
                authority_tier=authority_tier,
                territorial_scope=scope,
                source_spans=[
                    _make_source_span(
                        span_id=f"SPAN-{part_id}",
                        doc_id=doc_id,
                        source_uri=source_uri,
                        act_number=act_number,
                        section_id=part_code,
                        canonical_citation=f"{act_number}, {kind_raw.title()} {code}",
                        language=norm_lang,
                        start_char=p_start,
                        end_char=p_end,
                        text=p_txt,
                    )
                ],
            )
            store.upsert_node(part_node)
            created_nodes.append(part_node)
            current_part_id = part_id
            current_part_code = part_code
            current_chapter_id = None
            current_chapter_code = None
            continue

        if kind_raw in {"CHAPTER", "BAB"}:
            c_start, c_end, c_txt = _trim_span(raw_text, m.start(), block_end)
            chapter_code = f"CHAPTER-{code}"
            chapter_id = f"{prefix}-{chapter_code}-V{version}-{lang_tag}"
            parent_id = current_part_id or act_node_id
            chap_node = StatutoryNode(
                node_id=chapter_id,
                act_name=act_name,
                act_number=act_number,
                section_code=chapter_code,
                part_code=current_part_code,
                chapter_code=chapter_code,
                hierarchy_level=HierarchyLevel.CHAPTER,
                parent_node_id=parent_id,
                version=version,
                language=norm_lang,
                text=c_txt,
                valid_from=effective_from,
                effective_from=effective_from,
                is_in_force=True,
                amendment_act_ref=amendment_act_ref,
                gazette_ref=amendment_act_ref or act_number,
                authority_tier=authority_tier,
                territorial_scope=scope,
                source_spans=[
                    _make_source_span(
                        span_id=f"SPAN-{chapter_id}",
                        doc_id=doc_id,
                        source_uri=source_uri,
                        act_number=act_number,
                        section_id=chapter_code,
                        canonical_citation=f"{act_number}, {kind_raw.title()} {code}",
                        language=norm_lang,
                        start_char=c_start,
                        end_char=c_end,
                        text=c_txt,
                    )
                ],
            )
            store.upsert_node(chap_node)
            created_nodes.append(chap_node)
            current_chapter_id = chapter_id
            current_chapter_code = chapter_code
            continue

        # Section / Seksyen
        s_start, s_end, s_txt = _trim_span(raw_text, m.start(), block_end)
        sec_code = f"SEC-{code}"
        sec_id = f"{prefix}-{sec_code}-V{version}-{lang_tag}"
        sec_parent = current_chapter_id or current_part_id or act_node_id
        sec_node = StatutoryNode(
            node_id=sec_id,
            act_name=act_name,
            act_number=act_number,
            section_code=sec_code,
            part_code=current_part_code,
            chapter_code=current_chapter_code,
            hierarchy_level=HierarchyLevel.SECTION,
            parent_node_id=sec_parent,
            version=version,
            language=norm_lang,
            text=s_txt,
            valid_from=effective_from,
            effective_from=effective_from,
            is_in_force=True,
            amendment_act_ref=amendment_act_ref,
            gazette_ref=amendment_act_ref or act_number,
            authority_tier=authority_tier,
            territorial_scope=scope,
            source_spans=[
                _make_source_span(
                    span_id=f"SPAN-{sec_id}",
                    doc_id=doc_id,
                    source_uri=source_uri,
                    act_number=act_number,
                    section_id=sec_code,
                    canonical_citation=f"{act_number} s. {code}",
                    language=norm_lang,
                    start_char=s_start,
                    end_char=s_end,
                    text=s_txt,
                )
            ],
        )
        store.upsert_node(sec_node)
        created_nodes.append(sec_node)

        # Sub-boundaries inside Section: Subsections, Provisos, Illustrations
        sub_markers: list[tuple[int, HierarchyLevel, str]] = []
        for sm in _SUB_RE.finditer(raw_text, m.end(), s_end):
            sub_markers.append((sm.start(), HierarchyLevel.SUBSECTION, sm.group("code")))
        for pm in _PROVISO_RE.finditer(raw_text, m.end(), s_end):
            sub_markers.append((pm.start(), HierarchyLevel.PROVISO, "PROVISO"))
        for im in _ILLUSTRATION_RE.finditer(raw_text, m.end(), s_end):
            sub_markers.append((im.start(), HierarchyLevel.ILLUSTRATION, "ILLUSTRATION"))
        sub_markers.sort(key=lambda item: item[0])

        proviso_count = 0
        illus_count = 0
        for s_idx, (sub_pos, level, marker_code) in enumerate(sub_markers):
            sub_end = sub_markers[s_idx + 1][0] if s_idx + 1 < len(sub_markers) else s_end
            c_s, c_e, c_text = _trim_span(raw_text, sub_pos, sub_end)
            if not c_text:
                continue

            if level == HierarchyLevel.SUBSECTION:
                clean_sub = marker_code.strip("()").upper()
                child_code = f"{sec_code}({clean_sub})"
                child_id = f"{sec_id}-SUB-{clean_sub}"
                citation = f"{act_number} s. {code}({clean_sub})"
                sub_code_field: str | None = marker_code
            elif level == HierarchyLevel.PROVISO:
                proviso_count += 1
                child_code = f"{sec_code}-PROVISO-{proviso_count}"
                child_id = f"{sec_id}-PROV-{proviso_count}"
                citation = f"{act_number} s. {code} (Proviso {proviso_count})"
                sub_code_field = f"Proviso {proviso_count}"
            else:
                illus_count += 1
                child_code = f"{sec_code}-ILLUS-{illus_count}"
                child_id = f"{sec_id}-ILLUS-{illus_count}"
                citation = f"{act_number} s. {code} (Illustration {illus_count})"
                sub_code_field = f"Illustration {illus_count}"

            child_node = StatutoryNode(
                node_id=child_id,
                act_name=act_name,
                act_number=act_number,
                section_code=child_code,
                part_code=current_part_code,
                chapter_code=current_chapter_code,
                subsection_code=sub_code_field,
                hierarchy_level=level,
                parent_node_id=sec_id,
                version=version,
                language=norm_lang,
                text=c_text,
                valid_from=effective_from,
                effective_from=effective_from,
                is_in_force=True,
                amendment_act_ref=amendment_act_ref,
                gazette_ref=amendment_act_ref or act_number,
                authority_tier=authority_tier,
                territorial_scope=scope,
                source_spans=[
                    _make_source_span(
                        span_id=f"SPAN-{child_id}",
                        doc_id=doc_id,
                        source_uri=source_uri,
                        act_number=act_number,
                        section_id=child_code,
                        canonical_citation=citation,
                        language=norm_lang,
                        start_char=c_s,
                        end_char=c_e,
                        text=c_text,
                    )
                ],
            )
            store.upsert_node(child_node)
            created_nodes.append(child_node)

    return created_nodes


def ingest_amended_provision(
    store: TemporalGraphStore,
    prior_node_id: str,
    new_node: StatutoryNode,
) -> StatutoryNode:
    """
    Ingests an amended statutory version while preserving `prior_node_id` with
    `effective_to = new_node.effective_from - 1 day`, `is_in_force = False`,
    and connecting both via SUPERSEDED_BY, AMENDS, and AMENDED_BY edges.
    """
    eff_from = new_node.effective_from or new_node.valid_from
    if prior_node_id in store.nodes:
        prior = store.nodes[prior_node_id]
        prior_eff_from = prior.effective_from or prior.valid_from
        if eff_from <= prior_eff_from:
            raise ValueError(
                f"Amendment effective_from ({eff_from}) must be strictly after prior node effective_from ({prior_eff_from})."
            )
        prev_eff_to = eff_from - timedelta(days=1)
        if prev_eff_to < prior_eff_from:
            prev_eff_to = eff_from
    store.upsert_node(new_node, amends_node_id=prior_node_id)
    return store.nodes[new_node.node_id]


class BilingualCrosswalkResolver:
    """
    Resolves cross-lingual Malaysian statutory references and connects corresponding
    Bahasa Melayu (`ms`/`bm`) and English (`en`) nodes with `BM_EN_EQUIVALENT` edges.
    """

    @staticmethod
    def resolve_aliases(query: str) -> list[str]:
        return resolve_cross_lingual_statute_aliases(query)

    @staticmethod
    def link_corresponding_nodes(
        store: TemporalGraphStore,
        en_nodes: list[StatutoryNode],
        bm_nodes: list[StatutoryNode],
        authoritative: str = "ms",
        effective_date: date | None = None,
    ) -> list[tuple[str, str]]:
        """
        Matches corresponding English and Bahasa Melayu nodes sharing `(act_number, section_code,
        hierarchy_level, version)` and links them with bidirectional `BM_EN_EQUIVALENT`,
        `HAS_TRANSLATION`, and `AUTHORITATIVE_TEXT` edges.
        """
        bm_index: dict[tuple[str, str, HierarchyLevel, int], StatutoryNode] = {
            (n.act_number, n.section_code, n.hierarchy_level, n.version): n
            for n in bm_nodes
            if n.normalized_language == "ms"
        }
        linked_pairs: list[tuple[str, str]] = []
        for en_node in en_nodes:
            if en_node.normalized_language != "en":
                continue
            key = (
                en_node.act_number,
                en_node.section_code,
                en_node.hierarchy_level,
                en_node.version,
            )
            bm_node = bm_index.get(key)
            if not bm_node:
                continue
            auth_id = bm_node.node_id if authoritative in {"ms", "bm"} else en_node.node_id
            eff = effective_date or en_node.effective_from or en_node.valid_from
            store.link_translation(
                en_node_id=en_node.node_id,
                bm_node_id=bm_node.node_id,
                authoritative_node_id=auth_id,
                effective_date=eff,
                gazette_ref=en_node.amendment_act_ref or en_node.gazette_ref,
            )
            linked_pairs.append((en_node.node_id, bm_node.node_id))
        return linked_pairs


def load_lineage_fixture_store(fixture_path: Path) -> TemporalGraphStore:
    """
    Loads a deterministic Malaysian bilingual statutory lineage + judicial precedent
    JSON fixture into a fresh `TemporalGraphStore`.
    """
    payload: dict[str, Any] = json.loads(fixture_path.read_text(encoding="utf-8"))
    store = TemporalGraphStore()

    for doc in payload.get("structured_statutes", []):
        ingest_structured_statute(
            store=store,
            raw_text=doc["raw_text"],
            doc_id=doc["doc_id"],
            source_uri=doc["source_uri"],
            act_name=doc["act_name"],
            act_number=doc["act_number"],
            language=doc["language"],
            effective_from=date.fromisoformat(doc["effective_from"]),
            version=int(doc.get("version", 1)),
            authority_tier=AuthorityTier(int(doc.get("authority_tier", 2))),
            amendment_act_ref=doc.get("amendment_act_ref"),
            id_prefix=doc.get("id_prefix"),
        )

    for prov in payload.get("provisions", []):
        spans = [SourceSpan(**sp) for sp in prov.get("source_spans", [])]
        node = StatutoryNode(
            node_id=prov["node_id"],
            act_name=prov["act_name"],
            act_number=prov["act_number"],
            section_code=prov["section_code"],
            part_code=prov.get("part_code"),
            chapter_code=prov.get("chapter_code"),
            subsection_code=prov.get("subsection_code"),
            hierarchy_level=HierarchyLevel(prov.get("hierarchy_level", "Section")),
            parent_node_id=prov.get("parent_node_id"),
            version=int(prov.get("version", 1)),
            language=prov["language"],
            text=prov["text"],
            valid_from=date.fromisoformat(prov["effective_from"]),
            effective_from=date.fromisoformat(prov["effective_from"]),
            effective_to=(
                date.fromisoformat(prov["effective_to"])
                if prov.get("effective_to")
                else None
            ),
            is_in_force=bool(prov.get("is_in_force", True)),
            amendment_act_ref=prov.get("amendment_act_ref"),
            gazette_ref=prov.get("amendment_act_ref") or prov.get("gazette_ref"),
            authority_tier=AuthorityTier(int(prov.get("authority_tier", 2))),
            court_name=prov.get("court_name"),
            case_citation=prov.get("case_citation"),
            is_overruled=bool(prov.get("is_overruled", False)),
            source_spans=spans,
        )
        amends_id = prov.get("amends_node_id")
        if amends_id:
            ingest_amended_provision(store, amends_id, node)
        else:
            store.upsert_node(node)

    for link in payload.get("bilingual_links", []):
        store.link_translation(
            en_node_id=link["en_node_id"],
            bm_node_id=link["bm_node_id"],
            authoritative_node_id=link["authoritative_node_id"],
            effective_date=date.fromisoformat(link["effective_date"]),
            gazette_ref=link.get("gazette_ref"),
        )

    for jt in payload.get("judicial_treatments", []):
        store.add_judicial_treatment(
            case_node_id=jt["case_node_id"],
            target_node_id=jt["target_node_id"],
            edge_type=TemporalEdgeType(jt["edge_type"]),
            effective_date=date.fromisoformat(jt["effective_date"]),
            gazette_ref=jt.get("gazette_ref"),
        )

    return store
