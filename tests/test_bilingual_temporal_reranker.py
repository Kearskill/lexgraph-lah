from datetime import date

from lexgraph_lah.config import settings
from lexgraph_lah.graph.bilingual_router import normalize_and_expand_query
from lexgraph_lah.graph.reranker import rerank_statutes_and_spans
from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    get_default_temporal_store,
)
from lexgraph_lah.schemas.domain import (
    AuthorityTier,
    HierarchyLevel,
    SourceSpan,
    StatutoryNode,
    TemporalEdgeType,
    TerritorialScope,
)


def test_structural_hierarchy_and_strict_source_span_provenance():
    """
    Verifies Act -> Part -> Section -> Subsection -> SourceSpan hierarchy edges
    and strict SourceSpan metadata fields.
    """
    store = get_default_temporal_store()
    chain = store.get_hierarchy_chain("PDPA-2010-SEC-9-V2-SUB-1A")
    levels = [n.hierarchy_level for n in chain]
    assert levels == [
        HierarchyLevel.ACT,
        HierarchyLevel.PART,
        HierarchyLevel.SECTION,
        HierarchyLevel.SUBSECTION,
    ]

    sub_node = store.nodes["PDPA-2010-SEC-9-V2-SUB-1A"]
    assert len(sub_node.source_spans) >= 1
    span = sub_node.source_spans[0]
    assert span.act_number == "Act 709"
    assert span.section_id == "SEC-9(1A)"
    assert span.language == "en"
    assert span.pdf_page == 6
    assert span.char_offset_start == 375
    assert span.char_offset_end == 568
    assert len(span.sha256_hash) == 64

    edge_types = {e.edge_type for e in store.edges}
    assert {
        TemporalEdgeType.HAS_PART,
        TemporalEdgeType.HAS_SECTION,
        TemporalEdgeType.HAS_SUBSECTION,
    } <= edge_types


def test_abstention_gate_triggers_below_078_threshold():
    """
    Verifies the deterministic 0.78 Abstention Gate:
    - Out-of-domain queries return is_abstained=True with 0 spans.
    - Statutory queries above threshold return verified SourceSpans.
    """
    assert settings.abstention_threshold == 0.78
    store = get_default_temporal_store()

    abstained = store.search_with_abstention(
        query="What is the weather forecast for Tokyo tomorrow?",
        as_of_date=date(2026, 3, 15),
    )
    assert abstained.is_abstained is True
    assert abstained.results == []
    assert abstained.max_relevance_score < 0.78
    assert abstained.abstention_reason is not None
    assert "0.78" in abstained.abstention_reason

    grounded = store.search_with_abstention(
        query="72 hours personal data breach notification",
        as_of_date=date(2026, 3, 15),
    )
    assert grounded.is_abstained is False
    assert len(grounded.results) > 0
    assert grounded.max_relevance_score >= 0.78


def test_bilingual_has_translation_and_code_switched_routing():
    """
    Verifies HAS_TRANSLATION / AUTHORITATIVE_TEXT linking and synchronized
    retrieval across English, Bahasa Melayu, and code-switched queries.
    """
    store = get_default_temporal_store()

    pair = store.get_bilingual_pair("PDPA-2010-SEC-9-V2")
    assert pair is not None
    assert pair.en_node is not None and pair.bm_node is not None
    assert pair.en_node.node_id == "PDPA-2010-SEC-9-V2"
    assert pair.bm_node.node_id == "PDPA-2010-SEC-9-V2-BM"
    assert pair.authoritative_node_id == "PDPA-2010-SEC-9-V2-BM"

    assert any(
        e.edge_type == TemporalEdgeType.HAS_TRANSLATION
        and e.source_id == "PDPA-2010-SEC-9-V2"
        and e.target_id == "PDPA-2010-SEC-9-V2-BM"
        for e in store.edges
    )
    assert any(
        e.edge_type == TemporalEdgeType.AUTHORITATIVE_TEXT
        and e.source_id == "PDPA-2010-SEC-9-V2"
        and e.target_id == "PDPA-2010-SEC-9-V2-BM"
        for e in store.edges
    )

    _, bm_lang, _ = normalize_and_expand_query(
        "notis kebocoran data peribadi dalam tempoh 72 jam pemproses data"
    )
    assert bm_lang == "bm"

    _, cs_lang, _ = normalize_and_expand_query(
        "Boleh ke data processor waive liability kalau kena data breach?"
    )
    assert cs_lang == "code_switched"

    bm_search = store.search_with_abstention(
        query="pelantikan pegawai perlindungan data PPD di bawah Seksyen 12A",
        as_of_date=date(2026, 3, 15),
    )
    assert bm_search.is_abstained is False
    returned_ids = {r.node_id for r in bm_search.results}
    assert "PDPA-2010-SEC-12A-V1-BM" in returned_ids
    assert "PDPA-2010-SEC-12A-V1" in returned_ids
    assert len(bm_search.bilingual_pairs) >= 1


def test_bitemporal_gazette_pu_a_b_and_amends_repeals_filtering():
    """
    Verifies as_of_date filtering for Principal Acts, Amendment Acts, and
    P.U. (A) / P.U. (B) Subsidiary Legislation plus AMENDS/REPEALS edges.
    """
    store = get_default_temporal_store()

    # Pre-2025 query: P.U. (A) 342/2024, P.U. (B) 512/2024, Sec 12A, Sec 12B must NOT appear
    pre_2025 = store.query_point_in_time(as_of_date=date(2024, 6, 15))
    pre_ids = {n.node_id for n in pre_2025}
    assert "PDPA-2010-SEC-9-V1" in pre_ids
    assert "PDPA-2010-SEC-9-V2" not in pre_ids
    assert "PDPA-2010-SEC-12B-V1" not in pre_ids
    assert "PUA-342-2024-REG-3" not in pre_ids
    assert "PUB-512-2024-APPT" not in pre_ids

    # Post-2025 query: 2024 Amendment & P.U. Gazettes are active
    post_2025 = store.query_point_in_time(as_of_date=date(2025, 3, 1))
    post_ids = {n.node_id for n in post_2025}
    assert "PDPA-2010-SEC-9-V2" in post_ids
    assert "PDPA-2010-SEC-9-V1" not in post_ids
    assert "PDPA-2010-SEC-12B-V1" in post_ids
    assert "PUA-342-2024-REG-3" in post_ids
    assert "PUB-512-2024-APPT" in post_ids

    # Verify AMENDS edge recorded alongside AMENDED_BY
    assert any(
        e.edge_type == TemporalEdgeType.AMENDS
        and e.source_id == "PDPA-2010-SEC-9-V2"
        and e.target_id == "PDPA-2010-SEC-9-V1"
        for e in store.edges
    )

    # Verify REPEALS edge blocks repealed P.U. (A) instrument on repeal date
    custom = TemporalGraphStore()
    old_reg = StatutoryNode(
        node_id="PUA-100-2020",
        act_name="Legacy Regulations 2020",
        act_number="P.U. (A) 100/2020",
        section_code="REG-1",
        text="Legacy regulation text.",
        valid_from=date(2020, 1, 1),
        effective_from=date(2020, 1, 1),
        gazette_ref="P.U. (A) 100/2020",
        authority_tier=AuthorityTier.TIER_4_SUBSIDIARY_LEGISLATION,
    )
    new_reg = StatutoryNode(
        node_id="PUA-200-2025",
        act_name="New Regulations 2025",
        act_number="P.U. (A) 200/2025",
        section_code="REG-1",
        text="New regulation repealing legacy regulation.",
        valid_from=date(2025, 6, 1),
        effective_from=date(2025, 6, 1),
        gazette_ref="P.U. (A) 200/2025",
        authority_tier=AuthorityTier.TIER_4_SUBSIDIARY_LEGISLATION,
    )
    custom.upsert_node(old_reg)
    custom.upsert_node(new_reg)
    custom.repeal_node(
        "PUA-100-2020",
        "PUA-200-2025",
        effective_date=date(2025, 6, 1),
        gazette_ref="P.U. (A) 200/2025",
    )
    assert any(e.edge_type == TemporalEdgeType.REPEALS for e in custom.edges)
    assert [n.node_id for n in custom.query_point_in_time(date(2025, 5, 31))] == [
        "PUA-100-2020"
    ]
    assert [n.node_id for n in custom.query_point_in_time(date(2025, 6, 1))] == [
        "PUA-200-2025"
    ]


def test_five_tier_authority_reranker_and_territorial_isolation():
    """
    Verifies:
    1. 5-tier authority ranking strictly orders Tier 1 > Tier 2 > Tier 3 > Tier 4 > Tier 5
       when provisions have equivalent textual relevance.
    2. Territorial scope filtering prevents Peninsular/Sabah/Sarawak leakage.
    """
    common_text = "Statutory personal data breach compliance framework for Malaysia."
    nodes = [
        StatutoryNode(
            node_id="T5-CIRC",
            act_name="Circular",
            act_number="Circular 1/2025",
            section_code="C-1",
            text=common_text,
            valid_from=date(2025, 1, 1),
            authority_tier=AuthorityTier.TIER_5_AGENCY_CIRCULAR,
            source_spans=[
                SourceSpan(
                    span_id="S5",
                    act_number="Circular 1/2025",
                    section_id="C-1",
                    text=common_text,
                    char_offset_end=len(common_text),
                )
            ],
        ),
        StatutoryNode(
            node_id="T4-PUA",
            act_name="Regulations",
            act_number="P.U. (A) 1/2025",
            section_code="R-1",
            text=common_text,
            valid_from=date(2025, 1, 1),
            authority_tier=AuthorityTier.TIER_4_SUBSIDIARY_LEGISLATION,
            source_spans=[
                SourceSpan(
                    span_id="S4",
                    act_number="P.U. (A) 1/2025",
                    section_id="R-1",
                    text=common_text,
                    char_offset_end=len(common_text),
                )
            ],
        ),
        StatutoryNode(
            node_id="T3-ORD",
            act_name="Ordinance",
            act_number="Cap. 67",
            section_code="O-1",
            text=common_text,
            valid_from=date(2025, 1, 1),
            authority_tier=AuthorityTier.TIER_3_ORDINANCE,
            source_spans=[
                SourceSpan(
                    span_id="S3",
                    act_number="Cap. 67",
                    section_id="O-1",
                    text=common_text,
                    char_offset_end=len(common_text),
                )
            ],
        ),
        StatutoryNode(
            node_id="T2-ACT",
            act_name="Principal Act",
            act_number="Act 709",
            section_code="A-1",
            text=common_text,
            valid_from=date(2025, 1, 1),
            authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
            source_spans=[
                SourceSpan(
                    span_id="S2",
                    act_number="Act 709",
                    section_id="A-1",
                    text=common_text,
                    char_offset_end=len(common_text),
                )
            ],
        ),
        StatutoryNode(
            node_id="T1-CONST",
            act_name="Federal Constitution",
            act_number="Federal Constitution",
            section_code="ART-1",
            text=common_text,
            valid_from=date(1957, 8, 31),
            authority_tier=AuthorityTier.TIER_1_FEDERAL_CONSTITUTION,
            source_spans=[
                SourceSpan(
                    span_id="S1",
                    act_number="Federal Constitution",
                    section_id="ART-1",
                    text=common_text,
                    char_offset_end=len(common_text),
                )
            ],
        ),
    ]

    abstained, _, _, _, ranked = rerank_statutes_and_spans(
        query="personal data breach compliance framework",
        nodes=nodes,
        abstention_threshold=0.78,
    )
    assert abstained is False
    assert [r.node_id for r in ranked] == [
        "T1-CONST",
        "T2-ACT",
        "T3-ORD",
        "T4-PUA",
        "T5-CIRC",
    ]

    # Territorial isolation check
    store = get_default_temporal_store()
    sabah_res = store.search_with_abstention(
        query="working hours and overtime rates for employees",
        as_of_date=date(2026, 3, 15),
        territorial_scope=TerritorialScope.SABAH,
    )
    sabah_ids = {r.node_id for r in sabah_res.results}
    assert "SABAH-CAP67-SEC-104-V1" in sabah_ids
    assert "EA-1955-SEC-60A-V1" not in sabah_ids
    assert "SARAWAK-CAP76-SEC-105-V1" not in sabah_ids

    sarawak_res = store.search_with_abstention(
        query="working hours and overtime rates for employees",
        as_of_date=date(2026, 3, 15),
        territorial_scope=TerritorialScope.SARAWAK,
    )
    sarawak_ids = {r.node_id for r in sarawak_res.results}
    assert "SARAWAK-CAP76-SEC-105-V1" in sarawak_ids
    assert "SABAH-CAP67-SEC-104-V1" not in sarawak_ids
    assert "EA-1955-SEC-60A-V1" not in sarawak_ids
