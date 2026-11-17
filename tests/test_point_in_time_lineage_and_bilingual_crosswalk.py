import json
from datetime import date
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from lexgraph_lah.graph.ingestion import (
    BilingualCrosswalkResolver,
    ingest_structured_statute,
    load_lineage_fixture_store,
)
from lexgraph_lah.graph.temporal_store import TemporalGraphStore
from lexgraph_lah.main import app
from lexgraph_lah.schemas.domain import (
    AuthorityTier,
    HierarchyLevel,
    PointInTimeResearchRequest,
    StatutoryStatus,
    TemporalEdgeType,
)

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "malaysian_bilingual_lineage_fixture.json"


def test_structure_aware_ingestion_exact_offsets_and_bilingual_crosswalk():
    """
    Verifies Malaysian structural splitting (Act -> Part -> Chapter -> Section -> Subsection
    -> Proviso -> Illustration), exact SourceSpan character offsets, immutability,
    PART_OF edges, and BM_EN_EQUIVALENT bilingual crosswalk linking.
    """
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    en_doc, ms_doc = fixture["structured_statutes"]

    store = TemporalGraphStore()
    en_nodes = ingest_structured_statute(
        store=store,
        raw_text=en_doc["raw_text"],
        doc_id=en_doc["doc_id"],
        source_uri=en_doc["source_uri"],
        act_name=en_doc["act_name"],
        act_number=en_doc["act_number"],
        language="en",
        effective_from=date.fromisoformat(en_doc["effective_from"]),
        version=en_doc["version"],
        amendment_act_ref=en_doc["amendment_act_ref"],
        id_prefix="TEST-EN",
    )
    ms_nodes = ingest_structured_statute(
        store=store,
        raw_text=ms_doc["raw_text"],
        doc_id=ms_doc["doc_id"],
        source_uri=ms_doc["source_uri"],
        act_name=ms_doc["act_name"],
        act_number=ms_doc["act_number"],
        language="ms",
        effective_from=date.fromisoformat(ms_doc["effective_from"]),
        version=ms_doc["version"],
        amendment_act_ref=ms_doc["amendment_act_ref"],
        id_prefix="TEST-MS",
    )

    en_levels = {n.hierarchy_level for n in en_nodes}
    assert {
        HierarchyLevel.ACT,
        HierarchyLevel.PART,
        HierarchyLevel.CHAPTER,
        HierarchyLevel.SECTION,
        HierarchyLevel.SUBSECTION,
        HierarchyLevel.PROVISO,
        HierarchyLevel.ILLUSTRATION,
    } <= en_levels

    # Exact character offsets and immutable SourceSpans
    for node in en_nodes:
        assert len(node.source_spans) == 1
        sp = node.source_spans[0]
        assert sp.doc_id == en_doc["doc_id"]
        assert sp.source_uri == en_doc["source_uri"]
        assert len(sp.content_sha256) == 64
        assert sp.canonical_citation
        assert en_doc["raw_text"][sp.start_char : sp.end_char] == sp.text
        with pytest.raises(ValidationError):
            sp.text = "tampered"  # type: ignore[misc]

    for node in ms_nodes:
        sp = node.source_spans[0]
        assert ms_doc["raw_text"][sp.start_char : sp.end_char] == sp.text

    # PART_OF edges exist
    assert any(e.edge_type == TemporalEdgeType.PART_OF for e in store.edges)

    # Link BM <-> EN via BilingualCrosswalkResolver
    linked = BilingualCrosswalkResolver.link_corresponding_nodes(
        store=store,
        en_nodes=en_nodes,
        bm_nodes=ms_nodes,
        authoritative="ms",
    )
    assert len(linked) >= 4
    assert any(
        e.edge_type == TemporalEdgeType.BM_EN_EQUIVALENT
        and e.source_id == "TEST-EN-SEC-9-V2-EN"
        and e.target_id == "TEST-MS-SEC-9-V2-MS"
        for e in store.edges
    )

    # Cross-lingual statute alias resolution
    assert "penal code" in BilingualCrosswalkResolver.resolve_aliases("Kanun Keseksaan Seksyen 420")
    assert "contracts act 1950" in BilingualCrosswalkResolver.resolve_aliases("Akta Kontrak 1950 Seksyen 75")


def test_point_in_time_before_and_after_amendment_with_timeline():
    """
    Verifies:
    - Querying with as_of_date BEFORE the 2025-01-01 amendment returns V1 as active.
    - Querying AFTER the amendment returns V2 as active while exposing V1 in
      amendment_timeline with effective_to == 2024-12-31 and SUPERSEDED_BY/AMENDS edges.
    """
    store = load_lineage_fixture_store(FIXTURE_PATH)

    # Verify amendment transition metadata on V1 -> V2
    v1_en = store.nodes["FIX-PDPA-SEC-9-V1-EN"]
    assert v1_en.effective_to == date(2024, 12, 31)
    assert v1_en.is_in_force is False
    assert v1_en.status == StatutoryStatus.AMENDED

    assert any(
        e.edge_type == TemporalEdgeType.SUPERSEDED_BY
        and e.source_id == "FIX-PDPA-SEC-9-V1-EN"
        and e.target_id == "FIX-PDPA-SEC-9-V2-EN"
        for e in store.edges
    )
    assert any(
        e.edge_type == TemporalEdgeType.AMENDS
        and e.source_id == "FIX-PDPA-SEC-9-V2-EN"
        and e.target_id == "FIX-PDPA-SEC-9-V1-EN"
        for e in store.edges
    )

    # Pre-amendment query (2024-06-15)
    pre_res = store.execute_point_in_time_research(
        PointInTimeResearchRequest(
            query="Section 9 Security Principle Personal Data Protection Act 2010",
            as_of_date=date(2024, 6, 15),
            language_mode="en",
            include_repealed_lineage=True,
        )
    )
    assert pre_res.status == "grounded"
    active_pre = [e.node_id for e in pre_res.amendment_timeline if e.is_active_at_query_date]
    assert "FIX-PDPA-SEC-9-V1-EN" in active_pre
    assert "FIX-PDPA-SEC-9-V2-EN" not in active_pre

    # Post-amendment query (2025-06-15)
    post_res = store.execute_point_in_time_research(
        PointInTimeResearchRequest(
            query="Section 9 Security Principle data processor liability Act 709",
            as_of_date=date(2025, 6, 15),
            language_mode="en",
            include_repealed_lineage=True,
        )
    )
    assert post_res.status == "grounded"
    active_post = [e.node_id for e in post_res.amendment_timeline if e.is_active_at_query_date]
    superseded_post = [e.node_id for e in post_res.amendment_timeline if not e.is_active_at_query_date]
    assert "FIX-PDPA-SEC-9-V2-EN" in active_post
    assert "FIX-PDPA-SEC-9-V1-EN" in superseded_post


def test_bahasa_melayu_query_traverses_english_judicial_interpretations_and_ranks_7_tiers():
    """
    Verifies:
    1. Querying in Bahasa Melayu retrieves English judicial interpretations via BM_EN_EQUIVALENT.
    2. Federal Court (Tier 4) ranks strictly above High Court (Tier 6), and overruled
       cases are explicitly flagged.
    """
    store = load_lineage_fixture_store(FIXTURE_PATH)

    bm_res = store.execute_point_in_time_research(
        PointInTimeResearchRequest(
            query="Apakah liabiliti berkanun pemproses data di bawah Seksyen 9 Akta Perlindungan Data Peribadi 2010?",
            as_of_date=date(2025, 6, 15),
            language_mode="ms",
            include_repealed_lineage=True,
        )
    )
    assert bm_res.status == "grounded"
    assert bm_res.is_abstained is False
    assert bm_res.detected_language == "bm"

    # Traversed English judicial precedents via BM_EN_EQUIVALENT -> EN node <- INTERPRETS <- Case
    case_ids = [jt.case_node_id for jt in bm_res.judicial_treatments]
    assert "FIX-CASE-FC-2025" in case_ids
    assert "FIX-CASE-HC-2021" in case_ids

    # Federal Court ranks strictly above High Court, and High Court is flagged overruled
    assert case_ids.index("FIX-CASE-FC-2025") < case_ids.index("FIX-CASE-HC-2021")

    case_breakdown = [
        item for item in bm_res.authority_breakdown if item.hierarchy_level == HierarchyLevel.CASE
    ]
    fc_item = next(item for item in case_breakdown if item.node_id == "FIX-CASE-FC-2025")
    hc_item = next(item for item in case_breakdown if item.node_id == "FIX-CASE-HC-2021")

    assert fc_item.authority_tier == AuthorityTier.TIER_4_FEDERAL_COURT
    assert hc_item.authority_tier == AuthorityTier.TIER_6_HIGH_COURT
    assert hc_item.is_overruled is True
    assert hc_item.overruled_by_node_id == "FIX-CASE-FC-2025"
    assert fc_item.final_score > hc_item.final_score
    assert case_breakdown.index(fc_item) < case_breakdown.index(hc_item)

    # Every grounded claim cites at least one verified SourceSpan in citations
    citation_ids = {sp.span_id for sp in bm_res.citations}
    assert len(bm_res.claims) >= 2
    for claim in bm_res.claims:
        assert len(claim.source_span_ids) >= 1
        assert set(claim.source_span_ids) <= citation_ids


def test_zero_matching_sourcespans_triggers_deterministic_refusal():
    """Verifies queries with 0 matching SourceSpans trigger deterministic insufficient_evidence refusal."""
    store = load_lineage_fixture_store(FIXTURE_PATH)

    refusal = store.execute_point_in_time_research(
        PointInTimeResearchRequest(
            query="Best recipe for nasi lemak sambal and crispy fried anchovies",
            as_of_date=date(2026, 3, 15),
            language_mode="bilingual",
        )
    )
    assert refusal.status == "insufficient_evidence"
    assert refusal.is_abstained is True
    assert refusal.citations == []
    assert refusal.claims == []
    assert refusal.refusal_reason is not None
    assert "INSUFFICIENT_EVIDENCE" in refusal.refusal_reason


def test_api_endpoints_and_provenance_ui_end_to_end():
    """
    Verifies:
    1. POST /api/v1/research/point-in-time handles BM queries, cross-lingual statute aliases
       (Akta Kontrak 1950 / Kanun Keseksaan), 7-tier ranking (FC > COA > HC), and refusal.
    2. GET /api/v1/provisions/{provision_id}/lineage returns full chronological lineage & 404.
    3. GET / and GET /demo render the As-Of Date selector, BM | EN | Side-by-Side toggle,
       and interactive Citation & Lineage Inspector panel.
    """
    client = TestClient(app)

    # 1. BM query on PDPA Section 9 post-amendment (2026-03-15)
    pit_res = client.post(
        "/api/v1/research/point-in-time",
        json={
            "query": "Apakah liabiliti berkanun pemproses data di bawah Seksyen 9 Akta Perlindungan Data Peribadi 2010?",
            "as_of_date": "2026-03-15",
            "language_mode": "ms",
            "include_repealed_lineage": True,
        },
    )
    assert pit_res.status_code == 200
    body = pit_res.json()
    assert body["status"] == "grounded"
    assert body["is_abstained"] is False
    assert len(body["citations"]) >= 2
    assert len(body["claims"]) >= 2
    assert len(body["bilingual_crosswalk"]) >= 1
    assert any(e["node_id"] == "PDPA-2010-SEC-9-V1-BM" and not e["is_active_at_query_date"] for e in body["amendment_timeline"])
    assert any(e["node_id"] == "PDPA-2010-SEC-9-V2-BM" and e["is_active_at_query_date"] for e in body["amendment_timeline"])

    case_order = [
        item["node_id"]
        for item in body["authority_breakdown"]
        if item["hierarchy_level"] == "Case"
    ]
    assert "CASE-FC-2025-001" in case_order
    assert "CASE-HC-2021-004" in case_order
    assert case_order.index("CASE-FC-2025-001") < case_order.index("CASE-HC-2021-004")

    # Cross-lingual statute alias test: Akta Kontrak 1950 -> Contracts Act 1950 + Federal Court Cubic Electronics
    ca_res = client.post(
        "/api/v1/research/point-in-time",
        json={
            "query": "Apakah pampasan bagi pecah kontrak di bawah Seksyen 75 Akta Kontrak 1950?",
            "as_of_date": "2026-03-15",
            "language_mode": "bilingual",
        },
    )
    assert ca_res.status_code == 200
    ca_body = ca_res.json()
    assert ca_body["status"] == "grounded"
    assert any(jt["case_node_id"] == "CASE-FC-2019-CUBIC" for jt in ca_body["judicial_treatments"])

    # Insufficient evidence refusal via API
    ood_res = client.post(
        "/api/v1/research/point-in-time",
        json={
            "query": "Quantum entanglement in superconducting qubits",
            "as_of_date": "2026-03-15",
            "language_mode": "en",
        },
    )
    assert ood_res.status_code == 200
    assert ood_res.json()["status"] == "insufficient_evidence"
    assert ood_res.json()["is_abstained"] is True

    # 2. Provision lineage endpoint
    lineage_res = client.get(
        "/api/v1/provisions/PDPA-2010-SEC-9-V2/lineage",
        params={"as_of_date": "2024-06-15"},
    )
    assert lineage_res.status_code == 200
    lineage_data = lineage_res.json()
    assert lineage_data["current_active_node_id"] == "PDPA-2010-SEC-9-V1"
    assert [e["version"] for e in lineage_data["amendment_timeline"]] == [1, 2]
    assert lineage_data["bilingual_equivalent"]["bm_node"]["node_id"] == "PDPA-2010-SEC-9-V1-BM"
    assert len(lineage_data["judicial_treatments"]) >= 1

    missing_lineage = client.get("/api/v1/provisions/UNKNOWN-PROVISION/lineage")
    assert missing_lineage.status_code == 404

    # 3. Provenance UI assertions
    for route in ("/", "/demo"):
        html = client.get(route).text
        assert "pitAsOfDateInput" in html
        assert "langToggleMsBtn" in html
        assert "langToggleEnBtn" in html
        assert "langToggleBilingualBtn" in html
        assert "citationLineageInspector" in html
        assert "authorityBreakdownList" in html
        assert "amendmentTimelineView" in html
