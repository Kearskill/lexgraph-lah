from datetime import date

import pytest

from lexgraph_lah.agents.graph import temporal_retriever_node
from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    build_point_in_time_cypher,
    build_repeal_cypher,
    build_upsert_amendment_cypher,
    get_default_temporal_store,
)
from lexgraph_lah.schemas.domain import (
    StatutoryNode,
    StatutoryStatus,
    TemporalEdgeType,
)


def test_statutory_node_temporal_validation_and_hash():
    """Verify StatutoryNode computes deterministic SHA-256 content_hash and enforces date ordering."""
    node = StatutoryNode(
        node_id="ACT-1-SEC-1-V1",
        act_name="Contracts Act 1950",
        section_code="SEC-1",
        version=1,
        text="Section 1: Short title.",
        valid_from=date(2020, 1, 1),
    )
    assert len(node.content_hash) == 64
    assert node.is_active_on(date(2024, 6, 1)) is True
    assert node.is_active_on(date(2019, 12, 31)) is False

    with pytest.raises(
        ValueError, match="valid_to .* must be strictly after valid_from"
    ):
        StatutoryNode(
            node_id="INVALID-NODE",
            act_name="Contracts Act 1950",
            section_code="SEC-2",
            version=1,
            text="Invalid window",
            valid_from=date(2025, 1, 1),
            valid_to=date(2024, 1, 1),
        )


def test_amendment_supersedes_predecessor_and_point_in_time_routing():
    """
    Verify that a 2024 contract query retrieves ONLY the 2010 PDPA baseline (V1),
    whereas a 2025/2026 contract query retrieves ONLY the 2024 Amendment (V2).
    """
    store = get_default_temporal_store()

    # 1. Point-in-time query for 2024-06-15 (before 2025-01-01 amendment)
    active_2024 = store.query_point_in_time(as_of_date=date(2024, 6, 15))
    node_ids_2024 = {n.node_id for n in active_2024}

    assert "PDPA-2010-SEC-9-V1" in node_ids_2024
    assert "PDPA-2010-SEC-9-V2" not in node_ids_2024
    # Multi-hop CITES target should also be resolved
    assert "PDPA-2010-SEC-130-V1" in node_ids_2024

    # 2. Point-in-time query for 2026-03-01 (after 2025-01-01 amendment)
    active_2026 = store.query_point_in_time(as_of_date=date(2026, 3, 1))
    node_ids_2026 = {n.node_id for n in active_2026}

    assert "PDPA-2010-SEC-9-V2" in node_ids_2026
    assert "PDPA-2010-SEC-9-V1" not in node_ids_2026
    assert "PDPA-2010-SEC-130-V1" in node_ids_2026

    # Check AMENDED_BY edge creation
    v1_node = store.nodes["PDPA-2010-SEC-9-V1"]
    assert v1_node.status == StatutoryStatus.AMENDED
    assert v1_node.valid_to == date(2025, 1, 1)
    assert any(
        e.source_id == "PDPA-2010-SEC-9-V1"
        and e.target_id == "PDPA-2010-SEC-9-V2"
        and e.edge_type == TemporalEdgeType.AMENDED_BY
        for e in store.edges
    )


def test_repealed_by_excludes_statute_and_cited_targets():
    """Verify REPEALED_BY closes out a statute and prevents it from being returned after effective_date."""
    store = TemporalGraphStore()
    sec_a = StatutoryNode(
        node_id="ACT-A-SEC-1",
        act_name="Legacy Act",
        section_code="SEC-1",
        version=1,
        text="Legacy obligation.",
        valid_from=date(2015, 1, 1),
    )
    repealing_act = StatutoryNode(
        node_id="REPEAL-ACT-2025-SEC-99",
        act_name="Omnibus Repeal Act 2025",
        section_code="SEC-99",
        version=1,
        text="Legacy Act Section 1 is hereby repealed.",
        valid_from=date(2025, 7, 1),
    )
    store.upsert_node(sec_a)
    store.upsert_node(repealing_act)
    cypher_bundle = store.repeal_node(
        target_node_id="ACT-A-SEC-1",
        repealing_node_id="REPEAL-ACT-2025-SEC-99",
        effective_date=date(2025, 7, 1),
    )

    assert "MERGE (target)-[r:REPEALED_BY]->(rep)" in cypher_bundle.query
    assert cypher_bundle.params["effective_date"] == "2025-07-01"

    # Active in 2024
    res_2024 = store.query_point_in_time(
        as_of_date=date(2024, 1, 1), act_name="Legacy Act"
    )
    assert [n.node_id for n in res_2024] == ["ACT-A-SEC-1"]

    # Repealed by 2025-07-01
    res_post_repeal = store.query_point_in_time(
        as_of_date=date(2025, 7, 1), act_name="Legacy Act"
    )
    assert res_post_repeal == []


def test_cypher_builders_emit_parameterized_queries():
    """Verify Cypher query builders produce valid parameterized statements."""
    node = StatutoryNode(
        node_id="PDPA-2010-SEC-9-V2",
        act_name="Personal Data Protection Act 2010",
        section_code="SEC-9",
        version=2,
        text="Amended text",
        valid_from=date(2025, 1, 1),
    )
    upsert_bundle = build_upsert_amendment_cypher(
        node, predecessor_node_id="PDPA-2010-SEC-9-V1"
    )
    assert "MERGE (prev)-[r:AMENDED_BY]->(n)" in upsert_bundle.query
    assert upsert_bundle.params["predecessor_id"] == "PDPA-2010-SEC-9-V1"

    pit_bundle = build_point_in_time_cypher(
        as_of_date=date(2024, 5, 20),
        act_name="Personal Data Protection Act 2010",
        max_citation_hops=2,
    )
    assert "WHERE s.valid_from <= date($as_of_date)" in pit_bundle.query
    assert "MATCH (s)-[r:REPEALED_BY]->(:StatutoryNode)" in pit_bundle.query
    assert pit_bundle.params["as_of_date"] == "2024-05-20"
    assert pit_bundle.params["act_name"] == "Personal Data Protection Act 2010"

    repeal_bundle = build_repeal_cypher("OLD-ID", "NEW-ID", date(2025, 1, 1))
    assert repeal_bundle.params["target_node_id"] == "OLD-ID"


@pytest.mark.asyncio
async def test_temporal_retriever_node_zero_token_point_in_time_filtering():
    """Verify the LangGraph temporal_retriever_node populates retrieved_statutes with 0 LLM tokens."""
    state_2024 = {
        "document_id": "DOC-2024",
        "raw_text": "Clause 4: Data processor shall store records.",
        "reference_date": "2024-04-10",
        "extracted_clauses": [],
        "auditor_feedback": "",
        "is_grounded": False,
        "retry_count": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }
    out = await temporal_retriever_node(state_2024)
    assert out["prompt_tokens"] == 0
    assert out["completion_tokens"] == 0
    retrieved_ids = [s.node_id for s in out["retrieved_statutes"]]
    assert "PDPA-2010-SEC-9-V1" in retrieved_ids
    assert "PDPA-2010-SEC-9-V2" not in retrieved_ids
