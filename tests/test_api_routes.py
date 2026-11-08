from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from lexgraph_lah.api.routes import _COMPLIANCE_CACHE
from lexgraph_lah.main import app
from lexgraph_lah.schemas.domain import ClauseAudit, ClauseExtractionList, RiskSeverity
from lexgraph_lah.telemetry.tracer import telemetry_registry


def _mock_llm_single_pass(
    clauses: list[ClauseAudit], in_tok: int = 500, out_tok: int = 180
):
    raw_msg = SimpleNamespace(
        usage_metadata={"input_tokens": in_tok, "output_tokens": out_tok}
    )
    structured_mock = MagicMock()
    structured_mock.ainvoke = AsyncMock(
        return_value={"parsed": ClauseExtractionList(clauses=clauses), "raw": raw_msg}
    )
    llm_mock = MagicMock()
    llm_mock.with_structured_output.return_value = structured_mock
    return llm_mock


@pytest.mark.asyncio
async def test_compliance_check_and_semantic_cache_and_telemetry_endpoints():
    """
    Verifies:
    1. POST /compliance/check executes point-in-time Graph-RAG, returns active statutes & FinOps telemetry.
    2. Repeat identical POST /compliance/check hits the deterministic FinOps cache with 0 tokens ($0.00).
    3. GET /telemetry/metrics returns aggregated token, cost, and span metrics.
    """
    _COMPLIANCE_CACHE.clear()
    telemetry_registry.clear()

    raw_text = (
        "SEC-3.1 Breach Notice: Notification of a personal data breach shall be "
        "provided within 10 days."
    )
    expected_clauses = [
        ClauseAudit(
            clause_id="SEC-3.1",
            category="Data Breach Notification",
            exact_quote=raw_text,
            severity=RiskSeverity.HIGH,
            rationale="Exceeds 72-hour mandatory PDPA 2024 Amendment window.",
            recommended_redline="Notify within 24 hours.",
            violated_statute_ids=["PDPA-2010-SEC-9-V2"],
        )
    ]

    mock_llm = _mock_llm_single_pass(expected_clauses, in_tok=600, out_tok=200)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        with patch("lexgraph_lah.agents.graph.get_llm", return_value=mock_llm):
            # First request: invokes LLM
            res1 = await client.post(
                "/compliance/check",
                json={
                    "document_id": "CONTRACT-2026-001",
                    "raw_text": raw_text,
                    "reference_date": "2026-03-15",
                },
            )
            assert res1.status_code == 200
            data1 = res1.json()
            assert data1["overall_risk"] == "HIGH"
            assert data1["telemetry"]["total_tokens"] == 800
            assert data1["telemetry"]["estimated_cost_usd"] > 0.0
            active_ids = {s["node_id"] for s in data1["active_statutes"]}
            assert "PDPA-2010-SEC-9-V2" in active_ids
            assert "PDPA-2010-SEC-9-V1" not in active_ids

            # Second identical request: served from FinOps deterministic cache at 0 tokens
            res2 = await client.post(
                "/compliance/check",
                json={
                    "document_id": "CONTRACT-2026-001-DUP",
                    "raw_text": raw_text,
                    "reference_date": "2026-03-15",
                },
            )
            assert res2.status_code == 200
            data2 = res2.json()
            assert data2["document_id"] == "CONTRACT-2026-001-DUP"
            assert data2["telemetry"]["total_tokens"] == 0
            assert data2["telemetry"]["estimated_cost_usd"] == 0.0

        # Check /telemetry/metrics
        metrics_res = await client.get("/telemetry/metrics")
        assert metrics_res.status_code == 200
        metrics_data = metrics_res.json()
        assert metrics_data["total_runs"] == 1
        assert metrics_data["total_tokens"] == 800
        assert metrics_data["grounded_rate"] == 1.0
        assert len(metrics_data["spans"]) == 1


@pytest.mark.asyncio
async def test_graph_nodes_and_dashboard_endpoints():
    """
    Verifies:
    1. GET /graph/nodes?as_of_date=2024-06-15 filters out 2025 amendments.
    2. GET /graph/nodes without date filter returns all statutory versions and edges.
    3. GET /dashboard renders the Cytoscape.js + FinOps HTML UI.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res_2024 = await client.get("/graph/nodes", params={"as_of_date": "2024-06-15"})
        assert res_2024.status_code == 200
        payload_2024 = res_2024.json()
        ids_2024 = {n["node_id"] for n in payload_2024["nodes"]}
        assert "PDPA-2010-SEC-9-V1" in ids_2024
        assert "PDPA-2010-SEC-9-V2" not in ids_2024
        assert "MATCH (s:StatutoryNode)" in payload_2024["cypher_query"]

        res_all = await client.get("/graph/nodes")
        assert res_all.status_code == 200
        payload_all = res_all.json()
        ids_all = {n["node_id"] for n in payload_all["nodes"]}
        assert {
            "PDPA-2010-SEC-9-V1",
            "PDPA-2010-SEC-9-V2",
            "PDPA-2010-SEC-130-V1",
        } <= ids_all
        assert len(payload_all["edges"]) >= 3

        dash_res = await client.get("/dashboard")
        assert dash_res.status_code == 200
        assert "cytoscape" in dash_res.text
        assert "OpenTelemetry & FinOps Trace Spans" in dash_res.text
