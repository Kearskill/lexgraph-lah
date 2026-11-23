from __future__ import annotations

import json
from datetime import date

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from evals.calibration import (
    compute_brier_score,
    compute_ece,
    compute_mrr,
    compute_recall_at_k,
    compute_threshold_sweep,
    evaluate_oblique_stress_suite,
)
from lexgraph_lah.agents.graph import build_compliance_graph
from lexgraph_lah.config import settings
from lexgraph_lah.main import app
from lexgraph_lah.retrieval.hybrid_retriever import (
    DeterministicSubwordEmbedder,
    HybridStatutoryRetriever,
    LiveHTTPEmbeddingAdapter,
    normalize_ocr_text,
    stem_bm_token,
)
from lexgraph_lah.security.auth import hash_api_key


def test_bm_stemming_and_ocr_normalization():
    assert stem_bm_token("pemindahan") == "pindah"
    assert stem_bm_token("memindahkan") == "pindah"
    assert stem_bm_token("kebocoran") == "bocor"
    assert stem_bm_token("pelantikan") == "lantik"
    assert (
        normalize_ocr_text("Sect10n 12B n0tification in S a b a h after 3O days")
        == "Section 12B notification in Sabah after 30 days"
    )


def test_hybrid_retriever_oblique_en_bm_manglish_and_recall_at_3():
    retriever = HybridStatutoryRetriever()

    oblique_expectations = [
        (
            "Follow-the-sun global telemetry replication to regional support hubs outside Malaysia.",
            date(2026, 3, 15),
            {"PDPA-2010-SEC-129-V2", "PDPA-2010-SEC-129-V2-BM", "PDPD-CBPDT-2025-03"},
        ),
        (
            "Automated customer risk scoring without manual review.",
            date(2026, 3, 15),
            {
                "MOSTI-AIGE-2024-PRINCIPLES-V1",
                "MOSTI-AIGE-2024-PRINCIPLES-V1-BM",
                "ACT-873-SEC-35-V1",
            },
        ),
        (
            "Discretionary deferred fee splitting over monthly consumer instalments.",
            date(2026, 3, 15),
            {"ACT-873-SEC-35-V1", "ACT-873-SEC-35-V1-BM", "ACT-873-SKP-LIC-V1"},
        ),
        (
            "Semua rekod pelanggan disalin ke hab sokongan serantau di luar negara tanpa persetujuan bertulis.",
            date(2026, 3, 15),
            {"PDPA-2010-SEC-129-V2-BM", "PDPA-2010-SEC-129-V2", "PDPD-CBPDT-2025-03"},
        ),
        (
            "System buat auto-scoring guna AI tanpa human check untuk pelanggan skim bayaran ansuran tangguh.",
            date(2026, 3, 15),
            {
                "MOSTI-AIGE-2024-PRINCIPLES-V1",
                "MOSTI-AIGE-2024-PRINCIPLES-V1-BM",
                "ACT-873-SEC-35-V1",
            },
        ),
    ]

    hits_at_3 = 0
    for q, ref_date, expected in oblique_expectations:
        resp = retriever.explain(query=q, as_of_date=ref_date, top_k=5)
        assert resp.is_abstained is False
        assert resp.max_score >= 0.78
        assert resp.rrf_k == 60
        assert len(resp.candidates) >= 1
        top_cand = resp.candidates[0]
        assert top_cand.bm25_score > 0.0
        assert top_cand.vector_score > 0.0
        assert top_cand.rrf_score > 0.0
        assert top_cand.temporal_valid is True
        if expected & {c.node_id for c in resp.candidates[:3]}:
            hits_at_3 += 1

    assert (hits_at_3 / len(oblique_expectations)) >= 0.90


def test_hybrid_retriever_bitemporal_and_five_tier_territorial_filters():
    retriever = HybridStatutoryRetriever()

    # Pre-2025 query must retrieve Act 709 s. 129 V1 (whitelist), NEVER V2 or Act 873
    pre_resp = retriever.explain(
        query="Follow-the-sun global telemetry replication to regional support hubs outside Malaysia.",
        as_of_date=date(2024, 6, 15),
        top_k=5,
    )
    pre_ids = {c.node_id for c in pre_resp.candidates}
    assert "PDPA-2010-SEC-129-V1" in pre_ids or "PDPA-2010-SEC-129-V1-BM" in pre_ids
    assert "PDPA-2010-SEC-129-V2" not in pre_ids
    assert not any(nid.startswith("ACT-873") for nid in pre_ids)

    # 5-tier East/West/Offshore territorial enforcement
    scope_expectations = [
        (
            "Sabah",
            "working hours overtime in Sabah",
            "SABAH-CAP67-SEC-104",
            {"EA-1955-SEC-60A-V1", "SARAWAK-CAP76-SEC-105-V1"},
        ),
        (
            "Sarawak",
            "working hours overtime in Sarawak",
            "SARAWAK-CAP76-SEC-105",
            {"EA-1955-SEC-60A-V1", "SABAH-CAP67-SEC-104-V1"},
        ),
        (
            "Labuan",
            "offshore Labuan licensing authority",
            "LABUAN-FSA-SEC-10",
            {"EA-1955-SEC-60A-V1", "SABAH-CAP67-SEC-104-V1"},
        ),
        (
            "Peninsular Malaysia",
            "working hours overtime Peninsular",
            "EA-1955-SEC-60A",
            {"SABAH-CAP67-SEC-104-V1", "SARAWAK-CAP76-SEC-105-V1"},
        ),
    ]
    for scope, q, expected_prefix, forbidden_ids in scope_expectations:
        resp = retriever.explain(
            query=q,
            as_of_date=date(2026, 3, 15),
            territorial_scope=scope,
            top_k=5,
        )
        ids = {c.node_id for c in resp.candidates}
        assert any(nid.startswith(expected_prefix) for nid in ids), (scope, ids)
        assert not (ids & forbidden_ids), (scope, ids)

    tiers = {
        c.territorial_tier
        for c in retriever.explain(
            query="working hours overtime in Sabah",
            as_of_date=date(2026, 3, 15),
            territorial_scope="Sabah",
            top_k=10,
        ).candidates
    }
    assert "Sabah" in tiers


@pytest.mark.asyncio
async def test_graph_rag_rescues_oblique_clause_from_false_abstention():
    graph = build_compliance_graph()
    res = await graph.ainvoke(
        {
            "document_id": "OBLIQUE-GRAPH-01",
            "raw_text": (
                "SEC-4.1 Regional Telemetry: Vendor performs follow-the-sun global telemetry "
                "replication to regional support hubs outside Malaysia."
            ),
            "reference_date": "2026-03-15",
            "regimes": ["ACT_709"],
            "extracted_clauses": [],
            "auditor_feedback": "",
            "is_grounded": False,
            "retry_count": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
        }
    )
    assert res["is_abstained"] is False
    assert float(res["max_relevance_score"]) >= 0.78


def test_live_http_embedding_adapter_openai_and_gemini_mock_transport():
    # OpenAI response shape
    def _openai_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        inputs = body["input"]
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": idx, "embedding": [1.0, float(idx + 1), 0.0]}
                    for idx, _ in enumerate(inputs)
                ]
            },
        )

    oa = LiveHTTPEmbeddingAdapter(
        api_url="https://embeddings.example.com/v1/embeddings",
        api_key="test-key",
        model="text-embedding-3-small",
        dimensions=3,
        transport=httpx.MockTransport(_openai_handler),
    )
    oa_vecs = oa.embed_texts(["clause a", "clause b"])
    assert len(oa_vecs) == 2
    assert pytest.approx(sum(x * x for x in oa_vecs[0]), rel=1e-4) == 1.0

    # Gemini batchEmbedContents response shape
    def _gemini_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        reqs = body["requests"]
        return httpx.Response(
            200,
            json={"embeddings": [{"values": [0.6, 0.8, 0.0]} for _ in reqs]},
        )

    gm = LiveHTTPEmbeddingAdapter(
        api_url="https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:batchEmbedContents",
        api_key="test-key",
        model="text-embedding-004",
        dimensions=3,
        transport=httpx.MockTransport(_gemini_handler),
    )
    gm_vec = gm.embed_query("cross-border transfer")
    assert len(gm_vec) == 3
    assert pytest.approx(gm_vec[0], abs=1e-4) == 0.6
    assert pytest.approx(gm_vec[1], abs=1e-4) == 0.8

    # Zero-network subword embedder determinism
    emb = DeterministicSubwordEmbedder(dimensions=128)
    assert emb.embed_query("Act 709 Section 129") == emb.embed_query(
        "Act 709 Section 129"
    )


@pytest.mark.asyncio
async def test_retrieval_explain_endpoint_and_viewer_rbac(
    monkeypatch: pytest.MonkeyPatch,
):
    viewer_key = "lg_explain_viewer_key"
    api_keys = {
        hash_api_key(viewer_key): {
            "tenant_id": "tenant-explain",
            "role": "viewer",
            "subject": "explain-viewer",
        }
    }
    monkeypatch.setattr(settings, "auth_mode", "api_key")
    monkeypatch.setattr(settings, "auth_api_keys_json", json.dumps(api_keys))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        unauth = await client.post(
            "/api/v1/retrieval/explain",
            json={"query": "follow-the-sun telemetry replication"},
        )
        assert unauth.status_code == 401

        res = await client.post(
            "/api/v1/retrieval/explain",
            headers={"X-API-Key": viewer_key},
            json={
                "query": "follow-the-sun global telemetry replication to regional support hubs",
                "as_of_date": "2026-03-15",
                "top_k": 4,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["is_abstained"] is False
        assert body["rrf_k"] == 60
        assert len(body["candidates"]) >= 1
        c0 = body["candidates"][0]
        assert c0["temporal_valid"] is True
        assert c0["territorial_tier"] in {
            "Sabah",
            "Sarawak",
            "Labuan",
            "Peninsular",
            "Federal",
        }
        assert "bm25_score" in c0
        assert "vector_score" in c0
        assert "rrf_score" in c0


def test_calibration_metrics_math_and_oblique_stress_suite():
    # Exact analytic checks
    assert compute_brier_score([0.9, 0.2], [1.0, 0.0]) == pytest.approx(0.025, abs=1e-4)
    ece, bins = compute_ece([0.9, 0.2], [1.0, 0.0], n_bins=10)
    # bin 2: conf=0.2, acc=0.0, gap=0.2; bin 9: conf=0.9, acc=1.0, gap=0.1 -> mean gap = 0.15
    assert ece == pytest.approx(0.15, abs=1e-4)
    assert len(bins) == 10

    expected = [{"A", "B"}, {"C"}]
    ranked = [["X", "B", "A"], ["D", "E", "C"]]
    assert compute_recall_at_k(expected, ranked, 1) == 0.0
    assert compute_recall_at_k(expected, ranked, 2) == 0.5
    assert compute_recall_at_k(expected, ranked, 3) == 1.0
    assert compute_mrr(expected, ranked) == pytest.approx(
        (0.5 + 1.0 / 3.0) / 2.0, abs=1e-4
    )

    sweep = compute_threshold_sweep(
        [0.85, 0.40], [True, False], start=0.50, stop=0.95, step=0.05
    )
    assert len(sweep) == 10
    assert sweep[0].threshold == 0.50
    assert sweep[-1].threshold == 0.95

    report = evaluate_oblique_stress_suite()
    assert report.total_samples == 18
    assert report.recall_at_3 >= 0.90
    assert report.macro_f1 >= 0.95
    assert report.false_confidence_rate == 0.0
    assert report.temporal_contamination_rate == 0.0
    assert 0.0 <= report.ece_10_bin <= 0.30
    assert 0.0 <= report.brier_score <= 0.10
    assert len(report.threshold_sweep) == 10
