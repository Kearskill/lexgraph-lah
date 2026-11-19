from datetime import date

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from lexgraph_lah.graph.bilingual_critic import (
    audit_bilingual_divergence,
    audit_bilingual_pair,
)
from lexgraph_lah.graph.diff_engine import (
    diff_statute_lineage,
    evaluate_contract_delta_impact,
)
from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    get_default_temporal_store,
)
from lexgraph_lah.main import app
from lexgraph_lah.schemas.domain import (
    AuthorityTier,
    ContractDeltaAuditRequest,
    OutputPersona,
    RiskSeverity,
    StatutoryNode,
    StatutoryStatus,
    TemporalEdgeType,
    TerritorialScope,
)


def test_diff_statute_lineage_amended_newly_enacted_repealed_and_unchanged():
    """
    Verifies zero-token bi-temporal statutory diffing across:
      - AMENDED (PDPA-2010-SEC-9-V1 -> V2 across 2024-06-15 to 2026-03-15)
      - NEWLY_ENACTED (PDPA-2010-SEC-12B-V1 / P.U. (A) 342/2024 commencing 2025-01-01)
      - UNCHANGED (PDPA-2010-SEC-130-V1)
      - REPEALED (REPEALED_BY transition on custom store)
      - ValueError when from_date > to_date
    """
    store = get_default_temporal_store()

    # 1. AMENDED transition: PDPA Section 9 (2024-06-15 -> 2026-03-15)
    diff_sec9 = diff_statute_lineage(
        provision_id="PDPA-2010-SEC-9-V2",
        from_date=date(2024, 6, 15),
        to_date=date(2026, 3, 15),
        store=store,
    )
    assert diff_sec9.change_status == "AMENDED"
    assert diff_sec9.from_node_id == "PDPA-2010-SEC-9-V1"
    assert diff_sec9.to_node_id == "PDPA-2010-SEC-9-V2"
    assert date(2025, 1, 1) in diff_sec9.transition_dates
    assert any(t.edge_type == TemporalEdgeType.AMENDED_BY for t in diff_sec9.transitions)
    assert len(diff_sec9.from_source_spans) >= 1
    assert len(diff_sec9.to_source_spans) >= 1
    assert len(diff_sec9.unified_redline) >= 1
    assert diff_sec9.telemetry.total_tokens == 0
    assert diff_sec9.telemetry.estimated_cost_usd == 0.0
    assert diff_sec9.telemetry.estimated_cost_myr == 0.0

    # 2. NEWLY_ENACTED transition: Section 12B & P.U. (A) 342/2024
    diff_12b = diff_statute_lineage(
        provision_id="PDPA-2010-SEC-12B-V1",
        from_date=date(2024, 6, 15),
        to_date=date(2026, 3, 15),
        store=store,
    )
    assert diff_12b.change_status == "NEWLY_ENACTED"
    assert diff_12b.from_node_id is None
    assert diff_12b.to_node_id == "PDPA-2010-SEC-12B-V1"
    assert len(diff_12b.added_clauses) >= 1
    assert "P.U. (A) 342/2024" in diff_12b.related_gazettes
    assert diff_12b.telemetry.total_tokens == 0

    # 3. UNCHANGED transition
    diff_130 = diff_statute_lineage(
        provision_id="PDPA-2010-SEC-130-V1",
        from_date=date(2024, 6, 15),
        to_date=date(2026, 3, 15),
        store=store,
    )
    assert diff_130.change_status == "UNCHANGED"
    assert diff_130.added_clauses == []
    assert diff_130.removed_clauses == []
    assert diff_130.modified_clauses == []

    # 4. REPEALED transition
    custom = TemporalGraphStore()
    old_reg = StatutoryNode(
        node_id="PUA-100-2020",
        act_name="Legacy Regulations 2020",
        act_number="P.U. (A) 100/2020",
        section_code="REG-1",
        text="Legacy regulation obligation.",
        valid_from=date(2020, 1, 1),
        effective_from=date(2020, 1, 1),
        gazette_ref="P.U. (A) 100/2020",
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
    )
    new_reg = StatutoryNode(
        node_id="PUA-200-2025",
        act_name="New Regulations 2025",
        act_number="P.U. (A) 200/2025",
        section_code="REG-1",
        text="Repealing legacy regulation.",
        valid_from=date(2025, 6, 1),
        effective_from=date(2025, 6, 1),
        gazette_ref="P.U. (A) 200/2025",
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
    )
    custom.upsert_node(old_reg)
    custom.upsert_node(new_reg)
    custom.repeal_node(
        "PUA-100-2020",
        "PUA-200-2025",
        effective_date=date(2025, 6, 1),
        gazette_ref="P.U. (A) 200/2025",
    )
    rep_diff = diff_statute_lineage(
        provision_id="PUA-100-2020",
        from_date=date(2025, 5, 31),
        to_date=date(2025, 6, 15),
        store=custom,
    )
    assert rep_diff.change_status == "REPEALED"
    assert rep_diff.from_node_id == "PUA-100-2020"
    assert rep_diff.to_node_id is None
    assert rep_diff.to_status == StatutoryStatus.REPEALED
    assert len(rep_diff.removed_clauses) >= 1
    assert any(t.edge_type == TemporalEdgeType.REPEALED_BY for t in rep_diff.transitions)

    with pytest.raises(ValueError, match="from_date"):
        diff_statute_lineage("PDPA-2010-SEC-9-V2", date(2026, 5, 1), date(2024, 1, 1), store=store)


def test_contract_delta_audit_detects_pdpa_and_act854_gazette_regressions_with_pii_scrub():
    """
    Verifies Contract Delta-Audit flags a 2024-compliant agreement that becomes non-compliant
    in 2026 (Act A1727 / P.U. (A) 342/2024) and across Act 854 P.U. (A) 220/2024 commencement,
    scrubbing Malaysian PII at $0.00 cost.
    """
    store = get_default_temporal_store()

    # 1. Pre-2025 compliant -> Post-2025 non-compliant (10-day breach window + missing DPO + NRIC PII)
    req_pdpa = ContractDeltaAuditRequest(
        document_id="DELTA-PDPA-01",
        raw_text=(
            "Section 9 Security Principle: Data User shall take practical steps to protect "
            "personal data (Ref: 900101-14-5678). "
            "Section 12B Personal Data Breach Notification: Data user shall notify the "
            "Commissioner of a personal data breach within 10 days."
        ),
        from_date=date(2024, 6, 15),
        to_date=date(2026, 3, 15),
        persona=OutputPersona.PRACTITIONER,
    )
    res_pdpa = evaluate_contract_delta_impact(req_pdpa, store=store)
    assert res_pdpa.from_overall_risk == RiskSeverity.LOW
    assert res_pdpa.to_overall_risk == RiskSeverity.HIGH
    assert res_pdpa.became_non_compliant is True
    assert res_pdpa.compliance_regression_detected is True
    assert res_pdpa.pii_scrub.redaction_count >= 1
    assert "900101-14-5678" not in res_pdpa.pii_scrub.masked_text
    assert all("900101-14-5678" not in f.exact_quote for f in res_pdpa.delta_findings)
    assert any(f.rule_id == "ACT709-SEC12B-BREACH" for f in res_pdpa.delta_findings)
    assert res_pdpa.telemetry.total_tokens == 0
    assert res_pdpa.telemetry.estimated_cost_usd == 0.0

    # 2. Multi-regime Act 854 P.U. (A) 220/2024 commencement (2024-06-15 -> 2024-10-15)
    req_csa = ContractDeltaAuditRequest(
        document_id="DELTA-CSA-01",
        raw_text=(
            "SEC-2.1 Cyber Incident SLA: Vendor shall report any cyber security incident "
            "affecting NCII systems within 48 hours."
        ),
        from_date=date(2024, 6, 15),
        to_date=date(2024, 10, 15),
        regimes=["ACT_709", "ACT_854"],
    )
    res_csa = evaluate_contract_delta_impact(req_csa, store=store)
    assert res_csa.became_non_compliant is True
    assert any(f.rule_id == "DELTA-ACT_854-NOTICE" for f in res_csa.delta_findings)
    assert res_csa.telemetry.total_tokens == 0


def test_act388_bilingual_divergence_critic_detections_and_precedence():
    """
    Verifies Act 388 s. 63 Bilingual Divergence Critic:
      1. Seeded aligned Act 709 s. 9 V2 returns ALIGNED with authoritative_language='ms'.
      2. Seeded Penal Code s. 420 flags NUMERIC_DEADLINE_DISCREPANCY (10-year ceiling in EN only).
      3. Synthetic mismatches catch DEONTIC_MODALITY_MISMATCH, PENALTY_CEILING_DISCREPANCY,
         and MISSING_SUBCLAUSE while scrubbing inline PII.
    """
    store = get_default_temporal_store()

    aligned = audit_bilingual_divergence("PDPA-2010-SEC-9-V2", date(2026, 3, 15), store=store)
    assert aligned.alignment_status == "ALIGNED"
    assert aligned.has_divergence is False
    assert aligned.authoritative_language == "ms"
    assert "Act 388" in aligned.act_388_authority_basis
    assert aligned.telemetry.total_tokens == 0

    penal = audit_bilingual_divergence("ACT-574-SEC-420-V1", date(2026, 3, 15), store=store)
    assert penal.alignment_status == "DIVERGENCE_DETECTED"
    assert penal.has_divergence is True
    assert any(i.divergence_type == "NUMERIC_DEADLINE_DISCREPANCY" for i in penal.issues)

    # Synthetic full mismatch (modality + deadline + RM ceiling + missing subclause + inline PII)
    syn = audit_bilingual_pair(
        en_node=None,
        bm_node=None,
        authoritative_language="ms",
        as_of_date=date(2026, 3, 15),
        act_name="Synthetic Act 388 Audit",
        act_number="Act 709",
        section_code="SEC-99",
        en_text=(
            "Section 99 (1) For NRIC 900101-14-5678, the data user may notify within 48 hours "
            "or pay a fine up to RM 250,000."
        ),
        bm_text=(
            "Seksyen 99 (1) Bagi KP 900101-14-5678, pengguna data hendaklah memaklumkan dalam "
            "tempoh 72 jam atau denda sehingga RM 1,000,000. (2) Kegagalan adalah suatu kesalahan. "
            "Dengan syarat bahawa notis bertulis diberikan."
        ),
    )
    issue_types = {i.divergence_type for i in syn.issues}
    assert {
        "DEONTIC_MODALITY_MISMATCH",
        "NUMERIC_DEADLINE_DISCREPANCY",
        "PENALTY_CEILING_DISCREPANCY",
        "MISSING_SUBCLAUSE",
    } <= issue_types
    assert syn.authoritative_language == "ms"
    assert "900101-14-5678" not in syn.en_source_spans[0].text
    assert "900101-14-5678" not in syn.bm_source_spans[0].text
    assert syn.telemetry.total_tokens == 0


def test_labuan_territorial_isolation_and_act388_retrieval():
    """Verifies 5-way territorial isolation including Labuan [Act 704] and Act 388 s. 63 search."""
    store = get_default_temporal_store()

    labuan = store.search_with_abstention(
        query="offshore financial business licensing Labuan Act 704",
        as_of_date=date(2026, 3, 15),
        territorial_scope=TerritorialScope.LABUAN,
    )
    labuan_ids = {r.node_id for r in labuan.results}
    assert "LABUAN-FSA-SEC-10-V1" in labuan_ids
    assert "EA-1955-SEC-60A-V1" not in labuan_ids

    peninsular = store.search_with_abstention(
        query="working hours and overtime rates for employees",
        as_of_date=date(2026, 3, 15),
        territorial_scope=TerritorialScope.PENINSULAR_MALAYSIA,
    )
    assert "LABUAN-FSA-SEC-10-V1" not in {r.node_id for r in peninsular.results}

    act388_res = store.search_with_abstention(
        query="authoritative text Bahasa Melayu English Interpretation Acts Act 388 Section 63",
        as_of_date=date(2026, 3, 15),
    )
    assert "ACT-388-SEC-63-V1" in {r.node_id for r in act388_res.results}


@pytest.mark.asyncio
async def test_api_endpoints_mcp_tools_and_ui_lineage_divergence():
    """
    Verifies:
      1. GET/POST /api/v1/lineage/diff & POST /api/v1/lineage/delta-audit (with PII middleware header).
      2. GET /api/v1/crosswalk/{id}/divergence, POST /api/v1/crosswalk/divergence,
         and GET /api/v1/statutes/{id}/bilingual?include_divergence=true.
      3. MCP tools `diff_statutory_versions` and `audit_bilingual_crosswalk` via /api/v1/mcp/call.
      4. /dashboard Time-Travel Statutory Redline panel and /demo Act 388 divergence badges.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. GET & POST /api/v1/lineage/diff
        diff_get = await client.get(
            "/api/v1/lineage/diff",
            params={
                "provision_id": "PDPA-2010-SEC-9-V2",
                "from_date": "2024-06-15",
                "to_date": "2026-03-15",
            },
        )
        assert diff_get.status_code == 200
        assert diff_get.json()["change_status"] == "AMENDED"
        assert diff_get.json()["telemetry"]["total_tokens"] == 0

        diff_post = await client.post(
            "/api/v1/lineage/diff",
            json={
                "provision_id": "PDPA-2010-SEC-12B-V1",
                "from_date": "2024-06-15",
                "to_date": "2026-03-15",
            },
        )
        assert diff_post.status_code == 200
        assert diff_post.json()["change_status"] == "NEWLY_ENACTED"

        diff_404 = await client.get(
            "/api/v1/lineage/diff",
            params={
                "provision_id": "NO-SUCH-NODE",
                "from_date": "2024-06-15",
                "to_date": "2026-03-15",
            },
        )
        assert diff_404.status_code == 404

        diff_422 = await client.post(
            "/api/v1/lineage/diff",
            json={
                "provision_id": "PDPA-2010-SEC-9-V2",
                "from_date": "2026-06-15",
                "to_date": "2024-03-15",
            },
        )
        assert diff_422.status_code == 422

        # 2. POST /api/v1/lineage/delta-audit
        delta_res = await client.post(
            "/api/v1/lineage/delta-audit",
            json={
                "document_id": "API-DELTA-01",
                "raw_text": (
                    "SEC-1.1 Security: Customer 900101-14-5678 Data Processor shall maintain "
                    "reasonable safeguards. SEC-1.2 Breach Notification: Report personal data breach within 10 days."
                ),
                "from_date": "2024-06-15",
                "to_date": "2026-03-15",
                "persona": "RAKYAT",
            },
        )
        assert delta_res.status_code == 200
        assert delta_res.headers.get("X-PII-Scrub-Active") == "true"
        delta_json = delta_res.json()
        assert delta_json["became_non_compliant"] is True
        assert delta_json["pii_scrub"]["redaction_count"] >= 1
        assert "900101-14-5678" not in delta_json["pii_scrub"]["masked_text"]

        # 3. Crosswalk divergence endpoints & bilingual drawer endpoint
        cw_get = await client.get("/api/v1/crosswalk/ACT-574-SEC-420-V1/divergence")
        assert cw_get.status_code == 200
        assert cw_get.json()["has_divergence"] is True

        cw_post = await client.post(
            "/api/v1/crosswalk/divergence",
            json={
                "en_text": "Data user may notify 900101-14-5678 within 72 hours.",
                "bm_text": "Pengguna data hendaklah memaklumkan 900101-14-5678 dalam 72 jam.",
                "authoritative_language": "ms",
            },
        )
        assert cw_post.status_code == 200
        assert cw_post.headers.get("X-PII-Scrub-Active") == "true"
        assert cw_post.json()["has_divergence"] is True
        assert "900101-14-5678" not in cw_post.json()["en_source_spans"][0]["text"]

        biling_res = await client.get(
            "/api/v1/statutes/ACT-574-SEC-420-V1/bilingual",
            params={"include_divergence": "true"},
        )
        assert biling_res.status_code == 200
        assert biling_res.json()["divergence_report"]["has_divergence"] is True

        # 4. MCP tool invocations
        mcp_diff = await client.post(
            "/api/v1/mcp/call",
            json={
                "name": "diff_statutory_versions",
                "arguments": {
                    "provision_id": "PDPA-2010-SEC-9-V2",
                    "from_date": "2024-06-15",
                    "to_date": "2026-03-15",
                    "contract_text": "SEC-1.2 Breach Notification: Report personal data breach within 10 days.",
                },
            },
        )
        assert mcp_diff.status_code == 200
        assert mcp_diff.json()["result"]["change_status"] == "AMENDED"
        assert mcp_diff.json()["result"]["contract_delta_audit"]["became_non_compliant"] is True

        mcp_cw = await client.post(
            "/api/v1/mcp/call",
            json={
                "name": "audit_bilingual_crosswalk",
                "arguments": {
                    "node_id": "PDPA-2010-SEC-9-V2",
                    "as_of_date": "2026-03-15",
                },
            },
        )
        assert mcp_cw.status_code == 200
        assert mcp_cw.json()["result"]["alignment_status"] == "ALIGNED"

    # 5. UI HTML presence checks
    sync_client = TestClient(app)
    dash_html = sync_client.get("/dashboard").text
    assert "timeTravelRedlinePanel" in dash_html
    assert "diffFromDate" in dash_html
    assert "diffToDate" in dash_html
    assert "/api/v1/lineage/diff" in dash_html

    demo_html = sync_client.get("/demo").text
    assert "bilingual-divergence-badge" in demo_html
    assert "ACT 388" in demo_html
    assert "renderBilingualDivergenceBlock" in demo_html
