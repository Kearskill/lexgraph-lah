from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from lexgraph_lah.agents.graph import build_compliance_graph
from lexgraph_lah.main import app
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import ClauseAudit, ClauseExtractionList, RiskSeverity


def test_malaysian_pii_scrubber_masks_all_entity_types_under_50ms():
    """
    Verifies synthetic Malaysian NRIC, Passport, Phone, Email, and SSM registration
    numbers are masked deterministically in <50ms.
    """
    synthetic_text = (
        "Data Subject Ahmad Test (NRIC: 900101-14-5678, Passport: A12345678, "
        "Phone: +6012-3456789, Email: ahmad.test@example.my) entered a contract with "
        "Syarikat Contoh Sdn Bhd (SSM: 202001012345 (1358123-K))."
    )
    summary = scrub_malaysian_pii(synthetic_text)

    assert summary.scrub_latency_ms < 50.0
    assert summary.redaction_count >= 5
    assert "900101-14-5678" not in summary.masked_text
    assert "A12345678" not in summary.masked_text
    assert "+6012-3456789" not in summary.masked_text
    assert "ahmad.test@example.my" not in summary.masked_text
    assert "202001012345" not in summary.masked_text

    assert "<MY_NRIC_1>" in summary.masked_text
    assert "<MY_PASSPORT_1>" in summary.masked_text
    assert "<MY_PHONE_1>" in summary.masked_text
    assert "<EMAIL_1>" in summary.masked_text
    assert "<MY_SSM_1>" in summary.masked_text


@pytest.mark.asyncio
async def test_risk_assessor_masks_pii_before_llm_invocation():
    """
    Confirms no unmasked Malaysian NRIC or phone reaches ChatGoogleGenerativeAI.ainvoke.
    """
    captured_prompts: list[str] = []
    raw_contract = (
        "SEC-1.1 Subject Record: Customer 900101-14-5678 (+6012-3456789) data is stored "
        "under Section 9 security controls."
    )
    masked_quote = (
        "SEC-1.1 Subject Record: Customer <MY_NRIC_1> (<MY_PHONE_1>) data is stored "
        "under Section 9 security controls."
    )

    async def _fake_ainvoke(messages):
        captured_prompts.append(messages[1].content)
        raw_msg = SimpleNamespace(
            usage_metadata={"input_tokens": 120, "output_tokens": 60}
        )
        return {
            "parsed": ClauseExtractionList(
                clauses=[
                    ClauseAudit(
                        clause_id="SEC-1.1",
                        category="Security",
                        exact_quote=masked_quote,
                        severity=RiskSeverity.LOW,
                        rationale="Compliant.",
                        recommended_redline="None.",
                        violated_statute_ids=[],
                    )
                ]
            ),
            "raw": raw_msg,
        }

    structured_mock = MagicMock()
    structured_mock.ainvoke = AsyncMock(side_effect=_fake_ainvoke)
    llm_mock = MagicMock()
    llm_mock.with_structured_output.return_value = structured_mock

    with patch("lexgraph_lah.agents.graph.get_llm", return_value=llm_mock):
        graph = build_compliance_graph()
        final_state = await graph.ainvoke(
            {
                "document_id": "PII-GUARD-01",
                "raw_text": raw_contract,
                "reference_date": "2026-03-15",
                "extracted_clauses": [],
                "auditor_feedback": "",
                "is_grounded": False,
                "retry_count": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
            }
        )

    assert len(captured_prompts) == 1
    assert "900101-14-5678" not in captured_prompts[0]
    assert "+6012-3456789" not in captured_prompts[0]
    assert "<MY_NRIC_1>" in captured_prompts[0]
    assert "<MY_PHONE_1>" in captured_prompts[0]
    assert final_state["is_grounded"] is True


@pytest.mark.asyncio
async def test_api_v1_compliance_scan_pdpa_and_pii_and_mcp_endpoints():
    """
    Verifies:
    1. POST /api/v1/compliance/scan scrubs synthetic PII and maps gaps to Act 709 + SourceSpan IDs.
    2. Pre-2025 as_of_date omits 2024 Amendment Section 12A/12B rules.
    3. Out-of-domain text triggers 0.78 Abstention Gate.
    4. POST /api/v1/pii/scrub, GET /api/v1/retrieval/search, GET /api/v1/statutes/{id}/bilingual,
       and MCP tool endpoints work end-to-end with X-PII-Scrub-Active header.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Non-compliant 2026 document with synthetic NRIC & email
        scan_res = await client.post(
            "/api/v1/compliance/scan",
            json={
                "document_id": "SCAN-2026-GAP",
                "as_of_date": "2026-03-15",
                "territorial_scope": "All Malaysia",
                "persona": "PRACTITIONER",
                "raw_text": (
                    "Privacy Notice for Customer 910202-10-4321 (user.demo@example.my): "
                    "The Data Processor shall bear zero statutory liability for security failures. "
                    "Notification of a personal data breach shall be provided within 14 days. "
                    "Vendor may sell or disclose personal data to marketing brokers without data subject consent. "
                    "Company will not appoint a DPO."
                ),
            },
        )
        assert scan_res.status_code == 200
        assert scan_res.headers.get("X-PII-Scrub-Active") == "true"
        data = scan_res.json()
        assert data["is_abstained"] is False
        assert data["overall_risk"] == "CRITICAL"
        assert data["pii_scrub"]["redaction_count"] >= 2
        assert "910202-10-4321" not in data["pii_scrub"]["masked_text"]
        assert "user.demo@example.my" not in data["pii_scrub"]["masked_text"]

        rule_ids = {g["rule_id"] for g in data["gaps"]}
        assert {
            "ACT709-SEC9-SECURITY",
            "ACT709-SEC12B-BREACH",
            "ACT709-SEC8-DISCLOSURE",
            "ACT709-SEC12A-DPO",
        } <= rule_ids
        for gap in data["gaps"]:
            assert len(gap["source_span_ids"]) >= 1
            assert len(gap["source_spans"]) >= 1
            assert "910202-10-4321" not in gap["exact_quote"]
        assert len(data["bilingual_provisions"]) >= 2

        # 2. Pre-2025 point-in-time scan omits 12A/12B
        scan_2024 = await client.post(
            "/api/v1/compliance/scan",
            json={
                "document_id": "SCAN-2024-BASE",
                "as_of_date": "2024-06-15",
                "raw_text": "Data Processor shall bear zero statutory liability for personal data security failures.",
            },
        )
        assert scan_2024.status_code == 200
        rules_2024 = {g["rule_id"] for g in scan_2024.json()["gaps"]}
        assert "ACT709-SEC12B-BREACH" not in rules_2024
        assert "ACT709-SEC12A-DPO" not in rules_2024

        # 3. Out-of-domain abstention gate
        abstained_res = await client.post(
            "/api/v1/compliance/scan",
            json={
                "document_id": "OOD-CAKE",
                "as_of_date": "2026-03-15",
                "raw_text": "Preheat oven to 180C and mix flour, butter, cocoa powder, and sugar.",
            },
        )
        assert abstained_res.status_code == 200
        assert abstained_res.json()["is_abstained"] is True
        assert abstained_res.json()["gaps"] == []

        # 4. PII endpoint, retrieval endpoint, bilingual endpoint, MCP endpoints
        pii_res = await client.post(
            "/api/v1/pii/scrub",
            json={"text": "Contact 012-9988776 NRIC 880505-01-1234"},
        )
        assert pii_res.status_code == 200
        assert pii_res.json()["redaction_count"] == 2

        search_res = await client.get(
            "/api/v1/retrieval/search",
            params={
                "q": "notis kebocoran data 72 jam pemproses data",
                "as_of_date": "2026-03-15",
            },
        )
        assert search_res.status_code == 200
        assert search_res.json()["is_abstained"] is False
        assert len(search_res.json()["results"]) >= 1

        biling_res = await client.get("/api/v1/statutes/PDPA-2010-SEC-9-V2/bilingual")
        assert biling_res.status_code == 200
        assert biling_res.json()["en_node"]["node_id"] == "PDPA-2010-SEC-9-V2"
        assert biling_res.json()["bm_node"]["node_id"] == "PDPA-2010-SEC-9-V2-BM"

        mcp_list = await client.get("/api/v1/mcp/tools")
        assert mcp_list.status_code == 200
        tool_names = {t["name"] for t in mcp_list.json()["tools"]}
        assert len(tool_names) == 15
        assert {
            "lexgraph_pdpa_compliance_scan",
            "lexgraph_point_in_time_search",
            "lexgraph_pii_scrub",
            "resolve_deontic_envelope",
            "detect_contract_shadow_overrides",
            "audit_and_redline_contract",
            "diff_statutory_versions",
            "audit_bilingual_crosswalk",
            "scan_document_security",
            "scan_portfolio_blast_radius",
            "verify_compliance_attestation",
            "audit_counterparty_docx_redlines",
            "compile_incident_playbook",
            "record_hitl_review",
        } <= tool_names

        mcp_call = await client.post(
            "/api/v1/mcp/call",
            json={
                "name": "lexgraph_pii_scrub",
                "arguments": {"text": "NRIC 920303-14-5678"},
            },
        )
        assert mcp_call.status_code == 200
        assert "<MY_NRIC_1>" in mcp_call.json()["result"]["masked_text"]
