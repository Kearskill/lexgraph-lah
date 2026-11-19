import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import zlib
from datetime import date
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from lexgraph_lah.agents.graph import build_compliance_graph
from lexgraph_lah.graph.deontic_solver import DeonticEnvelopeResolver
from lexgraph_lah.ingestion.contract_ast import (
    build_contract_ast,
    extract_text_from_docx_bytes,
    extract_text_from_pdf_bytes,
)
from lexgraph_lah.ingestion.ooxml_redliner import (
    compile_track_changes_docx,
    inspect_ooxml_docx,
)
from lexgraph_lah.main import app
from lexgraph_lah.middleware.pii_scrubber import ReversiblePIIVault
from lexgraph_lah.schemas.domain import (
    ClauseAudit,
    ClauseExtractionList,
    ContractEdgeType,
    RiskSeverity,
    TerritorialScope,
)


def _make_simple_docx_bytes(paragraphs: list[str]) -> bytes:
    """Creates a minimal valid `.docx` ZIP archive from paragraphs."""
    from xml.sax.saxutils import escape

    body_xml = "".join(
        f'<w:p><w:r><w:t xml:space="preserve">{escape(p)}</w:t></w:r></w:p>'
        for p in paragraphs
    )
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body_xml}<w:sectPr/></w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        "</Relationships>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", doc_xml)
    return buf.getvalue()


def _make_simple_pdf_bytes(text: str) -> bytes:
    """Creates a minimal PDF containing a compressed content stream with `Tj` text."""
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream_body = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET".encode("latin-1")
    compressed = zlib.compress(stream_body)
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Length "
        + str(len(compressed)).encode("ascii")
        + b" /Filter /FlateDecode >>\nstream\n"
        + compressed
        + b"\nendstream\nendobj\n%%EOF\n"
    )


def test_deontic_envelope_bitemporal_transitions_act709_act854_bnm_rmit():
    """
    Verifies zero-token Strictest Composite Statutory Envelope resolution across:
      - Pre-2024-08-26 (2024-06-15): Act 854 NOT active yet, Act 709 V1 has no 72h mandate;
        with BNM RMiT active (since 2020-06-19) resolving 1h.
      - Late-2024 (2024-10-15): Act 854 & P.U. (A) 220/2024 (eff. 2024-08-26) active -> 6h / 14d;
        Act 709 72h mandate NOT yet active.
      - Post-2025 (2026-03-15): Act 709 V2 (72h) + Act 854 (6h) -> 6h strictest winner;
        + BNM RMiT -> 1h strictest winner with explicit InterRegimeConflictDelta provenance.
    """
    resolver = DeonticEnvelopeResolver()

    # 1. Pre-2024-08-26 under Act 709 + Act 854 (neither 72h nor 6h is active yet)
    env_mid2024 = resolver.resolve(
        regimes=["ACT_709", "ACT_854"],
        as_of_date=date(2024, 6, 15),
        territorial_scope=TerritorialScope.ALL_MALAYSIA,
    )
    assert "incident_notice_max_hours" not in env_mid2024.resolved_bounds
    assert "CSA-2024-SEC-23-V1" not in env_mid2024.active_node_ids

    # 2. Late-2024 (2024-10-15): Act 854 + P.U.(A) 220/2024 active -> 6.0h, 14.0d
    env_late2024 = resolver.resolve(
        regimes=["ACT_709", "ACT_854"],
        as_of_date=date(2024, 10, 15),
    )
    assert env_late2024.resolved_bounds["incident_notice_max_hours"].strictest_value == 6.0
    assert env_late2024.resolved_bounds["incident_notice_max_hours"].dominating_regime == "ACT_854"
    assert env_late2024.resolved_bounds["full_report_max_days"].strictest_value == 14.0
    assert "PDPA-2010-SEC-9-V2" not in env_late2024.active_node_ids

    # 3. Post-2025 (2026-03-15): Act 709 (72h) vs Act 854 (6h) -> 6h wins
    env_dual_2026 = resolver.resolve(
        regimes=["ACT_709", "ACT_854"],
        as_of_date=date(2026, 3, 15),
    )
    b_notice = env_dual_2026.resolved_bounds["incident_notice_max_hours"]
    assert b_notice.strictest_value == 6.0
    assert b_notice.dominating_regime == "ACT_854"
    assert len(env_dual_2026.inter_regime_conflicts) >= 1
    assert any(
        c.winning_regime == "ACT_854"
        and c.superseded_regime == "ACT_709"
        and c.winning_bound == 6.0
        and c.superseded_bound == 72.0
        for c in env_dual_2026.inter_regime_conflicts
    )

    # 4. Tri-regime (Act 709 + Act 854 + BNM RMiT): BNM RMiT 1h dominates 6h and 72h
    env_tri_2026 = resolver.resolve(
        regimes=["ACT_709", "ACT_854", "BNM_RMIT"],
        as_of_date=date(2026, 3, 15),
    )
    b_tri = env_tri_2026.resolved_bounds["incident_notice_max_hours"]
    assert b_tri.strictest_value == 1.0
    assert b_tri.dominating_regime == "BNM_RMIT"
    assert b_tri.dominating_node_id == "BNM-RMIT-SEC-10-32-V1"
    assert env_tri_2026.resolved_bounds["regulator_audit_access"].strictest_value is True


def test_contract_ast_shadow_override_en_bm_narrow_definition_and_reversible_pii_vault():
    """
    Verifies:
      - ReversiblePIIVault scrubs NRIC/Passport/SSM/Phone into [MYKAD_01], [PASSPORT_01],
        [SSM_REG_01], [PHONE_MY_01] so zero raw PII exists in ContractASTGraph.
      - EN 'Notwithstanding Clause 5.1' & BM 'Walau apa pun yang terkandung dalam Klausa 5.1'
        shadow override traps + DEFINES_TERM narrow-definition traps are detected cleanly.
    """
    en_contract = (
        'Clause 1 Definitions: "Security Incident" means only confirmed unlawful disclosure causing downtime exceeding 48 hours and excluding ransomware. '
        "SEC-5.1 Breach Notification: For NRIC 900101-14-5678, Passport A12345678, Tel +6012-3456789, SSM 202001012345 (1358123-K), "
        "Vendor shall report any Security Incident within 10 days. "
        "SEC-14.1 Liability Limitation: Notwithstanding Clause 5.1, the Vendor shall bear zero statutory liability."
    )

    ast_en, vault = build_contract_ast("AST-TEST-EN", raw_text=en_contract)

    # Zero raw PII leaks into AST
    assert "900101-14-5678" not in ast_en.scrubbed_text
    assert "A12345678" not in ast_en.scrubbed_text
    assert "202001012345" not in ast_en.scrubbed_text
    assert "+6012-3456789" not in ast_en.scrubbed_text
    assert "[MYKAD_01]" in ast_en.scrubbed_text
    assert "[PASSPORT_01]" in ast_en.scrubbed_text
    assert "[SSM_REG_01]" in ast_en.scrubbed_text
    assert "[PHONE_MY_01]" in ast_en.scrubbed_text
    assert vault.rehydrate(ast_en.scrubbed_text) == en_contract

    edge_types = {e.edge_type for e in ast_en.edges}
    assert ContractEdgeType.DEFINES_TERM in edge_types
    assert ContractEdgeType.OVERRIDES_NOTWITHSTANDING in edge_types
    assert len(ast_en.narrow_definition_traps) >= 1
    assert ast_en.narrow_definition_traps[0].term_name == "Security Incident"
    assert len(ast_en.shadow_override_traps) >= 1
    assert ast_en.shadow_override_traps[0].overriding_clause_id == "SEC-14.1"
    assert ast_en.shadow_override_traps[0].target_clause_id == "SEC-5.1"

    # Bahasa Melayu "Walau apa pun..." trap
    bm_contract = (
        "Klausa 5.1 Keselamatan Data: Pemproses Data hendaklah melaporkan pelanggaran data dalam 72 jam. "
        "Klausa 14.1 Had Liabiliti: Walau apa pun yang terkandung dalam Klausa 5.1, Pemproses Data "
        "mempunyai tiada liabiliti berkanun."
    )
    ast_bm, _ = build_contract_ast("AST-TEST-BM", raw_text=bm_contract)
    assert len(ast_bm.shadow_override_traps) >= 1
    assert ast_bm.shadow_override_traps[0].overriding_clause_id == "SEC-14.1"
    assert ast_bm.shadow_override_traps[0].target_clause_id == "SEC-5.1"


@pytest.mark.asyncio
async def test_counterfactual_critic_rejects_under_strict_24h_redline_and_passes_retry2():
    """
    Verifies the 5-node LangGraph Counterfactual Auditor:
      - Attempt 1 proposes a 24-hour redline under Act 709 + Act 854 (which requires <= 6h)
        and fails to neutralize the linked 'Notwithstanding' shadow override -> REJECTED.
      - Attempt 2 proposes a 4-hour initial notice + 14-day full report AND neutralizes
        SEC-14.1 -> PASSED on Retry 1 with 0% raw PII ever hitting the LLM prompt.
    """
    contract = (
        "SEC-5.1 Breach Notice: For NRIC 900101-14-5678, Vendor shall notify Client of any "
        "cyber incident within 10 days. "
        "SEC-14.1 Carve-Out: Notwithstanding Clause 5.1, Vendor shall bear zero statutory liability."
    )
    scrubbed_quote_5_1 = (
        "SEC-5.1 Breach Notice: For NRIC [MYKAD_01], Vendor shall notify Client of any "
        "cyber incident within 10 days."
    )
    scrubbed_quote_14_1 = (
        "SEC-14.1 Carve-Out: Notwithstanding Clause 5.1, Vendor shall bear zero statutory liability."
    )

    attempt1 = [
        ClauseAudit(
            clause_id="SEC-5.1",
            category="Incident Notification",
            exact_quote=scrubbed_quote_5_1,
            severity=RiskSeverity.HIGH,
            rationale="Under PDPA 72h rule, 10 days is too slow.",
            recommended_redline="Vendor shall notify Client within 24 hours.",
            violated_statute_ids=["PUA-220-2024-REG-4"],
            overriding_clause_id="SEC-14.1",
            overriding_clause_quote=scrubbed_quote_14_1,
            addresses_shadow_override=False,
            proposed_notice_hours=24.0,
        )
    ]
    attempt2 = [
        ClauseAudit(
            clause_id="SEC-5.1",
            category="Incident Notification",
            exact_quote=scrubbed_quote_5_1,
            severity=RiskSeverity.HIGH,
            rationale="Act 854 P.U. (A) 220/2024 mandates <= 6 hours and SEC-14.1 override neutralization.",
            recommended_redline=(
                "Notwithstanding anything to the contrary in SEC-14.1, Vendor shall notify Client "
                "and NACSA within 4 hours with initial particulars and submit a full report within 14 days."
            ),
            violated_statute_ids=["PUA-220-2024-REG-4", "PDPA-2010-SEC-9-V2"],
            overriding_clause_id="SEC-14.1",
            overriding_clause_quote=scrubbed_quote_14_1,
            addresses_shadow_override=True,
            proposed_notice_hours=4.0,
            proposed_report_days=14.0,
        )
    ]

    captured_prompts: list[str] = []

    async def _fake_ainvoke(messages):
        captured_prompts.append(messages[0].content + "\n" + messages[1].content)
        idx = len(captured_prompts) - 1
        clauses, in_tok, out_tok = [(attempt1, 450, 140), (attempt2, 520, 170)][idx]
        raw_msg = SimpleNamespace(usage_metadata={"input_tokens": in_tok, "output_tokens": out_tok})
        return {"parsed": ClauseExtractionList(clauses=clauses), "raw": raw_msg}

    structured_mock = MagicMock()
    structured_mock.ainvoke = AsyncMock(side_effect=_fake_ainvoke)
    llm_mock = MagicMock()
    llm_mock.with_structured_output.return_value = structured_mock

    with patch("lexgraph_lah.agents.graph.get_llm", return_value=llm_mock):
        graph = build_compliance_graph()
        final_state = await graph.ainvoke(
            {
                "document_id": "COUNTERFACTUAL-RETRY-01",
                "raw_text": contract,
                "reference_date": "2026-03-15",
                "regimes": ["ACT_709", "ACT_854"],
                "extracted_clauses": [],
                "auditor_feedback": "",
                "is_grounded": False,
                "retry_count": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
            }
        )

    assert len(captured_prompts) == 2
    assert "900101-14-5678" not in captured_prompts[0]
    assert "[MYKAD_01]" in captured_prompts[0]
    assert "6.0" in captured_prompts[1] or "Invariant-C" in captured_prompts[1]
    assert final_state["is_grounded"] is True
    assert final_state["retry_count"] == 1
    assert final_state["counterfactual_log"][0]["passed"] is False
    assert final_state["counterfactual_log"][1]["passed"] is True
    assert final_state["attestation_manifest"]["manifest_sha256"]


def test_ooxml_track_changes_docx_compiler_and_reversible_rehydration():
    """
    Verifies valid OOXML Track Changes generation (<w:del>, <w:ins>, <w:comment>, <w:trackRevisions/>)
    plus local ReversiblePIIVault re-hydration inside the compiled .docx.
    """
    raw_contract = (
        "SEC-8.1 Liability: Customer 900101-14-5678 Data Processor shall bear zero statutory liability. "
        "SEC-8.2 Notice: Breach notification shall be provided within 10 days."
    )
    vault = ReversiblePIIVault(token_style="vault")
    scrubbed, _ = vault.scrub(raw_contract)
    assert "900101-14-5678" not in scrubbed
    assert "[MYKAD_01]" in scrubbed

    quote_8_1 = "SEC-8.1 Liability: Customer [MYKAD_01] Data Processor shall bear zero statutory liability."
    findings = [
        ClauseAudit(
            clause_id="SEC-8.1",
            category="Statutory Liability",
            exact_quote=quote_8_1,
            severity=RiskSeverity.CRITICAL,
            rationale="Violates Act 709 s. 9(1A).",
            recommended_redline="SEC-8.1 Liability: Customer [MYKAD_01] Data Processor shall comply fully with Act 709 Section 9.",
            violated_statute_ids=["PDPA-2010-SEC-9-V2"],
        )
    ]
    docx_bytes = compile_track_changes_docx(
        document_id="OOXML-TEST-01",
        raw_text=scrubbed,
        findings=findings,
        rehydrate_pii=True,
        pii_vault=vault,
    )

    inspected = inspect_ooxml_docx(docx_bytes)
    assert inspected["track_revisions_enabled"] is True
    assert len(inspected["deletions"]) == 1
    assert len(inspected["insertions"]) == 1
    assert len(inspected["comments"]) == 1
    assert inspected["deletions"][0]["author"] == "lexgraph-lah"
    assert inspected["insertions"][0]["author"] == "lexgraph-lah"
    assert "900101-14-5678" in inspected["deletions"][0]["text"]
    assert "900101-14-5678" in inspected["insertions"][0]["text"]
    assert "PDPA-2010-SEC-9-V2" in inspected["comments"][0]["text"]

    # Also verify docx & pdf text extractors round-trip cleanly
    src_docx = _make_simple_docx_bytes(
        ["SEC-5.1 Vendor shall notify within 10 days."]
    )
    assert extract_text_from_docx_bytes(src_docx) == [
        (1, "SEC-5.1 Vendor shall notify within 10 days.")
    ]
    src_pdf = _make_simple_pdf_bytes("SEC-5.1 Vendor shall notify within 10 days.")
    assert "Vendor shall notify within 10 days." in extract_text_from_pdf_bytes(src_pdf)[0][1]


@pytest.mark.asyncio
async def test_sse_stream_multipart_upload_docx_export_dual_layer_and_mcp():
    """
    Verifies end-to-end HTTP routes:
      1. POST /compliance/stream emits SSE node_update, abstention_gate, finops_tick, complete.
      2. POST /compliance/upload ingests .docx & .pdf multiparts with multi-regime AST audit.
      3. POST /compliance/export-docx returns valid Track-Changes .docx + attestation headers.
      4. GET /graph/nodes?include_contract_ast=true & /dashboard & /demo expose Dual-Layer + Multi-Regime UI.
      5. New MCP tools resolve_deontic_envelope, detect_contract_shadow_overrides, audit_and_redline_contract.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. SSE Streaming endpoint
        sse_res = await client.post(
            "/compliance/stream",
            json={
                "document_id": "SSE-STREAM-01",
                "raw_text": (
                    "SEC-8.1 Processor Liability Exclusion: The Data Processor shall bear zero "
                    "statutory liability. SEC-8.2 Breach Notice: Notification within 10 days."
                ),
                "as_of_date": "2026-03-15",
                "regimes": ["ACT_709", "ACT_854"],
                "persona": "PRACTITIONER",
                "language": "bilingual",
            },
        )
        assert sse_res.status_code == 200
        assert "text/event-stream" in sse_res.headers["content-type"]
        body_txt = sse_res.text
        assert "event: node_update" in body_txt
        assert "event: abstention_gate" in body_txt
        assert "event: finops_tick" in body_txt
        assert "event: complete" in body_txt
        assert "contract_ast_ingestor" in body_txt
        assert "redline_manifest" in body_txt

        # 2. Multipart .docx upload
        docx_payload = _make_simple_docx_bytes(
            [
                "SEC-5.1 Breach Notification: Vendor shall report incidents within 10 days.",
                "SEC-14.1 Liability Cap: Notwithstanding Clause 5.1, Vendor shall bear zero statutory liability.",
            ]
        )
        up_res = await client.post(
            "/compliance/upload",
            files={
                "file": (
                    "vendor_dpa.docx",
                    docx_payload,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            },
            data={
                "regimes": "ACT_709,ACT_854,BNM_RMIT",
                "as_of_date": "2026-03-15",
                "persona": "RAKYAT",
                "language": "bilingual",
            },
        )
        assert up_res.status_code == 200
        up_json = up_res.json()
        assert up_json["deontic_envelope"]["resolved_bounds"]["incident_notice_max_hours"]["strictest_value"] == 1.0
        assert len(up_json["contract_ast"]["shadow_override_traps"]) >= 1
        assert up_json["attestation_manifest"]["manifest_sha256"]

        # 3. Export Track-Changes .docx
        exp_res = await client.post(
            "/compliance/export-docx",
            json={
                "document_id": "EXPORT-01",
                "raw_text": (
                    "SEC-8.1 Processor Liability Exclusion: Customer 900101-14-5678 Data Processor "
                    "shall bear zero statutory liability. SEC-8.2 Breach Notice: Notification within 10 days."
                ),
                "as_of_date": "2026-03-15",
                "regimes": ["ACT_709", "ACT_854"],
                "rehydrate_pii": True,
            },
        )
        assert exp_res.status_code == 200
        assert exp_res.headers.get("X-LexGraph-Attestation-SHA256")
        assert exp_res.headers.get("X-LexGraph-Graph-Hash")
        inspected = inspect_ooxml_docx(exp_res.content)
        assert inspected["track_revisions_enabled"] is True
        assert len(inspected["deletions"]) >= 1
        assert len(inspected["insertions"]) >= 1

        # 4. Dual-Layer Graph + UI checks
        dual_res = await client.get(
            "/graph/nodes",
            params={
                "as_of_date": "2026-03-15",
                "include_contract_ast": "true",
                "regimes": "ACT_709,ACT_854,BNM_RMIT",
            },
        )
        assert dual_res.status_code == 200
        dual_data = dual_res.json()
        assert len(dual_data["contract_nodes"]) >= 2
        assert len(dual_data["contract_edges"]) >= 1
        assert dual_data["deontic_envelope"]["resolved_bounds"]["incident_notice_max_hours"]["strictest_value"] == 1.0

        # 5. New MCP tools via /api/v1/mcp/call
        mcp_env = await client.post(
            "/api/v1/mcp/call",
            json={
                "name": "resolve_deontic_envelope",
                "arguments": {
                    "regimes": ["ACT_709", "ACT_854", "BNM_RMIT"],
                    "as_of_date": "2026-03-15",
                },
            },
        )
        assert mcp_env.status_code == 200
        assert (
            mcp_env.json()["result"]["resolved_bounds"]["incident_notice_max_hours"][
                "strictest_value"
            ]
            == 1.0
        )

        mcp_ast = await client.post(
            "/api/v1/mcp/call",
            json={
                "name": "detect_contract_shadow_overrides",
                "arguments": {
                    "raw_text": (
                        "SEC-5.1 Security: Notify in 24h. "
                        "SEC-14.1 Carve-out: Notwithstanding Clause 5.1, Vendor shall bear zero statutory liability."
                    )
                },
            },
        )
        assert mcp_ast.status_code == 200
        assert len(mcp_ast.json()["result"]["shadow_override_traps"]) >= 1

        mcp_audit = await client.post(
            "/api/v1/mcp/call",
            json={
                "name": "audit_and_redline_contract",
                "arguments": {
                    "document_id": "MCP-FULL-01",
                    "raw_text": (
                        "SEC-8.1 Processor Liability Exclusion: The Data Processor shall bear zero "
                        "statutory liability. SEC-8.2 Breach Notice: Notification within 10 days."
                    ),
                    "regimes": ["ACT_709", "ACT_854"],
                    "as_of_date": "2026-03-15",
                },
            },
        )
        assert mcp_audit.status_code == 200
        assert mcp_audit.json()["result"]["is_grounded"] is True
        assert mcp_audit.json()["result"]["attestation_manifest"]["manifest_sha256"]

    sync_client = TestClient(app)
    demo_html = sync_client.get("/demo").text
    assert "regimeChipsContainer" in demo_html
    assert "contractDropZone" in demo_html
    assert "runSseStreamBtn" in demo_html
    assert "downloadRedlineDocxBtn" in demo_html
    assert "shadowOverrideTrapBanner" in demo_html
    assert r'Clause 1 Definitions: \"Security Incident\"' in demo_html
    assert r"buffer.split('\n\n')" in demo_html

    dash_html = sync_client.get("/dashboard").text
    assert "dualLayerModeBtn" in dash_html
    assert "include_contract_ast" in dash_html


def test_ui_html_inline_scripts_have_valid_js_syntax() -> None:
    """Validate that inline <script> tags in /demo and /dashboard parse cleanly under Node."""
    node_bin = shutil.which("node")
    if not node_bin:
        return
    sync_client = TestClient(app)
    for route_path in ("/demo", "/dashboard"):
        html_doc = sync_client.get(route_path).text
        for script_body in re.findall(r"<script[^>]*>(.*?)</script>", html_doc, re.DOTALL):
            if not script_body.strip():
                continue
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".mjs", encoding="utf-8", delete=False
            ) as tmp_js:
                tmp_js.write(script_body)
                tmp_path = tmp_js.name
            try:
                proc = subprocess.run(
                    [node_bin, "--check", tmp_path],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert proc.returncode == 0, f"{route_path} inline JS error: {proc.stderr}"
            finally:
                os.unlink(tmp_path)
