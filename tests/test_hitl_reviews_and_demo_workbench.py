from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from evals.run_benchmark import load_extra_jsonl_cases, run_benchmark_async
from lexgraph_lah.config import settings
from lexgraph_lah.hitl.review_store import default_hitl_review_ledger
from lexgraph_lah.main import app
from lexgraph_lah.security.attestation_ledger import default_attestation_ledger
from lexgraph_lah.security.auth import hash_api_key


@pytest.mark.asyncio
async def test_hitl_reviews_all_decisions_pii_scrub_ed25519_rbac_and_golden_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    default_hitl_review_ledger.clear()
    default_attestation_ledger.clear()

    viewer_key = "lg_hitl_viewer"
    auditor_key = "lg_hitl_auditor"
    admin_key = "lg_hitl_admin"
    api_keys = {
        hash_api_key(viewer_key): {
            "tenant_id": "tenant-hitl",
            "role": "viewer",
            "subject": "hitl-viewer",
        },
        hash_api_key(auditor_key): {
            "tenant_id": "tenant-hitl",
            "role": "auditor",
            "subject": "counsel-auditor",
        },
        hash_api_key(admin_key): {
            "tenant_id": "tenant-hitl",
            "role": "admin",
            "subject": "counsel-admin",
        },
    }
    monkeypatch.setattr(settings, "auth_mode", "api_key")
    monkeypatch.setattr(settings, "auth_api_keys_json", json.dumps(api_keys))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Viewer blocked on POST /api/v1/hitl/reviews
        r_view = await client.post(
            "/api/v1/hitl/reviews",
            headers={"X-API-Key": viewer_key},
            json={
                "clause_id": "SEC-1.1",
                "decision": "ACCEPT_REDLINE",
                "original_clause_text": "SEC-1.1 Breach notice within 14 days.",
                "rationale": "Accept",
            },
        )
        assert r_view.status_code == 403

        # Auditor records ACCEPT_REDLINE, MODIFY_REDLINE, REJECT_FALSE_POSITIVE, ESCALATE_TO_COUNSEL with raw PII
        raw_nric = "900101-14-5678"
        raw_phone = "+6012-3456789"
        decisions = [
            (
                "ACCEPT_REDLINE",
                f"SEC-8.1 Processor bears zero statutory liability for NRIC {raw_nric}.",
                None,
                "CRITICAL",
                ["PDPA-2010-SEC-9-V2"],
            ),
            (
                "MODIFY_REDLINE",
                f"SEC-8.2 Breach notice within 14 days (Tel: {raw_phone}).",
                "SEC-8.2 Breach notice within 24 hours to Controller and 72 hours to Commissioner under Act 709 s. 12B.",
                "HIGH",
                ["PDPA-2010-SEC-12B-V1"],
            ),
            (
                "REJECT_FALSE_POSITIVE",
                "SEC-1.1 Data Processor shall implement ISO/IEC 27001 controls and notify within 24 hours under Section 9 and Section 12B.",
                None,
                "LOW",
                ["PDPA-2010-SEC-9-V2"],
            ),
            (
                "ESCALATE_TO_COUNSEL",
                "SEC-14.1 Notwithstanding Clause 5, sub-contractor liability is capped at RM100.",
                None,
                "CRITICAL",
                ["PDPA-2010-SEC-9-V2"],
            ),
        ]

        recorded_manifest_ids: list[str] = []
        for idx, (dec, orig, mod_txt, exp_risk, stat_ids) in enumerate(
            decisions, start=1
        ):
            resp = await client.post(
                "/api/v1/hitl/reviews",
                headers={"X-API-Key": auditor_key},
                json={
                    "audit_session_id": f"sess-hitl-{idx}",
                    "manifest_id": f"ATT-SRC-{idx}",
                    "document_id": f"HITL-DOC-{idx}",
                    "clause_id": f"SEC-{idx}",
                    "decision": dec,
                    "original_clause_text": orig,
                    "recommended_redline": "Compliant statutory text.",
                    "counsel_modified_text": mod_txt,
                    "rationale": f"Verified counsel note for {raw_nric} / {dec}",
                    "statutory_node_ids": stat_ids,
                    "regimes": ["ACT_709"],
                    "as_of_date": "2026-03-15",
                    "expected_overall_risk": exp_risk,
                },
            )
            assert resp.status_code == 200
            rec = resp.json()
            assert rec["decision"] == dec
            assert rec["reviewer_id"] == "counsel-auditor"
            assert raw_nric not in json.dumps(rec)
            assert raw_phone not in json.dumps(rec)
            recorded_manifest_ids.append(rec["attestation_manifest_id"])

        # Verify Ed25519 signature in AttestationLedger
        ver = default_attestation_ledger.verify(manifest_id=recorded_manifest_ids[0])
        assert ver.verified is True
        assert ver.signature_valid is True

        # Export JSONL RBAC -> admin ONLY
        assert (
            await client.get(
                "/api/v1/hitl/export-jsonl", headers={"X-API-Key": viewer_key}
            )
        ).status_code == 403
        assert (
            await client.get(
                "/api/v1/hitl/export-jsonl", headers={"X-API-Key": auditor_key}
            )
        ).status_code == 403

        exp_resp = await client.get(
            "/api/v1/hitl/export-jsonl", headers={"X-API-Key": admin_key}
        )
        assert exp_resp.status_code == 200
        jsonl_text = exp_resp.text
        assert raw_nric not in jsonl_text
        assert raw_phone not in jsonl_text
        lines = [ln for ln in jsonl_text.splitlines() if ln.strip()]
        assert len(lines) == 4

    # Write JSONL and ingest into evals/run_benchmark.py --extra-jsonl
    jsonl_path = tmp_path / "hitl_golden.jsonl"
    jsonl_path.write_text(jsonl_text, encoding="utf-8")
    extra_cases = load_extra_jsonl_cases(jsonl_path)
    assert len(extra_cases) == 4

    summary = await run_benchmark_async(mode="mock", trials=1, extra_jsonl=jsonl_path)
    assert summary.total_cases == 40
    assert summary.determinism_consistency_pct == 100.0
    assert summary.temporal_contamination_pct == 0.0


@pytest.mark.asyncio
async def test_mcp_record_hitl_review_tool_14():
    default_hitl_review_ledger.clear()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        tools_res = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert tools_res.status_code == 200
        tools = tools_res.json()["result"]["tools"]
        assert len(tools) == 14
        assert "record_hitl_review" in {t["name"] for t in tools}

        call_res = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "record_hitl_review",
                    "arguments": {
                        "tenant_id": "tenant-mcp-hitl",
                        "clause_id": "SEC-12B",
                        "decision": "ACCEPT_REDLINE",
                        "original_clause_text": "Notification within 14 days for NRIC 880505-01-1234.",
                        "rationale": "Enforce 72h Act 709 s. 12B notice window.",
                        "statutory_node_ids": ["PDPA-2010-SEC-12B-V1"],
                        "as_of_date": "2026-03-15",
                    },
                },
            },
        )
        assert call_res.status_code == 200
        sc = call_res.json()["result"]["structuredContent"]
        assert sc["decision"] == "ACCEPT_REDLINE"
        assert "880505-01-1234" not in sc["scrubbed_clause_text"]
        assert sc["pii_redaction_count"] >= 1


def test_demo_workbench_presets_and_hitl_controls():
    client = TestClient(app)
    for route in ("/", "/demo"):
        res = client.get(route)
        assert res.status_code == 200
        html = res.text
        assert "quickSampleScenarioBar" in html
        assert "1. Clean 2026 Malaysian SaaS MSA" in html
        assert "2. Oblique Cross-Border &amp; SLA Cascade Trap" in html
        assert "3. 2026 MyInvois &gt;RM10k &amp; SDSAS Stamp Duty Defect" in html
        assert "4. Adversarial Prompt-Injected Snippet" in html
        assert "submitHitlReview(" in html
        assert "/api/v1/hitl/reviews" in html
