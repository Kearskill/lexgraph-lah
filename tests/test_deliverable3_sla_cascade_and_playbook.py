from __future__ import annotations

import json
from datetime import date

import pytest
from httpx import ASGITransport, AsyncClient

from lexgraph_lah.compliance.sla_cascade import (
    compile_incident_playbook,
    verify_sla_cascade,
)
from lexgraph_lah.config import settings
from lexgraph_lah.main import app
from lexgraph_lah.schemas.domain import IncidentPlaybookRequest
from lexgraph_lah.security.attestation_ledger import AttestationLedger
from lexgraph_lah.security.auth import (
    default_api_key_registry,
    default_rate_limiter,
    hash_api_key,
)


def test_sla_cascade_all_roles_triage_buffer_and_bm_hari_bekerja():
    """
    Verifies sub-processor SLA cascade verifier across all 4 PartyRoles, impossible timelines,
    < 25% operational triage buffer breach, BM 'dalam tempoh 3 hari bekerja' parsing,
    compliant sub-processor window (0.25h), and bilingual EN/BM replacement redlines.
    """
    # 1. BNM Financial Institution: 48h vendor window breaches 1h BNM RMiT & 6h NACSA
    rep_fi = verify_sla_cascade(
        party_role="BNM_FINANCIAL_INSTITUTION",
        contract_text="Clause 7 Breach Notice: Vendor shall notify Client within 48 hours.",
        as_of_date=date(2026, 3, 15),
        regimes=["ACT_709", "ACT_854", "BNM_RMIT"],
    )
    assert rep_fi.cascade_breach_detected is True
    assert rep_fi.extracted_vendor_notice_hours == 48.0
    assert any(
        c.regime_id == "BNM_RMIT"
        and c.status == "SLA_CASCADE_BREACH"
        and c.deficit_hours > 0
        for c in rep_fi.checks
    )
    assert "BNM" in rep_fi.recommended_redline_en
    assert (
        "1 jam" in rep_fi.recommended_redline_bm
        or "minit" in rep_fi.recommended_redline_bm
    )
    assert rep_fi.telemetry.total_tokens == 0

    # 2. DATA_USER_CONTROLLER: 60h vendor notice vs 72h PDPA regulator leaves only 12h (< 25% of 72h = 18h)
    rep_buf = verify_sla_cascade(
        party_role="DATA_USER_CONTROLLER",
        contract_text="Clause 7 Breach Notice: Vendor shall notify Controller within 60 hours.",
        as_of_date=date(2026, 3, 15),
        regimes=["ACT_709"],
    )
    assert rep_buf.cascade_breach_detected is True
    pdp_chk = next(c for c in rep_buf.checks if c.regulator_deadline_hours == 72.0)
    assert pdp_chk.status == "SLA_CASCADE_BREACH"
    assert pdp_chk.slack_hours == 12.0
    assert pdp_chk.min_required_buffer_hours == 18.0
    assert "buffer" in (pdp_chk.breach_reason or "").lower()

    # 3. BM "dalam tempoh 3 hari bekerja" (72h) under NCII_ENTITY (vs 6h NACSA -> breach)
    rep_bm = verify_sla_cascade(
        party_role="NCII_ENTITY",
        contract_text="Klausa 8 Insiden Siber: Vendor wajib memaklumkan dalam tempoh 3 hari bekerja.",
        as_of_date=date(2026, 3, 15),
        regimes=["ACT_854", "ACT_709"],
    )
    assert rep_bm.is_business_days_window is True
    assert rep_bm.extracted_vendor_notice_hours == 72.0
    assert rep_bm.cascade_breach_detected is True

    # 4. PUBLIC_SECTOR_AGENCY_ACT_864 fast compliant window (15 minutes = 0.25h)
    rep_pub = verify_sla_cascade(
        party_role="PUBLIC_SECTOR_AGENCY_ACT_864",
        contract_text="Clause 7 Breach Notice: Processor shall notify within 15 minutes.",
        as_of_date=date(2026, 3, 15),
        regimes=["ACT_864", "ACT_709"],
    )
    assert rep_pub.extracted_vendor_notice_hours == 0.25
    assert rep_pub.cascade_breach_detected is False
    assert all(c.status == "COMPLIANT" for c in rep_pub.checks)


def test_incident_playbook_act388_s54_rollover_and_attestation():
    """
    Verifies chronological UTC + Asia/Kuala_Lumpur (+08:00) deadline milestones, Act 388 s. 54
    weekend rollover on day-based statutory periods, and Ed25519 attestation ledger verification.
    """
    ledger = AttestationLedger(":memory:")
    try:
        # 2026-03-08 is a Sunday -> +14 days lands on Sunday 2026-03-22 -> rolls to Monday 2026-03-23!
        playbook = compile_incident_playbook(
            IncidentPlaybookRequest(
                document_id="PLAY-S54-01",
                discovery_timestamp="2026-03-08T09:00:00+08:00",
                party_role="NCII_ENTITY",
                triggered_regimes=["ACT_854", "ACT_709"],
                as_of_date=date(2026, 3, 15),
                contract_text="Clause 5 Notice: Sub-processor notifies within 24 hours.",
            ),
            ledger=ledger,
            tenant_id="tenant-play",
        )
        assert playbook.telemetry.total_tokens == 0
        assert playbook.discovery_timestamp_myt.endswith("+08:00")
        assert len(playbook.sla_cascade_warnings) >= 1
        s54_milestones = [m for m in playbook.milestones if m.act_388_s54_applied]
        assert len(s54_milestones) >= 1
        rolled = [
            m
            for m in s54_milestones
            if m.act_388_s54_metadata
            and m.act_388_s54_metadata.get("rolled_from_weekly_holiday")
        ]
        assert len(rolled) >= 1
        assert playbook.attestation_manifest is not None
        ver = ledger.verify(manifest_id=playbook.attestation_manifest.manifest_id)
        assert ver.verified is True
    finally:
        ledger.close()


@pytest.mark.asyncio
async def test_incident_playbook_rest_mcp_and_rbac(monkeypatch: pytest.MonkeyPatch):
    """
    Verifies POST /api/v1/deontic/incident-playbook and MCP compile_incident_playbook
    with strict viewer=403 / auditor=200 RBAC enforcement.
    """
    default_api_key_registry.clear()
    default_rate_limiter.reset()

    viewer_key = "sla_viewer_01"
    auditor_key = "sla_auditor_02"
    keys = {
        hash_api_key(viewer_key): {
            "tenant_id": "tenant-sla",
            "role": "viewer",
            "subject": "v1",
        },
        hash_api_key(auditor_key): {
            "tenant_id": "tenant-sla",
            "role": "auditor",
            "subject": "a1",
        },
    }
    monkeypatch.setattr(settings, "env", "test")
    monkeypatch.setattr(settings, "auth_mode", "api_key")
    monkeypatch.setattr(settings, "auth_api_keys_json", json.dumps(keys))

    req_body = {
        "document_id": "PLAY-API-01",
        "discovery_timestamp": "2026-03-15T14:30:00Z",
        "party_role": "BNM_FINANCIAL_INSTITUTION",
        "triggered_regimes": ["ACT_709", "ACT_854", "BNM_RMIT"],
        "contract_text": "Clause 5 Breach: Sub-processor notifies within 48 hours.",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_view = await client.post(
            "/api/v1/deontic/incident-playbook",
            headers={"X-API-Key": viewer_key},
            json=req_body,
        )
        assert r_view.status_code == 403

        r_ok = await client.post(
            "/api/v1/deontic/incident-playbook",
            headers={"X-API-Key": auditor_key},
            json=req_body,
        )
        assert r_ok.status_code == 200
        data = r_ok.json()
        assert data["telemetry"]["total_tokens"] == 0
        assert data["discovery_timestamp_myt"].startswith("2026-03-15T22:30:00")
        assert len(data["sla_cascade_warnings"]) >= 1

        r_mcp = await client.post(
            "/mcp",
            headers={"X-API-Key": auditor_key},
            json={
                "jsonrpc": "2.0",
                "id": 77,
                "method": "tools/call",
                "params": {
                    "name": "compile_incident_playbook",
                    "arguments": req_body,
                },
            },
        )
        assert r_mcp.status_code == 200
        mcp_out = r_mcp.json()["result"]["structuredContent"]
        assert mcp_out["party_role"] == "BNM_FINANCIAL_INSTITUTION"
        assert len(mcp_out["milestones"]) >= 3
