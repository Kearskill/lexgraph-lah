from __future__ import annotations

import base64
import io
import json
import sqlite3
import zipfile
from datetime import date
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
from httpx import ASGITransport, AsyncClient

from lexgraph_lah.compliance.clause_cache import default_clause_cache
from lexgraph_lah.config import settings
from lexgraph_lah.graph.bilingual_critic import audit_bilingual_pair
from lexgraph_lah.graph.deontic_solver import DeonticEnvelopeResolver
from lexgraph_lah.graph.temporal_store import (
    build_pending_commencement_cypher,
    build_upsert_amendment_cypher,
    get_default_temporal_store,
)
from lexgraph_lah.hitl.precedent_playbook import (
    InMemoryPlaybookBackend,
    PostgresPlaybookBackend,
    PrecedentPlaybookStore,
    SQLitePlaybookBackend,
    default_precedent_playbook_store,
)
from lexgraph_lah.hitl.review_store import HITLReviewLedger, default_hitl_review_ledger
from lexgraph_lah.ingestion.contract_ast import build_contract_ast
from lexgraph_lah.ingestion.ooxml_redliner import inspect_ooxml_docx
from lexgraph_lah.main import app
from lexgraph_lah.middleware.pii_scrubber import (
    EncryptedPIISessionStore,
)
from lexgraph_lah.negotiation.counter_docx_compiler import compile_counter_redline_docx
from lexgraph_lah.negotiation.docx_redline_critic import (
    analyze_counterparty_docx_redlines,
)
from lexgraph_lah.schemas.domain import (
    PlaybookPromoteRequest,
    RiskSeverity,
    StatutoryStatus,
    TerritorialScope,
)
from lexgraph_lah.security.attestation_ledger import (
    AttestationLedger,
    default_attestation_ledger,
)
from lexgraph_lah.security.auth import hash_api_key
from lexgraph_lah.security.doc_firewall import ZipBombError
from lexgraph_lah.ui.render import render_workbench_html

_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _build_counterparty_redlined_docx() -> bytes:
    """Constructs a minimal valid `.docx` containing counterparty track-changes & PII."""
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body>"
        "<w:p>"
        '<w:r><w:t xml:space="preserve">SEC-9.1 Security Controls: </w:t></w:r>'
        '<w:ins w:id="10" w:author="Counterparty" w:date="2026-03-10T08:00:00Z">'
        '<w:r><w:t xml:space="preserve">Data Processor shall implement ISO/IEC 27001 controls and notify Data User within 24 hours.</w:t></w:r>'
        "</w:ins>"
        "</w:p>"
        "<w:p>"
        '<w:r><w:t xml:space="preserve">SEC-12B Breach Notice for NRIC 900101-14-5678 (TIN IG12345678900): </w:t></w:r>'
        '<w:del w:id="11" w:author="Counterparty" w:date="2026-03-10T08:05:00Z">'
        '<w:r><w:delText xml:space="preserve">Data Processor shall notify Controller within 24 hours under Act 709 s. 9.</w:delText></w:r>'
        "</w:del>"
        '<w:ins w:id="12" w:author="Counterparty" w:date="2026-03-10T08:05:00Z">'
        '<w:r><w:t xml:space="preserve">Vendor may notify within 14 days and bears zero statutory liability.</w:t></w:r>'
        "</w:ins>"
        "</w:p>"
        "<w:sectPr/></w:body></w:document>"
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
        zf.writestr("word/document.xml", document_xml)
    return buf.getvalue()


class _SqlitePgShimConnection:
    """Translates PostgreSQL `%s` placeholders + ON CONFLICT syntax cleanly for unit tests."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def cursor(self) -> _SqlitePgShimCursor:
        return _SqlitePgShimCursor(self._conn.cursor())

    def commit(self) -> None:
        self._conn.commit()


class _SqlitePgShimCursor:
    def __init__(self, cur: sqlite3.Cursor) -> None:
        self._cur = cur

    @property
    def rowcount(self) -> int:
        return self._cur.rowcount

    def execute(self, query: str, params: tuple[object, ...] = ()) -> None:
        translated = query.replace("%s", "?").replace("EXCLUDED.", "excluded.")
        self._cur.execute(translated, params)

    def fetchall(self) -> list[tuple[object, ...]]:
        return self._cur.fetchall()

    def fetchone(self) -> tuple[object, ...] | None:
        return self._cur.fetchone()


def test_counter_docx_compiler_in_place_ooxml_pii_playbook_and_zip_safety():
    store = get_default_temporal_store()
    ledger = AttestationLedger(":memory:")
    pii_store = EncryptedPIISessionStore(backend="memory")
    pb_store = PrecedentPlaybookStore(
        backend=InMemoryPlaybookBackend(),
        store=store,
        attestation_ledger=ledger,
    )

    # Seed Tenant A approved Playbook fallback for breach notice
    pb_store.promote_rule(
        tenant_id="tenant-a",
        request=PlaybookPromoteRequest(
            original_clause_text="SEC-12B Breach Notice: Vendor may notify within 14 days and bears zero statutory liability.",
            tier_1_preferred="Data Processor shall notify Controller within 24 hours and notify Commissioner within 72 hours under Act 709 s. 12B.",
            tier_2_fallback="Data Processor shall notify Controller within 48 hours and preserve Commissioner 72h notification under PDPA Act 709 s. 9 & s. 12B.",
            regimes=["ACT_709"],
            as_of_date=date(2026, 3, 15),
            rationale="House standard PDPA 72h compliance.",
        ),
        actor_id="counsel-a",
        actor_role="auditor",
    )

    docx_bytes = _build_counterparty_redlined_docx()
    diff = analyze_counterparty_docx_redlines(
        document_id="NEG-ROUNDTRIP-01",
        docx_bytes=docx_bytes,
        filename="counterparty_turn.docx",
        as_of_date=date(2026, 3, 15),
        regimes=["ACT_709"],
        tenant_id="tenant-a",
        audit_session_id="sess-roundtrip-a",
        store=store,
        ledger=ledger,
        pii_store=pii_store,
    )
    assert diff.regression_count >= 1
    assert diff.compliant_accept_count >= 1

    out_bytes, compile_res = compile_counter_redline_docx(
        document_id="NEG-ROUNDTRIP-01",
        docx_bytes=docx_bytes,
        filename="counterparty_turn.docx",
        diff=diff,
        counsel_author="LexGraph Counsel",
        counsel_initials="LGC",
        as_of_date=date(2026, 3, 15),
        regimes=["ACT_709"],
        tenant_id="tenant-a",
        audit_session_id="sess-roundtrip-a",
        rehydrate_pii=True,
        use_tenant_playbook=True,
        preferred_playbook_tier="TIER_2_FALLBACK",
        store=store,
        ledger=ledger,
        pii_store=pii_store,
        playbook_store=pb_store,
    )

    assert compile_res.in_place_ooxml_mutation is True
    assert compile_res.accepted_count >= 1
    assert compile_res.counter_proposed_count >= 1
    assert compile_res.comments_appended >= 1
    assert compile_res.rehydrated_pii_count >= 2
    assert compile_res.telemetry.total_tokens == 0
    assert compile_res.telemetry.estimated_cost_usd == 0.0
    assert compile_res.attestation_manifest is not None
    assert compile_res.attestation_manifest.signature_b64

    verify_res = ledger.verify(manifest=compile_res.attestation_manifest)
    assert verify_res.status == "VERIFIED"
    assert verify_res.signature_valid is True

    inspected = inspect_ooxml_docx(out_bytes)
    assert inspected["track_revisions_enabled"] is True
    assert any(d["author"] == "LexGraph Counsel" for d in inspected["deletions"])
    assert any(
        i["author"] == "LexGraph Counsel"
        and "48 hours" in i["text"]
        and "72h" in i["text"]
        for i in inspected["insertions"]
    )
    assert any(
        "900101-14-5678" in d["text"] and "IG12345678900" in d["text"]
        for d in inspected["deletions"]
    )
    assert any(
        c["author"] == "LexGraph Counsel" and "Act 709" in c["text"]
        for c in inspected["comments"]
    )

    with zipfile.ZipFile(io.BytesIO(out_bytes), "r") as zf:
        assert "word/comments.xml" in zf.namelist()
        ct_xml = zf.read("[Content_Types].xml").decode("utf-8")
        rels_xml = zf.read("word/_rels/document.xml.rels").decode("utf-8")
        doc_root = ET.fromstring(zf.read("word/document.xml"))
    assert "/word/comments.xml" in ct_xml
    assert "comments.xml" in rels_xml
    assert len(list(doc_root.iter(f"{{{_W_NS}}}commentRangeStart"))) >= 1
    assert len(list(doc_root.iter(f"{{{_W_NS}}}commentRangeEnd"))) >= 1
    assert len(list(doc_root.iter(f"{{{_W_NS}}}commentReference"))) >= 1

    # Cross-tenant session isolation: tenant-b MUST NOT rehydrate tenant-a PII
    _, cross_res = compile_counter_redline_docx(
        document_id="NEG-CROSS-TENANT",
        diff=diff,
        as_of_date=date(2026, 3, 15),
        regimes=["ACT_709"],
        tenant_id="tenant-b",
        audit_session_id="sess-roundtrip-a",
        rehydrate_pii=True,
        store=store,
        ledger=ledger,
        pii_store=pii_store,
        playbook_store=pb_store,
    )
    assert cross_res.rehydrated_pii_count == 0

    # Zip-bomb guard must still execute before XML mutation
    bomb_buf = io.BytesIO()
    with zipfile.ZipFile(bomb_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", b"<w:p/>" * 90_000)
    with pytest.raises(ZipBombError):
        compile_counter_redline_docx(
            document_id="NEG-BOMB",
            docx_bytes=bomb_buf.getvalue(),
            tenant_id="tenant-a",
            store=store,
        )


@pytest.mark.asyncio
async def test_counter_docx_rest_multipart_json_docx_and_mcp_tool_15(
    monkeypatch: pytest.MonkeyPatch,
):
    default_attestation_ledger.clear()
    viewer_key = "lg_p7_viewer"
    auditor_key = "lg_p7_auditor"
    tenant_b_key = "lg_p7_tenant_b"
    api_keys = {
        hash_api_key(viewer_key): {
            "tenant_id": "tenant-p7",
            "role": "viewer",
            "subject": "p7-viewer",
        },
        hash_api_key(auditor_key): {
            "tenant_id": "tenant-p7",
            "role": "auditor",
            "subject": "p7-auditor",
        },
        hash_api_key(tenant_b_key): {
            "tenant_id": "tenant-p7-other",
            "role": "auditor",
            "subject": "p7-other",
        },
    }
    monkeypatch.setattr(settings, "auth_mode", "api_key")
    monkeypatch.setattr(settings, "auth_api_keys_json", json.dumps(api_keys))

    docx_bytes = _build_counterparty_redlined_docx()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Viewer blocked on compile endpoint
        r_view = await client.post(
            "/api/v1/negotiation/compile-counter-docx",
            headers={"X-API-Key": viewer_key},
            json={
                "baseline_text": "SEC-1 Notify within 24h.",
                "proposed_text": "SEC-1 Notify within 14 days.",
            },
        )
        assert r_view.status_code == 403

        # 2. Multipart diff upload -> stores session under tenant-p7
        r_diff = await client.post(
            "/api/v1/negotiation/diff-docx",
            headers={"X-API-Key": auditor_key},
            files={
                "file": (
                    "counter.docx",
                    docx_bytes,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            },
            data={"document_id": "REST-P7-DOC", "as_of_date": "2026-03-15"},
        )
        assert r_diff.status_code == 200
        sess_id = r_diff.json()["audit_session_id"]
        deltas = r_diff.json()["clause_deltas"]
        assert sess_id and deltas

        # 3. Tenant B cannot access Tenant A's audit_session_id (404 fail-closed)
        r_cross = await client.post(
            "/api/v1/negotiation/compile-counter-docx",
            headers={"X-API-Key": tenant_b_key},
            json={"audit_session_id": sess_id},
        )
        assert r_cross.status_code == 404

        # 4. Compile via session ID returning binary .docx stream
        target_cid = deltas[-1]["clause_id"]
        r_bin = await client.post(
            "/api/v1/negotiation/compile-counter-docx?response_format=docx",
            headers={"X-API-Key": auditor_key},
            json={
                "document_id": "REST-P7-DOC",
                "audit_session_id": sess_id,
                "dispositions": {target_cid: "REJECT_REVERT_BASELINE"},
                "as_of_date": "2026-03-15",
            },
        )
        assert r_bin.status_code == 200
        assert (
            r_bin.headers["content-type"]
            == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        assert r_bin.headers["x-total-tokens"] == "0"
        assert int(r_bin.headers["x-rehydrated-pii-count"]) >= 1
        parsed_out = inspect_ooxml_docx(r_bin.content)
        assert parsed_out["track_revisions_enabled"] is True
        assert any(i["author"] == "LexGraph Counsel" for i in parsed_out["insertions"])

        # 5. MCP tool 15: tools/list & tools/call compile_counter_redline_docx
        r_list = await client.post(
            "/mcp",
            headers={"X-API-Key": auditor_key},
            json={"jsonrpc": "2.0", "id": 10, "method": "tools/list"},
        )
        assert r_list.status_code == 200
        tools = r_list.json()["result"]["tools"]
        assert len(tools) == 15
        assert "compile_counter_redline_docx" in {t["name"] for t in tools}

        r_call = await client.post(
            "/mcp",
            headers={"X-API-Key": auditor_key},
            json={
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "compile_counter_redline_docx",
                    "arguments": {
                        "document_id": "MCP-COUNTER-01",
                        "docx_base64": base64.b64encode(docx_bytes).decode("ascii"),
                        "as_of_date": "2026-03-15",
                        "regimes": ["ACT_709"],
                    },
                },
            },
        )
        assert r_call.status_code == 200
        mcp_out = r_call.json()["result"]["structuredContent"]
        assert mcp_out["telemetry"]["total_tokens"] == 0
        assert mcp_out["comments_appended"] >= 1
        mcp_docx_bytes = base64.b64decode(mcp_out["docx_base64"])
        assert len(inspect_ooxml_docx(mcp_docx_bytes)["comments"]) >= 1


@pytest.mark.asyncio
async def test_precedent_playbook_backends_422_guard_admin_waiver_and_cache_bust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = get_default_temporal_store()
    ledger = AttestationLedger(":memory:")
    rev_ledger = HITLReviewLedger(tmp_path / "hitl_p7.db")

    # 1. Verify Memory, SQLite & Postgres backends parity
    sqlite_pb = SQLitePlaybookBackend(tmp_path / "playbook.db")
    pg_conn = sqlite3.connect(":memory:", check_same_thread=False)
    pg_pb = PostgresPlaybookBackend(
        "postgresql://localhost/mock",
        connection_factory=lambda: _SqlitePgShimConnection(pg_conn),
    )

    for backend in (InMemoryPlaybookBackend(), sqlite_pb, pg_pb):
        pb = PrecedentPlaybookStore(
            backend=backend,
            review_ledger=rev_ledger,
            store=store,
            attestation_ledger=ledger,
        )
        r = pb.promote_rule(
            tenant_id="tenant-sql",
            request=PlaybookPromoteRequest(
                original_clause_text="Notify breach within 14 days.",
                tier_1_preferred="Notify Commissioner within 72 hours.",
                regimes=["ACT_709"],
                as_of_date=date(2026, 3, 15),
            ),
            actor_id="aud",
            actor_role="auditor",
        )
        assert pb.list_rules(tenant_id="tenant-sql").total == 1
        assert pb.list_rules(tenant_id="tenant-other").total == 0
        assert r.ast_fingerprint

    # 2. REST E2E: auditor 422 block (MODIFY_REDLINE & REJECT_FALSE_POSITIVE),
    # admin statutory_risk_waiver recorded in AttestationLedger, & per-tenant ClauseASTCache bust
    default_hitl_review_ledger.clear()
    default_attestation_ledger.clear()
    default_clause_cache.clear()
    default_precedent_playbook_store._backend.delete_tenant_rules(tenant_id="tenant-a")
    default_precedent_playbook_store._backend.delete_tenant_rules(tenant_id="tenant-b")

    viewer_b_key = "lg_pb_viewer_b"
    auditor_a_key = "lg_pb_aud_a"
    auditor_b_key = "lg_pb_aud_b"
    admin_a_key = "lg_pb_admin_a"
    api_keys = {
        hash_api_key(viewer_b_key): {
            "tenant_id": "tenant-b",
            "role": "viewer",
            "subject": "b-viewer",
        },
        hash_api_key(auditor_a_key): {
            "tenant_id": "tenant-a",
            "role": "auditor",
            "subject": "a-auditor",
        },
        hash_api_key(auditor_b_key): {
            "tenant_id": "tenant-b",
            "role": "auditor",
            "subject": "b-auditor",
        },
        hash_api_key(admin_a_key): {
            "tenant_id": "tenant-a",
            "role": "admin",
            "subject": "a-admin",
        },
    }
    monkeypatch.setattr(settings, "auth_mode", "api_key")
    monkeypatch.setattr(settings, "auth_api_keys_json", json.dumps(api_keys))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Record a MODIFY_REDLINE review that still has a weak 14-day breach SLA
        r_mod = await client.post(
            "/api/v1/hitl/reviews",
            headers={"X-API-Key": auditor_a_key},
            json={
                "document_id": "PB-DOC-1",
                "clause_id": "SEC-12B",
                "decision": "MODIFY_REDLINE",
                "original_clause_text": "SEC-12B Breach Notice: Vendor notifies within 14 days.",
                "recommended_redline": "Notify within 72 hours.",
                "counsel_modified_text": "Vendor shall notify Controller within 14 days of confirmation.",
                "rationale": "Commercial pushback.",
                "statutory_node_ids": ["PDPA-2010-SEC-12B-V1"],
                "regimes": ["ACT_709"],
                "as_of_date": "2026-03-15",
            },
        )
        assert r_mod.status_code == 200
        mod_review_id = r_mod.json()["review_id"]

        # Record a REJECT_FALSE_POSITIVE review on a 14-day notice under BNM RMiT 1h
        r_rej = await client.post(
            "/api/v1/hitl/reviews",
            headers={"X-API-Key": auditor_a_key},
            json={
                "document_id": "PB-DOC-2",
                "clause_id": "SEC-1",
                "decision": "REJECT_FALSE_POSITIVE",
                "original_clause_text": "SEC-1 Cyber incident notification within 14 days.",
                "rationale": "Claimed false positive.",
                "statutory_node_ids": ["BNM-RMIT-INCIDENT-V1"],
                "regimes": ["BNM_RMIT"],
                "as_of_date": "2026-03-15",
            },
        )
        assert r_rej.status_code == 200
        rej_review_id = r_rej.json()["review_id"]

        # Promoting weak MODIFY_REDLINE as auditor -> 422 STATUTORY_FLOOR_VIOLATION
        r_block_1 = await client.post(
            "/api/v1/hitl/playbook/promote",
            headers={"X-API-Key": auditor_a_key},
            json={
                "review_id": mod_review_id,
                "statutory_risk_waiver": True,
                "waiver_rationale": "Auditor cannot waive!",
            },
        )
        assert r_block_1.status_code == 422
        assert r_block_1.json()["detail"]["error_code"] == "STATUTORY_FLOOR_VIOLATION"

        # Promoting weak REJECT_FALSE_POSITIVE as auditor under BNM RMiT 1h -> 422
        r_block_2 = await client.post(
            "/api/v1/hitl/playbook/promote",
            headers={"X-API-Key": auditor_a_key},
            json={"review_id": rej_review_id},
        )
        assert r_block_2.status_code == 422
        assert r_block_2.json()["detail"]["error_code"] == "STATUTORY_FLOOR_VIOLATION"
        assert r_block_2.json()["detail"]["statutory_floor_value"] == 1.0

        # Cross-tenant review promotion blocked with 404
        r_cross_rev = await client.post(
            "/api/v1/hitl/playbook/promote",
            headers={"X-API-Key": auditor_b_key},
            json={"review_id": mod_review_id, "tier_1_preferred": "Notify within 24h."},
        )
        assert r_cross_rev.status_code == 404

        # Prime ClauseASTCache for BOTH tenant-a and tenant-b before playbook change
        audit_payload = {
            "document_id": "CACHE-PB-01",
            "raw_text": "SEC-12B Breach Notice: Data Processor shall notify Client of any personal data breach within 14 days.",
            "reference_date": "2026-03-15",
            "regimes": ["ACT_709"],
        }
        a1 = await client.post(
            "/compliance/check",
            headers={"X-API-Key": auditor_a_key},
            json=audit_payload,
        )
        b1 = await client.post(
            "/compliance/check",
            headers={"X-API-Key": auditor_b_key},
            json=audit_payload,
        )
        assert a1.status_code == 200 and b1.status_code == 200

        # Promote compliant Tenant A house rule
        r_ok = await client.post(
            "/api/v1/hitl/playbook/promote",
            headers={"X-API-Key": auditor_a_key},
            json={
                "original_clause_text": audit_payload["raw_text"],
                "tier_1_preferred": "Data Processor shall notify Controller within 12 hours of breach discovery.",
                "tier_2_fallback": "Data Processor shall notify Controller within 24 hours and Commissioner within 72 hours under PDPA s. 12B.",
                "regimes": ["ACT_709"],
                "as_of_date": "2026-03-15",
                "rationale": "Standard house SLA.",
            },
        )
        assert r_ok.status_code == 200
        promoted_rule_id = r_ok.json()["rule_id"]

        # Tenant A cache MUST bust & apply playbook rule; Tenant B MUST stay cached with 0 rules
        a2 = await client.post(
            "/compliance/check",
            headers={"X-API-Key": auditor_a_key},
            json=audit_payload,
        )
        b2 = await client.post(
            "/compliance/check",
            headers={"X-API-Key": auditor_b_key},
            json=audit_payload,
        )
        assert a2.json()["telemetry"]["cache_hit"] is False
        assert any(
            f.get("playbook_rule_id") == promoted_rule_id for f in a2.json()["findings"]
        )
        assert b2.json()["telemetry"]["cache_hit"] is True
        assert all(f.get("playbook_rule_id") is None for f in b2.json()["findings"])

        # Viewer GET /api/v1/hitl/playbook on tenant-b sees 0 rules
        r_list_b = await client.get(
            "/api/v1/hitl/playbook", headers={"X-API-Key": viewer_b_key}
        )
        assert r_list_b.status_code == 200
        assert r_list_b.json()["total"] == 0

        # Admin explicitly waives statutory floor -> succeeds & logs STATUTORY_RISK_WAIVER in Ed25519 ledger
        r_waiver = await client.post(
            "/api/v1/hitl/playbook/promote",
            headers={"X-API-Key": admin_a_key},
            json={
                "review_id": mod_review_id,
                "statutory_risk_waiver": True,
                "waiver_rationale": "Board Risk Committee exception WVR-2026-09 during 30-day transition.",
            },
        )
        assert r_waiver.status_code == 200
        waiver_data = r_waiver.json()
        assert waiver_data["statutory_risk_waiver"] is True
        assert waiver_data["waiver_attestation_manifest_id"]
        waiver_rec = default_attestation_ledger.get(
            waiver_data["waiver_attestation_manifest_id"]
        )
        assert waiver_rec is not None
        assert "STATUTORY_RISK_WAIVER" in waiver_rec.document_id


@pytest.mark.asyncio
async def test_act872_gig_workers_and_act882_pre_commencement_statutes():
    store = get_default_temporal_store()
    resolver = DeonticEnvelopeResolver(store)

    # 1. Verify Act 388 bilingual alignment on all seeded Act 872 and Act 882 pairs
    for nid in (
        "ACT-872-SEC-4-V1",
        "ACT-872-SEC-12-V1",
        "ACT-872-SEC-25-V1",
        "ACT-872-SEC-38-V1",
        "ACT-882-SEC-28-V1",
        "ACT-882-SEC-45-V1",
    ):
        en_node = store.nodes[nid]
        bm_node = store.nodes[en_node.translation_node_id or ""]
        div = audit_bilingual_pair(en_node, bm_node)
        assert div.has_divergence is False, (
            f"Unexpected Act 388 divergence on {nid}: {div.issues}"
        )

    # 2. Act 882 temporal lifecycle boundaries
    assert (
        store.nodes["ACT-882-SEC-28-V1"].status
        == StatutoryStatus.GAZETTED_PENDING_COMMENCEMENT
    )
    env_pre_gazette = resolver.resolve(
        regimes=["ACT_882"],
        as_of_date=date(2026, 4, 1),
        territorial_scope=TerritorialScope.ALL_MALAYSIA,
    )
    assert "ACT-882-SEC-28-V1" not in env_pre_gazette.active_node_ids
    assert "ACT-882-SEC-28-V1" not in env_pre_gazette.pending_commencement_node_ids

    env_pending = resolver.resolve(
        regimes=["ACT_872", "ACT_882", "ACT_864"],
        as_of_date=date(2026, 6, 15),
        territorial_scope=TerritorialScope.ALL_MALAYSIA,
    )
    assert "ACT-872-SEC-4-V1" in env_pending.active_node_ids
    assert "ACT-882-SEC-28-V1" not in env_pending.active_node_ids
    assert "ACT-882-SEC-28-V1" in env_pending.pending_commencement_node_ids
    assert "ACT-882-SEC-45-V1" in env_pending.pending_commencement_node_ids
    adv_sub = env_pending.pre_commencement_advisories[
        "gov_procurement_unauthorized_subcontract_prohibited"
    ]
    assert adv_sub.modality == "PRE_COMMENCEMENT_ADVISORY"

    env_commenced = resolver.resolve(
        regimes=["ACT_882", "ACT_864"],
        as_of_date=date(2027, 2, 1),
        territorial_scope=TerritorialScope.ALL_MALAYSIA,
    )
    assert "ACT-882-SEC-28-V1" in env_commenced.active_node_ids
    assert "ACT-882-SEC-45-V1" in env_commenced.active_node_ids
    assert not env_commenced.pending_commencement_node_ids

    # 3. End-to-end API audit on 2026-06-15 surfaces all 4 Act 872 traps & Act 882 PRE_COMMENCEMENT_ADVISORY
    transport = ASGITransport(app=app)
    contract_text = (
        "SEC-1 Gig Engagement: Gig worker engagement has no written service schedule and "
        "permits unilateral algorithmic deactivation without notice. "
        "SEC-2 Dispute & PERKESO: Gig worker agrees to waive Gig Workers Tribunal recourse "
        "and contract operates with no PERKESO deduction. "
        "SEC-3 Government Procurement: Vendor may sub-contract procurement obligations without approval "
        "of procuring authority and waives Procurement Appeal Tribunal recourse."
    )
    ast_graph, _ = build_contract_ast(
        document_id="A872-882-AST", raw_text=contract_text
    )
    assert any(
        c.extracted_metrics.get("gig_perkeso_omitted") for c in ast_graph.clauses
    )

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_audit = await client.post(
            "/compliance/check?use_cache=false",
            json={
                "document_id": "ACT872-882-E2E",
                "raw_text": contract_text,
                "reference_date": "2026-06-15",
                "regimes": ["ACT_872", "ACT_882", "ACT_864"],
            },
        )
        assert r_audit.status_code == 200
        body = r_audit.json()
        assert body["overall_risk"] == RiskSeverity.CRITICAL.value
        findings = body["findings"]
        gig_cats = [f for f in findings if "Gig Workers Act" in f["category"]]
        adv_cats = [f for f in findings if f.get("is_pre_commencement_advisory")]
        assert len(gig_cats) == 4
        assert len(adv_cats) == 2
        assert all(
            f["deontic_modality"] == "PRE_COMMENCEMENT_ADVISORY" for f in adv_cats
        )
        assert any("ACT-864-SEC-17-V1" in f["violated_statute_ids"] for f in adv_cats)

    # 4. Neo4j Cypher parity
    pending_cypher = build_pending_commencement_cypher(
        as_of_date=date(2026, 6, 15),
        territorial_scope=TerritorialScope.ALL_MALAYSIA,
    )
    assert "GAZETTED_PENDING_COMMENCEMENT" in pending_cypher.query
    upsert_cypher = build_upsert_amendment_cypher(
        new_node=store.nodes["ACT-882-SEC-28-V1"]
    )
    assert "gazette_date" in upsert_cypher.params


def test_legal_workbench_ui_phase7_closure_and_anti_vibe_compliance():
    html = render_workbench_html("audit")

    # Phase 7 Workbench controls present
    for marker in (
        "Promote to House Playbook",
        "Compile Counter-Markup .docx",
        "Hybrid Retrieval Scores",
        "Dead-Letter Queue (DLQ)",
        "Tenant Precedent Playbook (3-Tier)",
        'data-regime="ACT_872"',
        'data-regime="ACT_882"',
        "PRE_COMMENCEMENT_ADVISORY",
        "Practitioner Mode (IRAC)",
        "Rakyat Literacy (gov.my)",
        "ENGLISH (Section)",
        "BAHASA MELAYU (Seksyen)",
    ):
        assert marker in html

    # Strict anti-vibe CSS/UI guardrails: no purple palette, no linear gradients, no emojis
    lowered = html.lower()
    for forbidden in ("#7c3aed", "#8b5cf6", "#a855f7", "#9333ea", "linear-gradient("):
        assert forbidden not in lowered

    for ch in html:
        cp = ord(ch)
        assert not (0x1F300 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF), (
            f"Emoji codepoint U+{cp:04X} disallowed in Institutional Legal Workbench UI."
        )
