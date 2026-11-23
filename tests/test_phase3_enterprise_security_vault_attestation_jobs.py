from __future__ import annotations

import base64
import hashlib
import io
import json
import sqlite3
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any, Self

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from httpx import ASGITransport, AsyncClient

from lexgraph_lah.config import settings
from lexgraph_lah.ingestion.contract_ast import extract_docx_structured
from lexgraph_lah.ingestion.ooxml_redliner import inspect_ooxml_docx
from lexgraph_lah.main import app
from lexgraph_lah.middleware.pii_scrubber import EncryptedPIISessionStore
from lexgraph_lah.schemas.domain import ComplianceAttestationManifest
from lexgraph_lah.security.attestation_ledger import (
    AttestationLedger,
    PostgresAttestationBackend,
    build_chain_tip_signing_message,
    compute_manifest_sha256,
)
from lexgraph_lah.security.auth import (
    create_jwt_token,
    default_api_key_registry,
    default_rate_limiter,
    hash_api_key,
)
from lexgraph_lah.security.doc_firewall import (
    ZipBombError,
    sanitize_docx_bytes,
    scan_document_security,
)


def _make_clean_docx(text: str) -> bytes:
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
        f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", doc_xml.encode("utf-8"))
    return buf.getvalue()


def _make_clean_pdf(text: str) -> bytes:
    esc = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream_body = f"BT /F1 12 Tf 72 720 Td ({esc}) Tj ET".encode("latin-1")
    comp = zlib.compress(stream_body)
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Length "
        + str(len(comp)).encode("ascii")
        + b" /Filter /FlateDecode >>\nstream\n"
        + comp
        + b"\nendstream\nendobj\n%%EOF\n"
    )


@pytest.mark.asyncio
async def test_enterprise_auth_jwt_api_key_rbac_tenant_isolation_and_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Verifies:
      1. Production fail-closed guard (`ENV=production` + `AUTH_MODE=disabled` -> 503).
      2. SHA-256 API-key AuthN (`AUTH_MODE=api_key`), RBAC (`viewer` vs `auditor`) across
         REST, SSE `/compliance/stream`, and `POST /mcp`, plus cross-tenant spoofing rejection (403).
      3. HS256 and EdDSA JWT verification (`AUTH_MODE=jwt`), expired / `alg=none` rejection.
      4. Sliding-window rate limiter returning HTTP 429 with `Retry-After`.
    """
    default_api_key_registry.clear()
    default_rate_limiter.reset()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Fail-closed guard when ENV=production and AUTH_MODE=disabled
        monkeypatch.setattr(settings, "env", "production")
        monkeypatch.setattr(settings, "auth_mode", "disabled")
        res_health = await client.get("/health")
        assert res_health.status_code == 200
        res_fail_closed = await client.get("/graph/nodes")
        assert res_fail_closed.status_code == 503

        # 2. API Key AuthN + RBAC
        monkeypatch.setattr(settings, "env", "test")
        viewer_key = "lg_viewer_secret_001"
        auditor_key = "lg_auditor_secret_002"
        api_keys_map = {
            hash_api_key(viewer_key): {
                "tenant_id": "tenant-alpha",
                "role": "viewer",
                "subject": "alice-viewer",
            },
            hash_api_key(auditor_key): {
                "tenant_id": "tenant-alpha",
                "role": "auditor",
                "subject": "bob-auditor",
            },
        }
        monkeypatch.setattr(settings, "auth_mode", "api_key")
        monkeypatch.setattr(settings, "auth_api_keys_json", json.dumps(api_keys_map))

        # Unauthenticated / invalid key -> 401
        assert (await client.get("/graph/nodes")).status_code == 401
        assert (
            await client.get("/graph/nodes", headers={"X-API-Key": "wrong-key"})
        ).status_code == 401

        # Public key endpoint stays publicly readable
        assert (await client.get("/api/v1/attestation/public-key")).status_code == 200

        # Viewer allowed GET + verify POST + MCP tools/list, blocked on mutating /compliance/check & MCP tools/call
        r_view_get = await client.get("/graph/nodes", headers={"X-API-Key": viewer_key})
        assert r_view_get.status_code == 200
        assert r_view_get.headers["x-tenant-id"] == "tenant-alpha"

        r_view_verify = await client.post(
            "/api/v1/attestation/verify",
            headers={"X-API-Key": viewer_key},
            json={"manifest_id": "ATT-NONEXISTENT"},
        )
        assert r_view_verify.status_code == 200

        r_view_write = await client.post(
            "/compliance/check",
            headers={"X-API-Key": viewer_key},
            json={
                "document_id": "RBAC-DENY",
                "raw_text": "SEC-1 Data Processor bears zero liability.",
            },
        )
        assert r_view_write.status_code == 403

        r_mcp_list = await client.post(
            "/mcp",
            headers={"X-API-Key": viewer_key},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert r_mcp_list.status_code == 200
        assert len(r_mcp_list.json()["result"]["tools"]) == 14

        r_mcp_call_denied = await client.post(
            "/mcp",
            headers={"X-API-Key": viewer_key},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "scrub_malaysian_pii",
                    "arguments": {"text": "test"},
                },
            },
        )
        assert r_mcp_call_denied.status_code == 403

        # Cross-tenant header spoofing rejected
        r_spoof = await client.get(
            "/graph/nodes",
            headers={"X-API-Key": auditor_key, "X-Tenant-ID": "tenant-beta"},
        )
        assert r_spoof.status_code == 403

        # Auditor allowed SSE stream + MCP tools/call
        r_sse = await client.post(
            "/compliance/stream",
            headers={"Authorization": f"Bearer {auditor_key}"},
            json={
                "document_id": "AUTH-SSE-01",
                "raw_text": "SEC-1 Data Processor liability waived and notice within 10 days.",
                "as_of_date": "2026-03-15",
                "regimes": ["ACT_709"],
            },
        )
        assert r_sse.status_code == 200
        assert "event: complete" in r_sse.text

        # 3. JWT AuthN (HS256 + EdDSA + negative cases)
        monkeypatch.setattr(settings, "auth_mode", "jwt")
        monkeypatch.setattr(settings, "jwt_secret", "super-secret-jwt-key-123")
        hs_tok = create_jwt_token(
            {"sub": "jwt-user", "tenant_id": "tenant-jwt", "role": "auditor"},
            secret="super-secret-jwt-key-123",
            algorithm="HS256",
        )
        r_jwt_ok = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {hs_tok}"},
            json={
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "scrub_malaysian_pii",
                    "arguments": {"text": "NRIC 900101-14-5678"},
                },
            },
        )
        assert r_jwt_ok.status_code == 200
        assert r_jwt_ok.headers["x-tenant-id"] == "tenant-jwt"

        # Expired token -> 401
        exp_tok = create_jwt_token(
            {"sub": "exp", "tenant_id": "tenant-jwt", "role": "auditor"},
            secret="super-secret-jwt-key-123",
            algorithm="HS256",
            expires_in_seconds=-10,
        )
        assert (
            await client.get(
                "/graph/nodes", headers={"Authorization": f"Bearer {exp_tok}"}
            )
        ).status_code == 401

        # "alg=none" attack token -> 401
        none_hdr = (
            base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}')
            .rstrip(b"=")
            .decode()
        )
        none_pl = (
            base64.urlsafe_b64encode(b'{"tenant_id":"tenant-jwt","role":"admin"}')
            .rstrip(b"=")
            .decode()
        )
        assert (
            await client.get(
                "/graph/nodes",
                headers={"Authorization": f"Bearer {none_hdr}.{none_pl}."},
            )
        ).status_code == 401

        # EdDSA JWT verification
        ed_priv = Ed25519PrivateKey.generate()
        ed_priv_pem = ed_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
        ed_pub_pem = (
            ed_priv.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )
        monkeypatch.setattr(settings, "jwt_public_key_pem", ed_pub_pem)
        ed_tok = create_jwt_token(
            {"sub": "ed-user", "tenant_id": "tenant-ed", "role": "auditor"},
            private_key_pem=ed_priv_pem,
            algorithm="EdDSA",
        )
        r_ed = await client.get(
            "/graph/nodes", headers={"Authorization": f"Bearer {ed_tok}"}
        )
        assert r_ed.status_code == 200
        assert r_ed.headers["x-tenant-id"] == "tenant-ed"

        # 4. Sliding-window rate limiter -> 429 on 4th request
        default_rate_limiter.reset()
        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        monkeypatch.setattr(settings, "rate_limit_rpm", 3)
        monkeypatch.setattr(settings, "rate_limit_window_seconds", 60)
        for _ in range(3):
            ok_r = await client.get(
                "/graph/nodes", headers={"Authorization": f"Bearer {ed_tok}"}
            )
            assert ok_r.status_code == 200
        limited = await client.get(
            "/graph/nodes", headers={"Authorization": f"Bearer {ed_tok}"}
        )
        assert limited.status_code == 429
        assert "retry-after" in limited.headers
        assert limited.headers["x-ratelimit-remaining"] == "0"

    default_rate_limiter.reset()
    default_api_key_registry.clear()


def test_ooxml_zip_bomb_and_path_traversal_guards(monkeypatch: pytest.MonkeyPatch):
    """
    Verifies ZIP decompression-ratio bombs, oversized uncompressed payloads, excessive entry counts,
    and path-traversal OOXML payloads are blocked in doc_firewall and contract_ast.
    """
    # 1. High compression ratio (>100:1) zip bomb (500 KB of repetitive XML inside ~1 KB zip)
    bomb_buf = io.BytesIO()
    with zipfile.ZipFile(bomb_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", b"<w:p/>" * 90_000)  # 540,000 bytes repetitive
    bomb_bytes = bomb_buf.getvalue()
    assert len(bomb_bytes) < 4096

    rep = scan_document_security(
        document_id="BOMB-01", file_bytes=bomb_bytes, filename="bomb.docx"
    )
    assert rep.passed is False
    assert any(f.category == "ZIP_BOMB_OR_MALFORMED_ARCHIVE" for f in rep.findings)
    assert rep.sanitized_text == ""

    with pytest.raises(ZipBombError):
        sanitize_docx_bytes(bomb_bytes)
    with pytest.raises(ZipBombError):
        extract_docx_structured(bomb_bytes)

    # 2. Excessive entry count (> max_entries)
    monkeypatch.setattr(settings, "docx_max_entries", 5)
    many_buf = io.BytesIO()
    with zipfile.ZipFile(many_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", b"<w:document/>")
        for i in range(8):
            zf.writestr(f"customXml/item{i}.xml", b"<x/>")
    with pytest.raises(ZipBombError):
        extract_docx_structured(many_buf.getvalue())

    # 3. Path-traversal ZIP entry
    trav_buf = io.BytesIO()
    with zipfile.ZipFile(trav_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../evil.xml", b"<evil/>")
    trav_rep = scan_document_security(
        document_id="TRAV-01", file_bytes=trav_buf.getvalue(), filename="t.docx"
    )
    assert trav_rep.passed is False
    assert any(f.category == "ZIP_BOMB_OR_MALFORMED_ARCHIVE" for f in trav_rep.findings)


@pytest.mark.asyncio
async def test_cross_worker_aes256_gcm_pii_vault_sqlite_redis_and_export_rehydration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Verifies AES-256-GCM cross-worker PII session persistence (SQLite WAL + Redis client),
    tenant AAD isolation, TTL expiration, and end-to-end `/compliance/check` -> `/compliance/export-docx`
    re-hydration across separate worker store instances.
    """
    shared_key = b"k" * 32
    db_file = tmp_path / "pii_vault.db"

    worker1_store = EncryptedPIISessionStore(
        backend="sqlite", db_path=db_file, encryption_key=shared_key, ttl_seconds=60
    )
    worker2_store = EncryptedPIISessionStore(
        backend="sqlite", db_path=db_file, encryption_key=shared_key, ttl_seconds=60
    )
    worker1_store.save_session(
        "tenant-a",
        "sess-x",
        {"[MYKAD_01]": "900101-14-5678", "[TIN_MY_01]": "IG12345678900"},
    )

    # Confirm ciphertext at rest does not expose raw PII
    raw_con = sqlite3.connect(str(db_file))
    cipher_row = raw_con.execute("SELECT payload_b64 FROM pii_sessions").fetchone()
    raw_con.close()
    assert cipher_row is not None
    assert "900101-14-5678" not in cipher_row[0]
    assert "IG12345678900" not in cipher_row[0]

    # Worker 2 loads seamlessly; mismatched tenant fails AAD verification cleanly
    assert worker2_store.load_session("tenant-a", "sess-x") == {
        "[MYKAD_01]": "900101-14-5678",
        "[TIN_MY_01]": "IG12345678900",
    }
    assert worker2_store.load_session("tenant-b", "sess-x") is None

    # Expired TTL entry returns None
    worker1_store.save_session(
        "tenant-a", "sess-exp", {"[MYKAD_01]": "800101-10-1234"}, ttl_seconds=1
    )
    with worker1_store._lock:
        assert worker1_store._conn is not None
        worker1_store._conn.execute(
            "UPDATE pii_sessions SET expires_at = ? WHERE audit_session_id = ?",
            (time.time() - 5.0, "sess-exp"),
        )
        worker1_store._conn.commit()
    assert worker2_store.load_session("tenant-a", "sess-exp") is None
    worker1_store.close()
    worker2_store.close()

    # Redis backend check with fake client
    class _FakeRedis:
        def __init__(self) -> None:
            self.data: dict[str, bytes] = {}

        def setex(self, key: str, ttl: int, val: bytes) -> None:
            self.data[key] = val

        def get(self, key: str) -> bytes | None:
            return self.data.get(key)

        def delete(self, key: str) -> None:
            self.data.pop(key, None)

    fake_redis = _FakeRedis()
    r_store = EncryptedPIISessionStore(
        backend="redis", redis_client=fake_redis, encryption_key=shared_key
    )
    r_store.save_session("tenant-r", "sess-r", {"[KWSP_01]": "12345678"})
    assert r_store.load_session("tenant-r", "sess-r") == {"[KWSP_01]": "12345678"}
    r_store.delete_session("tenant-r", "sess-r")
    assert r_store.load_session("tenant-r", "sess-r") is None

    # End-to-end API route simulation across Worker 1 (/compliance/check) -> Worker 2 (/compliance/export-docx)
    import lexgraph_lah.api.routes as routes_mod

    routes_mod._COMPLIANCE_CACHE.clear()
    api_db = tmp_path / "api_pii_vault.db"
    w1_api_store = EncryptedPIISessionStore(
        backend="sqlite", db_path=api_db, encryption_key=shared_key
    )
    w2_api_store = EncryptedPIISessionStore(
        backend="sqlite", db_path=api_db, encryption_key=shared_key
    )
    monkeypatch.setattr(routes_mod, "default_pii_session_store", w1_api_store)

    raw_contract = (
        "SEC-5.1 Security & Notice: Personal data for NRIC 900101-14-5678 "
        "(LHDN TIN IG12345678900) managed by Vendor where Data Processor bears zero statutory "
        "liability and Vendor shall notify within 10 days."
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        chk = await client.post(
            "/compliance/check",
            headers={"X-Tenant-ID": "tenant-worker"},
            json={
                "document_id": "CROSS-WORKER-01",
                "raw_text": raw_contract,
                "as_of_date": "2026-03-15",
                "regimes": ["ACT_709"],
            },
        )
        assert chk.status_code == 200
        chk_body = chk.json()
        session_id = chk_body["audit_session_id"]
        assert session_id

        # Simulate routing export request to a separate Worker 2 instance with masked findings
        monkeypatch.setattr(routes_mod, "default_pii_session_store", w2_api_store)
        exp = await client.post(
            "/compliance/export-docx",
            headers={"X-Tenant-ID": "tenant-worker"},
            json={
                "document_id": "CROSS-WORKER-01",
                "raw_text": chk_body["pii_scrub"]["masked_text"],
                "as_of_date": "2026-03-15",
                "regimes": ["ACT_709"],
                "rehydrate_pii": True,
                "audit_session_id": session_id,
                "findings": chk_body["findings"],
            },
        )
        assert exp.status_code == 200
        assert exp.headers["x-lexgraph-audit-session-id"] == session_id
        assert len(exp.headers["x-lexgraph-attestation-signature"]) > 20
        inspected = inspect_ooxml_docx(exp.content)
        combined_text = " ".join(
            [d["text"] for d in inspected["deletions"]]
            + [ins["text"] for ins in inspected["insertions"]]
        )
        assert "900101-14-5678" in combined_text or "IG12345678900" in combined_text

    w1_api_store.close()
    w2_api_store.close()


@pytest.mark.asyncio
async def test_ed25519_signed_attestation_public_key_and_postgres_backend(
    tmp_path: Path,
):
    """
    Verifies Ed25519 signing on ledger chain tips, independent public-key verification via
    `GET /api/v1/attestation/public-key`, tamper detection, and `PostgresAttestationBackend`.
    """
    db_path = tmp_path / "att_ed25519.db"
    ledger = AttestationLedger(db_path=db_path)
    raw_doc = "SEC-1 Data Processor shall notify within 24 hours."
    manifest = ComplianceAttestationManifest(
        manifest_id="ATT-ED-01",
        document_id="DOC-ED-01",
        input_doc_sha256=hashlib.sha256(raw_doc.encode()).hexdigest(),
        graph_state_hash="g" * 64,
        as_of_date=__import__("datetime").date(2026, 3, 15),
        regimes=["ACT_709"],
        total_tokens=400,
    )
    manifest.manifest_sha256 = compute_manifest_sha256(manifest)
    rec = ledger.record(manifest)
    assert rec.signature_b64
    assert rec.signature_algorithm == "Ed25519"
    assert rec.signing_key_id

    ver = ledger.verify(manifest_id="ATT-ED-01", raw_text=raw_doc)
    assert ver.verified is True
    assert ver.signature_valid is True

    # Independently verify using public PEM key from ledger.get_public_key_info()
    pub_info = ledger.get_public_key_info()
    pub_key = serialization.load_pem_public_key(pub_info.public_key_pem.encode("ascii"))
    assert isinstance(pub_key, Ed25519PublicKey)
    tip_msg = build_chain_tip_signing_message(
        seq=1,
        manifest_id=rec.manifest_id,
        manifest_sha256=rec.manifest_sha256,
        chain_hash=rec.chain_hash,
    )
    pub_key.verify(base64.b64decode(rec.signature_b64), tip_msg)

    # Corrupt Ed25519 signature in SQLite -> detected cleanly
    assert ledger._conn is not None
    ledger._conn.execute(
        "UPDATE attestations SET signature_b64 = ? WHERE manifest_id = ?",
        (base64.b64encode(b"\x00" * 64).decode("ascii"), "ATT-ED-01"),
    )
    ledger._conn.commit()
    tampered = ledger.verify(manifest_id="ATT-ED-01", raw_text=raw_doc)
    assert tampered.verified is False
    assert tampered.status == "TAMPERED"
    assert tampered.signature_valid is False
    ledger.close()

    # HTTP GET /api/v1/attestation/public-key
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res_pub = await client.get("/api/v1/attestation/public-key")
        assert res_pub.status_code == 200
        body = res_pub.json()
        assert body["algorithm"] == "Ed25519"
        assert "BEGIN PUBLIC KEY" in body["public_key_pem"]
        assert len(body["fingerprint_sha256"]) == 64

    # PostgresAttestationBackend using SQLite shim underneath %s translation
    mem_pg_shim = sqlite3.connect(":memory:", check_same_thread=False)

    class _FakePgCursor:
        def __init__(self, conn: sqlite3.Connection) -> None:
            self._cur = conn.cursor()

        @property
        def description(self) -> Any:
            return self._cur.description

        def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            translated = sql.replace("DOUBLE PRECISION", "REAL").replace("%s", "?")
            self._cur.execute(translated, params)

        def fetchone(self) -> Any:
            return self._cur.fetchone()

        def fetchall(self) -> list[Any]:
            return self._cur.fetchall()

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            self._cur.close()

    class _FakePgConn:
        def cursor(self) -> _FakePgCursor:
            return _FakePgCursor(mem_pg_shim)

        def commit(self) -> None:
            mem_pg_shim.commit()

        def close(self) -> None:
            mem_pg_shim.close()

    pg_backend = PostgresAttestationBackend(
        "postgresql://unused/db", connection_factory=lambda: _FakePgConn()
    )
    pg_ledger = AttestationLedger(backend=pg_backend)
    pg_rec = pg_ledger.record(
        ComplianceAttestationManifest(
            manifest_id="ATT-PG-01",
            document_id="DOC-PG-01",
            input_doc_sha256=hashlib.sha256(raw_doc.encode()).hexdigest(),
            graph_state_hash="h" * 64,
            as_of_date=__import__("datetime").date(2026, 3, 15),
            regimes=["ACT_709"],
        )
    )
    assert pg_rec.signature_b64
    pg_ver = pg_ledger.verify(manifest_id="ATT-PG-01", raw_text=raw_doc)
    assert pg_ver.verified is True
    assert pg_ver.signature_valid is True
    pg_ledger.close()


@pytest.mark.asyncio
async def test_async_portfolio_jobs_over_500_contracts_and_zip_upload():
    """
    Verifies:
      1. Sync `POST /api/v1/portfolio/blast-radius` enforces <= 50 contracts (51 -> 422).
      2. Async `POST /api/v1/portfolio/jobs` + `GET /api/v1/portfolio/jobs/{job_id}` processes
         520 contracts with bounded concurrency and enforces tenant isolation.
      3. Multipart `.zip` archive upload containing `.docx`, `.pdf`, and `.txt` executes cleanly.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        too_many = [
            {
                "document_id": f"SYNC-{i:03d}",
                "raw_text": "Vendor Data Processor notifies within 10 days.",
            }
            for i in range(51)
        ]
        res_sync_limit = await client.post(
            "/api/v1/portfolio/blast-radius",
            json={
                "from_date": "2024-01-01",
                "to_date": "2026-06-01",
                "contracts": too_many,
            },
        )
        assert res_sync_limit.status_code == 422

        # 520-contract async batch job
        batch_520 = [
            {
                "document_id": f"BULK-{i:04d}",
                "raw_text": (
                    "Data Processor shall bear zero statutory liability and notify breaches within 14 days."
                    if i % 5 == 0
                    else "Vendor notifies personal data breach within 24 hours."
                ),
            }
            for i in range(520)
        ]
        res_submit = await client.post(
            "/api/v1/portfolio/jobs",
            headers={"X-Tenant-ID": "tenant-bulk"},
            json={
                "from_date": "2024-01-01",
                "to_date": "2026-06-01",
                "regimes": ["ACT_709"],
                "max_workers": 4,
                "contracts": batch_520,
            },
        )
        assert res_submit.status_code == 202
        job_id = res_submit.json()["job_id"]
        assert res_submit.json()["total_contracts"] == 520

        # Tenant isolation: another tenant cannot read this job
        res_other_tenant = await client.get(
            f"/api/v1/portfolio/jobs/{job_id}",
            headers={"X-Tenant-ID": "tenant-other"},
        )
        assert res_other_tenant.status_code == 404

        from lexgraph_lah.graph.portfolio_scanner import default_portfolio_job_manager

        default_portfolio_job_manager.wait_for_job(job_id, timeout=30.0)
        res_status = await client.get(
            f"/api/v1/portfolio/jobs/{job_id}",
            headers={"X-Tenant-ID": "tenant-bulk"},
        )
        assert res_status.status_code == 200
        job_body = res_status.json()
        assert job_body["status"] == "COMPLETED"
        assert job_body["processed_contracts"] == 520
        assert job_body["result"]["total_contracts_scanned"] == 520
        assert job_body["result"]["impacted_contracts_count"] >= 104

        # Multipart .zip upload containing .docx, .pdf, and .txt contracts
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "vendor_a.docx",
                _make_clean_docx(
                    "Data Processor bears zero liability and notifies breach within 10 days."
                ),
            )
            zf.writestr(
                "vendor_b.pdf",
                _make_clean_pdf(
                    "Vendor maintains full security safeguards and notifies within 24 hours."
                ),
            )
            zf.writestr(
                "vendor_c.txt",
                "Vendor applies Rule-of-78 flat rate interest calculation to BNPL credit.",
            )
        res_zip = await client.post(
            "/api/v1/portfolio/jobs",
            headers={"X-Tenant-ID": "tenant-zip"},
            data={
                "from_date": "2024-01-01",
                "to_date": "2026-06-01",
                "regimes": "ACT_709,ACT_873",
                "max_workers": "2",
            },
            files={
                "file": ("contracts.zip", zip_buf.getvalue(), "application/zip"),
            },
        )
        assert res_zip.status_code == 202
        zip_job_id = res_zip.json()["job_id"]
        default_portfolio_job_manager.wait_for_job(zip_job_id, timeout=20.0)
        res_zip_status = await client.get(
            f"/api/v1/portfolio/jobs/{zip_job_id}",
            headers={"X-Tenant-ID": "tenant-zip"},
        )
        assert res_zip_status.status_code == 200
        assert res_zip_status.json()["status"] == "COMPLETED"
        assert res_zip_status.json()["result"]["total_contracts_scanned"] == 3
