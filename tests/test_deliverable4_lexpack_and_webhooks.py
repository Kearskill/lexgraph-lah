from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import subprocess
import sys
import zipfile
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from httpx import ASGITransport, AsyncClient

from lexgraph_lah.attestation.bundle import (
    build_lexpack_bundle,
    verify_lexpack_bundle,
)
from lexgraph_lah.config import settings
from lexgraph_lah.graph.portfolio_scanner import (
    PortfolioJobManager,
    PostgresPortfolioJobStore,
    SQLitePortfolioJobStore,
)
from lexgraph_lah.main import app
from lexgraph_lah.schemas.domain import (
    ComplianceAttestationManifest,
    PortfolioAsyncJobRequest,
    PortfolioContractInput,
)
from lexgraph_lah.security.attestation_ledger import (
    AttestationLedger,
    Ed25519AttestationSigner,
    compute_manifest_sha256,
    default_attestation_ledger,
)
from lexgraph_lah.security.auth import (
    default_api_key_registry,
    default_rate_limiter,
    hash_api_key,
)
from lexgraph_lah.security.webhooks import (
    SSRFViolationError,
    validate_webhook_url_ssrf,
)


def _run_verify_cli(
    bundle: Path, pubkey: Path | None = None
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        "-m",
        "lexgraph_lah.attestation.verify_cli",
        "--bundle",
        str(bundle),
    ]
    if pubkey is not None:
        cmd.extend(["--pubkey", str(pubkey)])
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _tamper_zip_file(src_bytes: bytes, target_name: str, new_data: bytes) -> bytes:
    out = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(src_bytes), "r") as zin,
        zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zout,
    ):
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == target_name:
                data = new_data
            zout.writestr(item.filename, data)
    return out.getvalue()


@pytest.mark.asyncio
async def test_lexpack_bundle_endpoint_include_docx_isolation_and_offline_cli(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """
    Verifies:
      - GET /api/v1/attestation/{manifest_id}/bundle streams deterministic .lexpack.zip
      - include_docx=true enforces tenant isolation on audit_session_id
      - python -m lexgraph_lah.attestation.verify_cli exits 0 on intact bundles and non-zero
        with structured JSON failure on tampered manifest/signature/snapshot/wrong pubkey.
    """
    default_api_key_registry.clear()
    default_rate_limiter.reset()

    aud_a = "lexpack_auditor_a"
    aud_b = "lexpack_auditor_b"
    keys = {
        hash_api_key(aud_a): {
            "tenant_id": "tenant-a",
            "role": "auditor",
            "subject": "a",
        },
        hash_api_key(aud_b): {
            "tenant_id": "tenant-b",
            "role": "auditor",
            "subject": "b",
        },
    }
    monkeypatch.setattr(settings, "env", "test")
    monkeypatch.setattr(settings, "auth_mode", "api_key")
    monkeypatch.setattr(settings, "auth_api_keys_json", json.dumps(keys))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Export DOCX under tenant-a session to register manifest + session DOCX
        exp = await client.post(
            "/compliance/export-docx",
            headers={"X-API-Key": aud_a},
            json={
                "document_id": "BUNDLE-DOC-01",
                "raw_text": (
                    "Section 9 Security Principle: Vendor bears zero statutory liability "
                    "for NRIC 900101-14-5678 and notifies within 10 days."
                ),
                "as_of_date": "2026-03-15",
                "audit_session_id": "sess-bundle-a",
            },
        )
        assert exp.status_code == 200

        # Create/record deterministic manifest via check endpoint as well
        chk = await client.post(
            "/compliance/check",
            headers={"X-API-Key": aud_a},
            json={
                "document_id": "BUNDLE-CHK-01",
                "raw_text": "Section 9 Security: Data Processor owes zero statutory liability for PDPA breaches within 10 days.",
                "as_of_date": "2026-03-15",
                "audit_session_id": "sess-chk-a",
            },
        )
        assert chk.status_code == 200
        manifest_id = chk.json()["attestation_manifest"]["manifest_id"]

        b1 = await client.get(
            f"/api/v1/attestation/{manifest_id}/bundle",
            headers={"X-API-Key": aud_a},
        )
        b2 = await client.get(
            f"/api/v1/attestation/{manifest_id}/bundle",
            headers={"X-API-Key": aud_a},
        )
        assert b1.status_code == 200
        assert b1.content == b2.content  # deterministic bytes!
        with zipfile.ZipFile(io.BytesIO(b1.content), "r") as zf:
            names = set(zf.namelist())
            assert {
                "manifest.json",
                "signature.ed25519",
                "public_key.pem",
                "statutory_snapshot.json",
                "verification_instructions.txt",
            } <= names

        # include_docx=true succeeds for owning tenant-a, returns 404 for tenant-b
        b_docx = await client.get(
            f"/api/v1/attestation/{manifest_id}/bundle?include_docx=true&audit_session_id=sess-chk-a",
            headers={"X-API-Key": aud_a},
        )
        assert b_docx.status_code == 200
        with zipfile.ZipFile(io.BytesIO(b_docx.content), "r") as zf:
            assert "redlined_contract.docx" in zf.namelist()

        b_cross = await client.get(
            f"/api/v1/attestation/{manifest_id}/bundle?include_docx=true&audit_session_id=sess-chk-a",
            headers={"X-API-Key": aud_b},
        )
        assert b_cross.status_code == 404

    # Offline CLI verification tests
    bundle_path = tmp_path / "valid.lexpack.zip"
    pub_path = tmp_path / "pub.pem"
    bundle_path.write_bytes(b_docx.content)
    with zipfile.ZipFile(bundle_path, "r") as zf:
        pub_path.write_bytes(zf.read("public_key.pem"))

    proc_ok = await asyncio.to_thread(_run_verify_cli, bundle_path, pub_path)
    assert proc_ok.returncode == 0
    ok_json = json.loads(proc_ok.stdout)
    assert ok_json["verified"] is True
    assert ok_json["status"] == "VERIFIED"

    # Tamper manifest, statutory snapshot, signature, and mismatched pubkey
    with zipfile.ZipFile(bundle_path, "r") as zf:
        orig_manifest = zf.read("manifest.json")
        orig_snap = zf.read("statutory_snapshot.json")
        orig_sig = zf.read("signature.ed25519")

    tampered_paths = [
        (
            "manifest",
            _tamper_zip_file(b_docx.content, "manifest.json", orig_manifest + b" "),
        ),
        (
            "snapshot",
            _tamper_zip_file(
                b_docx.content, "statutory_snapshot.json", orig_snap + b" "
            ),
        ),
        (
            "signature",
            _tamper_zip_file(
                b_docx.content,
                "signature.ed25519",
                bytes([orig_sig[0] ^ 0xFF]) + orig_sig[1:],
            ),
        ),
    ]
    for label, t_bytes in tampered_paths:
        tp = tmp_path / f"tampered_{label}.lexpack.zip"
        tp.write_bytes(t_bytes)
        proc_bad = await asyncio.to_thread(_run_verify_cli, tp)
        assert proc_bad.returncode != 0
        bad_json = json.loads(proc_bad.stdout)
        assert bad_json["verified"] is False
        assert bad_json["status"] == "TAMPERED"

    # Wrong --pubkey fails offline CLI check
    wrong_signer = Ed25519AttestationSigner(key_id="wrong-key")
    wrong_pub = tmp_path / "wrong_pub.pem"
    wrong_pub.write_text(wrong_signer.public_key_pem(), encoding="utf-8")
    proc_wrong_key = await asyncio.to_thread(_run_verify_cli, bundle_path, wrong_pub)
    assert proc_wrong_key.returncode != 0
    assert json.loads(proc_wrong_key.stdout)["verified"] is False

    # Sanity check direct build_lexpack_bundle with isolated ledger
    iso_ledger = AttestationLedger(":memory:")
    try:
        m = ComplianceAttestationManifest(
            manifest_id="ATTEST-ISO-1",
            document_id="DOC-ISO",
            input_doc_sha256=hashlib.sha256(b"hello").hexdigest(),
            graph_state_hash="h" * 64,
            as_of_date=date(2026, 3, 15),
            citation_span_ids=[],
        )
        m.manifest_sha256 = compute_manifest_sha256(m)
        iso_ledger.record(m)
        z = build_lexpack_bundle("ATTEST-ISO-1", ledger=iso_ledger)
        assert verify_lexpack_bundle(z)["verified"] is True
    finally:
        iso_ledger.close()


def test_ssrf_guard_durable_sqlite_postgres_and_dual_signed_webhooks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """
    Verifies:
      - SSRF validation blocks loopback, RFC1918, metadata IPs, IPv4-mapped IPv6,
        non-HTTPS in ENV=production, and DNS rebinding
      - SQLitePortfolioJobStore persists jobs across PortfolioJobManager restarts
      - PostgresPortfolioJobStore roundtrips JSON via connection_factory
      - Dual-signed webhooks (X-LexGraph-Signature-256 + X-LexGraph-Ed25519) retry 3 attempts
        and verify cryptographically.
    """
    blocked_urls = [
        "http://127.0.0.1:8080/hook",
        "http://[::1]:8080/hook",
        "https://10.0.0.5/hook",
        "https://192.168.1.50/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:127.0.0.1]/hook",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://user:pass@example.com/hook",
    ]
    for url in blocked_urls:
        with pytest.raises(SSRFViolationError):
            validate_webhook_url_ssrf(url)

    # Non-HTTPS rejected when ENV=production
    with pytest.raises(SSRFViolationError):
        validate_webhook_url_ssrf(
            "http://hooks.example.com/callback",
            dns_resolver=lambda _h, _p: ["93.184.216.34"],
            is_production=True,
        )

    # DNS rebinding blocked when resolver returns internal IP
    with pytest.raises(SSRFViolationError):
        validate_webhook_url_ssrf(
            "https://rebind.example.com/hook",
            dns_resolver=lambda _h, _p: ["127.0.0.1"],
        )

    # Mock webhook server: fail twice 503, succeed 3rd time 200; verify both signatures
    signer = default_attestation_ledger.signer
    hmac_secret = "phase5-test-webhook-secret"
    received: list[tuple[bytes, dict[str, str]]] = []
    attempt_counter = {"n": 0}

    def _mock_handler(request: httpx.Request) -> httpx.Response:
        attempt_counter["n"] += 1
        received.append(
            (request.content, {k.lower(): v for k, v in request.headers.items()})
        )
        if attempt_counter["n"] < 3:
            return httpx.Response(503, text="retry")
        return httpx.Response(200, json={"ok": True})

    db_file = tmp_path / "portfolio_jobs.db"
    job_store = SQLitePortfolioJobStore(db_path=db_file)
    try:
        mgr = PortfolioJobManager(
            job_store=job_store,
            webhook_transport=httpx.MockTransport(_mock_handler),
            dns_resolver=lambda _h, _p: ["93.184.216.34"],
            hmac_secret=hmac_secret,
            signer=signer,
            webhook_max_attempts=3,
            webhook_backoff_base_seconds=0.0,
        )
        req = PortfolioAsyncJobRequest(
            from_date=date(2024, 6, 15),
            to_date=date(2026, 3, 15),
            regimes=["ACT_709", "ACT_854"],
            webhook_url="https://hooks.partner-legal.com/lexgraph",
            contracts=[
                PortfolioContractInput(
                    document_id="WH-1",
                    raw_text="Section 12B Notice: Breach notified within 48 hours.",
                )
            ],
        )
        submitted = mgr.submit_job(req, tenant_id="tenant-wh")
        done = mgr.wait_for_job(submitted.job_id, timeout=15.0)
        assert done is not None
        assert done.status == "COMPLETED"
        assert done.webhook_delivery is not None
        assert done.webhook_delivery.status == "DELIVERED"
        assert done.webhook_delivery.attempts == 3
        assert done.webhook_delivery.last_http_status == 200

        # Verify persisted durability via a brand-new SQLite store / manager instance
        job_store_reopened = SQLitePortfolioJobStore(db_path=db_file)
        try:
            mgr_restarted = PortfolioJobManager(job_store=job_store_reopened)
            reloaded = mgr_restarted.get_job(submitted.job_id, tenant_id="tenant-wh")
            assert reloaded is not None
            assert reloaded.status == "COMPLETED"
            assert reloaded.webhook_delivery is not None
            assert reloaded.webhook_delivery.status == "DELIVERED"
            assert (
                mgr_restarted.get_job(submitted.job_id, tenant_id="wrong-tenant")
                is None
            )
        finally:
            job_store_reopened.close()
    finally:
        job_store.close()

    # Verify both HMAC-SHA256 and Ed25519 headers on delivered payload
    assert len(received) == 3
    payload_bytes, hdrs = received[-1]
    expected_hmac = (
        "sha256="
        + hmac.new(
            hmac_secret.encode("utf-8"), payload_bytes, hashlib.sha256
        ).hexdigest()
    )
    assert hmac.compare_digest(hdrs["x-lexgraph-signature-256"], expected_hmac)
    pub_obj = serialization.load_pem_public_key(signer.public_key_pem().encode("utf-8"))
    assert isinstance(pub_obj, Ed25519PublicKey)
    pub_obj.verify(base64.b64decode(hdrs["x-lexgraph-ed25519"]), payload_bytes)

    # PostgresPortfolioJobStore fake connection_factory roundtrip
    fake_rows: dict[str, tuple[str, str, str, str]] = {}

    class _FakeCursor:
        def __init__(self) -> None:
            self._one: tuple[str, ...] | None = None

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            low_sql = sql.strip().lower()
            if low_sql.startswith("insert into portfolio_jobs"):
                jid, tid, st, pjson, uat = params
                fake_rows[jid] = (tid, st, pjson, uat)
            elif low_sql.startswith("select payload_json"):
                if "and tenant_id" in low_sql:
                    jid, tid = params
                    row = fake_rows.get(jid)
                    self._one = (row[2],) if row and row[0] == tid else None
                else:
                    jid = params[0]
                    row = fake_rows.get(jid)
                    self._one = (row[2],) if row else None

        def fetchone(self) -> tuple[str, ...] | None:
            return self._one

    class _FakeConn:
        def cursor(self) -> _FakeCursor:
            return _FakeCursor()

        def commit(self) -> None:
            return None

        def close(self) -> None:
            return None

    pg_store = PostgresPortfolioJobStore(
        dsn="postgresql://fake", connection_factory=lambda: _FakeConn()
    )
    try:
        assert done is not None
        pg_store.save(done)
        got = pg_store.get(done.job_id, tenant_id="tenant-wh")
        assert got is not None
        assert got.job_id == done.job_id
        assert pg_store.get(done.job_id, tenant_id="other") is None
    finally:
        pg_store.close()
