"""
Portable `.lexpack.zip` Air-Gapped Evidence Bundle Builder & Verifier.

Generates deterministic, offline-verifiable `.lexpack.zip` archives containing:
  - `manifest.json` (`AttestationLedgerRecord`, chain hashes, `as_of_date`,
    statutory `SourceSpan` digests, FinOps summary, bundle file SHA-256s)
  - `signature.ed25519` (raw 64-byte Ed25519 signature over `manifest.json`)
  - `public_key.pem` (Ed25519 SPKI PEM verification key)
  - `statutory_snapshot.json` (verbatim bilingual `SourceSpan` nodes cited in the verdict)
  - `verification_instructions.txt`
  - Optional `redlined_contract.docx` (when `docx_bytes` is supplied)
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import uuid
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lexgraph_lah.graph.temporal_store import get_default_temporal_store
from lexgraph_lah.schemas.domain import (
    AttestationLedgerRecord,
    ComplianceAttestationManifest,
)
from lexgraph_lah.security.attestation_ledger import (
    AttestationLedger,
    build_chain_tip_signing_message,
    compute_chain_hash,
    compute_manifest_sha256,
    default_attestation_ledger,
)
from lexgraph_lah.security.doc_firewall import (
    ZipBombError,
    validate_zip_archive_safety,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import (
    ComplianceSpanRecord,
    measure_latency_ms,
    telemetry_registry,
)

if TYPE_CHECKING:
    from lexgraph_lah.graph.temporal_store import TemporalGraphStore

BUNDLE_VERSION = "1.0"
_FIXED_ZIP_DT = (2026, 1, 1, 0, 0, 0)
_REQUIRED_BUNDLE_FILES = (
    "manifest.json",
    "signature.ed25519",
    "public_key.pem",
    "statutory_snapshot.json",
    "verification_instructions.txt",
)


def _canonical_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")


def _collect_statutory_snapshot(
    *,
    citation_span_ids: list[str],
    store: TemporalGraphStore,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """
    Collects verbatim bilingual `SourceSpan` nodes cited in the verdict (and any paired
    BM/EN translation spans) along with their SHA-256 digests.
    """
    target_ids = set(citation_span_ids)
    snapshot_entries: list[dict[str, Any]] = []
    span_digests: dict[str, str] = {}
    seen_spans: set[str] = set()

    # Deterministic order across store nodes
    matched_node_ids: set[str] = set()
    for nid, node in sorted(store.nodes.items()):
        if any(sp.span_id in target_ids for sp in node.source_spans):
            matched_node_ids.add(nid)
            if node.translation_node_id and node.translation_node_id in store.nodes:
                matched_node_ids.add(node.translation_node_id)

    for nid in sorted(matched_node_ids):
        node = store.nodes[nid]
        for sp in node.source_spans:
            if sp.span_id in seen_spans:
                continue
            seen_spans.add(sp.span_id)
            clean_txt = sp.text.strip()
            digest = (
                hashlib.sha256(clean_txt.encode("utf-8")).hexdigest()
                if clean_txt
                else sp.content_sha256
            )
            span_digests[sp.span_id] = digest
            snapshot_entries.append(
                {
                    "span_id": sp.span_id,
                    "node_id": node.node_id,
                    "act_name": node.act_name,
                    "act_number": sp.act_number,
                    "section_id": sp.section_id,
                    "canonical_citation": sp.canonical_citation,
                    "language": sp.language,
                    "effective_from": (
                        node.effective_from or node.valid_from
                    ).isoformat(),
                    "effective_to": node.effective_to.isoformat()
                    if node.effective_to
                    else None,
                    "gazette_ref": node.gazette_ref,
                    "content_sha256": digest,
                    "text": sp.text,
                }
            )

    return snapshot_entries, span_digests


def build_lexpack_bundle(
    manifest_id: str,
    *,
    ledger: AttestationLedger | None = None,
    store: TemporalGraphStore | None = None,
    docx_bytes: bytes | None = None,
    tenant_id: str = "default-tenant",
) -> bytes:
    """
    Builds a deterministic, air-gapped `.lexpack.zip` evidence bundle for `manifest_id`
    at 0 LLM tokens (`$0.00 USD / RM 0.00 MYR`).
    """
    att_ledger = ledger or default_attestation_ledger
    graph_store = store or get_default_temporal_store()

    with measure_latency_ms() as elapsed_holder:
        seq_and_rec = att_ledger.get_with_seq(manifest_id)
        if seq_and_rec is None:
            raise KeyError(
                f"Attestation manifest '{manifest_id}' was not found in the ledger."
            )
        seq, rec = seq_and_rec

        pub_info = att_ledger.get_public_key_info()
        pub_pem_bytes = pub_info.public_key_pem.encode("ascii")

        snapshot_entries, span_digests = _collect_statutory_snapshot(
            citation_span_ids=rec.citation_span_ids,
            store=graph_store,
        )
        snapshot_bytes = _canonical_json_bytes(
            {
                "bundle_version": BUNDLE_VERSION,
                "manifest_id": rec.manifest_id,
                "as_of_date": rec.as_of_date.isoformat(),
                "source_spans": snapshot_entries,
            }
        )

        instructions_text = (
            "lexgraph-lah Air-Gapped `.lexpack.zip` Evidence Bundle Verification Instructions\n"
            "===============================================================================\n"
            f"Bundle Version : {BUNDLE_VERSION}\n"
            f"Manifest ID    : {rec.manifest_id}\n"
            f"Document ID    : {rec.document_id}\n"
            f"As-Of Date     : {rec.as_of_date.isoformat()}\n"
            f"Signing Key ID : {pub_info.key_id} ({pub_info.algorithm})\n"
            f"Key Fingerprint: {pub_info.fingerprint_sha256}\n\n"
            "Offline CLI Verification (0 network calls):\n"
            "  python -m lexgraph_lah.attestation.verify_cli --bundle <path.lexpack.zip>\n"
            "  python -m lexgraph_lah.attestation.verify_cli --bundle <path.lexpack.zip> --pubkey public_key.pem\n\n"
            "Verification Checks Performed:\n"
            "  1. Ed25519 verification of `signature.ed25519` over exact `manifest.json` bytes.\n"
            "  2. SHA-256 verification of all bundled files listed in `bundle_files_sha256`.\n"
            "  3. Canonical `ComplianceAttestationManifest` SHA-256, append-only `chain_hash`, and\n"
            "     ledger `signature_b64` verification against `public_key.pem`.\n"
            "  4. Verbatim SHA-256 verification of every `SourceSpan` excerpt in `statutory_snapshot.json`.\n"
        )
        instructions_bytes = instructions_text.encode("utf-8")

        bundle_files: dict[str, bytes] = {
            "public_key.pem": pub_pem_bytes,
            "statutory_snapshot.json": snapshot_bytes,
            "verification_instructions.txt": instructions_bytes,
        }
        if docx_bytes is not None:
            bundle_files["redlined_contract.docx"] = docx_bytes

        bundle_files_sha256 = {
            fname: hashlib.sha256(content).hexdigest()
            for fname, content in sorted(bundle_files.items())
        }

        finops_summary: dict[str, Any] = {
            "total_tokens": rec.total_tokens,
            "estimated_cost_usd": rec.estimated_cost_usd,
            "estimated_cost_myr": rec.estimated_cost_myr,
            "model_used": rec.model_used,
            "telemetry_snapshot": rec.telemetry_snapshot,
        }

        manifest_payload: dict[str, Any] = {
            "bundle_version": BUNDLE_VERSION,
            "manifest_id": rec.manifest_id,
            "document_id": rec.document_id,
            "seq": seq,
            "as_of_date": rec.as_of_date.isoformat(),
            "regimes": rec.regimes,
            "territorial_scope": rec.territorial_scope,
            "signing_key_id": rec.signing_key_id or pub_info.key_id,
            "signature_algorithm": rec.signature_algorithm or "Ed25519",
            "public_key_fingerprint_sha256": pub_info.fingerprint_sha256,
            "chain_hashes": {
                "input_doc_sha256": rec.input_doc_sha256,
                "graph_state_hash": rec.graph_state_hash,
                "manifest_sha256": rec.manifest_sha256,
                "prev_chain_hash": rec.prev_chain_hash,
                "chain_hash": rec.chain_hash,
            },
            "statutory_source_span_digests": span_digests,
            "finops_summary": finops_summary,
            "bundle_files_sha256": bundle_files_sha256,
            "attestation_record": rec.model_dump(mode="json"),
        }
        manifest_bytes = _canonical_json_bytes(manifest_payload)
        sig_bytes = att_ledger.signer.sign(manifest_bytes)

        archive_entries: dict[str, bytes] = {
            **bundle_files,
            "manifest.json": manifest_bytes,
            "signature.ed25519": sig_bytes,
        }

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name in sorted(archive_entries.keys()):
                zinfo = zipfile.ZipInfo(filename=name, date_time=_FIXED_ZIP_DT)
                zinfo.compress_type = zipfile.ZIP_DEFLATED
                zinfo.external_attr = 0o644 << 16
                zf.writestr(zinfo, archive_entries[name])

        bundle_bytes = buf.getvalue()

    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_holder[0],
        retry_count=0,
        is_verified_grounded=True,
        trace_id=f"lexpack-{uuid.uuid4().hex[:8]}",
    )
    telemetry_registry.record_span(
        ComplianceSpanRecord(
            span_id=telemetry.trace_id or "lexpack",
            document_id=rec.document_id,
            reference_date=rec.as_of_date.isoformat(),
            active_statute_count=len(snapshot_entries),
            tenant_id=tenant_id,
            extra_attributes={
                "lexpack.manifest_id": rec.manifest_id,
                "lexpack.include_docx": docx_bytes is not None,
                "lexpack.bundle_bytes": len(bundle_bytes),
            },
            telemetry=telemetry,
            timestamp_epoch=time.time(),
        )
    )
    return bundle_bytes


def verify_lexpack_bundle(
    bundle: bytes | str | Path,
    *,
    pubkey_pem: str | bytes | None = None,
) -> dict[str, Any]:
    """
    Offline zero-network verifier for `.lexpack.zip` evidence bundles.
    Returns structured verification JSON dict (`verified: bool`, `status`, `reasons`, ...).
    """
    reasons: list[str] = []
    checks: dict[str, bool] = {
        "archive_safe": False,
        "required_files_present": False,
        "bundle_ed25519_valid": False,
        "bundle_files_sha256_valid": False,
        "manifest_sha256_valid": False,
        "chain_hash_valid": False,
        "ledger_tip_signature_valid": False,
        "statutory_snapshot_valid": False,
    }

    if isinstance(bundle, (str, Path)):
        p = Path(bundle)
        if not p.is_file():
            return {
                "verified": False,
                "status": "ERROR",
                "manifest_id": None,
                "checks": checks,
                "reasons": [f"Bundle file not found: {p}"],
            }
        bundle_bytes = p.read_bytes()
    else:
        bundle_bytes = bundle

    try:
        validate_zip_archive_safety(bundle_bytes)
        checks["archive_safe"] = True
    except ZipBombError as exc:
        return {
            "verified": False,
            "status": "TAMPERED",
            "manifest_id": None,
            "checks": checks,
            "reasons": [f"ZIP safety failure: {exc}"],
        }

    try:
        zf = zipfile.ZipFile(io.BytesIO(bundle_bytes), "r")
    except zipfile.BadZipFile as exc:
        return {
            "verified": False,
            "status": "TAMPERED",
            "manifest_id": None,
            "checks": checks,
            "reasons": [f"Malformed ZIP archive: {exc}"],
        }

    with zf:
        names = set(zf.namelist())
        missing = [req for req in _REQUIRED_BUNDLE_FILES if req not in names]
        if missing:
            reasons.append(f"Missing required bundle file(s): {', '.join(missing)}")
            return {
                "verified": False,
                "status": "TAMPERED",
                "manifest_id": None,
                "checks": checks,
                "reasons": reasons,
            }
        checks["required_files_present"] = True

        manifest_bytes = zf.read("manifest.json")
        sig_bytes = zf.read("signature.ed25519")
        embedded_pub_bytes = zf.read("public_key.pem")
        snapshot_bytes = zf.read("statutory_snapshot.json")

        file_bytes_map: dict[str, bytes] = {
            n: zf.read(n)
            for n in names
            if n not in {"manifest.json", "signature.ed25519"}
        }

    try:
        manifest_obj = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        reasons.append(f"Invalid manifest.json JSON: {exc}")
        return {
            "verified": False,
            "status": "TAMPERED",
            "manifest_id": None,
            "checks": checks,
            "reasons": reasons,
        }

    manifest_id = str(manifest_obj.get("manifest_id") or "")

    # 1. Load Ed25519 verification key (--pubkey overrides embedded public_key.pem)
    raw_pub_pem = (
        pubkey_pem.encode("utf-8")
        if isinstance(pubkey_pem, str)
        else (pubkey_pem if pubkey_pem is not None else embedded_pub_bytes)
    )
    try:
        loaded_key = serialization.load_pem_public_key(raw_pub_pem)
        if not isinstance(loaded_key, Ed25519PublicKey):
            reasons.append(
                "Invalid Ed25519 public key: Public key is not an Ed25519 key."
            )
            return {
                "verified": False,
                "status": "TAMPERED",
                "manifest_id": manifest_id or None,
                "checks": checks,
                "reasons": reasons,
            }
    except (ValueError, TypeError) as exc:
        reasons.append(f"Invalid Ed25519 public key: {exc}")
        return {
            "verified": False,
            "status": "TAMPERED",
            "manifest_id": manifest_id or None,
            "checks": checks,
            "reasons": reasons,
        }

    if (
        pubkey_pem is not None
        and hashlib.sha256(raw_pub_pem.strip()).hexdigest()
        != hashlib.sha256(embedded_pub_bytes.strip()).hexdigest()
    ):
        reasons.append(
            "Bundled public_key.pem does not match explicitly supplied --pubkey."
        )

    # 2. Verify Ed25519 signature over exact manifest.json bytes
    try:
        loaded_key.verify(sig_bytes, manifest_bytes)
        checks["bundle_ed25519_valid"] = True
    except InvalidSignature:
        reasons.append(
            "Ed25519 signature.ed25519 verification failed for manifest.json."
        )

    # 3. Verify SHA-256 of every bundled artifact declared in bundle_files_sha256
    declared_file_hashes = manifest_obj.get("bundle_files_sha256")
    files_ok = isinstance(declared_file_hashes, dict) and bool(declared_file_hashes)
    if not isinstance(declared_file_hashes, dict) or not declared_file_hashes:
        reasons.append("manifest.json missing bundle_files_sha256 map.")
        files_ok = False
    else:
        for fname, expected_sha in declared_file_hashes.items():
            if fname not in file_bytes_map:
                reasons.append(f"Declared bundle file missing from archive: {fname}")
                files_ok = False
                continue
            actual_sha = hashlib.sha256(file_bytes_map[fname]).hexdigest()
            if actual_sha != str(expected_sha):
                reasons.append(f"SHA-256 mismatch for bundled file '{fname}'.")
                files_ok = False
    checks["bundle_files_sha256_valid"] = files_ok

    # 4. Verify AttestationLedgerRecord manifest_sha256, chain_hash, and ledger Ed25519 signature
    try:
        rec = AttestationLedgerRecord(**manifest_obj["attestation_record"])
        seq = int(manifest_obj["seq"])
        basis = ComplianceAttestationManifest(
            manifest_id=rec.manifest_id,
            document_id=rec.document_id,
            input_doc_sha256=rec.input_doc_sha256,
            graph_state_hash=rec.graph_state_hash,
            as_of_date=rec.as_of_date,
            regimes=rec.regimes,
            territorial_scope=rec.territorial_scope,
            is_verified_grounded=rec.is_verified_grounded,
            retry_count=rec.retry_count,
            estimated_cost_usd=rec.estimated_cost_usd,
            estimated_cost_myr=rec.estimated_cost_myr,
            total_tokens=rec.total_tokens,
            model_used=rec.model_used,
            trace_id=rec.trace_id,
            citation_span_ids=rec.citation_span_ids,
        )
        recomputed_msha = compute_manifest_sha256(basis)
        chain_hashes = manifest_obj.get("chain_hashes") or {}
        if (
            recomputed_msha == rec.manifest_sha256
            and rec.manifest_sha256 == chain_hashes.get("manifest_sha256")
        ):
            checks["manifest_sha256_valid"] = True
        else:
            reasons.append("Canonical ComplianceAttestationManifest SHA-256 mismatch.")

        recomputed_chain = compute_chain_hash(
            seq=seq,
            manifest_id=rec.manifest_id,
            document_id=rec.document_id,
            manifest_sha256=rec.manifest_sha256,
            input_doc_sha256=rec.input_doc_sha256,
            graph_state_hash=rec.graph_state_hash,
            as_of_date=rec.as_of_date,
            regimes=rec.regimes,
            territorial_scope=rec.territorial_scope,
            is_verified_grounded=rec.is_verified_grounded,
            retry_count=rec.retry_count,
            estimated_cost_usd=rec.estimated_cost_usd,
            estimated_cost_myr=rec.estimated_cost_myr,
            total_tokens=rec.total_tokens,
            model_used=rec.model_used,
            citation_span_ids=sorted(set(rec.citation_span_ids)),
            prev_chain_hash=rec.prev_chain_hash,
        )
        if recomputed_chain == rec.chain_hash and rec.chain_hash == chain_hashes.get(
            "chain_hash"
        ):
            checks["chain_hash_valid"] = True
        else:
            reasons.append("AttestationLedgerRecord chain_hash mismatch.")

        tip_msg = build_chain_tip_signing_message(
            seq=seq,
            manifest_id=rec.manifest_id,
            manifest_sha256=rec.manifest_sha256,
            chain_hash=rec.chain_hash,
        )
        tip_sig = base64.b64decode(rec.signature_b64, validate=True)
        loaded_key.verify(tip_sig, tip_msg)
        checks["ledger_tip_signature_valid"] = True
    except (KeyError, ValueError, TypeError, InvalidSignature) as exc:
        reasons.append(f"Ledger record cryptographic verification failed: {exc}")

    # 5. Verify statutory_snapshot.json SourceSpans & verbatim digests
    try:
        snapshot_obj = json.loads(snapshot_bytes.decode("utf-8"))
        spans = snapshot_obj.get("source_spans")
        expected_digests = manifest_obj.get("statutory_source_span_digests")
        if not isinstance(spans, list) or not isinstance(expected_digests, dict):
            raise TypeError("Missing source_spans or statutory_source_span_digests.")

        seen_snap_ids: set[str] = set()
        snap_ok = True
        for sp in spans:
            sid = str(sp.get("span_id") or "")
            txt = str(sp.get("text") or "").strip()
            declared = str(sp.get("content_sha256") or "")
            actual = (
                hashlib.sha256(txt.encode("utf-8")).hexdigest() if txt else declared
            )
            if actual != declared:
                reasons.append(
                    f"Statutory SourceSpan '{sid}' verbatim text SHA-256 mismatch."
                )
                snap_ok = False
            if sid in expected_digests and expected_digests[sid] != actual:
                reasons.append(
                    f"Statutory SourceSpan '{sid}' digest differs from manifest digest."
                )
                snap_ok = False
            seen_snap_ids.add(sid)

        for sid in expected_digests:
            if sid not in seen_snap_ids:
                reasons.append(
                    f"Expected statutory SourceSpan '{sid}' missing from statutory_snapshot.json."
                )
                snap_ok = False

        checks["statutory_snapshot_valid"] = snap_ok
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        reasons.append(f"Invalid statutory_snapshot.json: {exc}")

    verified = all(checks.values()) and len(reasons) == 0
    return {
        "verified": verified,
        "status": "VERIFIED" if verified else "TAMPERED",
        "manifest_id": manifest_id or None,
        "as_of_date": manifest_obj.get("as_of_date"),
        "checks": checks,
        "reasons": reasons,
    }
