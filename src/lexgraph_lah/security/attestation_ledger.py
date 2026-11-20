"""
Tamper-evident SQLite WAL Attestation Ledger & Cryptographic Verifier.

Persists `ComplianceAttestationManifest` records and FinOps `TelemetrySummary`
snapshots inside an append-only SHA-256 hash chain so post-hoc alterations to
contracts, `as_of_date` snapshots, `citation_span_ids`, FinOps metrics, or ledger
rows are detected immediately.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from lexgraph_lah.config import settings
from lexgraph_lah.schemas.domain import (
    AttestationLedgerRecord,
    AttestationVerifyResponse,
    ComplianceAttestationManifest,
    TelemetrySummary,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary

GENESIS_CHAIN_HASH = "0" * 64


def compute_manifest_sha256(manifest: ComplianceAttestationManifest) -> str:
    """Computes the canonical SHA-256 digest of a ComplianceAttestationManifest."""
    basis = json.dumps(
        {
            "document_id": manifest.document_id,
            "input_doc_sha256": manifest.input_doc_sha256,
            "graph_state_hash": manifest.graph_state_hash,
            "as_of_date": manifest.as_of_date.isoformat(),
            "regimes": manifest.regimes,
            "total_tokens": manifest.total_tokens,
        },
        sort_keys=True,
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def compute_chain_hash(
    *,
    seq: int,
    manifest_id: str,
    document_id: str,
    manifest_sha256: str,
    input_doc_sha256: str,
    graph_state_hash: str,
    as_of_date: date,
    regimes: list[str],
    territorial_scope: str,
    is_verified_grounded: bool,
    retry_count: int,
    estimated_cost_usd: float,
    estimated_cost_myr: float,
    total_tokens: int,
    model_used: str | None,
    citation_span_ids: list[str],
    prev_chain_hash: str,
) -> str:
    """Computes the append-only hash-chain link binding a ledger row to its predecessor."""
    basis = json.dumps(
        {
            "seq": seq,
            "manifest_id": manifest_id,
            "document_id": document_id,
            "manifest_sha256": manifest_sha256,
            "input_doc_sha256": input_doc_sha256,
            "graph_state_hash": graph_state_hash,
            "as_of_date": as_of_date.isoformat(),
            "regimes": regimes,
            "territorial_scope": territorial_scope,
            "is_verified_grounded": is_verified_grounded,
            "retry_count": retry_count,
            "estimated_cost_usd": float(estimated_cost_usd),
            "estimated_cost_myr": float(estimated_cost_myr),
            "total_tokens": total_tokens,
            "model_used": model_used,
            "citation_span_ids": citation_span_ids,
            "prev_chain_hash": prev_chain_hash,
        },
        sort_keys=True,
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


class AttestationLedger:
    """Thread-safe append-only SQLite WAL ledger for ComplianceAttestationManifests."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        self._lock = threading.RLock()
        if self._db_path != ":memory:":
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    @property
    def db_path(self) -> str:
        return self._db_path

    def _init_schema(self) -> None:
        with self._lock:
            if self._db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL;")
                self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attestations (
                    seq INTEGER PRIMARY KEY,
                    manifest_id TEXT UNIQUE NOT NULL,
                    document_id TEXT NOT NULL,
                    input_doc_sha256 TEXT NOT NULL,
                    graph_state_hash TEXT NOT NULL,
                    as_of_date TEXT NOT NULL,
                    regimes_json TEXT NOT NULL,
                    territorial_scope TEXT NOT NULL,
                    is_verified_grounded INTEGER NOT NULL,
                    retry_count INTEGER NOT NULL,
                    estimated_cost_usd REAL NOT NULL,
                    estimated_cost_myr REAL NOT NULL,
                    total_tokens INTEGER NOT NULL,
                    model_used TEXT,
                    trace_id TEXT,
                    citation_span_ids_json TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    prev_chain_hash TEXT NOT NULL,
                    chain_hash TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    telemetry_json TEXT NOT NULL
                )
                """
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM attestations")
            self._conn.commit()

    def _row_to_record(self, row: sqlite3.Row) -> AttestationLedgerRecord:
        return AttestationLedgerRecord(
            manifest_id=row["manifest_id"],
            document_id=row["document_id"],
            input_doc_sha256=row["input_doc_sha256"],
            graph_state_hash=row["graph_state_hash"],
            as_of_date=date.fromisoformat(row["as_of_date"]),
            regimes=json.loads(row["regimes_json"]),
            territorial_scope=row["territorial_scope"],
            is_verified_grounded=bool(row["is_verified_grounded"]),
            retry_count=int(row["retry_count"]),
            estimated_cost_usd=float(row["estimated_cost_usd"]),
            estimated_cost_myr=float(row["estimated_cost_myr"]),
            total_tokens=int(row["total_tokens"]),
            model_used=row["model_used"],
            trace_id=row["trace_id"],
            citation_span_ids=json.loads(row["citation_span_ids_json"]),
            manifest_sha256=row["manifest_sha256"],
            prev_chain_hash=row["prev_chain_hash"],
            chain_hash=row["chain_hash"],
            recorded_at=row["recorded_at"],
            telemetry_snapshot=json.loads(row["telemetry_json"]),
        )

    def record(
        self,
        manifest: ComplianceAttestationManifest,
        telemetry: TelemetrySummary | None = None,
    ) -> AttestationLedgerRecord:
        """
        Appends a manifest + telemetry snapshot into the hash-chained ledger.

        Idempotent if an identical manifest_id + manifest_sha256 already exists;
        raises ValueError if manifest_id collides with a different digest.
        """
        computed_manifest_sha = manifest.manifest_sha256 or compute_manifest_sha256(
            manifest
        )
        manifest_id = (
            manifest.manifest_id.strip()
            if manifest.manifest_id
            else f"ATT-{computed_manifest_sha[:10].upper()}-{uuid.uuid4().hex[:6].upper()}"
        )
        model_used = manifest.model_used or (
            telemetry.model_name if telemetry else None
        )
        telemetry_dict: dict[str, Any] = (
            telemetry.model_dump(mode="json") if telemetry is not None else {}
        )

        with self._lock:
            existing = self._conn.execute(
                "SELECT * FROM attestations WHERE manifest_id = ?", (manifest_id,)
            ).fetchone()
            if existing is not None:
                rec = self._row_to_record(existing)
                if (
                    rec.manifest_sha256 == computed_manifest_sha
                    and rec.input_doc_sha256 == manifest.input_doc_sha256
                    and rec.graph_state_hash == manifest.graph_state_hash
                ):
                    manifest.manifest_id = rec.manifest_id
                    manifest.manifest_sha256 = rec.manifest_sha256
                    manifest.prev_chain_hash = rec.prev_chain_hash
                    manifest.chain_hash = rec.chain_hash
                    return rec
                raise ValueError(
                    f"Manifest ID collision for '{manifest_id}' with differing digest."
                )

            tail = self._conn.execute(
                "SELECT seq, chain_hash FROM attestations ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            next_seq = (int(tail["seq"]) + 1) if tail is not None else 1
            prev_hash = (
                str(tail["chain_hash"]) if tail is not None else GENESIS_CHAIN_HASH
            )

            sorted_citations = sorted(set(manifest.citation_span_ids))
            chain_hash = compute_chain_hash(
                seq=next_seq,
                manifest_id=manifest_id,
                document_id=manifest.document_id,
                manifest_sha256=computed_manifest_sha,
                input_doc_sha256=manifest.input_doc_sha256,
                graph_state_hash=manifest.graph_state_hash,
                as_of_date=manifest.as_of_date,
                regimes=manifest.regimes,
                territorial_scope=manifest.territorial_scope,
                is_verified_grounded=manifest.is_verified_grounded,
                retry_count=manifest.retry_count,
                estimated_cost_usd=manifest.estimated_cost_usd,
                estimated_cost_myr=manifest.estimated_cost_myr,
                total_tokens=manifest.total_tokens,
                model_used=model_used,
                citation_span_ids=sorted_citations,
                prev_chain_hash=prev_hash,
            )
            recorded_at = datetime.now(UTC).isoformat()

            self._conn.execute(
                """
                INSERT INTO attestations (
                    seq, manifest_id, document_id, input_doc_sha256, graph_state_hash,
                    as_of_date, regimes_json, territorial_scope, is_verified_grounded,
                    retry_count, estimated_cost_usd, estimated_cost_myr, total_tokens,
                    model_used, trace_id, citation_span_ids_json, manifest_sha256,
                    prev_chain_hash, chain_hash, recorded_at, telemetry_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    next_seq,
                    manifest_id,
                    manifest.document_id,
                    manifest.input_doc_sha256,
                    manifest.graph_state_hash,
                    manifest.as_of_date.isoformat(),
                    json.dumps(manifest.regimes),
                    manifest.territorial_scope,
                    1 if manifest.is_verified_grounded else 0,
                    manifest.retry_count,
                    manifest.estimated_cost_usd,
                    manifest.estimated_cost_myr,
                    manifest.total_tokens,
                    model_used,
                    manifest.trace_id,
                    json.dumps(sorted_citations),
                    computed_manifest_sha,
                    prev_hash,
                    chain_hash,
                    recorded_at,
                    json.dumps(telemetry_dict, sort_keys=True),
                ),
            )
            self._conn.commit()

            manifest.manifest_id = manifest_id
            manifest.manifest_sha256 = computed_manifest_sha
            manifest.prev_chain_hash = prev_hash
            manifest.chain_hash = chain_hash

            row = self._conn.execute(
                "SELECT * FROM attestations WHERE manifest_id = ?", (manifest_id,)
            ).fetchone()
            assert row is not None
            return self._row_to_record(row)

    def get(self, manifest_id: str) -> AttestationLedgerRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM attestations WHERE manifest_id = ?", (manifest_id,)
            ).fetchone()
            return self._row_to_record(row) if row is not None else None

    def list_records(self) -> list[AttestationLedgerRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM attestations ORDER BY seq ASC"
            ).fetchall()
            return [self._row_to_record(r) for r in rows]

    def verify(
        self,
        *,
        manifest_id: str | None = None,
        raw_text: str | None = None,
        expected_doc_sha256: str | None = None,
        manifest: ComplianceAttestationManifest | None = None,
    ) -> AttestationVerifyResponse:
        """
        Verifies document digest, canonical manifest SHA-256, citation spans,
        as_of_date integrity, and append-only ledger hash chain.
        """
        started = time.perf_counter()
        target_id = (
            manifest_id.strip()
            if manifest_id
            else (
                manifest.manifest_id.strip()
                if manifest and manifest.manifest_id
                else ""
            )
        )

        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM attestations ORDER BY seq ASC"
            ).fetchall()

        if not rows or not target_id:
            telemetry = compute_telemetry_summary(
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=(time.perf_counter() - started) * 1000.0,
                retry_count=0,
                is_verified_grounded=False,
            )
            return AttestationVerifyResponse(
                manifest_id=target_id or "UNKNOWN",
                verified=False,
                status="NOT_FOUND",
                tamper_reasons=[
                    f"Attestation manifest '{target_id or 'UNKNOWN'}' was not found in the ledger."
                ],
                telemetry=telemetry,
            )

        # Verify entire hash chain sequentially from GENESIS_CHAIN_HASH
        ledger_chain_valid = True
        expected_prev = GENESIS_CHAIN_HASH
        expected_seq = 1
        target_record: AttestationLedgerRecord | None = None
        target_chain_valid = False
        target_manifest_sha_valid = False
        tamper_reasons: list[str] = []

        for row in rows:
            rec = self._row_to_record(row)
            seq = int(row["seq"])

            row_manifest_basis = ComplianceAttestationManifest(
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
            recomputed_msha = compute_manifest_sha256(row_manifest_basis)
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
                prev_chain_hash=expected_prev,
            )

            row_ok = (
                seq == expected_seq
                and rec.prev_chain_hash == expected_prev
                and rec.manifest_sha256 == recomputed_msha
                and rec.chain_hash == recomputed_chain
            )
            if not row_ok:
                ledger_chain_valid = False
                tamper_reasons.append(
                    f"Ledger hash-chain integrity failure at sequence {seq} (manifest '{rec.manifest_id}')."
                )

            if rec.manifest_id == target_id:
                target_record = rec
                target_chain_valid = row_ok
                target_manifest_sha_valid = rec.manifest_sha256 == recomputed_msha

            expected_prev = rec.chain_hash
            expected_seq = seq + 1

        if target_record is None:
            telemetry = compute_telemetry_summary(
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=(time.perf_counter() - started) * 1000.0,
                retry_count=0,
                is_verified_grounded=False,
            )
            return AttestationVerifyResponse(
                manifest_id=target_id,
                verified=False,
                status="NOT_FOUND",
                ledger_chain_valid=ledger_chain_valid,
                tamper_reasons=[
                    f"Attestation manifest '{target_id}' was not found in the ledger."
                ],
                telemetry=telemetry,
            )

        digest_matches = True
        if raw_text is not None:
            actual_sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
            if actual_sha != target_record.input_doc_sha256:
                digest_matches = False
                tamper_reasons.append(
                    "Submitted document raw_text SHA-256 does not match attested input_doc_sha256."
                )

        if expected_doc_sha256 is not None and (
            expected_doc_sha256.strip().lower()
            != target_record.input_doc_sha256.lower()
        ):
            digest_matches = False
            tamper_reasons.append(
                "Provided expected_doc_sha256 does not match attested input_doc_sha256."
            )

        if manifest is not None:
            submitted_recomputed = compute_manifest_sha256(manifest)
            if manifest.manifest_sha256 and (
                manifest.manifest_sha256 != submitted_recomputed
                or manifest.manifest_sha256 != target_record.manifest_sha256
            ):
                target_manifest_sha_valid = False
                tamper_reasons.append(
                    "Submitted manifest_sha256 does not match canonical digest or ledger record."
                )
            if manifest.input_doc_sha256 != target_record.input_doc_sha256:
                digest_matches = False
                tamper_reasons.append(
                    "Submitted manifest input_doc_sha256 differs from ledger record."
                )
            if manifest.as_of_date != target_record.as_of_date:
                target_manifest_sha_valid = False
                tamper_reasons.append(
                    "Submitted manifest as_of_date differs from attested statutory snapshot."
                )
            if manifest.graph_state_hash != target_record.graph_state_hash:
                target_manifest_sha_valid = False
                tamper_reasons.append(
                    "Submitted manifest graph_state_hash differs from attested statutory graph state."
                )
            if manifest.regimes != target_record.regimes:
                target_manifest_sha_valid = False
                tamper_reasons.append(
                    "Submitted manifest regimes differ from attested record."
                )
            if manifest.territorial_scope != target_record.territorial_scope:
                target_manifest_sha_valid = False
                tamper_reasons.append(
                    "Submitted manifest territorial_scope differs from attested record."
                )
            if sorted(set(manifest.citation_span_ids)) != sorted(
                set(target_record.citation_span_ids)
            ):
                target_manifest_sha_valid = False
                tamper_reasons.append(
                    "Submitted manifest citation_span_ids differ from attested SourceSpan IDs."
                )
            if manifest.is_verified_grounded != target_record.is_verified_grounded:
                target_manifest_sha_valid = False
                tamper_reasons.append(
                    "Submitted manifest is_verified_grounded flag differs from attested record."
                )
            if manifest.chain_hash and manifest.chain_hash != target_record.chain_hash:
                target_chain_valid = False
                tamper_reasons.append(
                    "Submitted manifest chain_hash does not match ledger chain_hash."
                )

        verified = (
            digest_matches
            and target_manifest_sha_valid
            and target_chain_valid
            and ledger_chain_valid
            and len(tamper_reasons) == 0
        )

        telemetry = compute_telemetry_summary(
            prompt_tokens=0,
            completion_tokens=0,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            retry_count=0,
            is_verified_grounded=verified,
        )

        return AttestationVerifyResponse(
            manifest_id=target_record.manifest_id,
            verified=verified,
            status="VERIFIED" if verified else "TAMPERED",
            digest_matches=digest_matches,
            manifest_sha256_valid=target_manifest_sha_valid,
            chain_link_valid=target_chain_valid,
            ledger_chain_valid=ledger_chain_valid,
            tamper_reasons=tamper_reasons,
            record=target_record,
            telemetry=telemetry,
        )


default_attestation_ledger = AttestationLedger(db_path=settings.attestation_db_path)
