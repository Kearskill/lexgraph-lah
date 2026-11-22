"""
Tamper-evident Cryptographic Attestation Ledger & Verifier (SQLite WAL / PostgreSQL + Ed25519).

Persists `ComplianceAttestationManifest` records and FinOps `TelemetrySummary`
snapshots inside an append-only SHA-256 hash chain whose chain tips are signed
with Ed25519 (or an injected KMS `AttestationSigner`), so post-hoc alterations to
contracts, `as_of_date` snapshots, `citation_span_ids`, FinOps metrics, or ledger
rows/signatures are detected immediately.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from lexgraph_lah.config import settings
from lexgraph_lah.schemas.domain import (
    AttestationLedgerRecord,
    AttestationPublicKeyResponse,
    AttestationVerifyResponse,
    ComplianceAttestationManifest,
    TelemetrySummary,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary

GENESIS_CHAIN_HASH = "0" * 64


@runtime_checkable
class AttestationSigner(Protocol):
    """Protocol for asymmetric attestation signers (local Ed25519 or KMS-backed)."""

    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> str: ...

    def public_key_pem(self) -> str: ...

    def public_key_raw_bytes(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...

    def verify(self, message: bytes, signature: bytes) -> bool: ...


class Ed25519AttestationSigner:
    """Ed25519 asymmetric signer backed by PEM private key or process-local keypair."""

    def __init__(
        self,
        *,
        private_key_pem: str | None = None,
        key_id: str | None = None,
    ) -> None:
        raw_pem = (private_key_pem or "").strip()
        if raw_pem:
            loaded = serialization.load_pem_private_key(
                raw_pem.encode("utf-8"), password=None
            )
            if not isinstance(loaded, Ed25519PrivateKey):
                raise ValueError(
                    "ATTESTATION_ED25519_PRIVATE_KEY_PEM must be an Ed25519 key."
                )
            self._private_key = loaded
        else:
            self._private_key = Ed25519PrivateKey.generate()
        self._public_key: Ed25519PublicKey = self._private_key.public_key()
        self._key_id = (
            key_id or settings.attestation_ed25519_key_id or "lexgraph-ed25519-v1"
        ).strip()

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return "Ed25519"

    def public_key_raw_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False


def build_chain_tip_signing_message(
    *,
    seq: int,
    manifest_id: str,
    manifest_sha256: str,
    chain_hash: str,
) -> bytes:
    """Canonical byte payload signed by Ed25519 / KMS for each appended ledger chain tip."""
    payload = json.dumps(
        {
            "seq": seq,
            "manifest_id": manifest_id,
            "manifest_sha256": manifest_sha256,
            "chain_hash": chain_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return payload.encode()


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


@runtime_checkable
class AttestationStorageBackend(Protocol):
    """Persistence abstraction supporting SQLite WAL (single-node) and PostgreSQL (multi-replica)."""

    def init_schema(self) -> None: ...

    def get_by_manifest_id(self, manifest_id: str) -> dict[str, Any] | None: ...

    def get_tail_seq_and_hash(self) -> tuple[int, str] | None: ...

    def insert_row(self, row_data: dict[str, Any]) -> None: ...

    def list_rows(self) -> list[dict[str, Any]]: ...

    def clear(self) -> None: ...

    def close(self) -> None: ...


class SQLiteAttestationBackend:
    """Thread-safe SQLite WAL storage backend for append-only attestation rows."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    def init_schema(self) -> None:
        with self._lock:
            if self.db_path != ":memory:":
                self.conn.execute("PRAGMA journal_mode=WAL;")
                self.conn.execute("PRAGMA synchronous=NORMAL;")
            self.conn.execute(
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
                    signature_b64 TEXT NOT NULL DEFAULT '',
                    signing_key_id TEXT NOT NULL DEFAULT '',
                    signature_algorithm TEXT NOT NULL DEFAULT 'Ed25519',
                    recorded_at TEXT NOT NULL,
                    telemetry_json TEXT NOT NULL
                )
                """
            )
            existing_cols = {
                str(r["name"])
                for r in self.conn.execute("PRAGMA table_info(attestations)").fetchall()
            }
            for col_name, ddl_def in (
                ("signature_b64", "TEXT NOT NULL DEFAULT ''"),
                ("signing_key_id", "TEXT NOT NULL DEFAULT ''"),
                ("signature_algorithm", "TEXT NOT NULL DEFAULT 'Ed25519'"),
            ):
                if col_name not in existing_cols:
                    self.conn.execute(
                        f"ALTER TABLE attestations ADD COLUMN {col_name} {ddl_def}"
                    )
            self.conn.commit()

    def get_by_manifest_id(self, manifest_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM attestations WHERE manifest_id = ?", (manifest_id,)
            ).fetchone()
            return dict(row) if row is not None else None

    def get_tail_seq_and_hash(self) -> tuple[int, str] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT seq, chain_hash FROM attestations ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            return (
                (int(row["seq"]), str(row["chain_hash"])) if row is not None else None
            )

    def insert_row(self, row_data: dict[str, Any]) -> None:
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO attestations (
                    seq, manifest_id, document_id, input_doc_sha256, graph_state_hash,
                    as_of_date, regimes_json, territorial_scope, is_verified_grounded,
                    retry_count, estimated_cost_usd, estimated_cost_myr, total_tokens,
                    model_used, trace_id, citation_span_ids_json, manifest_sha256,
                    prev_chain_hash, chain_hash, signature_b64, signing_key_id,
                    signature_algorithm, recorded_at, telemetry_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row_data["seq"],
                    row_data["manifest_id"],
                    row_data["document_id"],
                    row_data["input_doc_sha256"],
                    row_data["graph_state_hash"],
                    row_data["as_of_date"],
                    row_data["regimes_json"],
                    row_data["territorial_scope"],
                    row_data["is_verified_grounded"],
                    row_data["retry_count"],
                    row_data["estimated_cost_usd"],
                    row_data["estimated_cost_myr"],
                    row_data["total_tokens"],
                    row_data["model_used"],
                    row_data["trace_id"],
                    row_data["citation_span_ids_json"],
                    row_data["manifest_sha256"],
                    row_data["prev_chain_hash"],
                    row_data["chain_hash"],
                    row_data["signature_b64"],
                    row_data["signing_key_id"],
                    row_data["signature_algorithm"],
                    row_data["recorded_at"],
                    row_data["telemetry_json"],
                ),
            )
            self.conn.commit()

    def list_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM attestations ORDER BY seq ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def clear(self) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM attestations")
            self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.close()


class PostgresAttestationBackend:
    """
    Multi-replica PostgreSQL storage backend for `AttestationLedger`.

    Loads `psycopg` dynamically via `importlib.import_module("psycopg")` unless a custom
    DB-API `connection_factory` is supplied (enabling deterministic unit tests).
    """

    def __init__(
        self,
        dsn: str,
        *,
        connection_factory: Callable[[], Any] | None = None,
    ) -> None:
        self._dsn = dsn
        self._connection_factory = connection_factory
        self._lock = threading.RLock()
        self._conn: Any = None

    def _get_conn(self) -> Any:
        if self._conn is None:
            if self._connection_factory is not None:
                self._conn = self._connection_factory()
            else:
                psycopg = importlib.import_module("psycopg")
                self._conn = psycopg.connect(self._dsn)
        return self._conn

    @staticmethod
    def _cursor_rows_to_dicts(cur: Any, rows: list[Any]) -> list[dict[str, Any]]:
        if not rows:
            return []
        if isinstance(rows[0], dict):
            return [dict(r) for r in rows]
        cols = [str(col[0]) for col in (cur.description or ())]
        return [dict(zip(cols, r, strict=False)) for r in rows]

    def init_schema(self) -> None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
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
                        estimated_cost_usd DOUBLE PRECISION NOT NULL,
                        estimated_cost_myr DOUBLE PRECISION NOT NULL,
                        total_tokens INTEGER NOT NULL,
                        model_used TEXT,
                        trace_id TEXT,
                        citation_span_ids_json TEXT NOT NULL,
                        manifest_sha256 TEXT NOT NULL,
                        prev_chain_hash TEXT NOT NULL,
                        chain_hash TEXT NOT NULL,
                        signature_b64 TEXT NOT NULL DEFAULT '',
                        signing_key_id TEXT NOT NULL DEFAULT '',
                        signature_algorithm TEXT NOT NULL DEFAULT 'Ed25519',
                        recorded_at TEXT NOT NULL,
                        telemetry_json TEXT NOT NULL
                    )
                    """
                )
            conn.commit()

    def get_by_manifest_id(self, manifest_id: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM attestations WHERE manifest_id = %s",
                    (manifest_id,),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                return self._cursor_rows_to_dicts(cur, [row])[0]

    def get_tail_seq_and_hash(self) -> tuple[int, str] | None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT seq, chain_hash FROM attestations ORDER BY seq DESC LIMIT 1"
                )
                row = cur.fetchone()
                if row is None:
                    return None
                if isinstance(row, dict):
                    return int(row["seq"]), str(row["chain_hash"])
                return int(row[0]), str(row[1])

    def insert_row(self, row_data: dict[str, Any]) -> None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO attestations (
                        seq, manifest_id, document_id, input_doc_sha256, graph_state_hash,
                        as_of_date, regimes_json, territorial_scope, is_verified_grounded,
                        retry_count, estimated_cost_usd, estimated_cost_myr, total_tokens,
                        model_used, trace_id, citation_span_ids_json, manifest_sha256,
                        prev_chain_hash, chain_hash, signature_b64, signing_key_id,
                        signature_algorithm, recorded_at, telemetry_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        row_data["seq"],
                        row_data["manifest_id"],
                        row_data["document_id"],
                        row_data["input_doc_sha256"],
                        row_data["graph_state_hash"],
                        row_data["as_of_date"],
                        row_data["regimes_json"],
                        row_data["territorial_scope"],
                        row_data["is_verified_grounded"],
                        row_data["retry_count"],
                        row_data["estimated_cost_usd"],
                        row_data["estimated_cost_myr"],
                        row_data["total_tokens"],
                        row_data["model_used"],
                        row_data["trace_id"],
                        row_data["citation_span_ids_json"],
                        row_data["manifest_sha256"],
                        row_data["prev_chain_hash"],
                        row_data["chain_hash"],
                        row_data["signature_b64"],
                        row_data["signing_key_id"],
                        row_data["signature_algorithm"],
                        row_data["recorded_at"],
                        row_data["telemetry_json"],
                    ),
                )
            conn.commit()

    def list_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM attestations ORDER BY seq ASC")
                rows = cur.fetchall()
                return self._cursor_rows_to_dicts(cur, rows)

    def clear(self) -> None:
        with self._lock:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute("DELETE FROM attestations")
            conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


class AttestationLedger:
    """
    Thread-safe append-only attestation ledger with SHA-256 hash chaining AND
    asymmetric Ed25519 / KMS chain-tip signatures across SQLite WAL or PostgreSQL.
    """

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        *,
        signer: AttestationSigner | None = None,
        backend: AttestationStorageBackend | None = None,
        postgres_dsn: str | None = None,
    ) -> None:
        self._db_path = str(db_path)
        self._lock = threading.RLock()
        self._signer: AttestationSigner = signer or Ed25519AttestationSigner(
            private_key_pem=settings.attestation_ed25519_private_key_pem or None,
            key_id=settings.attestation_ed25519_key_id,
        )
        if backend is not None:
            self._backend = backend
        elif postgres_dsn or (
            settings.attestation_backend.strip().lower() == "postgres"
            and settings.attestation_postgres_dsn.strip()
        ):
            self._backend = PostgresAttestationBackend(
                postgres_dsn or settings.attestation_postgres_dsn
            )
        else:
            self._backend = SQLiteAttestationBackend(self._db_path)

        self._conn: sqlite3.Connection | None = (
            self._backend.conn
            if isinstance(self._backend, SQLiteAttestationBackend)
            else None
        )
        self._backend.init_schema()

    @property
    def db_path(self) -> str:
        return self._db_path

    @property
    def signer(self) -> AttestationSigner:
        return self._signer

    def get_public_key_info(self) -> AttestationPublicKeyResponse:
        raw_pub = self._signer.public_key_raw_bytes()
        return AttestationPublicKeyResponse(
            key_id=self._signer.key_id,
            algorithm="Ed25519",
            public_key_pem=self._signer.public_key_pem(),
            public_key_b64=base64.b64encode(raw_pub).decode("ascii"),
            fingerprint_sha256=hashlib.sha256(raw_pub).hexdigest(),
        )

    def close(self) -> None:
        with self._lock:
            self._backend.close()

    def clear(self) -> None:
        with self._lock:
            self._backend.clear()

    def _row_to_record(self, row: dict[str, Any]) -> AttestationLedgerRecord:
        return AttestationLedgerRecord(
            manifest_id=str(row["manifest_id"]),
            document_id=str(row["document_id"]),
            input_doc_sha256=str(row["input_doc_sha256"]),
            graph_state_hash=str(row["graph_state_hash"]),
            as_of_date=date.fromisoformat(str(row["as_of_date"])),
            regimes=json.loads(str(row["regimes_json"])),
            territorial_scope=str(row["territorial_scope"]),
            is_verified_grounded=bool(row["is_verified_grounded"]),
            retry_count=int(row["retry_count"]),
            estimated_cost_usd=float(row["estimated_cost_usd"]),
            estimated_cost_myr=float(row["estimated_cost_myr"]),
            total_tokens=int(row["total_tokens"]),
            model_used=row.get("model_used"),
            trace_id=row.get("trace_id"),
            citation_span_ids=json.loads(str(row["citation_span_ids_json"])),
            manifest_sha256=str(row["manifest_sha256"]),
            prev_chain_hash=str(row["prev_chain_hash"]),
            chain_hash=str(row["chain_hash"]),
            signature_b64=str(row.get("signature_b64") or ""),
            signing_key_id=str(row.get("signing_key_id") or ""),
            signature_algorithm=str(row.get("signature_algorithm") or "Ed25519"),
            recorded_at=str(row["recorded_at"]),
            telemetry_snapshot=json.loads(str(row["telemetry_json"])),
        )

    def record(
        self,
        manifest: ComplianceAttestationManifest,
        telemetry: TelemetrySummary | None = None,
    ) -> AttestationLedgerRecord:
        """
        Appends a manifest + telemetry snapshot into the hash-chained ledger and signs
        the chain tip with Ed25519 / KMS.

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
            existing = self._backend.get_by_manifest_id(manifest_id)
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
                    manifest.signature_b64 = rec.signature_b64
                    manifest.signing_key_id = rec.signing_key_id
                    manifest.signature_algorithm = rec.signature_algorithm
                    return rec
                raise ValueError(
                    f"Manifest ID collision for '{manifest_id}' with differing digest."
                )

            tail = self._backend.get_tail_seq_and_hash()
            next_seq = (tail[0] + 1) if tail is not None else 1
            prev_hash = tail[1] if tail is not None else GENESIS_CHAIN_HASH

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
            tip_msg = build_chain_tip_signing_message(
                seq=next_seq,
                manifest_id=manifest_id,
                manifest_sha256=computed_manifest_sha,
                chain_hash=chain_hash,
            )
            signature_b64 = base64.b64encode(self._signer.sign(tip_msg)).decode("ascii")
            signing_key_id = self._signer.key_id
            signature_algorithm = self._signer.algorithm
            recorded_at = datetime.now(UTC).isoformat()

            row_payload: dict[str, Any] = {
                "seq": next_seq,
                "manifest_id": manifest_id,
                "document_id": manifest.document_id,
                "input_doc_sha256": manifest.input_doc_sha256,
                "graph_state_hash": manifest.graph_state_hash,
                "as_of_date": manifest.as_of_date.isoformat(),
                "regimes_json": json.dumps(manifest.regimes),
                "territorial_scope": manifest.territorial_scope,
                "is_verified_grounded": 1 if manifest.is_verified_grounded else 0,
                "retry_count": manifest.retry_count,
                "estimated_cost_usd": manifest.estimated_cost_usd,
                "estimated_cost_myr": manifest.estimated_cost_myr,
                "total_tokens": manifest.total_tokens,
                "model_used": model_used,
                "trace_id": manifest.trace_id,
                "citation_span_ids_json": json.dumps(sorted_citations),
                "manifest_sha256": computed_manifest_sha,
                "prev_chain_hash": prev_hash,
                "chain_hash": chain_hash,
                "signature_b64": signature_b64,
                "signing_key_id": signing_key_id,
                "signature_algorithm": signature_algorithm,
                "recorded_at": recorded_at,
                "telemetry_json": json.dumps(telemetry_dict, sort_keys=True),
            }
            self._backend.insert_row(row_payload)

            manifest.manifest_id = manifest_id
            manifest.manifest_sha256 = computed_manifest_sha
            manifest.prev_chain_hash = prev_hash
            manifest.chain_hash = chain_hash
            manifest.signature_b64 = signature_b64
            manifest.signing_key_id = signing_key_id
            manifest.signature_algorithm = signature_algorithm

            inserted = self._backend.get_by_manifest_id(manifest_id)
            assert inserted is not None
            return self._row_to_record(inserted)

    def get(self, manifest_id: str) -> AttestationLedgerRecord | None:
        with self._lock:
            row = self._backend.get_by_manifest_id(manifest_id)
            return self._row_to_record(row) if row is not None else None

    def list_records(self) -> list[AttestationLedgerRecord]:
        with self._lock:
            return [self._row_to_record(r) for r in self._backend.list_rows()]

    def _verify_row_signature(self, seq: int, rec: AttestationLedgerRecord) -> bool:
        if not rec.signature_b64:
            return False
        try:
            sig_bytes = base64.b64decode(rec.signature_b64, validate=True)
        except ValueError:
            return False
        tip_msg = build_chain_tip_signing_message(
            seq=seq,
            manifest_id=rec.manifest_id,
            manifest_sha256=rec.manifest_sha256,
            chain_hash=rec.chain_hash,
        )
        return self._signer.verify(tip_msg, sig_bytes)

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
        as_of_date integrity, append-only ledger hash chain, and Ed25519 signature.
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
            rows = self._backend.list_rows()

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

        ledger_chain_valid = True
        expected_prev = GENESIS_CHAIN_HASH
        expected_seq = 1
        target_record: AttestationLedgerRecord | None = None
        target_chain_valid = False
        target_manifest_sha_valid = False
        target_sig_valid = False
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

            sig_ok = self._verify_row_signature(seq, rec)
            if not sig_ok:
                ledger_chain_valid = False
                tamper_reasons.append(
                    f"Asymmetric Ed25519 signature verification failed at sequence {seq} (manifest '{rec.manifest_id}')."
                )

            if rec.manifest_id == target_id:
                target_record = rec
                target_chain_valid = row_ok
                target_manifest_sha_valid = rec.manifest_sha256 == recomputed_msha
                target_sig_valid = sig_ok

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
            if (
                manifest.signature_b64
                and manifest.signature_b64 != target_record.signature_b64
            ):
                target_sig_valid = False
                tamper_reasons.append(
                    "Submitted manifest Ed25519 signature differs from ledger signature."
                )

        verified = (
            digest_matches
            and target_manifest_sha_valid
            and target_chain_valid
            and ledger_chain_valid
            and target_sig_valid
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
            signature_valid=target_sig_valid,
            signing_key_id=target_record.signing_key_id or self._signer.key_id,
            signature_algorithm=target_record.signature_algorithm
            or self._signer.algorithm,
            tamper_reasons=tamper_reasons,
            record=target_record,
            telemetry=telemetry,
        )


default_attestation_ledger = AttestationLedger(db_path=settings.attestation_db_path)
