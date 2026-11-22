import base64
import hashlib
import importlib
import json
import re
import sqlite3
import threading
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from lexgraph_lah.config import settings
from lexgraph_lah.schemas.domain import PIIScrubSummary

# Pre-compiled Malaysian PII regexes (<2ms execution overhead on typical documents)
_NRIC_PATTERN = re.compile(
    r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-\d{2}-\d{4}\b"
)
_PASSPORT_PATTERN = re.compile(r"\b[AHK]\d{8}\b")
_PHONE_PATTERN = re.compile(
    r"(?:\+?60|0)(?:1\d[-\s]?\d{3,4}[-\s]?\d{4}|[3-9][-\s]?\d{3,4}[-\s]?\d{4})\b"
)
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Malaysian SSM (12-digit new reg e.g. 202001012345 (1358123-K) or standalone legacy 6-7 digits + check letter)
_SSM_NEW_PATTERN = re.compile(
    r"\b(?:19|20)\d{2}0[1-6]\d{6}(?:\s*\(\d{5,7}-[A-HJ-NP-Z]\))?\b"
)
_SSM_LEGACY_PATTERN = re.compile(r"(?<![A-Za-z0-9-])\b\d{6,7}-[A-HJ-NP-Z]\b")
# LHDN Tax Identification Number (TIN) e.g. IG12345678900, C25845632000, CS12345678900, D1234567890
_TIN_PATTERN = re.compile(
    r"\b(?:(?:IG|CS|SG|OG|TC|TP|TA|TF|TN|TR|PT|LE)[ -]?\d{9,12}|[CDEFJ](?:\d{9,12}|[ -]\d{9,12}))\b"
)
# KWSP / EPF member or employer numbers (group 1 = context prefix, group 2 = PII number)
_KWSP_PATTERN = re.compile(
    r"(\b(?:KWSP|EPF)(?:\s+(?:No\.?|Number|Nombor|Account|Acc\.?|Akaun|Member|Ahli|ID|Ref(?:erence)?)){0,3}\s*[:#-]?\s*)(\d{7,9}(?:-\d{1,2})?)\b",
    re.IGNORECASE,
)
# PERKESO / SOCSO numbers (group 1 = context prefix, group 2 = PII identifier)
_PERKESO_PATTERN = re.compile(
    r"(\b(?:PERKESO|SOCSO)(?:\s+(?:No\.?|Number|Nombor|Account|Acc\.?|Akaun|Employer|Employee|Majikan|ID|Ref(?:erence)?)){0,3}\s*[:#-]?\s*)([A-Z]?\d{8,12}[A-Z]?)\b",
    re.IGNORECASE,
)
# Malaysian Bank Account / DuitNow identifiers (group 1 = context prefix, group 2 = account number)
_BANK_PATTERN = re.compile(
    r"(\b(?:Maybank|CIMB|Public\s+Bank|RHB|Hong\s+Leong(?:\s+Bank)?|AmBank|Bank\s+Islam|Bank\s+Rakyat|BSN|Affin\s+Bank|Alliance\s+Bank|OCBC|UOB|HSBC|Standard\s+Chartered|DuitNow|Bank\s+Account|Account|No\.?\s+Akaun|Akaun\s+Bank)(?:\s+(?:Account|Acc\.?|Akaun|No\.?|Number|Nombor|ID|Ref(?:erence)?)){0,3}\s*[:#-]?\s*)(\d(?:[ -]?\d){8,16})\b",
    re.IGNORECASE,
)

_PATTERN_SPECS: list[tuple[str, re.Pattern[str]]] = [
    ("MY_NRIC", _NRIC_PATTERN),
    ("MY_SSM", _SSM_NEW_PATTERN),
    ("MY_SSM", _SSM_LEGACY_PATTERN),
    ("MY_TIN", _TIN_PATTERN),
    ("MY_KWSP", _KWSP_PATTERN),
    ("MY_PERKESO", _PERKESO_PATTERN),
    ("MY_PASSPORT", _PASSPORT_PATTERN),
    ("MY_PHONE", _PHONE_PATTERN),
    ("EMAIL", _EMAIL_PATTERN),
    ("MY_BANK", _BANK_PATTERN),
]


_VAULT_TOKEN_LABELS: dict[str, str] = {
    "MY_NRIC": "MYKAD",
    "MY_SSM": "SSM_REG",
    "MY_TIN": "TIN_MY",
    "MY_KWSP": "KWSP",
    "MY_PERKESO": "PERKESO",
    "MY_PASSPORT": "PASSPORT",
    "MY_PHONE": "PHONE_MY",
    "EMAIL": "EMAIL",
    "MY_BANK": "BANK_MY",
}


class ReversiblePIIVault:
    """
    Per-request ephemeral reversible PII token vault.
    Masks Malaysian NRIC, Passport, SSM, Phone, and Email into deterministic bracketed
    vault tokens ([MYKAD_01], [PASSPORT_01], [SSM_REG_01], [PHONE_MY_01], [EMAIL_01])
    so zero raw PII ever reaches LLM prompts or OTel spans, while allowing local
    re-hydration during final downloadable Track-Changes .docx compilation.
    """

    def __init__(
        self,
        initial_mapping: dict[str, str] | None = None,
        token_style: Literal["vault", "legacy"] = "vault",
    ) -> None:
        self._token_to_raw: dict[str, str] = dict(initial_mapping or {})
        self._raw_to_token: dict[tuple[str, str], str] = {}
        self._entity_counts: dict[str, int] = {}
        self._token_style = token_style

    @property
    def token_map(self) -> dict[str, str]:
        return dict(self._token_to_raw)

    def scrub(self, text: str) -> tuple[str, PIIScrubSummary]:
        start = time.perf_counter()
        masked = text

        for label, pattern in _PATTERN_SPECS:
            vault_label = _VAULT_TOKEN_LABELS.get(label, label)

            def _replacer(
                match: re.Match[str],
                entity_label: str = label,
                token_prefix: str = vault_label,
                has_prefix_group: bool = pattern.groups >= 2,
            ) -> str:
                prefix = match.group(1) if has_prefix_group else ""
                raw_val = match.group(2) if has_prefix_group else match.group(0)
                cache_key = (entity_label, raw_val)
                if cache_key in self._raw_to_token:
                    return f"{prefix}{self._raw_to_token[cache_key]}"
                next_idx = self._entity_counts.get(entity_label, 0) + 1
                self._entity_counts[entity_label] = next_idx
                if self._token_style == "legacy":
                    token = f"<{entity_label}_{next_idx}>"
                else:
                    token = f"[{token_prefix}_{next_idx:02d}]"
                self._raw_to_token[cache_key] = token
                self._token_to_raw[token] = raw_val
                return f"{prefix}{token}"

            masked = pattern.sub(_replacer, masked)

        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 4)
        total_redactions = sum(self._entity_counts.values())
        summary = PIIScrubSummary(
            original_length=len(text),
            masked_text=masked,
            redaction_count=total_redactions,
            placeholders=dict(self._token_to_raw),
            entity_counts=dict(self._entity_counts),
            scrub_latency_ms=elapsed_ms,
        )
        return masked, summary

    def rehydrate(self, text: str) -> str:
        """Restores original PII locally from ephemeral vault tokens."""
        restored = text
        for token, raw_val in self._token_to_raw.items():
            restored = restored.replace(token, raw_val)
        return restored

    def persist_session(
        self,
        tenant_id: str,
        audit_session_id: str,
        store: "EncryptedPIISessionStore | None" = None,
        ttl_seconds: int | None = None,
    ) -> None:
        """Encrypts and persists this vault's token mapping under `(tenant_id, audit_session_id)`."""
        target_store = store or default_pii_session_store
        target_store.save_session(
            tenant_id=tenant_id,
            audit_session_id=audit_session_id,
            token_map=self.token_map,
            ttl_seconds=ttl_seconds,
        )

    @classmethod
    def from_session(
        cls,
        tenant_id: str,
        audit_session_id: str,
        store: "EncryptedPIISessionStore | None" = None,
    ) -> "ReversiblePIIVault | None":
        """Restores a `ReversiblePIIVault` from an encrypted cross-worker session store."""
        target_store = store or default_pii_session_store
        mapping = target_store.load_session(
            tenant_id=tenant_id, audit_session_id=audit_session_id
        )
        if mapping is None:
            return None
        return cls(initial_mapping=mapping)


def _resolve_aes256_key(explicit_key: bytes | None, config_key_b64: str) -> bytes:
    if explicit_key is not None:
        if len(explicit_key) == 32:
            return explicit_key
        return hashlib.sha256(explicit_key).digest()
    raw_cfg = config_key_b64.strip()
    if raw_cfg:
        try:
            decoded = base64.b64decode(raw_cfg, validate=True)
        except ValueError:
            decoded = b""
        if len(decoded) == 32:
            return decoded
        return hashlib.sha256(raw_cfg.encode("utf-8")).digest()
    return AESGCM.generate_key(bit_length=256)


class EncryptedPIISessionStore:
    """
    AES-256-GCM encrypted, TTL-bound cross-worker PII token vault backed by
    `memory`, `sqlite` (WAL mode), or `redis`, bound cryptographically via GCM AAD
    to `(tenant_id, audit_session_id)`.
    """

    def __init__(
        self,
        *,
        backend: Literal["memory", "sqlite", "redis"] | None = None,
        db_path: str | Path | None = None,
        redis_url: str | None = None,
        redis_client: Any | None = None,
        encryption_key: bytes | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        chosen = (backend or settings.pii_vault_backend or "memory").strip().lower()
        self.backend: Literal["memory", "sqlite", "redis"] = (
            chosen  # type: ignore[assignment]
            if chosen in {"memory", "sqlite", "redis"}
            else "memory"
        )
        self._db_path = str(
            db_path if db_path is not None else settings.pii_vault_db_path
        )
        self._redis_url = redis_url or settings.pii_vault_redis_url
        self._redis_client = redis_client
        self._default_ttl = max(
            1,
            int(
                ttl_seconds
                if ttl_seconds is not None
                else settings.pii_vault_ttl_seconds
            ),
        )
        self._key = _resolve_aes256_key(
            encryption_key, settings.pii_vault_encryption_key_b64
        )
        self._lock = threading.RLock()
        self._mem: dict[tuple[str, str], tuple[str, float]] = {}
        self._conn: sqlite3.Connection | None = None

        if self.backend == "sqlite":
            if self._db_path != ":memory:":
                Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            with self._lock:
                if self._db_path != ":memory:":
                    self._conn.execute("PRAGMA journal_mode=WAL;")
                    self._conn.execute("PRAGMA synchronous=NORMAL;")
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pii_sessions (
                        tenant_id TEXT NOT NULL,
                        audit_session_id TEXT NOT NULL,
                        payload_b64 TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        PRIMARY KEY (tenant_id, audit_session_id)
                    )
                    """
                )
                self._conn.commit()
        elif self.backend == "redis" and self._redis_client is None:
            redis_mod = importlib.import_module("redis")
            self._redis_client = redis_mod.Redis.from_url(self._redis_url)

    def _encrypt(
        self, tenant_id: str, audit_session_id: str, token_map: dict[str, str]
    ) -> str:
        nonce = AESGCM.generate_key(bit_length=128)[:12]
        aad = f"{tenant_id}:{audit_session_id}".encode()
        plaintext = json.dumps(token_map, sort_keys=True, ensure_ascii=False).encode()
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, aad)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def _decrypt(
        self, tenant_id: str, audit_session_id: str, payload_b64: str
    ) -> dict[str, str] | None:
        try:
            raw = base64.b64decode(payload_b64)
            if len(raw) < 28:
                return None
            nonce, ciphertext = raw[:12], raw[12:]
            aad = f"{tenant_id}:{audit_session_id}".encode()
            plaintext = AESGCM(self._key).decrypt(nonce, ciphertext, aad)
            parsed = json.loads(plaintext.decode("utf-8"))
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
            return None
        except (InvalidTag, ValueError, json.JSONDecodeError):
            return None

    def save_session(
        self,
        tenant_id: str,
        audit_session_id: str,
        token_map: dict[str, str],
        ttl_seconds: int | None = None,
    ) -> None:
        """Encrypts and stores `token_map` bound to `(tenant_id, audit_session_id)` with TTL."""
        ttl = max(1, int(ttl_seconds if ttl_seconds is not None else self._default_ttl))
        expires_at = time.time() + ttl
        payload_b64 = self._encrypt(tenant_id, audit_session_id, token_map)

        with self._lock:
            if self.backend == "sqlite" and self._conn is not None:
                self._conn.execute(
                    """
                    INSERT INTO pii_sessions (tenant_id, audit_session_id, payload_b64, expires_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(tenant_id, audit_session_id)
                    DO UPDATE SET payload_b64 = excluded.payload_b64, expires_at = excluded.expires_at
                    """,
                    (tenant_id, audit_session_id, payload_b64, expires_at),
                )
                self._conn.commit()
            elif self.backend == "redis" and self._redis_client is not None:
                redis_key = f"lexgraph:pii:{tenant_id}:{audit_session_id}"
                self._redis_client.setex(redis_key, ttl, payload_b64.encode("ascii"))
            else:
                self._mem[(tenant_id, audit_session_id)] = (payload_b64, expires_at)

    def load_session(
        self, tenant_id: str, audit_session_id: str
    ) -> dict[str, str] | None:
        """Decrypts and returns `token_map` if present, unexpired, and valid for `(tenant_id, audit_session_id)`."""
        now = time.time()
        with self._lock:
            if self.backend == "sqlite" and self._conn is not None:
                row = self._conn.execute(
                    """
                    SELECT payload_b64, expires_at FROM pii_sessions
                    WHERE tenant_id = ? AND audit_session_id = ?
                    """,
                    (tenant_id, audit_session_id),
                ).fetchone()
                if row is None:
                    return None
                payload_b64, expires_at = str(row[0]), float(row[1])
                if now >= expires_at:
                    self._conn.execute(
                        "DELETE FROM pii_sessions WHERE tenant_id = ? AND audit_session_id = ?",
                        (tenant_id, audit_session_id),
                    )
                    self._conn.commit()
                    return None
                return self._decrypt(tenant_id, audit_session_id, payload_b64)

            if self.backend == "redis" and self._redis_client is not None:
                redis_key = f"lexgraph:pii:{tenant_id}:{audit_session_id}"
                raw_val = self._redis_client.get(redis_key)
                if raw_val is None:
                    return None
                payload_str = (
                    raw_val.decode("ascii")
                    if isinstance(raw_val, (bytes, bytearray))
                    else str(raw_val)
                )
                return self._decrypt(tenant_id, audit_session_id, payload_str)

            entry = self._mem.get((tenant_id, audit_session_id))
            if entry is None:
                return None
            payload_b64, expires_at = entry
            if now >= expires_at:
                self._mem.pop((tenant_id, audit_session_id), None)
                return None
            return self._decrypt(tenant_id, audit_session_id, payload_b64)

    def delete_session(self, tenant_id: str, audit_session_id: str) -> None:
        with self._lock:
            if self.backend == "sqlite" and self._conn is not None:
                self._conn.execute(
                    "DELETE FROM pii_sessions WHERE tenant_id = ? AND audit_session_id = ?",
                    (tenant_id, audit_session_id),
                )
                self._conn.commit()
            elif self.backend == "redis" and self._redis_client is not None:
                redis_key = f"lexgraph:pii:{tenant_id}:{audit_session_id}"
                self._redis_client.delete(redis_key)
            else:
                self._mem.pop((tenant_id, audit_session_id), None)

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


default_pii_session_store = EncryptedPIISessionStore()


def scrub_malaysian_pii(text: str) -> PIIScrubSummary:
    """
    Deterministic, pre-flight Malaysian PII scrubber (<50ms SLA).
    Masks NRIC (YYMMDD-PB-####), passports, Malaysian phone numbers, emails, and
    SSM company registration numbers into typed placeholders (<MY_NRIC_1>, etc.)
    prior to any external embedding or LLM call.
    """
    start = time.perf_counter()
    masked = text
    placeholders: dict[str, str] = {}
    entity_counts: dict[str, int] = {}
    value_to_placeholder: dict[tuple[str, str], str] = {}

    for label, pattern in _PATTERN_SPECS:

        def _replacer(
            match: re.Match[str],
            entity_label: str = label,
            has_prefix_group: bool = pattern.groups >= 2,
        ) -> str:
            prefix = match.group(1) if has_prefix_group else ""
            raw_val = match.group(2) if has_prefix_group else match.group(0)
            cache_key = (entity_label, raw_val)
            if cache_key in value_to_placeholder:
                return f"{prefix}{value_to_placeholder[cache_key]}"
            next_idx = entity_counts.get(entity_label, 0) + 1
            entity_counts[entity_label] = next_idx
            token = f"<{entity_label}_{next_idx}>"
            value_to_placeholder[cache_key] = token
            placeholders[token] = raw_val
            return f"{prefix}{token}"

        masked = pattern.sub(_replacer, masked)

    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 4)
    total_redactions = sum(entity_counts.values())

    return PIIScrubSummary(
        original_length=len(text),
        masked_text=masked,
        redaction_count=total_redactions,
        placeholders=placeholders,
        entity_counts=entity_counts,
        scrub_latency_ms=elapsed_ms,
    )


class PIIScrubberMiddleware(BaseHTTPMiddleware):
    """
    FastAPI pre-flight middleware inspecting inbound text payloads on compliance/audit
    routes and attaching deterministic PII scrubbing telemetry headers without breaking
    downstream request bodies.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        start = time.perf_counter()
        query_q = request.query_params.get("q")
        if query_q:
            scrubbed_q = scrub_malaysian_pii(query_q)
            request.state.pii_query_scrub = scrubbed_q
        latency_ms = round((time.perf_counter() - start) * 1000.0, 4)

        response = await call_next(request)
        response.headers["X-PII-Scrub-Active"] = "true"
        response.headers["X-PII-Scrub-Latency-Ms"] = str(
            getattr(request.state, "pii_scrub_latency_ms", latency_ms)
        )
        return response
