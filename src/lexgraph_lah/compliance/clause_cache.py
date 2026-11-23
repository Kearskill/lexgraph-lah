"""Deterministic Clause-AST Isomorphic Verdict Cache (0 LLM tokens).

Computes canonical SHA-256 digests over PII-scrubbed normalized clause texts,
intra-contract AST dependency edges, evaluation date, territorial scope,
normalized regime set hash, and active statutory graph digest so structurally
identical or PII-variant contracts reuse verified compliance verdicts at
$0.00 / RM 0.00 cost.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import threading
import time
from collections import OrderedDict
from datetime import date
from typing import Any, Protocol

from pydantic import BaseModel

from lexgraph_lah.config import settings
from lexgraph_lah.graph.deontic_solver import normalize_regime_key
from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    get_default_temporal_store,
)
from lexgraph_lah.schemas.domain import (
    ContractASTGraph,
    StatutoryNode,
    TerritorialScope,
)
from lexgraph_lah.telemetry.tracer import emit_otel_attributes

_WHITESPACE_RE = re.compile(r"\s+")
# Normalize indexed PII placeholders (e.g. [NRIC_1] vs [NRIC_2]) to type-level
# tokens so structurally identical contracts with varying PII occurrences hit
# the same isomorphic AST digest.
_INDEXED_PII_TOKEN_RE = re.compile(r"\[([A-Z0-9_]+)_\d+\]")


def _normalize_clause_text(text: str) -> str:
    collapsed = _WHITESPACE_RE.sub(" ", text).strip()
    return _INDEXED_PII_TOKEN_RE.sub(r"[\1]", collapsed)


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def compute_regime_set_hash(regimes: list[str] | tuple[str, ...] | None) -> str:
    """Compute canonical SHA-256 over a normalized, sorted statutory regime set."""
    if not regimes:
        normalized: list[str] = []
    else:
        normalized = sorted(
            {normalize_regime_key(r) for r in regimes if str(r).strip()}
        )
    return _sha256_hex({"regimes": normalized})


def compute_statutory_graph_digest(
    store: TemporalGraphStore | None = None,
    *,
    as_of_date: date,
    territorial_scope: TerritorialScope | str = TerritorialScope.ALL_MALAYSIA,
    regimes: list[str] | tuple[str, ...] | None = None,
    active_nodes: list[StatutoryNode] | None = None,
) -> str:
    """Compute SHA-256 digest of all active statutory nodes at (as_of_date, scope)."""
    scope = (
        territorial_scope
        if isinstance(territorial_scope, TerritorialScope)
        else TerritorialScope(str(territorial_scope))
    )
    if active_nodes is None:
        graph_store = store or get_default_temporal_store()
        nodes = graph_store.query_point_in_time(
            as_of_date=as_of_date,
            include_citations=False,
            include_translations=False,
            territorial_scope=scope,
        )
    else:
        nodes = active_nodes

    regime_set = {normalize_regime_key(r) for r in regimes} if regimes else None
    node_records = sorted(
        (
            {
                "node_id": n.node_id,
                "version": n.version,
                "content_hash": n.content_hash,
                "effective_from": n.effective_from.isoformat()
                if n.effective_from
                else None,
                "effective_to": n.effective_to.isoformat() if n.effective_to else None,
                "is_in_force": n.is_in_force,
                "regime_code": n.regime_code,
            }
            for n in nodes
            if not regime_set
            or not n.regime_code
            or normalize_regime_key(n.regime_code) in regime_set
        ),
        key=lambda item: (str(item["node_id"]), int(str(item["version"]))),
    )
    return _sha256_hex(
        {
            "as_of_date": as_of_date.isoformat(),
            "territorial_scope": scope.value,
            "nodes": node_records,
        }
    )


def compute_clause_ast_digest(
    ast_graph: ContractASTGraph,
    *,
    as_of_date: date,
    territorial_scope: TerritorialScope | str,
    regime_set_hash: str,
    statutory_graph_digest: str,
    from_date: date | None = None,
    persona: str | None = None,
    language: str | None = None,
    act_filter: str | None = None,
    abstention_threshold: float | None = None,
    cache_namespace: str = "compliance",
) -> str:
    """Compute canonical isomorphic SHA-256 digest of a parsed ContractASTGraph.

    Excludes ``document_id`` and transient session metadata so two contracts
    with identical scrubbed clause structures, metrics, tables, and dependency
    edges produce the exact same digest.
    """
    scope_val = (
        territorial_scope.value
        if isinstance(territorial_scope, TerritorialScope)
        else str(territorial_scope)
    )
    clauses_payload = [
        {
            "clause_id": c.clause_id,
            "heading": _normalize_clause_text(c.heading),
            "section_type": c.section_type,
            "text": _normalize_clause_text(c.text),
            "defined_terms": sorted(_normalize_clause_text(t) for t in c.defined_terms),
            "referenced_clauses": sorted(c.referenced_clauses),
            "extracted_metrics": {
                str(k): c.extracted_metrics[k]
                for k in sorted(c.extracted_metrics.keys())
            },
            "table_rows": [
                [_normalize_clause_text(cell) for cell in row] for row in c.table_rows
            ],
        }
        for c in ast_graph.clauses
    ]
    # Also include normalized AST scrubbed_text fallback when clause splitting is minimal.
    normalized_full_text = _normalize_clause_text(ast_graph.scrubbed_text)
    edges_payload = sorted(
        (
            {
                "source_clause_id": e.source_clause_id,
                "target_clause_id": e.target_clause_id,
                "edge_type": e.edge_type.value,
                "trigger_phrase": _normalize_clause_text(e.trigger_phrase),
                "term_name": _normalize_clause_text(e.term_name)
                if e.term_name
                else None,
                "is_hostile_trap": bool(e.is_hostile_trap),
            }
            for e in ast_graph.edges
        ),
        key=lambda item: (
            str(item["source_clause_id"]),
            str(item["target_clause_id"]),
            str(item["edge_type"]),
            str(item["term_name"] or ""),
        ),
    )

    canonical_payload: dict[str, Any] = {
        "schema_v": 1,
        "namespace": cache_namespace,
        "as_of_date": as_of_date.isoformat(),
        "from_date": from_date.isoformat() if from_date else None,
        "territorial_scope": scope_val,
        "regime_set_hash": regime_set_hash,
        "statutory_graph_digest": statutory_graph_digest,
        "persona": persona,
        "language": language,
        "act_filter": act_filter,
        "abstention_threshold": abstention_threshold,
        "clauses": clauses_payload,
        "edges": edges_payload,
        "normalized_text_sha256": hashlib.sha256(
            normalized_full_text.encode("utf-8")
        ).hexdigest(),
    }
    return _sha256_hex(canonical_payload)


class _RedisClientProtocol(Protocol):
    def get(self, key: str) -> bytes | str | None: ...
    def setex(self, key: str, time: int, value: str) -> Any: ...
    def set(self, key: str, value: str) -> Any: ...
    def delete(self, *keys: str) -> Any: ...


class ClauseASTCache:
    """Thread-safe isomorphic verdict cache supporting memory and Redis backends."""

    def __init__(
        self,
        *,
        backend: str | None = None,
        ttl_seconds: int | None = None,
        max_entries: int = 2048,
        redis_url: str | None = None,
        redis_client: _RedisClientProtocol | None = None,
        key_prefix: str = "lexgraph:clause_cache:",
    ) -> None:
        chosen = (backend or settings.clause_cache_backend or "memory").strip().lower()
        if chosen not in {"memory", "redis"}:
            raise ValueError(
                f"Unsupported CLAUSE_CACHE_BACKEND={chosen!r}; expected 'memory' or 'redis'."
            )
        self._backend = chosen
        self._ttl_seconds = (
            int(ttl_seconds)
            if ttl_seconds is not None
            else int(settings.clause_cache_ttl_seconds)
        )
        self._max_entries = max(1, int(max_entries))
        self._key_prefix = key_prefix
        self._lock = threading.RLock()
        self._memory: OrderedDict[str, tuple[float | None, str]] = OrderedDict()
        self._redis: _RedisClientProtocol | None = redis_client
        if self._backend == "redis" and self._redis is None:
            url = (redis_url or settings.clause_cache_redis_url or "").strip()
            if not url:
                raise RuntimeError(
                    "CLAUSE_CACHE_BACKEND='redis' requires CLAUSE_CACHE_REDIS_URL."
                )
            redis_mod = importlib.import_module("redis")
            self._redis = redis_mod.Redis.from_url(url)

    @property
    def backend_name(self) -> str:
        return self._backend

    def get(self, digest: str) -> dict[str, Any] | None:
        if not digest:
            return None
        if self._backend == "redis":
            assert self._redis is not None
            raw = self._redis.get(f"{self._key_prefix}{digest}")
            if raw is None:
                return None
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            loaded = json.loads(raw)
            return dict(loaded) if isinstance(loaded, dict) else None

        now = time.monotonic()
        with self._lock:
            entry = self._memory.get(digest)
            if entry is None:
                return None
            expires_at, serialized = entry
            if expires_at is not None and now >= expires_at:
                self._memory.pop(digest, None)
                return None
            self._memory.move_to_end(digest)
            loaded = json.loads(serialized)
            return dict(loaded) if isinstance(loaded, dict) else None

    def set(
        self,
        digest: str,
        value: dict[str, Any] | BaseModel,
        *,
        ttl_seconds: int | None = None,
    ) -> None:
        if not digest:
            return
        payload = (
            value.model_dump(mode="json")
            if isinstance(value, BaseModel)
            else dict(value)
        )
        serialized = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        effective_ttl = self._ttl_seconds if ttl_seconds is None else int(ttl_seconds)

        if self._backend == "redis":
            assert self._redis is not None
            key = f"{self._key_prefix}{digest}"
            if effective_ttl > 0:
                self._redis.setex(key, effective_ttl, serialized)
            else:
                self._redis.set(key, serialized)
            return

        expires_at = (time.monotonic() + effective_ttl) if effective_ttl > 0 else None
        with self._lock:
            self._memory[digest] = (expires_at, serialized)
            self._memory.move_to_end(digest)
            while len(self._memory) > self._max_entries:
                self._memory.popitem(last=False)

    def delete(self, digest: str) -> None:
        if not digest:
            return
        if self._backend == "redis":
            assert self._redis is not None
            self._redis.delete(f"{self._key_prefix}{digest}")
            return
        with self._lock:
            self._memory.pop(digest, None)

    def clear(self) -> None:
        if self._backend == "redis":
            # Avoid destructive FLUSHDB in Redis; caller-owned keys expire via TTL.
            return
        with self._lock:
            self._memory.clear()

    def size(self) -> int:
        if self._backend == "redis":
            return 0
        now = time.monotonic()
        with self._lock:
            expired = [
                k
                for k, (exp, _) in self._memory.items()
                if exp is not None and now >= exp
            ]
            for k in expired:
                self._memory.pop(k, None)
            return len(self._memory)


def record_cache_otel_event(
    *,
    cache_hit: bool,
    digest: str,
    surface: str,
    tenant_id: str | None = None,
) -> None:
    """Emit structured OpenTelemetry attributes for Clause-AST cache lookups."""
    attrs: dict[str, Any] = {
        "lexgraph.cache_hit": bool(cache_hit),
        "lexgraph.clause_ast_digest": digest[:16],
        "lexgraph.cache_surface": surface,
    }
    if tenant_id:
        attrs["lexgraph.tenant_id"] = tenant_id
    emit_otel_attributes(attrs)


default_clause_cache = ClauseASTCache()

__all__ = [
    "ClauseASTCache",
    "compute_clause_ast_digest",
    "compute_regime_set_hash",
    "compute_statutory_graph_digest",
    "default_clause_cache",
    "record_cache_otel_event",
]
