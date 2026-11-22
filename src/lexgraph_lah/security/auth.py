"""
Enterprise AuthN/RBAC, Multi-Tenant Isolation, and Sliding-Window Rate Limiting.

Supports three runtime modes controlled via `AUTH_MODE` (`settings.auth_mode`):
- `disabled`: Non-production test/dev default (respects optional `X-Tenant-ID`, fail-closed HTTP 503 if `ENV=production`).
- `api_key`: Validates `X-API-Key` / `Authorization: Bearer` against SHA-256 hashed keys (`AUTH_API_KEYS_JSON` or runtime registry).
- `jwt`: Validates HS256 / EdDSA (Ed25519) / RS256 Bearer JWTs via `JWT_SECRET` or `JWT_PUBLIC_KEY_PEM`.

Implemented as pure ASGI middleware so streaming SSE (`/compliance/stream`) and JSON-RPC (`POST /mcp`) payloads pass cleanly without Starlette `BaseHTTPMiddleware` body-consumption hangs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from collections import defaultdict, deque
from contextvars import ContextVar
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from pydantic import BaseModel, Field
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from lexgraph_lah.config import settings

AuthRole = Literal["viewer", "auditor", "admin"]
VALID_AUTH_ROLES: set[str] = {"viewer", "auditor", "admin"}

PUBLIC_EXEMPT_GET_PATHS: set[str] = {
    "/",
    "/health",
    "/demo",
    "/dashboard",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/api/v1/attestation/public-key",
}

MCP_VIEWER_METHODS: set[str] = {
    "initialize",
    "notifications/initialized",
    "tools/list",
    "ping",
}


class JWTValidationError(ValueError):
    """Raised when a Bearer JWT fails structural, signature, or claim checks."""


class TenantAuthContext(BaseModel):
    """Authenticated tenant and RBAC principal attached to `request.state.tenant_context`."""

    tenant_id: str = "default-tenant"
    subject: str = "anonymous"
    role: AuthRole = "admin"
    auth_method: Literal["disabled", "api_key", "jwt"] = "disabled"
    claims: dict[str, Any] = Field(default_factory=dict)


def hash_api_key(raw_key: str) -> str:
    """Returns canonical lowercase SHA-256 hex digest of an API key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * ((4 - len(segment) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except Exception as exc:
        raise JWTValidationError("Malformed base64url JWT segment.") from exc


def create_jwt_token(
    payload: dict[str, Any],
    *,
    secret: str | None = None,
    private_key_pem: str | None = None,
    algorithm: Literal["HS256", "EdDSA", "RS256"] = "HS256",
    expires_in_seconds: int = 3600,
) -> str:
    """Signs a compact JWS/JWT using HS256, EdDSA (Ed25519), or RS256."""
    now = int(time.time())
    claims = dict(payload)
    claims.setdefault("iat", now)
    claims.setdefault("exp", now + expires_in_seconds)

    header_b64 = _b64url_encode(
        json.dumps({"alg": algorithm, "typ": "JWT"}, separators=(",", ":")).encode()
    )
    payload_b64 = _b64url_encode(
        json.dumps(claims, separators=(",", ":"), default=str).encode()
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    if algorithm == "HS256":
        if not secret:
            raise ValueError("HS256 token creation requires a non-empty `secret`.")
        sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    elif algorithm == "EdDSA":
        if not private_key_pem:
            raise ValueError("EdDSA token creation requires `private_key_pem`.")
        priv = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError("EdDSA requires an Ed25519 private key.")
        sig = priv.sign(signing_input)
    elif algorithm == "RS256":
        if not private_key_pem:
            raise ValueError("RS256 token creation requires `private_key_pem`.")
        priv = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
        if not isinstance(priv, RSAPrivateKey):
            raise ValueError("RS256 requires an RSA private key.")
        sig = priv.sign(signing_input, PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError(f"Unsupported JWT algorithm: {algorithm}")

    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def verify_jwt_token(
    token: str,
    *,
    secret: str | None = None,
    public_key_pem: str | None = None,
    issuer: str | None = None,
    audience: str | None = None,
) -> dict[str, Any]:
    """Verifies a compact JWS/JWT signature and standard `exp`/`nbf`/`iss`/`aud` claims."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JWTValidationError("JWT must consist of three dot-separated segments.")

    header_raw = _b64url_decode(parts[0])
    payload_raw = _b64url_decode(parts[1])
    sig_bytes = _b64url_decode(parts[2])

    try:
        header = json.loads(header_raw.decode("utf-8"))
        claims = json.loads(payload_raw.decode("utf-8"))
    except Exception as exc:
        raise JWTValidationError(
            "JWT header or payload is not valid UTF-8 JSON."
        ) from exc

    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JWTValidationError("JWT header and payload must be JSON objects.")

    alg = str(header.get("alg") or "").strip()
    if not alg or alg.lower() == "none":
        raise JWTValidationError("JWT 'none' or missing algorithm is rejected.")

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

    if alg == "HS256":
        if not secret:
            raise JWTValidationError(
                "HS256 JWT received but JWT_SECRET is not configured."
            )
        expected_sig = hmac.new(
            secret.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(sig_bytes, expected_sig):
            raise JWTValidationError("Invalid HS256 JWT signature.")
    elif alg == "EdDSA":
        if not public_key_pem:
            raise JWTValidationError(
                "EdDSA JWT received but JWT_PUBLIC_KEY_PEM is missing."
            )
        pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(pub, Ed25519PublicKey):
            raise JWTValidationError("Configured public key is not Ed25519.")
        try:
            pub.verify(sig_bytes, signing_input)
        except InvalidSignature as exc:
            raise JWTValidationError("Invalid EdDSA JWT signature.") from exc
    elif alg == "RS256":
        if not public_key_pem:
            raise JWTValidationError(
                "RS256 JWT received but JWT_PUBLIC_KEY_PEM is missing."
            )
        pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(pub, RSAPublicKey):
            raise JWTValidationError("Configured public key is not RSA.")
        try:
            pub.verify(sig_bytes, signing_input, PKCS1v15(), hashes.SHA256())
        except InvalidSignature as exc:
            raise JWTValidationError("Invalid RS256 JWT signature.") from exc
    else:
        raise JWTValidationError(f"Unsupported JWT algorithm '{alg}'.")

    now = time.time()
    exp = claims.get("exp")
    if exp is not None:
        try:
            if now >= float(exp):
                raise JWTValidationError("JWT token has expired.")
        except (TypeError, ValueError) as exc:
            raise JWTValidationError("JWT 'exp' claim must be numeric.") from exc

    nbf = claims.get("nbf")
    if nbf is not None:
        try:
            if now < float(nbf):
                raise JWTValidationError("JWT token is not yet valid ('nbf').")
        except (TypeError, ValueError) as exc:
            raise JWTValidationError("JWT 'nbf' claim must be numeric.") from exc

    if issuer and claims.get("iss") != issuer:
        raise JWTValidationError("JWT 'iss' claim mismatch.")

    if audience:
        aud_claim = claims.get("aud")
        aud_list = (
            [str(a) for a in aud_claim]
            if isinstance(aud_claim, list)
            else ([str(aud_claim)] if aud_claim is not None else [])
        )
        if audience not in aud_list:
            raise JWTValidationError("JWT 'aud' claim mismatch.")

    return claims


class APIKeyRegistry:
    """Thread-safe registry mapping SHA-256 key digests to tenant & role metadata."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._keys: dict[str, dict[str, str]] = {}

    def register_hash(
        self,
        key_sha256: str,
        *,
        tenant_id: str,
        role: AuthRole = "auditor",
        subject: str = "api-client",
    ) -> None:
        with self._lock:
            self._keys[key_sha256.strip().lower()] = {
                "tenant_id": tenant_id,
                "role": role,
                "subject": subject,
            }

    def register_key(
        self,
        raw_key: str,
        *,
        tenant_id: str,
        role: AuthRole = "auditor",
        subject: str = "api-client",
    ) -> str:
        digest = hash_api_key(raw_key)
        self.register_hash(digest, tenant_id=tenant_id, role=role, subject=subject)
        return digest

    def clear(self) -> None:
        with self._lock:
            self._keys.clear()

    def lookup(self, raw_key: str, *, extra_json: str = "") -> dict[str, str] | None:
        presented = hash_api_key(raw_key)
        candidates: dict[str, dict[str, str]] = {}
        if extra_json and extra_json.strip():
            try:
                parsed = json.loads(extra_json)
                if isinstance(parsed, dict):
                    for k_hash, entry in parsed.items():
                        if isinstance(entry, dict) and entry.get("tenant_id"):
                            role_val = str(entry.get("role") or "auditor").lower()
                            candidates[str(k_hash).strip().lower()] = {
                                "tenant_id": str(entry["tenant_id"]),
                                "role": role_val
                                if role_val in VALID_AUTH_ROLES
                                else "auditor",
                                "subject": str(entry.get("subject") or "api-key-user"),
                            }
            except json.JSONDecodeError:
                pass
        with self._lock:
            candidates.update(self._keys)

        matched: dict[str, str] | None = None
        for expected_hash, meta in candidates.items():
            if hmac.compare_digest(presented, expected_hash):
                matched = dict(meta)
        return matched


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter keyed by tenant and client IP."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()

    def allow(
        self,
        key: str,
        *,
        limit: int | None = None,
        window_seconds: int | None = None,
    ) -> tuple[bool, int, float]:
        """Returns `(allowed, remaining, retry_after_seconds)`."""
        max_reqs = max(1, limit if limit is not None else settings.rate_limit_rpm)
        win = float(
            max(
                1,
                window_seconds
                if window_seconds is not None
                else settings.rate_limit_window_seconds,
            )
        )
        now = time.monotonic()
        cutoff = now - win
        with self._lock:
            q = self._events[key]
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= max_reqs:
                retry_after = max(0.01, (q[0] + win) - now)
                return False, 0, round(retry_after, 3)
            q.append(now)
            remaining = max(0, max_reqs - len(q))
            return True, remaining, 0.0


default_api_key_registry = APIKeyRegistry()
default_rate_limiter = SlidingWindowRateLimiter()
_CURRENT_TENANT_CTX: ContextVar[TenantAuthContext | None] = ContextVar(
    "lexgraph_tenant_ctx", default=None
)


def get_request_tenant_id(request: Any = None) -> str:
    """Resolves verified tenant ID from request state, async ContextVar, or headers."""
    if request is not None:
        state = getattr(request, "state", None)
        ctx = getattr(state, "tenant_context", None) if state is not None else None
        if isinstance(ctx, TenantAuthContext):
            return ctx.tenant_id
    ctx_var = _CURRENT_TENANT_CTX.get()
    if isinstance(ctx_var, TenantAuthContext):
        return ctx_var.tenant_id
    if request is not None:
        headers = getattr(request, "headers", None)
        if headers is not None:
            hdr = headers.get("X-Tenant-ID")
            if hdr and hdr.strip():
                return hdr.strip()
    return "default-tenant"


def _normalize_path(path: str) -> str:
    if len(path) > 1 and path.endswith("/"):
        return path.rstrip("/")
    return path


def _extract_bearer_token(headers: Headers) -> str | None:
    auth_hdr = headers.get("authorization")
    if not auth_hdr:
        return None
    parts = auth_hdr.strip().split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
        return parts[1].strip()
    return None


def _is_role_authorized(
    *,
    role: AuthRole,
    method: str,
    path: str,
    body_bytes: bytes | None,
) -> tuple[bool, str]:
    if role == "admin":
        return True, ""
    norm_path = _normalize_path(path)
    upper_method = method.upper()

    if role == "auditor":
        if norm_path.startswith("/api/v1/admin"):
            return False, "Auditor role cannot invoke admin-only endpoints."
        return True, ""

    # Viewer role: read-only GET/HEAD, attestation verification, and read-only MCP methods
    if upper_method in {"GET", "HEAD", "OPTIONS"}:
        return True, ""
    if norm_path == "/api/v1/attestation/verify" and upper_method == "POST":
        return True, ""
    if norm_path == "/mcp" and upper_method == "POST":
        if body_bytes is None:
            return False, "Viewer role cannot execute mutating MCP calls."
        try:
            rpc_obj = json.loads(body_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, "Malformed JSON-RPC body on MCP request."
        if isinstance(rpc_obj, list):
            methods = [
                str(item.get("method") or "")
                for item in rpc_obj
                if isinstance(item, dict)
            ]
            if methods and all(m in MCP_VIEWER_METHODS for m in methods):
                return True, ""
            return (
                False,
                "Viewer role is restricted to read-only MCP discovery methods.",
            )
        if isinstance(rpc_obj, dict):
            rpc_method = str(rpc_obj.get("method") or "")
            if rpc_method in MCP_VIEWER_METHODS:
                return True, ""
            return False, f"Viewer role cannot invoke MCP method '{rpc_method}'."
        return False, "Invalid JSON-RPC payload."

    return (
        False,
        f"Role '{role}' does not have write permission for {upper_method} {norm_path}.",
    )


class EnterpriseSecurityMiddleware:
    """
    Pure ASGI middleware enforcing fail-closed production AuthN, SHA-256 API key or
    JWT Bearer authentication, RBAC across REST/SSE/MCP, cross-tenant spoofing protection,
    and per-tenant sliding-window rate limiting.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method") or "GET").upper()
        path = _normalize_path(str(scope.get("path") or "/"))
        headers = Headers(scope=scope)
        auth_mode = settings.auth_mode.strip().lower()

        if settings.is_production and auth_mode == "disabled" and path != "/health":
            resp = JSONResponse(
                status_code=503,
                content={
                    "detail": "Service unavailable: ENV=production requires AUTH_MODE=api_key or jwt."
                },
            )
            await resp(scope, receive, send)
            return

        is_public_exempt = (
            method in {"GET", "HEAD", "OPTIONS"} and path in PUBLIC_EXEMPT_GET_PATHS
        )

        # Authenticate principal unless endpoint is explicitly public read-only
        header_tenant = (headers.get("x-tenant-id") or "").strip()
        if auth_mode == "disabled" or is_public_exempt:
            ctx = TenantAuthContext(
                tenant_id=header_tenant or "default-tenant",
                subject="anonymous" if is_public_exempt else "local-dev",
                role="viewer"
                if is_public_exempt and auth_mode != "disabled"
                else "admin",
                auth_method="disabled",
            )
        elif auth_mode == "api_key":
            raw_key = (headers.get("x-api-key") or "").strip() or (
                _extract_bearer_token(headers) or ""
            )
            if not raw_key:
                resp = JSONResponse(
                    status_code=401,
                    content={"detail": "Missing API key credential."},
                    headers={"WWW-Authenticate": "Bearer"},
                )
                await resp(scope, receive, send)
                return
            entry = default_api_key_registry.lookup(
                raw_key, extra_json=settings.auth_api_keys_json
            )
            if entry is None:
                resp = JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid API key credential."},
                    headers={"WWW-Authenticate": "Bearer"},
                )
                await resp(scope, receive, send)
                return
            if header_tenant and header_tenant != entry["tenant_id"]:
                resp = JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Cross-tenant X-Tenant-ID spoofing rejected for API key principal."
                    },
                )
                await resp(scope, receive, send)
                return
            role_val: AuthRole = (
                entry["role"]  # type: ignore[assignment]
                if entry["role"] in VALID_AUTH_ROLES
                else "auditor"
            )
            ctx = TenantAuthContext(
                tenant_id=entry["tenant_id"],
                subject=entry["subject"],
                role=role_val,
                auth_method="api_key",
            )
        elif auth_mode == "jwt":
            token = _extract_bearer_token(headers)
            if not token:
                resp = JSONResponse(
                    status_code=401,
                    content={"detail": "Missing Bearer JWT token."},
                    headers={"WWW-Authenticate": "Bearer"},
                )
                await resp(scope, receive, send)
                return
            try:
                claims = verify_jwt_token(
                    token,
                    secret=settings.jwt_secret or None,
                    public_key_pem=settings.jwt_public_key_pem or None,
                    issuer=settings.jwt_issuer,
                    audience=settings.jwt_audience,
                )
            except JWTValidationError as exc:
                resp = JSONResponse(
                    status_code=401,
                    content={"detail": f"Invalid Bearer JWT: {exc}"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
                await resp(scope, receive, send)
                return

            claim_tenant = str(
                claims.get("tenant_id")
                or claims.get("tid")
                or claims.get("org_id")
                or ""
            ).strip()
            if not claim_tenant:
                resp = JSONResponse(
                    status_code=403,
                    content={"detail": "JWT missing required tenant_id claim."},
                )
                await resp(scope, receive, send)
                return
            if header_tenant and header_tenant != claim_tenant:
                resp = JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Cross-tenant X-Tenant-ID spoofing rejected for JWT principal."
                    },
                )
                await resp(scope, receive, send)
                return

            raw_role = str(claims.get("role") or "auditor").strip().lower()
            if raw_role not in VALID_AUTH_ROLES:
                resp = JSONResponse(
                    status_code=403,
                    content={"detail": f"Invalid RBAC role '{raw_role}' in JWT."},
                )
                await resp(scope, receive, send)
                return
            jwt_role: AuthRole = raw_role  # type: ignore[assignment]
            ctx = TenantAuthContext(
                tenant_id=claim_tenant,
                subject=str(claims.get("sub") or "jwt-subject"),
                role=jwt_role,
                auth_method="jwt",
                claims=claims,
            )
        else:
            resp = JSONResponse(
                status_code=503,
                content={
                    "detail": f"Unsupported AUTH_MODE configuration '{auth_mode}'."
                },
            )
            await resp(scope, receive, send)
            return

        scope_state = scope.setdefault("state", {})
        if isinstance(scope_state, dict):
            scope_state["tenant_context"] = ctx

        # For MCP RBAC on `viewer`, inspect JSON-RPC method cleanly while replaying body downstream
        downstream_receive = receive
        buffered_body: bytes | None = None
        if (
            not is_public_exempt
            and auth_mode != "disabled"
            and path == "/mcp"
            and method == "POST"
            and ctx.role == "viewer"
        ):
            chunks: list[bytes] = []
            while True:
                msg = await receive()
                if msg["type"] == "http.request":
                    chunks.append(msg.get("body", b""))
                    if not msg.get("more_body", False):
                        break
                elif msg["type"] == "http.disconnect":
                    break
            buffered_body = b"".join(chunks)
            sent_body = False

            async def _replay_receive() -> Message:
                nonlocal sent_body
                if not sent_body:
                    sent_body = True
                    return {
                        "type": "http.request",
                        "body": buffered_body or b"",
                        "more_body": False,
                    }
                return await receive()

            downstream_receive = _replay_receive

        if not is_public_exempt and auth_mode != "disabled":
            ok_rbac, rbac_reason = _is_role_authorized(
                role=ctx.role,
                method=method,
                path=path,
                body_bytes=buffered_body,
            )
            if not ok_rbac:
                resp = JSONResponse(
                    status_code=403,
                    content={"detail": rbac_reason},
                    headers={"X-Tenant-ID": ctx.tenant_id},
                )
                await resp(scope, downstream_receive, send)
                return

        rate_headers: list[tuple[bytes, bytes]] = [
            (b"x-tenant-id", ctx.tenant_id.encode("latin-1"))
        ]
        if settings.rate_limit_enabled and path != "/health":
            client_info = scope.get("client")
            client_ip = (
                str(client_info[0])
                if isinstance(client_info, (tuple, list)) and client_info
                else "local"
            )
            allowed, remaining, retry_after = default_rate_limiter.allow(
                f"{ctx.tenant_id}:{client_ip}"
            )
            limit_str = str(max(1, settings.rate_limit_rpm)).encode("latin-1")
            if not allowed:
                resp = JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Retry later."},
                    headers={
                        "Retry-After": str(max(1, int(retry_after) + 1)),
                        "X-RateLimit-Limit": str(max(1, settings.rate_limit_rpm)),
                        "X-RateLimit-Remaining": "0",
                        "X-Tenant-ID": ctx.tenant_id,
                    },
                )
                await resp(scope, downstream_receive, send)
                return
            rate_headers.extend(
                [
                    (b"x-ratelimit-limit", limit_str),
                    (b"x-ratelimit-remaining", str(remaining).encode("latin-1")),
                ]
            )

        async def _send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                raw_hdrs: list[tuple[bytes, bytes]] = list(message.get("headers") or [])
                existing_names = {k.lower() for k, _ in raw_hdrs}
                for hk, hv in rate_headers:
                    if hk.lower() not in existing_names:
                        raw_hdrs.append((hk, hv))
                        existing_names.add(hk.lower())
                message = {**message, "headers": raw_hdrs}
            await send(message)

        ctx_token = _CURRENT_TENANT_CTX.set(ctx)
        try:
            await self.app(scope, downstream_receive, _send_with_headers)
        finally:
            _CURRENT_TENANT_CTX.reset(ctx_token)
