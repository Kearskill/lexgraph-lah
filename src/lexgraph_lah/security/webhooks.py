"""
SSRF-hardened & Dual-Signed Outbound Webhook Delivery (`X-LexGraph-Signature-256` +
`X-LexGraph-Ed25519`) for asynchronous portfolio blast-radius jobs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import socket
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from lexgraph_lah.config import settings
from lexgraph_lah.schemas.domain import WebhookDeliveryStatus
from lexgraph_lah.security.attestation_ledger import (
    AttestationSigner,
    default_attestation_ledger,
)

DNSResolver = Callable[[str, int], list[str]]

_BLOCKED_HOSTNAMES: set[str] = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.goog",
}


class SSRFViolationError(ValueError):
    """Raised when a webhook URL targets a prohibited internal, loopback, metadata, or insecure host."""


def _default_dns_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            raw_ip = sockaddr[0].split("%", 1)[0]
            if raw_ip not in ips:
                ips.append(raw_ip)
    return ips


def _is_forbidden_ip(ip_str: str) -> str | None:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"Invalid IP address '{ip_str}'."

    # Unwrap IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1, ::ffff:169.254.169.254)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped

    if ip_obj.is_loopback:
        return f"Loopback address '{ip_obj}' is blocked by SSRF guard."
    if ip_obj.is_link_local:
        return (
            f"Link-local / cloud metadata address '{ip_obj}' is blocked by SSRF guard."
        )
    if ip_obj.is_private:
        return f"RFC1918 / private IP address '{ip_obj}' is blocked by SSRF guard."
    if ip_obj.is_multicast:
        return f"Multicast IP address '{ip_obj}' is blocked by SSRF guard."
    if ip_obj.is_reserved:
        return f"Reserved IP address '{ip_obj}' is blocked by SSRF guard."
    if ip_obj.is_unspecified:
        return f"Unspecified IP address '{ip_obj}' is blocked by SSRF guard."
    if not ip_obj.is_global:
        return f"Non-global IP address '{ip_obj}' is blocked by SSRF guard."
    return None


def validate_webhook_url_ssrf(
    url: str,
    *,
    dns_resolver: DNSResolver | None = None,
    is_production: bool | None = None,
) -> list[str]:
    """
    Validates `webhook_url` against SSRF vectors:
      - Requires `http` or `https` (`https` mandatory when `ENV=production`)
      - Rejects embedded userinfo credentials (`user:pass@host`)
      - Rejects loopback (`127.0.0.0/8`, `::1`), RFC1918 private IPs, link-local
        `169.254.0.0/16` / `fe80::/10` metadata endpoints, multicast, and non-global IPs
      - Re-resolves DNS records to detect DNS rebinding to internal IPs
    Returns resolved public IP list on success; raises `SSRFViolationError` otherwise.
    """
    raw = (url or "").strip()
    if not raw:
        raise SSRFViolationError("Webhook URL cannot be empty.")

    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    prod_mode = settings.is_production if is_production is None else is_production

    if scheme not in {"http", "https"}:
        raise SSRFViolationError(
            f"Unsupported webhook URL scheme '{scheme or 'none'}'; only http/https allowed."
        )
    if prod_mode and scheme != "https":
        raise SSRFViolationError(
            "Non-HTTPS webhook URL is rejected in production (ENV=production)."
        )
    if parsed.username or parsed.password:
        raise SSRFViolationError("Embedded credentials in webhook URL are prohibited.")

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise SSRFViolationError("Webhook URL missing hostname.")
    if host in _BLOCKED_HOSTNAMES or host.endswith((".localhost", ".internal")):
        raise SSRFViolationError(f"Webhook hostname '{host}' is blocked by SSRF guard.")

    port = parsed.port or (443 if scheme == "https" else 80)

    # Direct IP literal check
    try:
        ip_literal = ipaddress.ip_address(host)
        err = _is_forbidden_ip(str(ip_literal))
        if err:
            raise SSRFViolationError(err)
        return [str(ip_literal)]
    except ValueError:
        pass

    resolver = dns_resolver or _default_dns_resolver
    try:
        resolved_ips = resolver(host, port)
    except OSError as exc:
        raise SSRFViolationError(
            f"DNS resolution failed for webhook host '{host}': {exc}"
        ) from exc

    if not resolved_ips:
        raise SSRFViolationError(
            f"Webhook host '{host}' resolved to zero IP addresses."
        )

    for ip_str in resolved_ips:
        err = _is_forbidden_ip(ip_str)
        if err:
            raise SSRFViolationError(
                f"Webhook host '{host}' resolved to forbidden IP '{ip_str}': {err}"
            )
    return resolved_ips


def sign_webhook_payload(
    payload_bytes: bytes,
    *,
    hmac_secret: str | None = None,
    signer: AttestationSigner | None = None,
) -> tuple[str, str]:
    """
    Returns `(hmac_sha256_header, ed25519_b64_header)` for canonical webhook `payload_bytes`.
    """
    secret = (
        hmac_secret
        if hmac_secret is not None
        else settings.portfolio_webhook_hmac_secret
    ).encode("utf-8")
    sig_hmac = "sha256=" + hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()

    active_signer = signer or default_attestation_ledger.signer
    sig_ed = base64.b64encode(active_signer.sign(payload_bytes)).decode("ascii")
    return sig_hmac, sig_ed


def deliver_signed_webhook(
    *,
    webhook_url: str,
    payload: dict[str, Any],
    hmac_secret: str | None = None,
    signer: AttestationSigner | None = None,
    dns_resolver: DNSResolver | None = None,
    transport: httpx.BaseTransport | None = None,
    max_attempts: int | None = None,
    backoff_base_seconds: float | None = None,
    timeout_seconds: float | None = None,
    is_production: bool | None = None,
) -> WebhookDeliveryStatus:
    """
    Delivers a dual-signed webhook (`X-LexGraph-Signature-256` + `X-LexGraph-Ed25519`)
    with pre-attempt DNS rebinding SSRF checks, redirect blocking (`follow_redirects=False`),
    and bounded exponential backoff (`3` attempts by default).
    """
    attempts_limit = max(
        1,
        int(
            max_attempts
            if max_attempts is not None
            else settings.portfolio_webhook_max_attempts
        ),
    )
    backoff_base = max(
        0.0,
        float(
            backoff_base_seconds
            if backoff_base_seconds is not None
            else settings.portfolio_webhook_backoff_base_seconds
        ),
    )
    timeout = max(
        0.5,
        float(
            timeout_seconds
            if timeout_seconds is not None
            else settings.portfolio_webhook_timeout_seconds
        ),
    )

    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")
    sig_hmac, sig_ed = sign_webhook_payload(
        payload_bytes, hmac_secret=hmac_secret, signer=signer
    )
    active_signer = signer or default_attestation_ledger.signer

    headers = {
        "Content-Type": "application/json",
        "X-LexGraph-Signature-256": sig_hmac,
        "X-LexGraph-Ed25519": sig_ed,
        "X-LexGraph-Signing-Key-Id": active_signer.key_id,
    }

    last_status: int | None = None
    last_error: str | None = None

    for attempt in range(1, attempts_limit + 1):
        # Re-validate DNS before EVERY attempt to defeat DNS rebinding
        try:
            validate_webhook_url_ssrf(
                webhook_url,
                dns_resolver=dns_resolver,
                is_production=is_production,
            )
        except SSRFViolationError as exc:
            return WebhookDeliveryStatus(
                webhook_url=webhook_url,
                status="BLOCKED_SSRF",
                attempts=attempt,
                last_http_status=last_status,
                last_error=str(exc),
                signature_hmac_256=sig_hmac,
                signature_ed25519=sig_ed,
            )

        try:
            client_kwargs: dict[str, Any] = {
                "timeout": timeout,
                "follow_redirects": False,
            }
            if transport is not None:
                client_kwargs["transport"] = transport
            with httpx.Client(**client_kwargs) as client:
                resp = client.post(webhook_url, content=payload_bytes, headers=headers)
            last_status = resp.status_code
            if 200 <= resp.status_code < 300:
                return WebhookDeliveryStatus(
                    webhook_url=webhook_url,
                    status="DELIVERED",
                    attempts=attempt,
                    last_http_status=resp.status_code,
                    last_error=None,
                    delivered_at=datetime.now(UTC).isoformat(),
                    signature_hmac_256=sig_hmac,
                    signature_ed25519=sig_ed,
                )
            last_error = f"HTTP {resp.status_code}"
        except (httpx.HTTPError, OSError, TimeoutError) as exc:
            last_error = str(exc)

        if attempt < attempts_limit and backoff_base > 0.0:
            time.sleep(backoff_base * (2 ** (attempt - 1)))

    return WebhookDeliveryStatus(
        webhook_url=webhook_url,
        status="FAILED",
        attempts=attempts_limit,
        last_http_status=last_status,
        last_error=last_error or "Webhook delivery exhausted retries.",
        signature_hmac_256=sig_hmac,
        signature_ed25519=sig_ed,
    )
