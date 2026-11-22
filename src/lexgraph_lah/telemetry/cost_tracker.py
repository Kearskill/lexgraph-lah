from __future__ import annotations

import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from lexgraph_lah.config import settings
from lexgraph_lah.schemas.domain import TelemetrySummary

LogicalModelTier = Literal["fast_tier", "reasoning_tier"]

_OFFLINE_GEMINI_KEYS: set[str] = {
    "mock-key-for-ci",
    "mock-ci-key-zero-cost",
    "your_key_here",
    "",
}


class BudgetExceededError(RuntimeError):
    """Raised when a compliance run exceeds the configured FinOps USD or MYR cost ceiling."""


@dataclass(frozen=True, slots=True)
class ModelPricing:
    """Per-1M-token USD pricing entry for a Gemini model tier."""

    model_name: str
    input_cost_per_1m_usd: float
    output_cost_per_1m_usd: float
    cached_input_cost_per_1m_usd: float


MODEL_PRICING_CATALOG: dict[str, ModelPricing] = {
    "gemini-2.5-flash": ModelPricing(
        model_name="gemini-2.5-flash",
        input_cost_per_1m_usd=0.15,
        output_cost_per_1m_usd=0.60,
        cached_input_cost_per_1m_usd=0.0375,
    ),
    "gemini-2.5-flash-lite": ModelPricing(
        model_name="gemini-2.5-flash-lite",
        input_cost_per_1m_usd=0.10,
        output_cost_per_1m_usd=0.40,
        cached_input_cost_per_1m_usd=0.025,
    ),
    "gemini-2.0-flash": ModelPricing(
        model_name="gemini-2.0-flash",
        input_cost_per_1m_usd=0.10,
        output_cost_per_1m_usd=0.40,
        cached_input_cost_per_1m_usd=0.025,
    ),
    "gemini-2.5-pro": ModelPricing(
        model_name="gemini-2.5-pro",
        input_cost_per_1m_usd=1.25,
        output_cost_per_1m_usd=10.00,
        cached_input_cost_per_1m_usd=0.3125,
    ),
    "gemini-4-hydrogen": ModelPricing(
        model_name="gemini-4-hydrogen",
        input_cost_per_1m_usd=0.50,
        output_cost_per_1m_usd=2.50,
        cached_input_cost_per_1m_usd=0.05,
    ),
    "gemini-4-neon": ModelPricing(
        model_name="gemini-4-neon",
        input_cost_per_1m_usd=3.00,
        output_cost_per_1m_usd=15.00,
        cached_input_cost_per_1m_usd=0.15,
    ),
}


def resolve_logical_tier(model_or_tier: str | None) -> LogicalModelTier:
    """Maps a logical tier or legacy alias to `'fast_tier'` or `'reasoning_tier'`."""
    low = (model_or_tier or "").strip().lower()
    if low in {
        "reasoning_tier",
        "gemini-4-neon",
        settings.complex_model_name.lower(),
        settings.lexgraph_model_reasoning.lower(),
        "gemini-2.5-pro",
    }:
        return "reasoning_tier"
    return "fast_tier"


def resolve_provider_model_id(
    selected_model: str | None,
    *,
    mode: Literal["mock", "live"] | None = None,
) -> str:
    """
    Resolves a logical complexity tier (`fast_tier`/`reasoning_tier`) or legacy alias
    (`gemini-4-hydrogen`/`gemini-4-neon`) to the target provider Gemini model ID:
      - In `mock`/offline mode: preserves `gemini-4-hydrogen` & `gemini-4-neon` for CI invariants.
      - In `live` mode: maps to `LEXGRAPH_MODEL_FAST` / `LEXGRAPH_MODEL_REASONING`.
    Explicit production Gemini model IDs pass through unchanged.
    """
    raw = (selected_model or settings.model_name).strip()
    is_live = (
        mode == "live"
        if mode is not None
        else settings.gemini_api_key.strip() not in _OFFLINE_GEMINI_KEYS
    )

    if not is_live:
        if raw == "fast_tier":
            return settings.fast_model_name
        if raw == "reasoning_tier":
            return settings.complex_model_name
        return raw

    if raw in {"fast_tier", settings.fast_model_name, "gemini-4-hydrogen"}:
        return settings.lexgraph_model_fast
    if raw in {"reasoning_tier", settings.complex_model_name, "gemini-4-neon"}:
        return settings.lexgraph_model_reasoning
    return raw


def get_model_pricing(model_name: str | None) -> ModelPricing:
    """Returns catalog pricing for a model name, falling back to configured Settings."""
    if model_name and model_name in MODEL_PRICING_CATALOG:
        return MODEL_PRICING_CATALOG[model_name]
    return ModelPricing(
        model_name=model_name or settings.model_name,
        input_cost_per_1m_usd=settings.input_cost_per_1m_usd,
        output_cost_per_1m_usd=settings.output_cost_per_1m_usd,
        cached_input_cost_per_1m_usd=settings.cached_input_cost_per_1m_usd,
    )


def select_model_tier(
    *,
    retry_count: int = 0,
    regimes: list[str] | None = None,
    cross_clause_anomaly_count: int = 0,
    security_finding_count: int = 0,
) -> tuple[str, str]:
    """
    Deterministically selects the LLM tier for an audit pass.

    Escalates counterfactual retries, multi-regime audits, cross-clause AST anomalies,
    and security-flagged documents to ``settings.complex_model_name`` (``gemini-4-neon``);
    keeps simple single-regime scans on ``settings.fast_model_name`` (``gemini-4-hydrogen``).
    """
    reasons: list[str] = []
    if retry_count > 0:
        reasons.append(f"counterfactual_retry:{retry_count}")
    if cross_clause_anomaly_count > 0:
        reasons.append(f"cross_clause_anomalies:{cross_clause_anomaly_count}")
    if regimes and len(regimes) >= 2:
        reasons.append(f"multi_regime:{len(regimes)}")
    if security_finding_count > 0:
        reasons.append(f"security_findings:{security_finding_count}")

    if reasons:
        return settings.complex_model_name, ";".join(reasons)
    return settings.fast_model_name, "single_regime_fast_path"


select_model_for_audit = select_model_tier


def _parse_bnm_usd_rate(payload: dict[str, Any]) -> float:
    data = payload.get("data")
    entries: list[dict[str, Any]]
    if isinstance(data, list):
        entries = [e for e in data if isinstance(e, dict)]
    elif isinstance(data, dict):
        entries = [data]
    else:
        raise TypeError("BNM exchange-rate response missing 'data' object/list.")

    target: dict[str, Any] | None = None
    for entry in entries:
        code = str(entry.get("currency_code") or "").strip().upper()
        if code == "USD":
            target = entry
            break
    if target is None and len(entries) == 1:
        target = entries[0]
    if target is None:
        raise ValueError("BNM exchange-rate payload contained no USD entry.")

    unit = float(target.get("unit") or 1.0)
    rate_block = target.get("rate")
    raw_mid = (
        rate_block.get("middle_rate")
        if isinstance(rate_block, dict)
        else target.get("middle_rate")
    )
    if raw_mid is None:
        raise ValueError("BNM USD entry missing 'middle_rate'.")
    parsed = float(raw_mid) / (unit if unit > 0 else 1.0)
    if parsed <= 0:
        raise ValueError(f"Invalid non-positive BNM FX rate: {parsed}")
    return round(parsed, 4)


class BNMFXRateProvider:
    """
    Async Bank Negara Malaysia OpenAPI USD/MYR rate adapter (`api.bnm.gov.my/public/exchange-rate`)
    with 24-hour TTL cache and deterministic offline fallback to `LEXGRAPH_USD_MYR_FALLBACK`
    or `USD_TO_MYR_RATE`.
    """

    def __init__(
        self,
        *,
        api_url: str | None = None,
        cache_ttl_seconds: int | None = None,
        fetcher: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
        enabled: bool | None = None,
    ) -> None:
        self._api_url = api_url
        self._cache_ttl_seconds = cache_ttl_seconds
        self._fetcher = fetcher
        self._enabled = enabled
        self._lock = threading.RLock()
        self._cached_rate: float | None = None
        self._cached_at_monotonic: float = 0.0

    def clear_cache(self) -> None:
        with self._lock:
            self._cached_rate = None
            self._cached_at_monotonic = 0.0

    def _fallback_rate(self) -> float:
        fb = (
            settings.lexgraph_usd_myr_fallback
            if settings.lexgraph_usd_myr_fallback is not None
            else settings.usd_to_myr_rate
        )
        return float(fb)

    async def get_usd_to_myr_rate(
        self, *, force_refresh: bool = False
    ) -> tuple[float, str]:
        """Returns `(usd_to_myr_rate, source)` where source is `'bnm_live'`, `'bnm_cache'`, or `'fallback'`."""
        ttl = max(
            1,
            int(
                self._cache_ttl_seconds
                if self._cache_ttl_seconds is not None
                else settings.bnm_fx_cache_ttl_seconds
            ),
        )
        is_enabled = (
            self._enabled
            if self._enabled is not None
            else (settings.bnm_fx_enabled or self._fetcher is not None)
        )
        if not is_enabled:
            return self._fallback_rate(), "fallback"

        now_mono = time.monotonic()
        if not force_refresh:
            with self._lock:
                if (
                    self._cached_rate is not None
                    and (now_mono - self._cached_at_monotonic) < ttl
                ):
                    return self._cached_rate, "bnm_cache"

        url = (self._api_url or settings.bnm_fx_api_url).strip()
        try:
            if self._fetcher is not None:
                payload = await self._fetcher(url)
            else:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        url,
                        headers={"Accept": "application/vnd.BNM.API.v1+json"},
                    )
                    resp.raise_for_status()
                    payload = resp.json()
            rate = _parse_bnm_usd_rate(payload)
            with self._lock:
                self._cached_rate = rate
                self._cached_at_monotonic = time.monotonic()
            return rate, "bnm_live"
        except (httpx.HTTPError, OSError, TimeoutError, ValueError, TypeError):
            with self._lock:
                if self._cached_rate is not None:
                    return self._cached_rate, "bnm_cache"
            return self._fallback_rate(), "fallback"


default_bnm_fx_provider = BNMFXRateProvider()


def compute_telemetry_summary(
    prompt_tokens: int,
    completion_tokens: int,
    latency_ms: float,
    retry_count: int,
    is_verified_grounded: bool,
    input_cost_per_1m_usd: float | None = None,
    output_cost_per_1m_usd: float | None = None,
    usd_to_myr_rate: float | None = None,
    trace_id: str | None = None,
    *,
    cached_prompt_tokens: int = 0,
    cached_input_cost_per_1m_usd: float | None = None,
    model_name: str | None = None,
) -> TelemetrySummary:
    """
    Deterministically computes USD and MYR token costs from raw usage metadata
    and packages a TelemetrySummary for FinOps reporting and SLA assertions.

    When ``model_name`` is omitted, preserves exact ``settings`` defaults so existing
    single-tier FinOps calculations remain invariant. ``cached_prompt_tokens`` is
    treated as the cached subset of ``prompt_tokens`` (capped at ``prompt_tokens``).
    """
    pricing = get_model_pricing(model_name)
    in_rate = (
        input_cost_per_1m_usd
        if input_cost_per_1m_usd is not None
        else pricing.input_cost_per_1m_usd
    )
    out_rate = (
        output_cost_per_1m_usd
        if output_cost_per_1m_usd is not None
        else pricing.output_cost_per_1m_usd
    )
    cached_rate = (
        cached_input_cost_per_1m_usd
        if cached_input_cost_per_1m_usd is not None
        else pricing.cached_input_cost_per_1m_usd
    )
    fx_rate = (
        usd_to_myr_rate if usd_to_myr_rate is not None else settings.usd_to_myr_rate
    )

    safe_prompt = max(0, prompt_tokens)
    safe_cached = min(safe_prompt, max(0, cached_prompt_tokens))
    uncached_prompt = safe_prompt - safe_cached
    safe_completion = max(0, completion_tokens)
    total_tokens = safe_prompt + safe_completion

    cost_usd = (
        (uncached_prompt / 1_000_000.0) * in_rate
        + (safe_cached / 1_000_000.0) * cached_rate
        + (safe_completion / 1_000_000.0) * out_rate
    )
    cost_myr = cost_usd * fx_rate

    return TelemetrySummary(
        prompt_tokens=safe_prompt,
        cached_prompt_tokens=safe_cached,
        completion_tokens=safe_completion,
        total_tokens=total_tokens,
        estimated_cost_usd=round(cost_usd, 6),
        estimated_cost_myr=round(cost_myr, 6),
        latency_ms=round(max(0.0, latency_ms), 2),
        retry_count=max(0, retry_count),
        is_verified_grounded=is_verified_grounded,
        model_name=model_name,
        trace_id=trace_id,
    )


def assert_within_budget(
    telemetry: TelemetrySummary,
    max_cost_usd: float = 0.005,
    max_tokens: int = 15_000,
) -> None:
    """
    FinOps SLA guardrail: raises BudgetExceededError if a single compliance audit
    exceeds either the dollar ceiling or token ceiling.
    """
    if telemetry.estimated_cost_usd > max_cost_usd:
        raise BudgetExceededError(
            f"FinOps SLA breach: run cost ${telemetry.estimated_cost_usd:.6f} USD "
            f"exceeded ceiling ${max_cost_usd:.6f} USD."
        )
    if telemetry.total_tokens > max_tokens:
        raise BudgetExceededError(
            f"FinOps SLA breach: total tokens ({telemetry.total_tokens}) "
            f"exceeded ceiling ({max_tokens})."
        )
