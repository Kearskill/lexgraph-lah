from dataclasses import dataclass

from lexgraph_lah.config import settings
from lexgraph_lah.schemas.domain import TelemetrySummary


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
