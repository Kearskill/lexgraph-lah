from lexgraph_lah.config import settings
from lexgraph_lah.schemas.domain import TelemetrySummary


class BudgetExceededError(RuntimeError):
    """Raised when a compliance run exceeds the configured FinOps USD or MYR cost ceiling."""


def compute_telemetry_summary(
    prompt_tokens: int,
    completion_tokens: int,
    latency_ms: float,
    retry_count: int,
    is_verified_grounded: bool,
    input_cost_per_1m_usd: float | None = None,
    output_cost_per_1m_usd: float | None = None,
    usd_to_myr_rate: float | None = None,
) -> TelemetrySummary:
    """
    Deterministically computes USD and MYR token costs from raw usage metadata
    and packages a TelemetrySummary for FinOps reporting and SLA assertions.
    """
    in_rate = (
        input_cost_per_1m_usd
        if input_cost_per_1m_usd is not None
        else settings.input_cost_per_1m_usd
    )
    out_rate = (
        output_cost_per_1m_usd
        if output_cost_per_1m_usd is not None
        else settings.output_cost_per_1m_usd
    )
    fx_rate = (
        usd_to_myr_rate if usd_to_myr_rate is not None else settings.usd_to_myr_rate
    )

    safe_prompt = max(0, prompt_tokens)
    safe_completion = max(0, completion_tokens)
    total_tokens = safe_prompt + safe_completion

    cost_usd = (safe_prompt / 1_000_000.0) * in_rate + (
        safe_completion / 1_000_000.0
    ) * out_rate
    cost_myr = cost_usd * fx_rate

    return TelemetrySummary(
        total_tokens=total_tokens,
        estimated_cost_usd=round(cost_usd, 6),
        estimated_cost_myr=round(cost_myr, 6),
        latency_ms=round(max(0.0, latency_ms), 2),
        retry_count=max(0, retry_count),
        is_verified_grounded=is_verified_grounded,
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
