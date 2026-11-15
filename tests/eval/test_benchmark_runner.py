import pytest

from evals.run_benchmark import (
    format_markdown_report,
    get_benchmark_dataset,
    run_benchmark_async,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary


@pytest.mark.asyncio
async def test_benchmark_runner_mock_mode_and_markdown_table():
    """
    Verifies the 10-case golden benchmark suite in mock mode produces 100% determinism
    consistency, 100% verdict accuracy, 100% verbatim grounding, and renders a Markdown
    report with p50/p95 latency and USD/MYR cost metrics.
    """
    dataset = get_benchmark_dataset()
    assert len(dataset) >= 10

    summary = await run_benchmark_async(mode="mock", trials=2)
    assert summary.total_cases == 10
    assert summary.trials_per_case == 2
    assert summary.total_runs == 20
    assert summary.determinism_consistency_pct == 100.0
    assert summary.verdict_accuracy_pct == 100.0
    assert summary.verbatim_grounding_pct == 100.0
    assert summary.temporal_recall_pct == 100.0
    assert summary.temporal_contamination_pct == 0.0
    assert summary.mean_cost_usd > 0.0
    assert summary.mean_cost_myr > 0.0

    report = format_markdown_report(summary)
    assert "Determinism Consistency (%)" in report
    assert "Verdict Accuracy (%)" in report
    assert "Latency (p50 / p95 ms)" in report
    assert "Mean Cost per Audit (USD & MYR)" in report
    assert "BENCH-09-CRITIC-SELF-CORRECTION-LOOP" in report


def test_finops_myr_usd_deterministic_rounding():
    """
    Verifies compute_telemetry_summary deterministically calculates and rounds USD and MYR
    token costs to 6 decimal places and clamps negative token/latency inputs to 0.
    """
    # 1,000 prompt tokens @ $0.15/1M = $0.000150 USD
    # 500 completion tokens @ $0.60/1M = $0.000300 USD
    # Total USD = $0.000450 USD
    # Total MYR @ 4.40 FX = RM 0.001980 MYR
    summary = compute_telemetry_summary(
        prompt_tokens=1000,
        completion_tokens=500,
        latency_ms=18.4567,
        retry_count=1,
        is_verified_grounded=True,
        input_cost_per_1m_usd=0.15,
        output_cost_per_1m_usd=0.60,
        usd_to_myr_rate=4.40,
        trace_id="span-test1234",
    )
    assert summary.prompt_tokens == 1000
    assert summary.completion_tokens == 500
    assert summary.total_tokens == 1500
    assert summary.estimated_cost_usd == 0.00045
    assert summary.estimated_cost_myr == 0.00198
    assert summary.latency_ms == 18.46
    assert summary.retry_count == 1
    assert summary.is_verified_grounded is True
    assert summary.trace_id == "span-test1234"

    # Fractional token test verifying 6-decimal rounding
    frac = compute_telemetry_summary(
        prompt_tokens=333,
        completion_tokens=177,
        latency_ms=-5.0,
        retry_count=-1,
        is_verified_grounded=False,
        input_cost_per_1m_usd=0.15,
        output_cost_per_1m_usd=0.60,
        usd_to_myr_rate=4.425,
    )
    expected_usd = (333 / 1_000_000.0) * 0.15 + (177 / 1_000_000.0) * 0.60
    assert frac.estimated_cost_usd == round(expected_usd, 6)
    assert frac.estimated_cost_myr == round(expected_usd * 4.425, 6)
    assert frac.latency_ms == 0.0
    assert frac.retry_count == 0
