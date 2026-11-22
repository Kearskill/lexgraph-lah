from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from evals.run_benchmark import get_benchmark_dataset, run_benchmark_async
from lexgraph_lah.agents.graph import (
    _invoke_structured_llm_with_backoff,
    get_llm,
)
from lexgraph_lah.config import settings
from lexgraph_lah.schemas.domain import ClauseExtractionList
from lexgraph_lah.telemetry.cost_tracker import (
    BNMFXRateProvider,
    default_bnm_fx_provider,
    resolve_logical_tier,
    resolve_provider_model_id,
    select_model_tier,
)


def test_configurable_model_tier_aliasing_preserves_mock_and_resolves_live(
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Verifies:
      - Logical tiers (`fast_tier` / `reasoning_tier`) and legacy aliases
        (`gemini-4-hydrogen` / `gemini-4-neon`) remain invariant in mock/offline mode.
      - In live mode (`GEMINI_API_KEY` active or `mode='live'`), tiers map dynamically via
        `LEXGRAPH_MODEL_FAST` / `LEXGRAPH_MODEL_REASONING`.
    """
    assert resolve_logical_tier("gemini-4-hydrogen") == "fast_tier"
    assert resolve_logical_tier("gemini-4-neon") == "reasoning_tier"
    assert resolve_logical_tier("gemini-2.5-pro") == "reasoning_tier"

    # Mock/offline preserves legacy aliases for FinOps & MCP benchmarks
    monkeypatch.setattr(settings, "gemini_api_key", "mock-key-for-ci")
    m_fast, _ = select_model_tier(regimes=["ACT_709"])
    m_complex, _ = select_model_tier(regimes=["ACT_709", "ACT_854"])
    assert resolve_provider_model_id(m_fast) == "gemini-4-hydrogen"
    assert resolve_provider_model_id(m_complex) == "gemini-4-neon"
    assert resolve_provider_model_id("fast_tier", mode="mock") == "gemini-4-hydrogen"
    assert resolve_provider_model_id("reasoning_tier", mode="mock") == "gemini-4-neon"

    # Live resolution maps via configurable fast/reasoning model IDs
    monkeypatch.setattr(settings, "gemini_api_key", "AIza-live-test-key")
    monkeypatch.setattr(settings, "lexgraph_model_fast", "gemini-2.5-flash")
    monkeypatch.setattr(settings, "lexgraph_model_reasoning", "gemini-2.5-pro")
    assert resolve_provider_model_id("gemini-4-hydrogen") == "gemini-2.5-flash"
    assert resolve_provider_model_id("gemini-4-neon") == "gemini-2.5-pro"
    assert resolve_provider_model_id("fast_tier") == "gemini-2.5-flash"
    assert resolve_provider_model_id("reasoning_tier") == "gemini-2.5-pro"
    assert resolve_provider_model_id("gemini-2.0-flash") == "gemini-2.0-flash"

    llm_fast = get_llm("gemini-4-hydrogen")
    llm_reason = get_llm("gemini-4-neon")
    assert "gemini-2.5-flash" in str(llm_fast.model)
    assert "gemini-2.5-pro" in str(llm_reason.model)


@pytest.mark.asyncio
async def test_structured_llm_backoff_and_schema_validation():
    """
    Verifies exponential backoff recovers from transient 429/timeout failures and rejects
    invalid/missing structured ClauseExtractionList outputs deterministically.
    """
    attempts = {"count": 0}

    class _FlakyStructuredLLM:
        async def ainvoke(self, messages: list[object]) -> dict[str, object]:
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise RuntimeError("429 Resource Exhausted rate limit hit")
            return {
                "parsed": ClauseExtractionList(clauses=[]),
                "raw": SimpleNamespace(
                    usage_metadata={"input_tokens": 100, "output_tokens": 20}
                ),
            }

    out = await _invoke_structured_llm_with_backoff(
        _FlakyStructuredLLM(), [], max_retries=3, base_delay=0.001
    )
    assert attempts["count"] == 3
    assert isinstance(out["parsed"], ClauseExtractionList)

    # Permanent validation error (parsed=None) fails immediately without masking schema errors
    class _BrokenStructuredLLM:
        async def ainvoke(self, messages: list[object]) -> dict[str, object]:
            return {"parsed": None, "parsing_error": "invalid JSON fields"}

    with pytest.raises(ValueError, match="ClauseExtractionList"):
        await _invoke_structured_llm_with_backoff(
            _BrokenStructuredLLM(), [], max_retries=2, base_delay=0.001
        )


@pytest.mark.asyncio
async def test_bnm_fx_rate_provider_live_cache_and_fallback(
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Verifies Bank Negara Malaysia OpenAPI USD/MYR rate parsing, 24h cache hits,
    and deterministic fallback to `LEXGRAPH_USD_MYR_FALLBACK` when offline or disabled.
    """
    calls = {"n": 0}

    async def _fake_bnm_fetch(url: str) -> dict[str, object]:
        calls["n"] += 1
        return {
            "data": [
                {"currency_code": "SGD", "unit": 1, "rate": {"middle_rate": 3.31}},
                {"currency_code": "USD", "unit": 1, "rate": {"middle_rate": 4.325}},
            ]
        }

    provider = BNMFXRateProvider(
        fetcher=_fake_bnm_fetch, cache_ttl_seconds=86400, enabled=True
    )
    r1, src1 = await provider.get_usd_to_myr_rate()
    assert r1 == 4.325
    assert src1 == "bnm_live"
    assert calls["n"] == 1

    # Second call hits 24h cache without re-fetching
    r2, src2 = await provider.get_usd_to_myr_rate()
    assert r2 == 4.325
    assert src2 == "bnm_cache"
    assert calls["n"] == 1

    # Offline/HTTP error falls back to LEXGRAPH_USD_MYR_FALLBACK when uncached
    async def _failing_fetch(url: str) -> dict[str, object]:
        raise httpx.ConnectError("BNM API offline")

    monkeypatch.setattr(settings, "lexgraph_usd_myr_fallback", 4.51)
    offline_provider = BNMFXRateProvider(
        fetcher=_failing_fetch, cache_ttl_seconds=86400, enabled=True
    )
    r3, src3 = await offline_provider.get_usd_to_myr_rate()
    assert r3 == 4.51
    assert src3 == "fallback"

    # Disabled mode skips network cleanly
    disabled_provider = BNMFXRateProvider(enabled=False)
    r4, src4 = await disabled_provider.get_usd_to_myr_rate()
    assert r4 == 4.51
    assert src4 == "fallback"


@pytest.mark.asyncio
async def test_live_mode_benchmark_metrics_and_artifact_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Exercises `evals/run_benchmark.py --mode live` end-to-end with a patched live Gemini client
    (simulating verbatim hallucination -> counterfactual retry recovery), live BNM FX rate,
    and JSON + Markdown artifact generation in `output_dir`.
    """
    monkeypatch.setattr(settings, "gemini_api_key", "AIza-live-eval-key")
    default_bnm_fx_provider.clear_cache()

    dataset = get_benchmark_dataset()
    langgraph_cases = [c for c in dataset if c.check_kind == "langgraph"]

    # Map normalized prefix markers -> mock attempts per audit pass
    def _match_case_for_prompt(human_content: str):
        for c in langgraph_cases:
            # Match core clause fragments even when PII scrubber masked raw identifiers
            if (
                c.case_id == "BENCH-16-PII-SCRUB-MYKAD-GUARD"
                and "MyKad" in human_content
            ):
                return c
            if c.contract_text[:45] in human_content:
                return c
        return None

    class _DynamicLiveLLM:
        def with_structured_output(self, schema: object, include_raw: bool = True):
            return _DynamicStructuredRunner()

    attempt_tracker: dict[str, int] = {}

    class _DynamicStructuredRunner:
        async def ainvoke(self, messages: list[object]) -> dict[str, object]:
            sys_txt = str(getattr(messages[0], "content", ""))
            human_txt = str(getattr(messages[1], "content", ""))
            case = _match_case_for_prompt(human_txt)
            assert case is not None
            idx = 1 if "PREVIOUS AUDIT FAILED" in sys_txt else 0
            attempt_idx = min(idx, len(case.mock_attempts) - 1)
            attempt_tracker[case.case_id] = attempt_tracker.get(case.case_id, 0) + 1
            clauses, in_tok, out_tok = case.mock_attempts[attempt_idx]
            return {
                "parsed": ClauseExtractionList(clauses=clauses),
                "raw": SimpleNamespace(
                    usage_metadata={"input_tokens": in_tok, "output_tokens": out_tok}
                ),
            }

    async def _mock_fx_get(*, force_refresh: bool = False) -> tuple[float, str]:
        return 4.33, "bnm_live"

    with (
        patch("lexgraph_lah.agents.graph.get_llm", return_value=_DynamicLiveLLM()),
        patch.object(
            default_bnm_fx_provider, "get_usd_to_myr_rate", side_effect=_mock_fx_get
        ),
    ):
        summary = await run_benchmark_async(
            mode="live",
            trials=2,
            output_dir=tmp_path,
        )

    assert summary.mode == "live"
    assert summary.total_cases == len(dataset)
    assert summary.total_runs == len(dataset) * 2
    assert summary.fx_rate_used == 4.33
    assert summary.fx_rate_source == "bnm_live"
    assert summary.cross_trial_verdict_stability_pct == 100.0
    assert summary.counterfactual_retry_recovery_rate_pct == 100.0
    assert summary.citation_hallucination_rejection_count >= 1
    assert summary.abstention_precision_pct == 100.0
    assert summary.latency_p50_ms >= 0.0
    assert summary.latency_p95_ms >= summary.latency_p50_ms
    assert summary.total_cost_myr == round(
        sum(r.cost_myr for r in summary.case_results), 6
    )

    assert summary.results_artifact_path is not None
    json_file = Path(summary.results_artifact_path)
    md_file = json_file.with_suffix(".md")
    assert json_file.is_file()
    assert md_file.is_file()
    persisted = json.loads(json_file.read_text(encoding="utf-8"))
    assert persisted["cross_trial_verdict_stability_pct"] == 100.0
    assert persisted["citation_hallucination_rejection_count"] >= 1
    assert "Cross-Trial Verdict Stability (%)" in md_file.read_text(encoding="utf-8")
