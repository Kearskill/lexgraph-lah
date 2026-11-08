from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lexgraph_lah.agents.graph import build_compliance_graph
from lexgraph_lah.eval.harness import (
    GoldenLegalScenario,
    evaluate_entity_and_citation_grounding,
    evaluate_temporal_context,
    get_golden_legal_scenarios,
)
from lexgraph_lah.schemas.domain import ClauseAudit, ClauseExtractionList, RiskSeverity
from lexgraph_lah.telemetry.cost_tracker import (
    BudgetExceededError,
    assert_within_budget,
    compute_telemetry_summary,
)
from lexgraph_lah.telemetry.tracer import (
    ComplianceSpanRecord,
    measure_latency_ms,
    telemetry_registry,
)


def _make_mock_llm_With_structured_responses(
    responses: list[tuple[list[ClauseAudit], int, int]],
):
    """
    Helper that mocks `get_llm()` so `llm.with_structured_output(...).ainvoke(...)`
    returns sequential `(clauses, input_tokens, output_tokens)` tuples.
    """
    side_effects = []
    for clauses, in_tok, out_tok in responses:
        raw_msg = SimpleNamespace(
            usage_metadata={"input_tokens": in_tok, "output_tokens": out_tok}
        )
        side_effects.append(
            {
                "parsed": ClauseExtractionList(clauses=clauses),
                "raw": raw_msg,
            }
        )

    structured_mock = MagicMock()
    structured_mock.ainvoke = AsyncMock(side_effect=side_effects)

    llm_mock = MagicMock()
    llm_mock.with_structured_output.return_value = structured_mock
    return llm_mock


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    get_golden_legal_scenarios(),
    ids=lambda s: s.scenario_id,
)
async def test_golden_legal_scenarios_end_to_end_pipeline(
    scenario: GoldenLegalScenario,
):
    """
    Runs each synthetic golden legal scenario through the compiled LangGraph pipeline
    (`temporal_retriever` -> `risk_assessor` -> `citation_auditor`) and asserts:
      1. Temporal Context Recall == 1.0 (100% active statutes retrieved)
      2. Temporal Contamination Rate == 0.0 (0% superseded/post-dated statutes leaked)
      3. Entity/Clause Recall == 1.0
      4. Verbatim Grounding Precision == 1.0
      5. FinOps SLA compliance (< $0.005 USD per run)
    """
    mock_llm = _make_mock_llm_With_structured_responses(
        [(scenario.simulated_llm_extractions, 650, 220)]
    )

    with patch("lexgraph_lah.agents.graph.get_llm", return_value=mock_llm):
        graph = build_compliance_graph()
        initial_state = {
            "document_id": scenario.scenario_id,
            "raw_text": scenario.contract_text,
            "reference_date": scenario.reference_date.isoformat(),
            "act_filter": scenario.act_filter,
            "extracted_clauses": [],
            "auditor_feedback": "",
            "is_grounded": False,
            "retry_count": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
        }

        with measure_latency_ms() as elapsed_holder:
            final_state = await graph.ainvoke(initial_state)

    retrieved_statutes = final_state["retrieved_statutes"]
    extracted_clauses = final_state["extracted_clauses"]

    # 1. Temporal Context Recall & Contamination Assertions
    ctx_recall, ctx_contamination = evaluate_temporal_context(
        retrieved_statutes=retrieved_statutes,
        expected_ids=scenario.expected_active_statute_ids,
        forbidden_ids=scenario.forbidden_statute_ids,
    )
    assert ctx_recall == 1.0, f"Expected 100% temporal context recall, got {ctx_recall}"
    assert ctx_contamination == 0.0, (
        f"Temporal contamination detected! Forbidden statutes leaked: {retrieved_statutes}"
    )

    # 2. Entity Resolution & Verbatim Grounding Assertions
    clause_recall, grounding_precision = evaluate_entity_and_citation_grounding(
        extracted_clauses=extracted_clauses,
        raw_contract_text=scenario.contract_text,
        expected_clause_ids=scenario.expected_clause_ids,
    )
    assert clause_recall == 1.0
    assert grounding_precision == 1.0
    assert final_state["is_grounded"] is True
    assert final_state["retry_count"] == 0

    # 3. FinOps Telemetry & Budget Assertion
    telemetry = compute_telemetry_summary(
        prompt_tokens=final_state["prompt_tokens"],
        completion_tokens=final_state["completion_tokens"],
        latency_ms=elapsed_holder[0],
        retry_count=final_state["retry_count"],
        is_verified_grounded=final_state["is_grounded"],
    )
    assert_within_budget(telemetry, max_cost_usd=scenario.max_budget_usd)

    telemetry_registry.record_span(
        ComplianceSpanRecord(
            span_id=f"span-{scenario.scenario_id}",
            document_id=scenario.scenario_id,
            reference_date=scenario.reference_date.isoformat(),
            active_statute_count=len(retrieved_statutes),
            telemetry=telemetry,
            timestamp_epoch=1700000000.0,
        )
    )


@pytest.mark.asyncio
async def test_self_correction_loop_recovers_from_hallucinated_quote_within_budget():
    """
    Simulates a first-pass LLM hallucination (paraphrased quote) caught by `citation_auditor_node`,
    followed by a second-pass self-corrected verbatim quote, and verifies token accumulation
    across retries stays within FinOps budget.
    """
    contract_text = (
        "SEC-9.1 Liability Cap: Total aggregate liability shall not exceed RM 100,000."
    )

    hallucinated_attempt = [
        ClauseAudit(
            clause_id="SEC-9.1",
            category="Liability",
            exact_quote="Total liability is capped at RM 100,000.",  # Paraphrased / mutated!
            severity=RiskSeverity.HIGH,
            rationale="Cap is low.",
            recommended_redline="Increase cap to RM 500,000.",
        )
    ]
    corrected_attempt = [
        ClauseAudit(
            clause_id="SEC-9.1",
            category="Liability",
            exact_quote="SEC-9.1 Liability Cap: Total aggregate liability shall not exceed RM 100,000.",
            severity=RiskSeverity.HIGH,
            rationale="Cap is low.",
            recommended_redline="Increase cap to RM 500,000.",
        )
    ]

    mock_llm = _make_mock_llm_With_structured_responses(
        [
            (hallucinated_attempt, 500, 150),
            (corrected_attempt, 620, 150),
        ]
    )

    with patch("lexgraph_lah.agents.graph.get_llm", return_value=mock_llm):
        graph = build_compliance_graph()
        final_state = await graph.ainvoke(
            {
                "document_id": "DOC-SELF-CORRECT",
                "raw_text": contract_text,
                "reference_date": "2026-01-15",
                "extracted_clauses": [],
                "auditor_feedback": "",
                "is_grounded": False,
                "retry_count": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
            }
        )

    assert final_state["is_grounded"] is True
    assert final_state["retry_count"] == 1
    assert final_state["prompt_tokens"] == 1120
    assert final_state["completion_tokens"] == 300

    telemetry = compute_telemetry_summary(
        prompt_tokens=final_state["prompt_tokens"],
        completion_tokens=final_state["completion_tokens"],
        latency_ms=42.5,
        retry_count=final_state["retry_count"],
        is_verified_grounded=final_state["is_grounded"],
    )
    assert_within_budget(telemetry, max_cost_usd=0.005)


def test_finops_budget_guardrail_raises_on_runaway_cost():
    """Verify assert_within_budget raises BudgetExceededError when cost or tokens exceed SLA."""
    excessive_telemetry = compute_telemetry_summary(
        prompt_tokens=100_000,
        completion_tokens=50_000,
        latency_ms=1200.0,
        retry_count=2,
        is_verified_grounded=False,
    )
    with pytest.raises(BudgetExceededError, match="FinOps SLA breach"):
        assert_within_budget(excessive_telemetry, max_cost_usd=0.005)
