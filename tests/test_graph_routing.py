import pytest

from lexgraph_lah.agents.graph import citation_auditor_node, route_after_audit
from lexgraph_lah.schemas.domain import ClauseAudit, RiskSeverity


@pytest.mark.asyncio
async def test_citation_auditor_blocks_hallucinated_quote():
    """Verify the deterministic critic catches non-verbatim quotes and increments retry_count."""
    mock_state = {
        "document_id": "DOC-001",
        "raw_text": "Section 1: Liability is capped at RM 50,000.",
        "extracted_clauses": [
            ClauseAudit(
                clause_id="SEC-1",
                category="Liability",
                exact_quote="Hallucinated quote that does not exist in raw_text.",
                severity=RiskSeverity.HIGH,
                rationale="Test rationale",
                recommended_redline="Test redline",
            )
        ],
        "auditor_feedback": "",
        "is_grounded": False,
        "retry_count": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }

    result = await citation_auditor_node(mock_state)
    assert result["is_grounded"] is False
    assert result["retry_count"] == 1
    assert "SEC-1" in result["auditor_feedback"]


def test_router_stops_at_max_retries():
    """Ensure bounded reflection loop prevents infinite LLM billing loops."""
    state_at_limit = {"is_grounded": False, "retry_count": 2}
    assert route_after_audit(state_at_limit) == "__end__"
