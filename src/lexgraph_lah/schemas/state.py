import operator
from typing import Annotated, Any, NotRequired, TypedDict

from lexgraph_lah.schemas.domain import ClauseAudit, StatutoryNode


class AgentState(TypedDict):
    document_id: str
    raw_text: str
    reference_date: NotRequired[str | None]
    act_filter: NotRequired[str | None]
    regimes: NotRequired[list[str] | None]
    territorial_scope: NotRequired[str | None]
    persona: NotRequired[str | None]
    language: NotRequired[str | None]
    abstention_threshold: NotRequired[float | None]
    is_abstained: NotRequired[bool]
    abstention_reason: NotRequired[str | None]
    max_relevance_score: NotRequired[float]
    pii_scrub: NotRequired[dict[str, Any] | None]
    pii_vault_map: NotRequired[dict[str, str] | None]
    contract_ast: NotRequired[dict[str, Any] | None]
    retrieved_statutes: NotRequired[list[StatutoryNode]]
    deontic_envelope: NotRequired[dict[str, Any] | None]
    extracted_clauses: list[ClauseAudit]
    executive_summary: NotRequired[str]
    auditor_feedback: str
    counterfactual_log: NotRequired[list[dict[str, Any]]]
    is_grounded: bool
    retry_count: int
    attestation_manifest: NotRequired[dict[str, Any] | None]
    security_report: NotRequired[dict[str, Any] | None]
    security_findings: NotRequired[list[dict[str, Any]]]
    selected_model: NotRequired[str | None]
    model_routing_reason: NotRequired[str | None]
    trace_id: NotRequired[str | None]
    prompt_tokens: Annotated[int, operator.add]
    completion_tokens: Annotated[int, operator.add]
    hallucination_rejections: NotRequired[Annotated[int, operator.add]]
