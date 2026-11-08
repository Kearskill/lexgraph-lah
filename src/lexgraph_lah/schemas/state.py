import operator
from typing import Annotated, NotRequired, TypedDict

from lexgraph_lah.schemas.domain import ClauseAudit, StatutoryNode


class AgentState(TypedDict):
    document_id: str
    raw_text: str
    reference_date: NotRequired[str | None]
    act_filter: NotRequired[str | None]
    retrieved_statutes: NotRequired[list[StatutoryNode]]
    extracted_clauses: list[ClauseAudit]
    auditor_feedback: str
    is_grounded: bool
    retry_count: int
    prompt_tokens: Annotated[int, operator.add]
    completion_tokens: Annotated[int, operator.add]
