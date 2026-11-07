import operator
from typing import Annotated, TypedDict
from lexgraph_lah.schemas.domain import ClauseAudit


class AgentState(TypedDict):
    document_id: str
    raw_text: str
    extracted_clauses: list[ClauseAudit]
    auditor_feedback: str
    is_grounded: bool
    retry_count: int
    prompt_tokens: Annotated[int, operator.add]
    completion_tokens: Annotated[int, operator.add]
