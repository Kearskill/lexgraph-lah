from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import END, StateGraph

from lexgraph_lah.config import settings
from lexgraph_lah.schemas.domain import ClauseExtractionList
from lexgraph_lah.schemas.state import AgentState

MAX_RETRIES = 2


def get_llm():
    return ChatGoogleGenerativeAI(
        model=settings.model_name,
        google_api_key=settings.gemini_api_key,
        temperature=0.0,
    )


async def risk_assessor_node(state: AgentState) -> dict:
    """Node 1: Extracts risky clauses using strict Pydantic structured output."""
    llm = get_llm()
    structured_llm = llm.with_structured_output(ClauseExtractionList, include_raw=True)

    system_prompt = (
        "You are a Principal Legal & Compliance AI Auditor. Analyze the contract text and extract "
        "high-risk clauses. CRITICAL RULE: The exact_quote field MUST be copied verbatim "
        "(character-for-character) from the source text."
    )
    if state.get("auditor_feedback"):
        system_prompt += f"\n\nPREVIOUS AUDIT FAILED: {state['auditor_feedback']}"

    result = await structured_llm.ainvoke(
        [
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"CONTRACT TEXT:\n{state['raw_text']}"),
        ]
    )

    parsed: ClauseExtractionList = result["parsed"]
    raw_msg = result["raw"]
    usage = getattr(raw_msg, "usage_metadata", {}) or {}

    return {
        "extracted_clauses": parsed.clauses if parsed else [],
        "prompt_tokens": usage.get("input_tokens", 0),
        "completion_tokens": usage.get("output_tokens", 0),
    }


async def citation_auditor_node(state: AgentState) -> dict:
    """Node 2: Deterministic zero-hallucination guardrail checking verbatim quotes."""
    raw_text = state["raw_text"]
    unverified_ids = [
        clause.clause_id
        for clause in state["extracted_clauses"]
        if clause.exact_quote not in raw_text
    ]

    if unverified_ids:
        return {
            "is_grounded": False,
            "auditor_feedback": (
                f"Hallucinated or altered quotes detected in {unverified_ids}. "
                "You MUST copy exact_quote as an exact substring from CONTRACT TEXT."
            ),
            "retry_count": state.get("retry_count", 0) + 1,
            "prompt_tokens": 0,
            "completion_tokens": 0,
        }

    return {
        "is_grounded": True,
        "auditor_feedback": "All citations verified verbatim.",
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }


def route_after_audit(state: AgentState) -> str:
    if state["is_grounded"] or state.get("retry_count", 0) >= MAX_RETRIES:
        return END
    return "risk_assessor"


def build_compliance_graph():
    workflow = StateGraph(AgentState)
    workflow.add_node("risk_assessor", risk_assessor_node)
    workflow.add_node("citation_auditor", citation_auditor_node)

    workflow.set_entry_point("risk_assessor")
    workflow.add_edge("risk_assessor", "citation_auditor")
    workflow.add_conditional_edges(
        "citation_auditor",
        route_after_audit,
        {"risk_assessor": "risk_assessor", END: END},
    )
    return workflow.compile()
