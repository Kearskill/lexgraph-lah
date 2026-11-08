from datetime import date

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import END, StateGraph

from lexgraph_lah.config import settings
from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    get_default_temporal_store,
)
from lexgraph_lah.schemas.domain import ClauseExtractionList
from lexgraph_lah.schemas.state import AgentState

MAX_RETRIES = 2

_DEFAULT_TEMPORAL_STORE: TemporalGraphStore = get_default_temporal_store()


def get_llm():
    return ChatGoogleGenerativeAI(
        model=settings.model_name,
        google_api_key=settings.gemini_api_key,
        temperature=0.0,
    )


async def temporal_retriever_node(state: AgentState) -> dict:
    """
    Node 0: Point-in-time Graph-RAG statutory resolver.
    Deterministically filters active statutes as of `reference_date` (or today)
    and resolves multi-hop CITES edges before LLM invocation (0 LLM tokens used).
    """
    raw_ref_date = state.get("reference_date")
    as_of_date = date.fromisoformat(raw_ref_date) if raw_ref_date else date.today()
    act_filter = state.get("act_filter")

    active_statutes = _DEFAULT_TEMPORAL_STORE.query_point_in_time(
        as_of_date=as_of_date,
        act_name=act_filter,
        include_citations=True,
    )

    return {
        "retrieved_statutes": active_statutes,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }


async def risk_assessor_node(state: AgentState) -> dict:
    """Node 1: Extracts risky clauses using strict Pydantic structured output."""
    llm = get_llm()
    structured_llm = llm.with_structured_output(ClauseExtractionList, include_raw=True)

    system_prompt = (
        "You are a Principal Legal & Compliance AI Auditor. Analyze the contract text and extract "
        "high-risk clauses. CRITICAL RULE: The exact_quote field MUST be copied verbatim "
        "(character-for-character) from the source text."
    )

    retrieved_statutes = state.get("retrieved_statutes") or []
    if retrieved_statutes:
        statute_block = "\n".join(
            f"- [{s.node_id}] ({s.act_name} {s.section_code}, v{s.version}, "
            f"valid_from={s.valid_from}, valid_to={s.valid_to or 'PRESENT'}): {s.text}"
            for s in retrieved_statutes
        )
        system_prompt += (
            "\n\nPOINT-IN-TIME STATUTORY CONTEXT (Evaluate compliance strictly against these "
            f"provisions active on the contract reference date):\n{statute_block}"
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
    workflow.add_node("temporal_retriever", temporal_retriever_node)
    workflow.add_node("risk_assessor", risk_assessor_node)
    workflow.add_node("citation_auditor", citation_auditor_node)

    workflow.set_entry_point("temporal_retriever")
    workflow.add_edge("temporal_retriever", "risk_assessor")
    workflow.add_edge("risk_assessor", "citation_auditor")
    workflow.add_conditional_edges(
        "citation_auditor",
        route_after_audit,
        {"risk_assessor": "risk_assessor", END: END},
    )
    return workflow.compile()
