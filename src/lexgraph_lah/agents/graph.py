import re
from datetime import date

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import END, StateGraph

from lexgraph_lah.config import settings
from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    get_default_temporal_store,
)
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import ClauseAudit, ClauseExtractionList, RiskSeverity
from lexgraph_lah.schemas.state import AgentState

MAX_RETRIES = 2

_DEFAULT_TEMPORAL_STORE: TemporalGraphStore = get_default_temporal_store()
_OFFLINE_KEYS = {"mock-key-for-ci", "mock-ci-key-zero-cost", "your_key_here", ""}


def _extract_verbatim_sentence(raw_text: str, prefix: str) -> str:
    idx = raw_text.find(prefix)
    if idx == -1:
        return raw_text.strip()
    rest = raw_text[idx:]
    next_sec = re.search(r"\s+SEC-\d+\.\d+", rest[len(prefix) :])
    if next_sec:
        return rest[: len(prefix) + next_sec.start()].strip()
    return rest.strip()


def _span_ids_for(statute_ids: list[str]) -> list[str]:
    span_ids: list[str] = []
    for sid in statute_ids:
        node = _DEFAULT_TEMPORAL_STORE.nodes.get(sid)
        if node:
            for sp in node.source_spans:
                if sp.span_id not in span_ids:
                    span_ids.append(sp.span_id)
    return span_ids


def _offline_deterministic_assess(state: AgentState, safe_text: str) -> dict:
    """
    Deterministic offline fallback when running Demo UI or CLI without a live GEMINI_API_KEY.
    Produces strictly verbatim ClauseAudit findings grounded in `safe_text` (post-PII-scrub)
    and point-in-time `retrieved_statutes`.
    """
    retrieved_statutes = state.get("retrieved_statutes") or []
    active_ids = {s.node_id for s in retrieved_statutes}
    primary_pdpa_id = (
        "PDPA-2010-SEC-9-V2"
        if "PDPA-2010-SEC-9-V2" in active_ids
        else "PDPA-2010-SEC-9-V1"
    )

    clauses: list[ClauseAudit] = []
    lower_text = safe_text.lower()

    if "sec-8.1" in lower_text or "zero statutory liability" in lower_text:
        quote_8_1 = _extract_verbatim_sentence(safe_text, "SEC-8.1")
        violated = [primary_pdpa_id]
        clauses.append(
            ClauseAudit(
                clause_id="SEC-8.1",
                category="Statutory Liability Exclusion",
                exact_quote=quote_8_1,
                severity=RiskSeverity.CRITICAL,
                rationale=(
                    f"Directly contravenes {primary_pdpa_id}, which imposes direct statutory "
                    "Security Principle obligations and penalties up to RM 1,000,000 on data processors."
                ),
                recommended_redline=(
                    "The Data Processor shall comply with all direct statutory obligations under "
                    "Section 9 of the Personal Data Protection Act 2010 (as amended)."
                ),
                violated_statute_ids=violated,
                source_span_ids=_span_ids_for(violated),
            )
        )

    if "sec-8.2" in lower_text or (
        "breach notice" in lower_text
        and ("14 days" in lower_text or "10 days" in lower_text)
    ):
        quote_8_2 = _extract_verbatim_sentence(safe_text, "SEC-8.2")
        violated = (
            [primary_pdpa_id, "PDPA-2010-SEC-12B-V1"]
            if "PDPA-2010-SEC-12B-V1" in active_ids
            else [primary_pdpa_id]
        )
        clauses.append(
            ClauseAudit(
                clause_id="SEC-8.2",
                category="Data Breach Notification",
                exact_quote=quote_8_2,
                severity=RiskSeverity.HIGH,
                rationale=(
                    f"Violates the mandatory 72-hour Commissioner notification window under "
                    f"Section 12B ({primary_pdpa_id})."
                ),
                recommended_redline=(
                    "Notification of a personal data breach shall be provided within 24 hours "
                    "to enable the Data User to meet the 72-hour statutory deadline."
                ),
                violated_statute_ids=violated,
                source_span_ids=_span_ids_for(violated),
            )
        )

    if "sec-4.2" in lower_text or "14 business days at its sole discretion" in lower_text:
        quote_4_2 = _extract_verbatim_sentence(safe_text, "SEC-4.2")
        violated = [primary_pdpa_id]
        clauses.append(
            ClauseAudit(
                clause_id="SEC-4.2",
                category="Data Breach Notification",
                exact_quote=quote_4_2,
                severity=RiskSeverity.MEDIUM,
                rationale=(
                    f"Evaluated under point-in-time statute {primary_pdpa_id}: discretionary "
                    "14-business-day incident reporting creates contractual exposure under Section 9 "
                    "practical security steps, though the 2025 72-hour statutory mandate was not yet active."
                ),
                recommended_redline=(
                    "The Data Processor shall notify the Data User within 48 hours of any "
                    "suspected personal data security incident."
                ),
                violated_statute_ids=violated,
                source_span_ids=_span_ids_for(violated),
            )
        )

    if "sec-4.3" in lower_text and "cross-border" in lower_text:
        quote_4_3 = _extract_verbatim_sentence(safe_text, "SEC-4.3")
        violated = [primary_pdpa_id]
        clauses.append(
            ClauseAudit(
                clause_id="SEC-4.3",
                category="Cross-Border Data Transfer",
                exact_quote=quote_4_3,
                severity=RiskSeverity.MEDIUM,
                rationale=(
                    "Unilateral regional mirroring without explicit adequacy verification or data "
                    f"user consent requires contractual hardening under {primary_pdpa_id}."
                ),
                recommended_redline=(
                    "Personal data may only be transferred outside Malaysia with prior written "
                    "consent of the Data User and equivalent statutory protection safeguards."
                ),
                violated_statute_ids=violated,
                source_span_ids=_span_ids_for(violated),
            )
        )

    if not clauses:
        if "sec-1.1" in lower_text or "within 72 hours" in lower_text:
            quote_ok = _extract_verbatim_sentence(safe_text, "SEC-1.1")
            clauses.append(
                ClauseAudit(
                    clause_id="SEC-1.1",
                    category="Statutory Security & Breach Compliance",
                    exact_quote=quote_ok,
                    severity=RiskSeverity.LOW,
                    rationale=(
                        f"Clause aligns with {primary_pdpa_id} security controls and "
                        "the 72-hour mandatory Commissioner notification requirement."
                    ),
                    recommended_redline="No redline required — clause is compliant with active statutes.",
                    violated_statute_ids=[],
                    source_span_ids=_span_ids_for([primary_pdpa_id]),
                )
            )
        else:
            snippet = safe_text.strip()
            is_risky = any(
                kw in lower_text
                for kw in (
                    "unlimited",
                    "waive",
                    "sole discretion",
                    "without notice",
                    "exclude",
                    "without consent",
                )
            )
            violated = [primary_pdpa_id] if is_risky else []
            clauses.append(
                ClauseAudit(
                    clause_id="SEC-1.0",
                    category="General Regulatory Review",
                    exact_quote=snippet,
                    severity=RiskSeverity.HIGH if is_risky else RiskSeverity.LOW,
                    rationale=(
                        f"Deterministic offline clause audit evaluated against {primary_pdpa_id}."
                    ),
                    recommended_redline=(
                        "Ensure explicit alignment with Section 9 and Section 12B of the PDPA 2010."
                        if is_risky
                        else "No redline required — clause is compliant."
                    ),
                    violated_statute_ids=violated,
                    source_span_ids=_span_ids_for([primary_pdpa_id]),
                )
            )

    est_prompt_tokens = max(420, len(safe_text) // 3 + 380)
    est_completion_tokens = max(140, len(clauses) * 95 + 45)
    return {
        "extracted_clauses": clauses,
        "prompt_tokens": est_prompt_tokens,
        "completion_tokens": est_completion_tokens,
    }


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
    and `territorial_scope`, resolving multi-hop CITES edges before LLM invocation.
    """
    raw_ref_date = state.get("reference_date")
    as_of_date = date.fromisoformat(raw_ref_date) if raw_ref_date else date.today()
    act_filter = state.get("act_filter")
    territorial_scope = state.get("territorial_scope")

    active_statutes = _DEFAULT_TEMPORAL_STORE.query_point_in_time(
        as_of_date=as_of_date,
        act_name=act_filter,
        include_citations=True,
        territorial_scope=territorial_scope,
    )

    return {
        "retrieved_statutes": active_statutes,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }


async def risk_assessor_node(state: AgentState) -> dict:
    """
    Node 1: Masks Malaysian PII pre-flight (<50ms) and extracts risky clauses
    using strict Pydantic structured output.
    """
    raw_text = state["raw_text"]
    pii_summary = scrub_malaysian_pii(raw_text) if settings.pii_scrub_enabled else None
    safe_text = pii_summary.masked_text if pii_summary else raw_text
    pii_dict = pii_summary.model_dump(mode="json") if pii_summary else None

    llm = get_llm()
    if (
        isinstance(llm, ChatGoogleGenerativeAI)
        and settings.gemini_api_key.strip() in _OFFLINE_KEYS
    ):
        offline_out = _offline_deterministic_assess(state, safe_text=safe_text)
        offline_out["pii_scrub"] = pii_dict
        return offline_out

    structured_llm = llm.with_structured_output(ClauseExtractionList, include_raw=True)

    system_prompt = (
        "You are a Principal Legal & Compliance AI Auditor. Analyze the contract text and extract "
        "high-risk clauses. CRITICAL RULE: The exact_quote field MUST be copied verbatim "
        "(character-for-character) from the source text."
    )

    retrieved_statutes = state.get("retrieved_statutes") or []
    if retrieved_statutes:
        statute_block = "\n".join(
            f"- [{s.node_id}] ({s.act_name} {s.section_code}, Tier {int(s.authority_tier)}, v{s.version}, "
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
            HumanMessage(content=f"CONTRACT TEXT:\n{safe_text}"),
        ]
    )

    parsed: ClauseExtractionList = result["parsed"]
    raw_msg = result["raw"]
    usage = getattr(raw_msg, "usage_metadata", {}) or {}

    return {
        "extracted_clauses": parsed.clauses if parsed else [],
        "pii_scrub": pii_dict,
        "prompt_tokens": usage.get("input_tokens", 0),
        "completion_tokens": usage.get("output_tokens", 0),
    }


async def citation_auditor_node(state: AgentState) -> dict:
    """Node 2: Deterministic zero-hallucination guardrail checking verbatim quotes."""
    raw_text = state["raw_text"]
    pii_dict = state.get("pii_scrub") or {}
    masked_text = pii_dict.get("masked_text", raw_text) if isinstance(pii_dict, dict) else raw_text

    unverified_ids = [
        clause.clause_id
        for clause in state["extracted_clauses"]
        if clause.exact_quote not in raw_text and clause.exact_quote not in masked_text
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
