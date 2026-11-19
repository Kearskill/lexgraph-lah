import asyncio
import concurrent.futures
from datetime import date
from typing import Any

from lexgraph_lah.agents.graph import build_compliance_graph
from lexgraph_lah.compliance.pdpa_scanner import scan_pdpa_compliance
from lexgraph_lah.graph.bilingual_critic import audit_bilingual_divergence
from lexgraph_lah.graph.deontic_solver import DeonticEnvelopeResolver, normalize_regimes
from lexgraph_lah.graph.diff_engine import (
    diff_statute_lineage,
    evaluate_contract_delta_impact,
)
from lexgraph_lah.graph.temporal_store import get_default_temporal_store
from lexgraph_lah.ingestion.contract_ast import build_contract_ast
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import (
    ContractDeltaAuditRequest,
    OutputPersona,
    PDPAComplianceScanRequest,
    RiskSeverity,
    TerritorialScope,
)
from lexgraph_lah.schemas.state import AgentState

MCP_TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "lexgraph_pdpa_compliance_scan",
        "description": (
            "Scans contract or policy text against Malaysian PDPA 2010 [Act 709] & 2024 Amendment "
            "provisions after pre-flight Malaysian PII scrubbing, returning structured gap citations "
            "with SourceSpan IDs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {"type": "string"},
                "raw_text": {"type": "string"},
                "as_of_date": {"type": "string", "format": "date"},
                "territorial_scope": {
                    "type": "string",
                    "enum": [s.value for s in TerritorialScope],
                },
                "persona": {
                    "type": "string",
                    "enum": [p.value for p in OutputPersona],
                },
            },
            "required": ["raw_text"],
        },
    },
    {
        "name": "lexgraph_point_in_time_search",
        "description": (
            "Executes bilingual (BM/EN/code-switched) point-in-time Malaysian statutory retrieval "
            "with 5-tier authority reranking, territorial scope isolation, and 0.78 Abstention Gate."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "as_of_date": {"type": "string", "format": "date"},
                "territorial_scope": {"type": "string"},
                "abstention_threshold": {"type": "number", "default": 0.78},
            },
            "required": ["query"],
        },
    },
    {
        "name": "lexgraph_pii_scrub",
        "description": "Masks Malaysian NRIC, Passport, Phone, Email, and SSM registration numbers into typed placeholders.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "resolve_deontic_envelope",
        "description": (
            "Zero-token O(V + E) Deontic Conflict Solver that resolves the Strictest Composite "
            "Statutory Envelope across colliding Malaysian regimes (Act 709 PDPA, Act 854 Cyber Security Act "
            "& P.U.(A) 220/2024, and BNM RMiT) as of a specific point-in-time date and territorial scope."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "regimes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["ACT_709", "ACT_854", "BNM_RMIT"],
                },
                "as_of_date": {"type": "string", "format": "date"},
                "territorial_scope": {
                    "type": "string",
                    "enum": [s.value for s in TerritorialScope],
                },
            },
            "required": ["regimes"],
        },
    },
    {
        "name": "detect_contract_shadow_overrides",
        "description": (
            "Builds the Intra-Contract Dependency Graph (DEFINES_TERM, OVERRIDES_NOTWITHSTANDING, "
            "CROSS_REFERENCES) after reversible Malaysian PII vault scrubbing to detect hostile "
            "'Notwithstanding' / 'Walau apa pun' shadow override traps and narrow definition traps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {"type": "string"},
                "raw_text": {"type": "string"},
            },
            "required": ["raw_text"],
        },
    },
    {
        "name": "audit_and_redline_contract",
        "description": (
            "Executes the full 5-node Multi-Regime Counterfactual Compliance & Redline workflow "
            "(Contract AST -> Deontic Retriever -> Cross-Clause Assessor -> Counterfactual Auditor -> "
            "Cryptographic Attestation Manifest) with zero-PII guarantees."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {"type": "string"},
                "raw_text": {"type": "string"},
                "regimes": {"type": "array", "items": {"type": "string"}},
                "as_of_date": {"type": "string", "format": "date"},
                "territorial_scope": {
                    "type": "string",
                    "enum": [s.value for s in TerritorialScope],
                },
                "persona": {
                    "type": "string",
                    "enum": [p.value for p in OutputPersona],
                },
                "language": {
                    "type": "string",
                    "enum": ["bm", "ms", "en", "bilingual"],
                },
            },
            "required": ["raw_text"],
        },
    },
    {
        "name": "diff_statutory_versions",
        "description": (
            "Zero-token bi-temporal statutory diff engine comparing a Malaysian statutory or P.U. "
            "gazette provision between `from_date` and `to_date` across AMENDED_BY and REPEALED_BY "
            "chains, with optional Contract Delta-Audit regression evaluation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "provision_id": {"type": "string"},
                "from_date": {"type": "string", "format": "date"},
                "to_date": {"type": "string", "format": "date"},
                "contract_text": {"type": "string"},
                "territorial_scope": {
                    "type": "string",
                    "enum": [s.value for s in TerritorialScope],
                },
                "regimes": {"type": "array", "items": {"type": "string"}},
                "persona": {
                    "type": "string",
                    "enum": [p.value for p in OutputPersona],
                },
            },
            "required": ["provision_id", "from_date", "to_date"],
        },
    },
    {
        "name": "audit_bilingual_crosswalk",
        "description": (
            "Zero-token Act 388 s. 63 Bilingual Divergence Critic inspecting paired Bahasa Melayu "
            "and English statutory SourceSpans for deontic modality mismatches, numeric/deadline "
            "discrepancies, RM penalty ceiling differences, and missing sub-clauses."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "node_id": {"type": "string"},
                "as_of_date": {"type": "string", "format": "date"},
                "en_text": {"type": "string"},
                "bm_text": {"type": "string"},
                "authoritative_language": {
                    "type": "string",
                    "enum": ["ms", "bm", "en"],
                },
                "act_name": {"type": "string"},
                "act_number": {"type": "string"},
                "section_code": {"type": "string"},
            },
        },
    },
]

_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
    RiskSeverity.CRITICAL: 4,
}


def _dispatch_sync_only(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
    if tool_name == "lexgraph_pdpa_compliance_scan":
        req = PDPAComplianceScanRequest(
            document_id=arguments.get("document_id", "MCP-SCAN-001"),
            raw_text=arguments["raw_text"],
            as_of_date=(
                date.fromisoformat(arguments["as_of_date"])
                if arguments.get("as_of_date")
                else None
            ),
            territorial_scope=TerritorialScope(
                arguments.get("territorial_scope", TerritorialScope.ALL_MALAYSIA.value)
            ),
            persona=OutputPersona(
                arguments.get("persona", OutputPersona.PRACTITIONER.value)
            ),
        )
        return scan_pdpa_compliance(req).model_dump(mode="json")

    if tool_name == "lexgraph_point_in_time_search":
        store = get_default_temporal_store()
        as_of = (
            date.fromisoformat(arguments["as_of_date"])
            if arguments.get("as_of_date")
            else date.today()
        )
        res = store.search_with_abstention(
            query=arguments["query"],
            as_of_date=as_of,
            territorial_scope=arguments.get("territorial_scope"),
            abstention_threshold=float(arguments.get("abstention_threshold", 0.78)),
        )
        return res.model_dump(mode="json")

    if tool_name == "lexgraph_pii_scrub":
        return scrub_malaysian_pii(arguments["text"]).model_dump(mode="json")

    if tool_name == "resolve_deontic_envelope":
        resolver = DeonticEnvelopeResolver(get_default_temporal_store())
        as_of = (
            date.fromisoformat(arguments["as_of_date"])
            if arguments.get("as_of_date")
            else date.today()
        )
        envelope = resolver.resolve(
            regimes=arguments.get("regimes") or ["ACT_709", "ACT_854", "BNM_RMIT"],
            as_of_date=as_of,
            territorial_scope=arguments.get(
                "territorial_scope", TerritorialScope.ALL_MALAYSIA.value
            ),
        )
        return envelope.model_dump(mode="json")

    if tool_name == "detect_contract_shadow_overrides":
        ast_graph, _ = build_contract_ast(
            document_id=arguments.get("document_id", "MCP-AST-001"),
            raw_text=arguments["raw_text"],
            token_style="vault",
        )
        return ast_graph.model_dump(mode="json")

    if tool_name == "diff_statutory_versions":
        from_d = date.fromisoformat(arguments["from_date"])
        to_d = date.fromisoformat(arguments["to_date"])
        diff_res = diff_statute_lineage(
            provision_id=arguments["provision_id"],
            from_date=from_d,
            to_date=to_d,
            store=get_default_temporal_store(),
        )
        payload = diff_res.model_dump(mode="json")
        if arguments.get("contract_text"):
            delta_req = ContractDeltaAuditRequest(
                document_id=arguments.get("document_id", "MCP-DELTA-001"),
                raw_text=arguments["contract_text"],
                from_date=from_d,
                to_date=to_d,
                regimes=arguments.get("regimes"),
                territorial_scope=TerritorialScope(
                    arguments.get("territorial_scope", TerritorialScope.ALL_MALAYSIA.value)
                ),
                persona=OutputPersona(
                    arguments.get("persona", OutputPersona.PRACTITIONER.value)
                ),
            )
            delta_res = evaluate_contract_delta_impact(
                delta_req, store=get_default_temporal_store()
            )
            payload["contract_delta_audit"] = delta_res.model_dump(mode="json")
        return payload

    if tool_name == "audit_bilingual_crosswalk":
        crosswalk_as_of = (
            date.fromisoformat(arguments["as_of_date"])
            if arguments.get("as_of_date")
            else None
        )
        report = audit_bilingual_divergence(
            node_id=arguments.get("node_id"),
            as_of_date=crosswalk_as_of,
            store=get_default_temporal_store(),
            en_text=arguments.get("en_text"),
            bm_text=arguments.get("bm_text"),
            authoritative_language=arguments.get("authoritative_language"),
            act_name=arguments.get("act_name", ""),
            act_number=arguments.get("act_number", ""),
            section_code=arguments.get("section_code", ""),
        )
        return report.model_dump(mode="json")

    return None


async def dispatch_mcp_tool_async(
    tool_name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    """Async MCP tool dispatcher compatible with FastAPI routes."""
    sync_result = _dispatch_sync_only(tool_name, arguments)
    if sync_result is not None:
        return sync_result

    if tool_name == "audit_and_redline_contract":
        as_of = (
            date.fromisoformat(arguments["as_of_date"])
            if arguments.get("as_of_date")
            else date.today()
        )
        regimes = normalize_regimes(
            arguments.get("regimes") or ["ACT_709", "ACT_854", "BNM_RMIT"]
        )
        scope = arguments.get("territorial_scope", TerritorialScope.ALL_MALAYSIA.value)
        persona = arguments.get("persona", OutputPersona.PRACTITIONER.value)
        language = arguments.get("language", "bilingual")

        graph = build_compliance_graph()
        initial_state: AgentState = {
            "document_id": arguments.get("document_id", "MCP-REDLINE-001"),
            "raw_text": arguments["raw_text"],
            "reference_date": as_of.isoformat(),
            "regimes": regimes,
            "territorial_scope": scope,
            "persona": persona,
            "language": language,
            "extracted_clauses": [],
            "auditor_feedback": "",
            "is_grounded": False,
            "retry_count": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
        }
        final_state = await graph.ainvoke(initial_state)
        clauses = final_state.get("extracted_clauses", [])
        overall = (
            max(clauses, key=lambda c: _SEVERITY_RANK[c.severity]).severity
            if clauses
            else RiskSeverity.LOW
        )
        return {
            "document_id": initial_state["document_id"],
            "as_of_date": as_of.isoformat(),
            "regimes": regimes,
            "overall_risk": overall.value,
            "is_abstained": bool(final_state.get("is_abstained", False)),
            "is_grounded": bool(final_state.get("is_grounded", False)),
            "executive_summary": final_state.get("executive_summary", ""),
            "findings": [c.model_dump(mode="json") for c in clauses],
            "deontic_envelope": final_state.get("deontic_envelope"),
            "contract_ast": final_state.get("contract_ast"),
            "attestation_manifest": final_state.get("attestation_manifest"),
            "counterfactual_log": final_state.get("counterfactual_log", []),
        }

    raise ValueError(f"Unknown MCP tool: {tool_name}")


def dispatch_mcp_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Executes an MCP tool call synchronously and returns JSON-serializable structured output."""
    sync_result = _dispatch_sync_only(tool_name, arguments)
    if sync_result is not None:
        return sync_result

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(dispatch_mcp_tool_async(tool_name, arguments))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(asyncio.run, dispatch_mcp_tool_async(tool_name, arguments))
        return future.result()
