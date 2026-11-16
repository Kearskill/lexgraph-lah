from datetime import date
from typing import Any

from lexgraph_lah.compliance.pdpa_scanner import scan_pdpa_compliance
from lexgraph_lah.graph.temporal_store import get_default_temporal_store
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import (
    OutputPersona,
    PDPAComplianceScanRequest,
    TerritorialScope,
)

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
]


def dispatch_mcp_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Executes an MCP tool call locally and returns JSON-serializable structured output."""
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

    raise ValueError(f"Unknown MCP tool: {tool_name}")
