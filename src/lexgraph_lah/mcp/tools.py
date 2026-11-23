import asyncio
import base64
import concurrent.futures
from datetime import date
from typing import Any

from lexgraph_lah.agents.graph import build_compliance_graph
from lexgraph_lah.compliance.pdpa_scanner import scan_pdpa_compliance
from lexgraph_lah.compliance.sla_cascade import compile_incident_playbook
from lexgraph_lah.graph.bilingual_critic import audit_bilingual_divergence
from lexgraph_lah.graph.deontic_solver import DeonticEnvelopeResolver, normalize_regimes
from lexgraph_lah.graph.diff_engine import (
    diff_statute_lineage,
    evaluate_contract_delta_impact,
)
from lexgraph_lah.graph.portfolio_scanner import scan_portfolio_blast_radius
from lexgraph_lah.graph.temporal_store import get_default_temporal_store
from lexgraph_lah.ingestion.contract_ast import build_contract_ast
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.negotiation.docx_redline_critic import (
    analyze_counterparty_docx_redlines,
)
from lexgraph_lah.schemas.domain import (
    CommentAnnotation,
    ComplianceAttestationManifest,
    ContractDeltaAuditRequest,
    IncidentPlaybookRequest,
    OutputPersona,
    PDPAComplianceScanRequest,
    PortfolioBlastRadiusRequest,
    PortfolioContractInput,
    RedlineRevisionInput,
    RiskSeverity,
    TerritorialScope,
)
from lexgraph_lah.schemas.state import AgentState
from lexgraph_lah.security.attestation_ledger import default_attestation_ledger
from lexgraph_lah.security.doc_firewall import scan_document_security

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
            "& P.U.(A) 220/2024, BNM RMiT, Act 265, Sabah Cap. 67, Sarawak Cap. 76, Labuan Act 704, "
            "Act 136, and Act 658) as of a specific point-in-time date and territorial scope."
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
    {
        "name": "scan_document_security",
        "description": (
            "Zero-token Adversarial Document Sanitizer & Indirect Prompt Injection (IPI) Firewall. "
            "Detects hidden OOXML runs (<w:vanish/>, tiny/white fonts, macros/customXml), hidden PDF "
            "layers (3 Tr), and EN/BM prompt/statutory spoof overrides before ContractASTGraph ingestion."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {"type": "string"},
                "raw_text": {"type": "string"},
                "docx_base64": {"type": "string"},
                "pdf_base64": {"type": "string"},
                "filename": {"type": "string"},
            },
        },
    },
    {
        "name": "scan_portfolio_blast_radius",
        "description": (
            "Zero-token Portfolio Gazette Blast-Radius Scanner evaluating up to 50 contracts between "
            "from_date and to_date against intervening statutory amendments, P.U. gazette commencements, "
            "and 5-territory deontic bounds with pre-flight PII scrubbing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_date": {"type": "string", "format": "date"},
                "to_date": {"type": "string", "format": "date"},
                "contracts": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 50,
                    "items": {
                        "type": "object",
                        "properties": {
                            "contract_id": {"type": "string"},
                            "document_id": {"type": "string"},
                            "title": {"type": "string"},
                            "text": {"type": "string"},
                            "raw_text": {"type": "string"},
                            "territorial_scope": {
                                "type": "string",
                                "enum": [s.value for s in TerritorialScope],
                            },
                            "regimes": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                    },
                },
                "regimes": {"type": "array", "items": {"type": "string"}},
                "default_territorial_scope": {
                    "type": "string",
                    "enum": [s.value for s in TerritorialScope],
                },
                "persona": {
                    "type": "string",
                    "enum": [p.value for p in OutputPersona],
                },
            },
            "required": ["from_date", "to_date", "contracts"],
        },
    },
    {
        "name": "verify_compliance_attestation",
        "description": (
            "Cryptographically verifies a ComplianceAttestationManifest and its append-only SQLite WAL "
            "hash chain against the original contract SHA-256 digest, as_of_date snapshot, and "
            "SourceSpan citation IDs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest_id": {"type": "string"},
                "raw_text": {"type": "string"},
                "expected_doc_sha256": {"type": "string"},
                "manifest": {"type": "object"},
            },
        },
    },
    {
        "name": "audit_counterparty_docx_redlines",
        "description": (
            "Zero-token counterparty OOXML track-changes (<w:ins>, <w:del>, <w:moveFrom>, <w:moveTo>) "
            "and comment-thread (<w:commentRangeStart>, word/comments.xml) negotiation critic. "
            "Detects IPI spoofing/hidden runs, evaluates baseline vs proposed clauses via DeonticEnvelopeResolver, "
            "and returns CounterpartyRedlineDiff + Ed25519 AttestationManifest."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {"type": "string"},
                "docx_base64": {
                    "type": "string",
                    "description": "Base64-encoded counterparty redlined .docx binary.",
                },
                "filename": {"type": "string"},
                "baseline_text": {"type": "string"},
                "proposed_text": {"type": "string"},
                "revisions": {
                    "type": "array",
                    "items": {"type": "object"},
                },
                "comments": {
                    "type": "array",
                    "items": {"type": "object"},
                },
                "as_of_date": {"type": "string", "format": "date"},
                "regimes": {"type": "array", "items": {"type": "string"}},
                "territorial_scope": {
                    "type": "string",
                    "enum": [s.value for s in TerritorialScope],
                },
                "audit_session_id": {"type": "string"},
            },
        },
    },
    {
        "name": "compile_incident_playbook",
        "description": (
            "Zero-token multi-regulator incident timeline compiler (UTC + Asia/Kuala_Lumpur with "
            "Act 388 s. 54 computation-of-time metadata) and sub-processor SLA cascade verifier across "
            "BNM RMiT (1h), NACSA (6h/14d), PDPA (72h/7d), and Act 864 regimes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {"type": "string"},
                "discovery_timestamp": {
                    "type": "string",
                    "description": "ISO-8601 incident discovery timestamp (normalized to Asia/Kuala_Lumpur).",
                },
                "party_role": {
                    "type": "string",
                    "enum": [
                        "DATA_USER_CONTROLLER",
                        "NCII_ENTITY",
                        "BNM_FINANCIAL_INSTITUTION",
                        "PUBLIC_SECTOR_AGENCY_ACT_864",
                    ],
                    "default": "DATA_USER_CONTROLLER",
                },
                "triggered_regimes": {"type": "array", "items": {"type": "string"}},
                "territorial_scope": {
                    "type": "string",
                    "enum": [s.value for s in TerritorialScope],
                },
                "as_of_date": {"type": "string", "format": "date"},
                "contract_text": {"type": "string"},
                "clauses": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["discovery_timestamp"],
        },
    },
]

_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
    RiskSeverity.CRITICAL: 4,
}


def _dispatch_sync_only(
    tool_name: str, arguments: dict[str, Any]
) -> dict[str, Any] | None:
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
        doc_id = arguments.get("document_id", "MCP-AST-001")
        raw_text = arguments["raw_text"]
        sec_report = scan_document_security(
            document_id=doc_id,
            raw_text=raw_text,
        )
        clean_text = (
            sec_report.sanitized_text
            if sec_report.findings
            else (sec_report.sanitized_text or raw_text)
        )
        ast_graph, _ = build_contract_ast(
            document_id=doc_id,
            raw_text=clean_text,
            token_style="vault",
        )
        payload = ast_graph.model_dump(mode="json")
        payload["security_findings"] = [
            f.model_dump(mode="json") for f in sec_report.findings
        ]
        payload["security_report"] = sec_report.model_dump(mode="json")
        return payload

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
                    arguments.get(
                        "territorial_scope", TerritorialScope.ALL_MALAYSIA.value
                    )
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

    if tool_name == "scan_document_security":
        doc_id = arguments.get("document_id", "MCP-SEC-001")
        raw_text = arguments.get("raw_text")
        filename = arguments.get("filename")
        file_bytes: bytes | None = None
        if arguments.get("docx_base64"):
            file_bytes = base64.b64decode(arguments["docx_base64"])
            filename = filename or "upload.docx"
        elif arguments.get("pdf_base64"):
            file_bytes = base64.b64decode(arguments["pdf_base64"])
            filename = filename or "upload.pdf"

        if raw_text is None and file_bytes is None:
            raise ValueError(
                "scan_document_security requires 'raw_text', 'docx_base64', or 'pdf_base64'."
            )
        sec_report = scan_document_security(
            document_id=doc_id,
            raw_text=raw_text,
            file_bytes=file_bytes,
            filename=filename,
        )
        return sec_report.model_dump(mode="json")

    if tool_name == "scan_portfolio_blast_radius":
        raw_contracts = arguments.get("contracts")
        if not isinstance(raw_contracts, list) or not raw_contracts:
            raise ValueError(
                "scan_portfolio_blast_radius requires a non-empty 'contracts' list (max 50)."
            )
        req_blast = PortfolioBlastRadiusRequest(
            from_date=date.fromisoformat(arguments["from_date"]),
            to_date=date.fromisoformat(arguments["to_date"]),
            contracts=[PortfolioContractInput(**item) for item in raw_contracts],
            regimes=arguments.get("regimes"),
            default_territorial_scope=TerritorialScope(
                arguments.get(
                    "default_territorial_scope", TerritorialScope.ALL_MALAYSIA.value
                )
            ),
            persona=OutputPersona(
                arguments.get("persona", OutputPersona.PRACTITIONER.value)
            ),
        )
        return scan_portfolio_blast_radius(
            req_blast, store=get_default_temporal_store()
        ).model_dump(mode="json")

    if tool_name == "verify_compliance_attestation":
        manifest_arg = arguments.get("manifest")
        manifest_obj = (
            ComplianceAttestationManifest(**manifest_arg)
            if isinstance(manifest_arg, dict)
            else None
        )
        verify_res = default_attestation_ledger.verify(
            manifest_id=arguments.get("manifest_id"),
            raw_text=arguments.get("raw_text"),
            expected_doc_sha256=arguments.get("expected_doc_sha256"),
            manifest=manifest_obj,
        )
        return verify_res.model_dump(mode="json")

    if tool_name == "audit_counterparty_docx_redlines":
        raw_b64 = arguments.get("docx_base64")
        docx_bytes = base64.b64decode(raw_b64, validate=True) if raw_b64 else None
        raw_revs = arguments.get("revisions") or []
        rev_objs = [
            RedlineRevisionInput(**r) if isinstance(r, dict) else r for r in raw_revs
        ]
        raw_comments = arguments.get("comments") or []
        comment_objs = [
            CommentAnnotation(**c) if isinstance(c, dict) else c for c in raw_comments
        ]
        redline_as_of = (
            date.fromisoformat(arguments["as_of_date"])
            if arguments.get("as_of_date")
            else None
        )
        redline_diff = analyze_counterparty_docx_redlines(
            document_id=arguments.get("document_id", "MCP-NEG-001"),
            docx_bytes=docx_bytes,
            filename=arguments.get("filename"),
            revisions=rev_objs or None,
            baseline_text=arguments.get("baseline_text"),
            proposed_text=arguments.get("proposed_text"),
            comments=comment_objs or None,
            as_of_date=redline_as_of,
            regimes=arguments.get("regimes"),
            territorial_scope=arguments.get("territorial_scope"),
            audit_session_id=arguments.get("audit_session_id"),
        )
        return redline_diff.model_dump(mode="json")

    if tool_name == "compile_incident_playbook":
        req_payload: dict[str, Any] = {
            "discovery_timestamp": arguments["discovery_timestamp"],
        }
        for key in (
            "document_id",
            "party_role",
            "triggered_regimes",
            "territorial_scope",
            "as_of_date",
            "contract_text",
            "clauses",
        ):
            if arguments.get(key) is not None:
                req_payload[key] = arguments[key]
        playbook_req = IncidentPlaybookRequest.model_validate(req_payload)
        return compile_incident_playbook(playbook_req).model_dump(mode="json")

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
        manifest_payload = final_state.get("attestation_manifest")
        if isinstance(manifest_payload, dict):
            manifest_obj = ComplianceAttestationManifest(**manifest_payload)
            default_attestation_ledger.record(manifest_obj)
            manifest_payload = manifest_obj.model_dump(mode="json")

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
            "attestation_manifest": manifest_payload,
            "security_findings": final_state.get("security_findings", []),
            "security_report": final_state.get("security_report"),
            "selected_model": final_state.get("selected_model"),
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
