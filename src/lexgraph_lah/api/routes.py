import hashlib
import json
import time
import uuid
from datetime import date
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from lexgraph_lah.agents.graph import _DEFAULT_TEMPORAL_STORE, build_compliance_graph
from lexgraph_lah.compliance.pdpa_scanner import scan_pdpa_compliance
from lexgraph_lah.config import settings
from lexgraph_lah.graph.reranker import filter_by_territorial_scope
from lexgraph_lah.graph.temporal_store import build_point_in_time_cypher
from lexgraph_lah.mcp.tools import MCP_TOOL_DEFINITIONS, dispatch_mcp_tool
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    BilingualClausePair,
    ClauseAudit,
    ComplianceCheckRequest,
    ContractAuditResponse,
    GraphTopologyResponse,
    IRACAnalysis,
    PDPAComplianceScanRequest,
    PDPAComplianceScanResponse,
    PIIScrubSummary,
    RakyatGuidance,
    RetrievalSearchResponse,
    RiskSeverity,
    TelemetryMetricsResponse,
    TerritorialScope,
)
from lexgraph_lah.schemas.state import AgentState
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import (
    ComplianceSpanRecord,
    measure_latency_ms,
    telemetry_registry,
)

router = APIRouter()


class PIIScrubRequest(BaseModel):
    text: str = Field(..., min_length=1)


class MCPToolCallRequest(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


def _resolve_fixtures_dir() -> Path:
    repo_root_candidate = Path(__file__).resolve().parents[3] / "examples" / "fixtures"
    if repo_root_candidate.is_dir():
        return repo_root_candidate
    return Path.cwd() / "examples" / "fixtures"


def _load_all_fixtures() -> list[dict[str, Any]]:
    fixtures_dir = _resolve_fixtures_dir()
    if not fixtures_dir.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for path in sorted(fixtures_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        data.setdefault("fixture_id", path.stem)
        data.setdefault("filename", path.name)
        items.append(data)
    return items


# Semantic/exact-match response cache to avoid redundant LLM billing on identical (text, reference_date, act_filter)
_COMPLIANCE_CACHE: dict[str, ContractAuditResponse] = {}

_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
    RiskSeverity.CRITICAL: 4,
}


def _compute_overall_risk(clauses: list[ClauseAudit]) -> RiskSeverity:
    if not clauses:
        return RiskSeverity.LOW
    return max(clauses, key=lambda c: _SEVERITY_RANK[c.severity]).severity


def _cache_key(req: ComplianceCheckRequest) -> str:
    scope_val = req.territorial_scope.value if req.territorial_scope else TerritorialScope.ALL_MALAYSIA.value
    payload = (
        f"{req.raw_text.strip()}|{req.reference_date or 'TODAY'}|"
        f"{req.act_filter or 'ALL'}|{scope_val}|{req.persona.value}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _build_audit_persona_blocks(
    document_id: str,
    effective_date: date,
    clauses: list[ClauseAudit],
    overall_risk: RiskSeverity,
) -> tuple[IRACAnalysis, RakyatGuidance]:
    violated = sorted({sid for c in clauses for sid in c.violated_statute_ids})
    stat_str = ", ".join(violated) if violated else "Act 709 (PDPA) Part II Principles"
    high_risk_clauses = [c for c in clauses if c.severity in {RiskSeverity.MEDIUM, RiskSeverity.HIGH, RiskSeverity.CRITICAL}]

    if not high_risk_clauses:
        irac = IRACAnalysis(
            issue=f"Whether {document_id} complies with Malaysian statutory provisions effective on {effective_date.isoformat()}.",
            rule=f"Applicable Malaysian provisions ({stat_str}) active as of {effective_date.isoformat()}.",
            application="All reviewed clauses satisfy baseline statutory safeguards without exclusionary waivers or delayed breach SLAs.",
            conclusion=f"Overall Risk: {overall_risk.value}. Clauses align with active Malaysian statutory mandates.",
        )
        rakyat = RakyatGuidance(
            plain_summary_en="This agreement meets Malaysia's personal data security and breach reporting timelines as of the selected date.",
            plain_summary_bm="Perjanjian ini mematuhi piawaian keselamatan data peribadi dan tempoh pemberitahuan kebocoran data Malaysia bagi tarikh ini.",
            gov_my_checklist=[
                "Keep your bilingual Bahasa Melayu and English privacy notice updated.",
                "Verify your Data Protection Officer (DPO) contact details at https://portal.pdp.gov.my.",
                "Retain signed compliance records for inspection by JPDP (https://www.pdp.gov.my).",
            ],
            official_portals=["https://www.pdp.gov.my", "https://portal.pdp.gov.my", "https://lom.agc.gov.my"],
        )
        return irac, rakyat

    cats = ", ".join(c.category for c in high_risk_clauses)
    irac = IRACAnalysis(
        issue=f"Whether {document_id} breaches statutory duties under {stat_str} as of {effective_date.isoformat()}.",
        rule=f"Malaysian statutory mandates ({stat_str}) governing data processor security liability and 72-hour breach notification.",
        application=f"Identified {len(high_risk_clauses)} exposed clause(s) across {cats}.",
        conclusion=f"Overall Risk: {overall_risk.value}. Adopt the recommended redlines prior to contract execution.",
    )
    rakyat = RakyatGuidance(
        plain_summary_en=(
            f"Attention ({overall_risk.value} Risk): This contract has {len(high_risk_clauses)} clause(s) "
            "that do not protect your personal data properly under Malaysian law (for example, shifting blame away from the vendor or delaying data leak alerts past 72 hours)."
        ),
        plain_summary_bm=(
            f"Perhatian (Risiko {overall_risk.value}): Kontrak ini mengandungi {len(high_risk_clauses)} klausa "
            "berisiko di bawah undang-undang Malaysia, seperti mengecualikan liabiliti pemproses data atau melambatkan notis kebocoran data."
        ),
        gov_my_checklist=[
            "Ask the vendor to remove any clause saying they have 'zero liability' if your data leaks.",
            "Ensure confirmed personal data breaches must be escalated in <= 24h so JPDP can be notified within 72h at https://portal.pdp.gov.my.",
            "Check official Malaysian PDPA guidance or file a public complaint at https://www.pdp.gov.my.",
        ],
        official_portals=["https://www.pdp.gov.my", "https://portal.pdp.gov.my", "https://lom.agc.gov.my"],
    )
    return irac, rakyat


@router.post("/compliance/check", response_model=ContractAuditResponse)
async def check_compliance(
    payload: ComplianceCheckRequest,
    use_cache: Annotated[
        bool, Query(description="Enable deterministic FinOps cache lookup")
    ] = True,
) -> ContractAuditResponse:
    """
    Executes the multi-stage temporal Graph-RAG & compliance pipeline:
    1. Resolves point-in-time statutes active on `reference_date` & `territorial_scope`.
    2. Masks Malaysian PII pre-flight (<50ms) and runs `risk_assessor_node` + `citation_auditor_node`.
    3. Records OpenTelemetry / FinOps cost metrics (USD & MYR) and bilingual/persona metadata.
    """
    key = _cache_key(payload)
    if use_cache and key in _COMPLIANCE_CACHE:
        cached = _COMPLIANCE_CACHE[key]
        zero_cost_telemetry = compute_telemetry_summary(
            prompt_tokens=0,
            completion_tokens=0,
            latency_ms=0.1,
            retry_count=0,
            is_verified_grounded=cached.telemetry.is_verified_grounded,
            trace_id=cached.telemetry.trace_id or "span-cached",
        )
        return cached.model_copy(
            update={
                "document_id": payload.document_id,
                "telemetry": zero_cost_telemetry,
            }
        )

    effective_date = payload.reference_date or date.today()
    scope = payload.territorial_scope or TerritorialScope.ALL_MALAYSIA
    graph = build_compliance_graph()

    initial_state: AgentState = {
        "document_id": payload.document_id,
        "raw_text": payload.raw_text,
        "reference_date": effective_date.isoformat(),
        "act_filter": payload.act_filter,
        "territorial_scope": scope.value,
        "persona": payload.persona.value,
        "abstention_threshold": payload.abstention_threshold or settings.abstention_threshold,
        "extracted_clauses": [],
        "auditor_feedback": "",
        "is_grounded": False,
        "retry_count": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }

    with measure_latency_ms() as elapsed_holder:
        final_state = await graph.ainvoke(initial_state)

    clauses: list[ClauseAudit] = final_state.get("extracted_clauses", [])
    active_statutes = final_state.get("retrieved_statutes", [])
    pii_dict = final_state.get("pii_scrub")
    pii_scrub = PIIScrubSummary(**pii_dict) if isinstance(pii_dict, dict) else None
    overall_risk = _compute_overall_risk(clauses)

    bilingual_pairs: list[BilingualClausePair] = []
    seen_pairs: set[str] = set()
    for stat in active_statutes:
        pair = _DEFAULT_TEMPORAL_STORE.get_bilingual_pair(stat.node_id)
        if pair:
            pair_key = f"{pair.act_number}:{pair.section_code}"
            if pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                bilingual_pairs.append(pair)

    irac_summary, rakyat_summary = _build_audit_persona_blocks(
        document_id=payload.document_id,
        effective_date=effective_date,
        clauses=clauses,
        overall_risk=overall_risk,
    )

    span_id = f"span-{uuid.uuid4().hex[:8]}"
    telemetry = compute_telemetry_summary(
        prompt_tokens=final_state.get("prompt_tokens", 0),
        completion_tokens=final_state.get("completion_tokens", 0),
        latency_ms=elapsed_holder[0],
        retry_count=final_state.get("retry_count", 0),
        is_verified_grounded=final_state.get("is_grounded", False),
        trace_id=span_id,
    )

    telemetry_registry.record_span(
        ComplianceSpanRecord(
            span_id=span_id,
            document_id=payload.document_id,
            reference_date=effective_date.isoformat(),
            active_statute_count=len(active_statutes),
            telemetry=telemetry,
            timestamp_epoch=time.time(),
        )
    )

    response = ContractAuditResponse(
        document_id=payload.document_id,
        reference_date=effective_date,
        overall_risk=overall_risk,
        findings=clauses,
        active_statutes=active_statutes,
        telemetry=telemetry,
        persona=payload.persona,
        territorial_scope=scope,
        pii_scrub=pii_scrub,
        bilingual_provisions=bilingual_pairs,
        irac_summary=irac_summary,
        rakyat_summary=rakyat_summary,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )
    if use_cache:
        _COMPLIANCE_CACHE[key] = response
    return response


@router.post("/api/v1/compliance/scan", response_model=PDPAComplianceScanResponse)
async def api_v1_compliance_scan(
    payload: PDPAComplianceScanRequest,
) -> PDPAComplianceScanResponse:
    """
    Pre-flight PII-scrubbed Act 709 (PDPA) Compliance Gap Scanner returning strict
    Pydantic/JSON gap analysis mapped to Act 709 principles, 5-tier authority weights,
    bilingual EN/BM provisions, and verifiable SourceSpan IDs.
    """
    return scan_pdpa_compliance(payload, store=_DEFAULT_TEMPORAL_STORE)


@router.post("/api/v1/pii/scrub", response_model=PIIScrubSummary)
async def api_v1_pii_scrub(payload: PIIScrubRequest) -> PIIScrubSummary:
    """Masks Malaysian NRIC, Passport, Phone, Email, and SSM numbers in <50ms."""
    return scrub_malaysian_pii(payload.text)


@router.get("/api/v1/retrieval/search", response_model=RetrievalSearchResponse)
async def api_v1_retrieval_search(
    q: Annotated[str, Query(..., min_length=1, description="BM, EN, or code-switched legal query")],
    as_of_date: Annotated[date | None, Query(description="Point-in-time date (YYYY-MM-DD)")] = None,
    territorial_scope: Annotated[str | None, Query(description="Peninsular Malaysia | Sabah | Sarawak | Federal Territories | All Malaysia")] = None,
    threshold: Annotated[float | None, Query(ge=0.0, le=1.0, description="Abstention relevance threshold (default 0.78)")] = None,
) -> RetrievalSearchResponse:
    """
    Hybrid bilingual statutory search with 5-tier Malaysian authority reranking,
    territorial scope filtering, and deterministic 0.78 Abstention Gate.
    """
    effective_threshold = threshold if threshold is not None else settings.abstention_threshold
    return _DEFAULT_TEMPORAL_STORE.search_with_abstention(
        query=q,
        as_of_date=as_of_date or date.today(),
        territorial_scope=territorial_scope,
        abstention_threshold=effective_threshold,
    )


@router.get("/api/v1/statutes/{node_id}/bilingual", response_model=BilingualClausePair)
async def api_v1_bilingual_statute(node_id: str) -> BilingualClausePair:
    """Returns synchronized English (Section) & Bahasa Melayu (Seksyen) statutory pair + SourceSpans."""
    pair = _DEFAULT_TEMPORAL_STORE.get_bilingual_pair(node_id)
    if not pair:
        raise HTTPException(status_code=404, detail=f"Statutory node '{node_id}' not found.")
    return pair


@router.get("/api/v1/mcp/tools")
async def api_v1_mcp_tools() -> dict[str, Any]:
    """Lists MCP-compatible tools exposed by lexgraph-lah."""
    return {"tools": MCP_TOOL_DEFINITIONS}


@router.post("/api/v1/mcp/call")
async def api_v1_mcp_call(payload: MCPToolCallRequest) -> dict[str, Any]:
    """Invokes an MCP tool wrapper cleanly via HTTP."""
    try:
        result = dispatch_mcp_tool(payload.name, payload.arguments)
        return {"tool": payload.name, "result": result}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/graph/nodes", response_model=GraphTopologyResponse)
async def get_graph_nodes(
    as_of_date: Annotated[
        date | None,
        Query(
            description="Optional point-in-time filter (YYYY-MM-DD). Returns all versions if omitted."
        ),
    ] = None,
    act_name: Annotated[
        str | None, Query(description="Optional canonical act name filter")
    ] = None,
    territorial_scope: Annotated[
        str | None, Query(description="Optional Malaysian territorial jurisdiction filter")
    ] = None,
    language: Annotated[
        str | None, Query(description="Optional language filter ('en' or 'bm')")
    ] = None,
) -> GraphTopologyResponse:
    """
    Returns statutory graph nodes, temporal/citation edges (`AMENDED_BY`, `REPEALED_BY`, `CITES`,
    `HAS_TRANSLATION`), and the corresponding parameterized Cypher query for visualization.
    """
    if as_of_date is not None:
        nodes = _DEFAULT_TEMPORAL_STORE.query_point_in_time(
            as_of_date=as_of_date,
            act_name=act_name,
            include_citations=True,
            language=language,
            territorial_scope=territorial_scope,
        )
        cypher_bundle = build_point_in_time_cypher(
            as_of_date=as_of_date,
            act_name=act_name,
            territorial_scope=territorial_scope,
        )
    else:
        all_nodes = list(_DEFAULT_TEMPORAL_STORE.nodes.values())
        nodes = [
            n
            for n in all_nodes
            if (act_name is None or n.act_name == act_name)
            and (language is None or n.language == language)
        ]
        nodes = filter_by_territorial_scope(nodes, territorial_scope)
        cypher_bundle = build_point_in_time_cypher(
            as_of_date=date.today(),
            act_name=act_name,
            territorial_scope=territorial_scope,
        )

    node_id_set = {n.node_id for n in nodes}
    edges = [
        e
        for e in _DEFAULT_TEMPORAL_STORE.edges
        if e.source_id in node_id_set or e.target_id in node_id_set
    ]

    return GraphTopologyResponse(
        as_of_date=as_of_date,
        nodes=nodes,
        edges=edges,
        cypher_query=cypher_bundle.query,
    )


@router.get("/telemetry/metrics", response_model=TelemetryMetricsResponse)
async def get_telemetry_metrics() -> TelemetryMetricsResponse:
    """
    Returns aggregated FinOps and OpenTelemetry span metrics across compliance runs.
    """
    spans = telemetry_registry.list_spans()
    total_runs = len(spans)
    if total_runs == 0:
        return TelemetryMetricsResponse(
            total_runs=0,
            total_tokens=0,
            total_cost_usd=0.0,
            total_cost_myr=0.0,
            average_latency_ms=0.0,
            grounded_rate=1.0,
            spans=[],
        )

    total_tokens = sum(s.telemetry.total_tokens for s in spans)
    total_usd = round(sum(s.telemetry.estimated_cost_usd for s in spans), 6)
    total_myr = round(sum(s.telemetry.estimated_cost_myr for s in spans), 6)
    avg_latency = round(sum(s.telemetry.latency_ms for s in spans) / total_runs, 2)
    grounded_count = sum(1 for s in spans if s.telemetry.is_verified_grounded)
    grounded_rate = round(grounded_count / total_runs, 4)

    return TelemetryMetricsResponse(
        total_runs=total_runs,
        total_tokens=total_tokens,
        total_cost_usd=total_usd,
        total_cost_myr=total_myr,
        average_latency_ms=avg_latency,
        grounded_rate=grounded_rate,
        spans=[s.model_dump() for s in reversed(spans)],
    )


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>lexgraph-lah | Temporal Graph-RAG & FinOps Console</title>
  <script src="https://unpkg.com/cytoscape@3.29.2/dist/cytoscape.min.js"></script>
  <style>
    :root {
      --bg: #0b0f19;
      --panel: #111827;
      --border: #1f2937;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #38bdf8;
      --green: #22c55e;
      --amber: #f59e0b;
      --red: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      background: var(--bg);
      color: var(--text);
      padding: 20px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 14px;
      margin-bottom: 20px;
    }
    header h1 { font-size: 1.25rem; color: var(--accent); }
    .controls { display: flex; gap: 10px; align-items: center; }
    input, button {
      background: var(--panel);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 7px 12px;
      border-radius: 6px;
      font-size: 0.85rem;
    }
    button { cursor: pointer; border-color: var(--accent); color: var(--accent); }
    button:hover { background: #1e293b; }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .kpi-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
    }
    .kpi-label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; }
    .kpi-value { font-size: 1.4rem; font-weight: 700; margin-top: 6px; color: var(--accent); }
    .main-grid {
      display: grid;
      grid-template-columns: 1.3fr 1fr;
      gap: 16px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
    }
    .panel h2 { font-size: 0.95rem; margin-bottom: 10px; color: var(--muted); }
    #cy {
      width: 100%;
      height: 400px;
      background: #090d16;
      border-radius: 6px;
      border: 1px solid var(--border);
    }
    table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin-top: 8px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); }
    pre {
      margin-top: 12px;
      padding: 10px;
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 0.75rem;
      overflow-x: auto;
      color: #a5f3fc;
    }
  </style>
</head>
<body>
  <header>
    <h1>lexgraph-lah // Point-in-Time Legal Graph-RAG & FinOps Telemetry</h1>
    <div class="controls">
      <label for="asOfDate" style="font-size:0.8rem;color:var(--muted)">Point-in-Time Date:</label>
      <input type="date" id="asOfDate" value="2024-06-15" />
      <button onclick="refreshAll(true)">Filter Point-in-Time</button>
      <button onclick="refreshAll(false)">Show All Versions</button>
    </div>
  </header>

  <section class="kpi-grid">
    <div class="kpi-card"><div class="kpi-label">Compliance Runs</div><div class="kpi-value" id="kpiRuns">0</div></div>
    <div class="kpi-card"><div class="kpi-label">Total Tokens</div><div class="kpi-value" id="kpiTokens">0</div></div>
    <div class="kpi-card"><div class="kpi-label">Total Spend (USD)</div><div class="kpi-value" id="kpiUsd">$0.000000</div></div>
    <div class="kpi-card"><div class="kpi-label">Total Spend (MYR)</div><div class="kpi-value" id="kpiMyr">RM 0.000000</div></div>
    <div class="kpi-card"><div class="kpi-label">Avg Latency</div><div class="kpi-value" id="kpiLatency">0 ms</div></div>
    <div class="kpi-card"><div class="kpi-label">Grounded Rate</div><div class="kpi-value" id="kpiGrounded">100%</div></div>
  </section>

  <section class="main-grid">
    <div class="panel">
      <h2>Interactive Cytoscape Statutory Graph (AMENDED_BY / REPEALED_BY / CITES)</h2>
      <div id="cy"></div>
      <pre id="cypherBox">// Cypher Query</pre>
    </div>
    <div class="panel">
      <h2>OpenTelemetry & FinOps Trace Spans</h2>
      <table>
        <thead>
          <tr>
            <th>Span ID</th>
            <th>Document</th>
            <th>Ref Date</th>
            <th>Tokens</th>
            <th>USD</th>
            <th>Latency</th>
            <th>Grounded</th>
          </tr>
        </thead>
        <tbody id="spanTableBody"></tbody>
      </table>
    </div>
  </section>

  <script>
    async function refreshAll(useDateFilter) {
      const dateVal = document.getElementById('asOfDate').value;
      const graphUrl = useDateFilter && dateVal ? `/graph/nodes?as_of_date=${dateVal}` : '/graph/nodes';

      const [graphRes, metricsRes] = await Promise.all([
        fetch(graphUrl).then(r => r.json()),
        fetch('/telemetry/metrics').then(r => r.json())
      ]);

      document.getElementById('cypherBox').textContent = graphRes.cypher_query;

      const elements = [];
      graphRes.nodes.forEach(n => {
        elements.push({
          data: {
            id: n.node_id,
            label: `${n.node_id}\\n(${n.status})`,
            status: n.status
          }
        });
      });
      graphRes.edges.forEach(e => {
        elements.push({
          data: {
            id: `${e.source_id}-${e.edge_type}-${e.target_id}`,
            source: e.source_id,
            target: e.target_id,
            label: `${e.edge_type} (${e.effective_date})`
          }
        });
      });

      cytoscape({
        container: document.getElementById('cy'),
        elements: elements,
        style: [
          {
            selector: 'node',
            style: {
              'label': 'data(label)',
              'text-wrap': 'wrap',
              'font-size': '10px',
              'color': '#e5e7eb',
              'background-color': ele => ele.data('status') === 'ACTIVE' ? '#22c55e' : (ele.data('status') === 'AMENDED' ? '#f59e0b' : '#ef4444'),
              'width': 32,
              'height': 32
            }
          },
          {
            selector: 'edge',
            style: {
              'label': 'data(label)',
              'font-size': '9px',
              'color': '#9ca3af',
              'curve-style': 'bezier',
              'target-arrow-shape': 'triangle',
              'line-color': '#38bdf8',
              'target-arrow-color': '#38bdf8',
              'width': 2
            }
          }
        ],
        layout: { name: 'breadthfirst', directed: true, padding: 25 }
      });

      document.getElementById('kpiRuns').textContent = metricsRes.total_runs;
      document.getElementById('kpiTokens').textContent = metricsRes.total_tokens;
      document.getElementById('kpiUsd').textContent = `$${metricsRes.total_cost_usd.toFixed(6)}`;
      document.getElementById('kpiMyr').textContent = `RM ${metricsRes.total_cost_myr.toFixed(6)}`;
      document.getElementById('kpiLatency').textContent = `${metricsRes.average_latency_ms} ms`;
      document.getElementById('kpiGrounded').textContent = `${(metricsRes.grounded_rate * 100).toFixed(1)}%`;

      const tbody = document.getElementById('spanTableBody');
      tbody.innerHTML = '';
      metricsRes.spans.forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${s.span_id}</td>
          <td>${s.document_id}</td>
          <td>${s.reference_date || '-'}</td>
          <td>${s.telemetry.total_tokens}</td>
          <td>$${s.telemetry.estimated_cost_usd.toFixed(6)}</td>
          <td>${s.telemetry.latency_ms} ms</td>
          <td>${s.telemetry.is_verified_grounded ? 'YES' : 'NO'}</td>
        `;
        tbody.appendChild(tr);
      });
    }
    refreshAll(false);
  </script>
</body>
</html>
"""


@router.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard() -> HTMLResponse:
    """Serves the interactive Cytoscape.js statutory graph & FinOps telemetry dashboard."""
    return HTMLResponse(content=DASHBOARD_HTML)


@router.get("/health")
async def get_health() -> dict[str, Any]:
    """Liveness and readiness probe for Docker Compose and CI orchestration."""
    return {
        "status": "ok",
        "service": "lexgraph-lah",
        "version": "0.1.0",
        "model_name": settings.model_name,
        "usd_to_myr_rate": settings.usd_to_myr_rate,
        "phoenix_collector_endpoint": settings.phoenix_collector_endpoint,
    }


@router.get("/fixtures")
async def list_fixtures() -> dict[str, Any]:
    """Returns the Malaysian regulatory compliance test fixtures from examples/fixtures/."""
    fixtures = _load_all_fixtures()
    return {"count": len(fixtures), "fixtures": fixtures}


@router.get("/fixtures/{fixture_id}")
async def get_fixture(fixture_id: str) -> dict[str, Any]:
    """Returns a single compliance fixture by its fixture_id or filename stem."""
    normalized = fixture_id.removesuffix(".json")
    for item in _load_all_fixtures():
        if item.get("fixture_id") == normalized or item.get("filename") == fixture_id:
            return item
    raise HTTPException(status_code=404, detail=f"Fixture '{fixture_id}' not found.")


DEMO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>lexgraph-lah | Deterministic Multi-Agent Compliance & FinOps Audit Studio</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen font-sans">
  <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-10">
    <div class="max-w-7xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
      <div>
        <div class="flex items-center gap-3">
          <span class="px-2.5 py-1 text-xs font-mono font-bold uppercase tracking-wider rounded bg-sky-500/20 text-sky-400 border border-sky-500/30">v0.1.0</span>
          <h1 class="text-xl font-bold tracking-tight text-white">lexgraph-lah <span class="text-sky-400 font-normal">// Compliance & FinOps Audit Studio</span></h1>
        </div>
        <p class="text-xs text-slate-400 mt-1">Point-in-Time Malaysian Statutory Graph-RAG &bull; Verbatim Substring Critic &bull; FinOps USD/MYR Receipt &bull; OpenTelemetry</p>
      </div>
      <div class="flex items-center gap-3 text-xs font-medium">
        <a href="/dashboard" class="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 transition">Cytoscape Graph Console (/dashboard)</a>
        <a href="/docs" class="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 transition">OpenAPI (/docs)</a>
        <a href="http://localhost:6006" target="_blank" rel="noopener noreferrer" class="px-3 py-2 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 transition flex items-center gap-1.5">
          <span>Arize Phoenix OTel UI (:6006)</span>
          <span>&nearr;</span>
        </a>
      </div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-6 py-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
    <!-- Left Column: Fixture Loader & Input Form -->
    <section class="lg:col-span-5 space-y-5">
      <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="text-sm font-semibold uppercase tracking-wider text-sky-400">1. Load Malaysian Compliance Fixture</h2>
          <span class="text-xs text-slate-400 font-mono">examples/fixtures/</span>
        </div>

        <div>
          <label for="fixtureSelect" class="block text-xs text-slate-400 mb-1.5">Select Preset Scenario or Custom Input:</label>
          <select id="fixtureSelect" onchange="onFixtureSelect()" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-sky-400">
            <option value="01_compliant_clause">01 — Compliant PDPA 2024 Amendment DPA (Clean Pass)</option>
            <option value="02_non_compliant_violation" selected>02 — Non-Compliant Processor Exclusion & 14-Day Breach Delay (Violation)</option>
            <option value="03_ambiguous_edge_case">03 — 2024 Pre-Amendment Legacy Contract & Escalation (Edge Case)</option>
            <option value="custom">Custom Clause / JSON Payload</option>
          </select>
          <p id="fixtureDesc" class="text-xs text-slate-400 mt-2 italic"></p>
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div>
            <label for="docIdInput" class="block text-xs text-slate-400 mb-1">Document ID</label>
            <input id="docIdInput" type="text" value="MY-PDPA-2026-VIOLATION-02" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-sm font-mono text-slate-100" />
          </div>
          <div>
            <label for="refDateInput" class="block text-xs text-slate-400 mb-1">Point-in-Time Reference Date</label>
            <input id="refDateInput" type="date" value="2026-03-15" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-sm font-mono text-slate-100" />
          </div>
        </div>

        <div>
          <label for="actFilterInput" class="block text-xs text-slate-400 mb-1">Statutory Act Filter</label>
          <input id="actFilterInput" type="text" value="Personal Data Protection Act 2010" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-100" />
        </div>

        <div>
          <label for="rawTextInput" class="block text-xs text-slate-400 mb-1">Contract / Policy Clauses to Audit</label>
          <textarea id="rawTextInput" rows="7" class="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-sm font-mono text-slate-100 leading-relaxed focus:outline-none focus:border-sky-400"></textarea>
        </div>

        <div class="flex items-center justify-between pt-1">
          <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input id="useCacheCheckbox" type="checkbox" class="rounded bg-slate-950 border-slate-700 text-sky-500" />
            <span>Enable SHA-256 FinOps Cache (<code class="text-sky-400">$0.00</code> on repeat run)</span>
          </label>
        </div>

        <button id="runAuditBtn" onclick="runComplianceAudit()" class="w-full py-2.5 px-4 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-sm shadow transition flex items-center justify-center gap-2">
          <span>Run Compliance Audit</span>
        </button>
      </div>
    </section>

    <!-- Right Column: Output Cards -->
    <section class="lg:col-span-7 space-y-5">
      <!-- Top Row: FinOps Receipt Card & Agent Execution Trail -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
        <!-- (c) FinOps Receipt Card -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-semibold uppercase tracking-wider text-emerald-400">FinOps Receipt (USD & MYR)</h2>
            <span id="receiptTraceBadge" class="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">span-ready</span>
          </div>
          <div class="grid grid-cols-2 gap-3 mb-3">
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-3">
              <div class="text-[11px] uppercase text-slate-400">Audit Cost (USD)</div>
              <div id="receiptUsd" class="text-lg font-bold font-mono text-emerald-400 mt-0.5">$0.000000</div>
            </div>
            <div class="bg-slate-950 border border-slate-800 rounded-lg p-3">
              <div class="text-[11px] uppercase text-slate-400">Audit Cost (MYR)</div>
              <div id="receiptMyr" class="text-lg font-bold font-mono text-sky-400 mt-0.5">RM 0.000000</div>
            </div>
          </div>
          <div class="space-y-1.5 text-xs font-mono border-t border-slate-800 pt-3">
            <div class="flex justify-between"><span class="text-slate-400">Input (Prompt) Tokens:</span><span id="receiptPromptTokens" class="text-slate-200">0</span></div>
            <div class="flex justify-between"><span class="text-slate-400">Output (Completion) Tokens:</span><span id="receiptCompletionTokens" class="text-slate-200">0</span></div>
            <div class="flex justify-between"><span class="text-slate-400">Total Tokens Billed:</span><span id="receiptTotalTokens" class="text-white font-bold">0</span></div>
            <div class="flex justify-between"><span class="text-slate-400">End-to-End Latency:</span><span id="receiptLatency" class="text-slate-200">0.00 ms</span></div>
            <div class="flex justify-between"><span class="text-slate-400">Critic Retry Loops:</span><span id="receiptRetries" class="text-slate-200">0 / 2</span></div>
          </div>
          <div class="mt-3 pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
            <span class="text-slate-400">OpenTelemetry Collector:</span>
            <a href="http://localhost:6006" target="_blank" rel="noopener noreferrer" class="text-amber-400 hover:underline font-mono">Inspect Trace in Phoenix (:6006) &nearr;</a>
          </div>
        </div>

        <!-- (b) Agent Node Execution Trail -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between mb-3">
              <h2 class="text-sm font-semibold uppercase tracking-wider text-sky-400">LangGraph Execution Trail</h2>
              <span id="groundingBadge" class="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">GROUNDED</span>
            </div>
            <ol id="agentTrailList" class="space-y-2.5 text-xs">
              <li class="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between">
                <div>
                  <div class="font-mono font-semibold text-sky-300">01. temporal_retriever_node</div>
                  <div id="trailNode0Desc" class="text-slate-400 mt-0.5">Point-in-time Graph-RAG statutory filter (0 LLM tokens)</div>
                </div>
                <span class="font-mono text-emerald-400">0 tok</span>
              </li>
              <li class="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between">
                <div>
                  <div class="font-mono font-semibold text-purple-300">02. risk_assessor_node</div>
                  <div id="trailNode1Desc" class="text-slate-400 mt-0.5">Gemini 2.5 Flash Pydantic v2 structured clause extraction</div>
                </div>
                <span id="trailNode1Tokens" class="font-mono text-purple-300">0 tok</span>
              </li>
              <li class="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between">
                <div>
                  <div class="font-mono font-semibold text-emerald-300">03. citation_auditor_node</div>
                  <div id="trailNode2Desc" class="text-slate-400 mt-0.5">Deterministic verbatim substring critic (route_after_audit)</div>
                </div>
                <span class="font-mono text-emerald-400">0 tok</span>
              </li>
            </ol>
          </div>
          <div class="mt-3 pt-2 border-t border-slate-800 text-[11px] text-slate-400 font-mono flex justify-between">
            <span>StateGraph(AgentState)</span>
            <span>MAX_RETRIES = 2</span>
          </div>
        </div>
      </div>

      <!-- (a) Deterministic Verdict & Citations Card -->
      <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h2 class="text-sm font-semibold uppercase tracking-wider text-sky-400">Deterministic Compliance Verdict & Citations</h2>
            <p id="verdictSubheader" class="text-xs text-slate-400 mt-0.5">Select a fixture and click "Run Compliance Audit" to inspect point-in-time statutory grounding.</p>
          </div>
          <div id="overallRiskBadge" class="px-3 py-1 rounded-full text-xs font-bold font-mono uppercase bg-slate-800 text-slate-300 border border-slate-700">
            READY
          </div>
        </div>

        <!-- Point-in-Time Active Statutes Resolved -->
        <div>
          <div class="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Active Point-in-Time Statutes Resolved (TemporalGraphStore):</div>
          <div id="activeStatutesContainer" class="flex flex-wrap gap-2 text-xs"></div>
        </div>

        <!-- Extracted Clause Audit Cards -->
        <div class="space-y-3" id="findingsContainer"></div>
      </div>
    </section>
  </main>

  <script>
    let FIXTURES_MAP = {};

    const FALLBACK_FIXTURES = {
      "01_compliant_clause": {
        fixture_id: "01_compliant_clause",
        title: "01 — Compliant PDPA 2024 Amendment DPA (Clean Pass)",
        description: "2026 Malaysian Data Processing Agreement adhering to Section 9 direct processor security obligations and Section 12B 72-hour mandatory breach notification.",
        document_id: "MY-PDPA-2026-COMPLIANT-01",
        reference_date: "2026-03-15",
        act_filter: "Personal Data Protection Act 2010",
        raw_text: "SEC-1.1 Security Principle Compliance: Both the Data User and the Data Processor shall implement ISO/IEC 27001 technical and organizational security controls in strict compliance with Section 9 of the Personal Data Protection Act 2010 (as amended by the Personal Data Protection (Amendment) Act 2024). SEC-1.2 Mandatory Data Breach Notification: In the event of any personal data breach, the Data Processor shall notify the Data User within 24 hours of discovery, and the Data User shall notify the Personal Data Protection Commissioner within 72 hours in accordance with Section 12B."
      },
      "02_non_compliant_violation": {
        fixture_id: "02_non_compliant_violation",
        title: "02 — Non-Compliant Processor Exclusion & 14-Day Breach Delay (Statutory Violation)",
        description: "2026 Cloud Vendor Contract violating PDPA (Amendment) Act 2024 Section 9 direct processor liability and Section 12B 72-hour breach notification mandate.",
        document_id: "MY-PDPA-2026-VIOLATION-02",
        reference_date: "2026-03-15",
        act_filter: "Personal Data Protection Act 2010",
        raw_text: "SEC-8.1 Processor Liability Exclusion: The Data Processor shall bear zero statutory liability for unauthorized data disclosure or security failures. SEC-8.2 Breach Notice: Notification of a personal data breach shall be provided within 14 days of confirmation."
      },
      "03_ambiguous_edge_case": {
        fixture_id: "03_ambiguous_edge_case",
        title: "03 — 2024 Pre-Amendment Legacy Contract & Discretionary Incident Escalation (Edge Case)",
        description: "Point-in-time audit as of 2024-06-15 (prior to the 2025-01-01 PDPA Amendment) demonstrating temporal statutory routing (PDPA-2010-SEC-9-V1) and multi-agent audit escalation.",
        document_id: "MY-PDPA-2024-LEGACY-EDGE-03",
        reference_date: "2024-06-15",
        act_filter: "Personal Data Protection Act 2010",
        raw_text: "SEC-4.1 Data Security: The Data Processor shall implement commercially reasonable technical safeguards to protect personal data. SEC-4.2 Incident Reporting: The Data Processor may report security incidents within 14 business days at its sole discretion. SEC-4.3 Cross-Border Subprocessing: Personal data may be mirrored to regional recovery nodes subject to periodic review."
      }
    };

    async function initFixtures() {
      FIXTURES_MAP = { ...FALLBACK_FIXTURES };
      try {
        const res = await fetch('/fixtures');
        if (res.ok) {
          const data = await res.json();
          (data.fixtures || []).forEach(f => {
            FIXTURES_MAP[f.fixture_id] = f;
          });
        }
      } catch (_) {}
      onFixtureSelect();
      await runComplianceAudit();
    }

    function onFixtureSelect() {
      const sel = document.getElementById('fixtureSelect').value;
      if (sel === 'custom') {
        document.getElementById('fixtureDesc').textContent = 'Custom input mode: edit Document ID, Reference Date, or Contract Clauses below.';
        return;
      }
      const f = FIXTURES_MAP[sel];
      if (!f) return;
      document.getElementById('fixtureDesc').textContent = f.description || '';
      document.getElementById('docIdInput').value = f.document_id;
      document.getElementById('refDateInput').value = f.reference_date;
      document.getElementById('actFilterInput').value = f.act_filter || '';
      document.getElementById('rawTextInput').value = f.raw_text;
    }

    function riskBadgeClasses(risk) {
      if (risk === 'LOW') return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      if (risk === 'MEDIUM') return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
    }

    async function runComplianceAudit() {
      const btn = document.getElementById('runAuditBtn');
      btn.disabled = true;
      btn.innerHTML = '<span>Auditing Contract via LangGraph...</span>';

      const useCache = document.getElementById('useCacheCheckbox').checked;
      const payload = {
        document_id: document.getElementById('docIdInput').value.trim() || 'CUSTOM-DOC-01',
        raw_text: document.getElementById('rawTextInput').value.trim(),
        reference_date: document.getElementById('refDateInput').value || null,
        act_filter: document.getElementById('actFilterInput').value.trim() || null
      };

      try {
        const res = await fetch(`/compliance/check?use_cache=${useCache}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        renderAuditResponse(data);
      } catch (err) {
        document.getElementById('verdictSubheader').textContent = `Error running compliance audit: ${err}`;
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>Run Compliance Audit</span>';
      }
    }

    function renderAuditResponse(data) {
      const t = data.telemetry || {};
      const promptTok = t.prompt_tokens ?? Math.round((t.total_tokens || 0) * 0.75);
      const compTok = t.completion_tokens ?? ((t.total_tokens || 0) - promptTok);

      document.getElementById('receiptTraceBadge').textContent = t.trace_id || 'span-recorded';
      document.getElementById('receiptUsd').textContent = `$${(t.estimated_cost_usd || 0).toFixed(6)}`;
      document.getElementById('receiptMyr').textContent = `RM ${(t.estimated_cost_myr || 0).toFixed(6)}`;
      document.getElementById('receiptPromptTokens').textContent = promptTok;
      document.getElementById('receiptCompletionTokens').textContent = compTok;
      document.getElementById('receiptTotalTokens').textContent = t.total_tokens || 0;
      document.getElementById('receiptLatency').textContent = `${(t.latency_ms || 0).toFixed(2)} ms`;
      document.getElementById('receiptRetries').textContent = `${t.retry_count || 0} / 2`;

      const statutes = data.active_statutes || [];
      document.getElementById('trailNode0Desc').textContent = `Resolved ${statutes.length} active statute(s) as of ${data.reference_date}`;
      document.getElementById('trailNode1Tokens').textContent = `${t.total_tokens || 0} tok`;
      document.getElementById('trailNode2Desc').textContent = t.is_verified_grounded
        ? `All ${(data.findings || []).length} extracted clause quote(s) verified verbatim (retries: ${t.retry_count || 0})`
        : `Unverified quote blocked after ${t.retry_count || 0} retries`;

      const gBadge = document.getElementById('groundingBadge');
      gBadge.textContent = t.is_verified_grounded ? 'VERBATIM GROUNDED' : 'UNGROUNDED';
      gBadge.className = `text-xs font-mono px-2 py-0.5 rounded border ${t.is_verified_grounded ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border-rose-500/30'}`;

      const risk = data.overall_risk || 'LOW';
      const verdictLabel = risk === 'LOW' ? 'LOW RISK — COMPLIANT' : (risk === 'MEDIUM' ? 'MEDIUM RISK — ESCALATE / REDLINE' : `${risk} RISK — STATUTORY VIOLATION`);
      const rBadge = document.getElementById('overallRiskBadge');
      rBadge.textContent = verdictLabel;
      rBadge.className = `px-3 py-1 rounded-full text-xs font-bold font-mono uppercase border ${riskBadgeClasses(risk)}`;

      document.getElementById('verdictSubheader').textContent = `Document ${data.document_id} audited as of point-in-time date ${data.reference_date}`;

      const statContainer = document.getElementById('activeStatutesContainer');
      statContainer.innerHTML = '';
      statutes.forEach(s => {
        const pill = document.createElement('div');
        pill.className = 'px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono';
        pill.innerHTML = `<span class="text-sky-400 font-bold">${s.node_id}</span> <span class="text-slate-400">(${s.section_code} v${s.version}, valid_from=${s.valid_from})</span>`;
        statContainer.appendChild(pill);
      });

      const findingsContainer = document.getElementById('findingsContainer');
      findingsContainer.innerHTML = '';
      const findings = data.findings || [];
      if (findings.length === 0) {
        findingsContainer.innerHTML = '<div class="p-4 rounded-lg bg-emerald-950/30 border border-emerald-800/40 text-emerald-300 text-xs">No high-risk clauses detected. Contract complies with active point-in-time statutes.</div>';
        return;
      }

      findings.forEach(c => {
        const card = document.createElement('div');
        card.className = 'p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5';
        const violatedPills = (c.violated_statute_ids || []).map(id =>
          `<span class="px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 font-mono text-[11px]">${id}</span>`
        ).join(' ');
        card.innerHTML = `
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <span class="font-mono font-bold text-sm text-white">${c.clause_id}</span>
              <span class="text-xs text-slate-400">&bull; ${c.category}</span>
            </div>
            <div class="flex items-center gap-2">
              ${violatedPills}
              <span class="px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${riskBadgeClasses(c.severity)}">${c.severity}</span>
            </div>
          </div>
          <div class="p-2.5 rounded bg-slate-900 border-l-2 border-sky-400 font-mono text-xs text-slate-200">
            <div class="text-[10px] uppercase text-sky-400 mb-1">Verbatim Grounded Substring (exact_quote):</div>
            "${c.exact_quote}"
          </div>
          <div class="text-xs text-slate-300"><strong class="text-slate-100">Legal & Statutory Rationale:</strong> ${c.rationale}</div>
          <div class="text-xs text-emerald-300 bg-emerald-950/20 border border-emerald-800/40 rounded p-2.5">
            <strong class="text-emerald-400">Recommended Remediation / Redline:</strong> ${c.recommended_redline}
          </div>
        `;
        findingsContainer.appendChild(card);
      });
    }

    initFixtures();
  </script>
</body>
</html>
"""


@router.get("/", response_class=HTMLResponse)
@router.get("/demo", response_class=HTMLResponse)
async def get_demo_ui() -> HTMLResponse:
    """Serves the interactive Judge-Friendly Compliance & FinOps Demo UI at `/` and `/demo`."""
    return HTMLResponse(content=DEMO_HTML)
