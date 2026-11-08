import hashlib
import time
import uuid
from datetime import date
from typing import Annotated

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse

from lexgraph_lah.agents.graph import _DEFAULT_TEMPORAL_STORE, build_compliance_graph
from lexgraph_lah.graph.temporal_store import build_point_in_time_cypher
from lexgraph_lah.schemas.domain import (
    ClauseAudit,
    ComplianceCheckRequest,
    ContractAuditResponse,
    GraphTopologyResponse,
    RiskSeverity,
    TelemetryMetricsResponse,
)
from lexgraph_lah.schemas.state import AgentState
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import (
    ComplianceSpanRecord,
    measure_latency_ms,
    telemetry_registry,
)

router = APIRouter()

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
    payload = f"{req.raw_text.strip()}|{req.reference_date or 'TODAY'}|{req.act_filter or 'ALL'}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@router.post("/compliance/check", response_model=ContractAuditResponse)
async def check_compliance(
    payload: ComplianceCheckRequest,
    use_cache: Annotated[
        bool, Query(description="Enable deterministic FinOps cache lookup")
    ] = True,
) -> ContractAuditResponse:
    """
    Executes the multi-stage temporal Graph-RAG & compliance pipeline:
    1. Resolves point-in-time statutes active on `reference_date`.
    2. Runs `risk_assessor_node` and `citation_auditor_node` with bounded self-correction.
    3. Records OpenTelemetry / FinOps cost metrics (USD & MYR).
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
        )
        return cached.model_copy(
            update={
                "document_id": payload.document_id,
                "telemetry": zero_cost_telemetry,
            }
        )

    effective_date = payload.reference_date or date.today()
    graph = build_compliance_graph()

    initial_state: AgentState = {
        "document_id": payload.document_id,
        "raw_text": payload.raw_text,
        "reference_date": effective_date.isoformat(),
        "act_filter": payload.act_filter,
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
    telemetry = compute_telemetry_summary(
        prompt_tokens=final_state.get("prompt_tokens", 0),
        completion_tokens=final_state.get("completion_tokens", 0),
        latency_ms=elapsed_holder[0],
        retry_count=final_state.get("retry_count", 0),
        is_verified_grounded=final_state.get("is_grounded", False),
    )

    telemetry_registry.record_span(
        ComplianceSpanRecord(
            span_id=f"span-{uuid.uuid4().hex[:8]}",
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
        overall_risk=_compute_overall_risk(clauses),
        findings=clauses,
        active_statutes=active_statutes,
        telemetry=telemetry,
    )
    if use_cache:
        _COMPLIANCE_CACHE[key] = response
    return response


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
) -> GraphTopologyResponse:
    """
    Returns statutory graph nodes, temporal/citation edges (`AMENDED_BY`, `REPEALED_BY`, `CITES`),
    and the corresponding parameterized Cypher query for visualization.
    """
    if as_of_date is not None:
        nodes = _DEFAULT_TEMPORAL_STORE.query_point_in_time(
            as_of_date=as_of_date,
            act_name=act_name,
            include_citations=True,
        )
        cypher_bundle = build_point_in_time_cypher(
            as_of_date=as_of_date, act_name=act_name
        )
    else:
        all_nodes = list(_DEFAULT_TEMPORAL_STORE.nodes.values())
        nodes = [n for n in all_nodes if act_name is None or n.act_name == act_name]
        cypher_bundle = build_point_in_time_cypher(
            as_of_date=date.today(), act_name=act_name
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
