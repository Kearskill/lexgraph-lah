# Architecture & Engineering Roadmap (`lexgraph-lah`)

## 1. System Architecture & Four Core Pillars

`lexgraph-lah` is a production-grade legal compliance and statutory analysis engine structured around four pillars:

1. **Graph-RAG Pipeline:** Hybrid retrieval combining multi-hop knowledge graph traversals (statutory hierarchies, amendments, cross-references) with vector search to assemble point-in-time statutory context prior to contract adjudication.
2. **Automated Entity Resolution:** Canonicalization and deduplication of legal entities, acts, and section citations (e.g., `SEC-1.1`) across contracts and statutes into normalized graph nodes and edges.
3. **Multi-Stage Compliance Engine:** Orchestrated via LangGraph (`StateGraph` over `AgentState`). It runs a structured-output LLM extraction node (`risk_assessor_node`) followed by a deterministic zero-cost substring verifier (`citation_auditor_node`) in a bounded self-correction loop (`MAX_RETRIES = 2` in `route_after_audit`) to prevent runaway token spend.
4. **OpenTelemetry & FinOps Observability:** Strict tracing via `arize-phoenix-otel` and `openinference-instrumentation-langchain`, tracking token accumulation (`prompt_tokens`, `completion_tokens`), latency, retry overhead, and USD/MYR cost per compliance run (`TelemetrySummary`).

---

## 2. Track A: Temporal & Amendment-Aware Graph-RAG Schema (Milestone A)

### Goal
Introduce temporal metadata and relationship edges (`VALID_FROM`, `VALID_TO`, `AMENDED_BY`, `REPEALED_BY`, `CITES`) to statutory graph nodes so `lexgraph-lah` can execute point-in-time compliance audits (e.g., auditing a 2024 contract strictly against statutes active on its execution date in 2024, excluding 2025/2026 amendments).

### Architectural Design
1. **Temporal Domain Models (`src/lexgraph_lah/schemas/domain.py`):**
   - `StatutoryStatus`: Enum (`ACTIVE`, `AMENDED`, `REPEALED`).
   - `TemporalEdgeType`: Enum (`VALID_FROM`, `VALID_TO`, `AMENDED_BY`, `REPEALED_BY`, `CITES`).
   - `StatutoryNode`: Represents a versioned statutory provision with `node_id`, `act_name`, `section_code`, `version`, `text`, `valid_from: date`, `valid_to: date | None`, `status: StatutoryStatus`, and `content_hash: str` (SHA-256 for deduplication and semantic cache keys).
   - `StatutoryEdge`: Directed edge between statutory nodes with `source_id`, `target_id`, `edge_type: TemporalEdgeType`, and `effective_date: date`.
   - `ClauseAudit` enrichment: Includes optional `violated_statute_ids: list[str]` linking contract findings to specific versioned `StatutoryNode` IDs.
2. **Cypher Query Builder & Temporal Graph Store (`src/lexgraph_lah/graph/temporal_store.py`):**
   - **Parameterized Cypher Generation:**
     - *Upsert & Supersede (`AMENDED_BY` / `REPEALED_BY`):* Atomically closes the predecessor version's `valid_to` window and inserts the new `StatutoryNode` linked via `:AMENDED_BY` or `:REPEALED_BY`.
     - *Point-in-Time Traversal:* Queries nodes where `valid_from <= $as_of_date AND (valid_to IS NULL OR valid_to > $as_of_date)` and filters out nodes with a `:REPEALED_BY` edge effective on or before `$as_of_date`, traversing `:CITES*1..2` edges under the same temporal predicate.
   - **Deterministic In-Memory Graph Engine (`TemporalGraphStore`):**
     - Provides an immediate, zero-dependency execution backend for point-in-time resolution and multi-hop citation traversal while emitting exact parameterized Cypher queries for Neo4j/Memgraph production deployment.
   - **FinOps Optimization:**
     - Pruning superseded or repealed statutes deterministically at the graph layer before prompt construction reduces input token payloads by eliminating irrelevant historical or post-dated legislative text.
3. **LangGraph Pipeline Integration (`src/lexgraph_lah/agents/graph.py` & `src/lexgraph_lah/schemas/state.py`):**
   - Extend `AgentState` with `reference_date: str | None` (ISO-8601 `YYYY-MM-DD`) and `retrieved_statutes: list[StatutoryNode]`.
   - Add `temporal_retriever_node` as the entry point before `risk_assessor_node`, resolving active statutes for `reference_date` at zero LLM token cost and injecting the formatted statutory context into `risk_assessor_node`.

---

## 3. Track B: Automated Legal Evaluation & FinOps Harness (Milestone B)

### Goal
Build a deterministic evaluation and FinOps assertion suite to prevent hallucinations in multi-stage legal reasoning, measure temporal context recall/precision, verify entity/citation grounding, and enforce per-run LLM cost ceilings.

### Architectural Design
1. **FinOps Cost Tracker & Telemetry (`src/lexgraph_lah/telemetry/cost_tracker.py` & `tracer.py`):**
   - Deterministic token-to-cost calculator using configured pricing (`input_cost_per_1m_usd`, `output_cost_per_1m_usd`, `usd_to_myr_rate`).
   - Budget guardrail enforcement (`assert_within_budget`) to fail fast or alert when a compliance run exceeds its USD/MYR cost ceiling.
   - OpenTelemetry span enrichment recording token counts, retry counts, grounding status, and temporal statute count.
2. **Deterministic Legal Evaluation Suite (`tests/eval/test_legal_eval_harness.py`):**
   - **Synthetic Golden Dataset:** Multi-era legal compliance test cases (e.g., a 2024 contract evaluated against a statute amended in 2025, plus verbatim vs. subtly mutated quotes).
   - **Core Evaluation Metrics:**
     - *Temporal Context Recall & Contamination Rate:* Asserts `100%` recall of statutes active at `reference_date` and `0%` contamination from post-contract amendments or repealed provisions.
     - *Entity & Citation Grounding Rate:* Asserts exact-match recall on expected `clause_id`s and verifies `citation_auditor_node` blocks `100%` of synthetic quote mutations.
     - *FinOps SLA Assertion:* Asserts per-query token consumption and estimated USD cost remain strictly under the target budget threshold (e.g., `< $0.005 USD` per compliance run).

---

## 4. Track C: FastAPI Backend & Interactive Telemetry/Graph UI (Milestone C)

### Goal
Expose the compliance engine, temporal knowledge graph, and FinOps telemetry via FastAPI endpoints (`/compliance/check`, `/graph/nodes`, `/telemetry/metrics`) paired with an interactive visualization dashboard rendering D3/Cytoscape citation graphs and OpenTelemetry cost/latency traces.

### Architectural Design (`src/lexgraph_lah/api/routes.py` & `src/lexgraph_lah/main.py`)
1. **`POST /compliance/check` (`ComplianceCheckRequest` -> `ContractAuditResponse`):**
   - Executes the compiled LangGraph pipeline (`temporal_retriever` -> `risk_assessor` -> `citation_auditor`) for a given `reference_date`.
   - Includes a deterministic SHA-256 FinOps cache (`_COMPLIANCE_CACHE` keyed by `(raw_text, reference_date, act_filter)`) that serves repeat compliance queries at `0` LLM tokens (`$0.000000 USD`).
   - Appends a `ComplianceSpanRecord` into `telemetry_registry` on every uncached execution.
2. **`GET /graph/nodes` (`GraphTopologyResponse`):**
   - Accepts optional `as_of_date` and `act_name` query parameters to return point-in-time `StatutoryNode`s, `StatutoryEdge`s (`AMENDED_BY`, `REPEALED_BY`, `CITES`), and the underlying parameterized Cypher query.
3. **`GET /telemetry/metrics` (`TelemetryMetricsResponse`):**
   - Aggregates total runs, cumulative tokens, total USD/MYR spend, average latency (ms), grounded citation rate, and the ordered list of OpenTelemetry/FinOps span records.
4. **`GET /dashboard` (Interactive Cytoscape.js & FinOps Console):**
   - Zero-build interactive HTML/JS console that renders the directed statutory citation & amendment graph via Cytoscape.js, displays the active parameterized Cypher query, and streams FinOps KPI cards and trace span tables.
