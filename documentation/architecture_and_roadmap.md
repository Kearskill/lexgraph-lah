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

---

## 5. Track D: Bi-Temporal Statutory Redline Diff, Act 388 Bilingual Divergence Critic & v2 Benchmark

### Goal
Extend `lexgraph-lah` with zero-token (`$0.00 USD / RM 0.00 MYR`) bi-temporal statutory version redlining, Contract Delta-Audit regression checks, Act 388 s. 63 Bahasa Melayu <-> English divergence detection, 8-tool MCP registration, interactive UI lineage/divergence explorers, and an expanded 20-scenario v2 determinism benchmark.

### Architectural Design
1. **Zero-Token Bi-Temporal Statutory Diff & Contract Delta-Audit (`src/lexgraph_lah/graph/diff_engine.py`):**
   - `diff_statute_lineage(provision_id, from_date, to_date)` resolves active versions at `from_date` and `to_date` across `AMENDED_BY`, `SUPERSEDED_BY`, and `REPEALED_BY` chains, returning `StatutoryVersionDiff` (`ADDED`/`REMOVED`/`MODIFIED`/`UNCHANGED` clause segments, transition dates, related `P.U.` gazettes, `SourceSpan` provenance, and `0` LLM tokens).
   - `evaluate_contract_delta_impact(ContractDeltaAuditRequest)` runs pre-flight Malaysian PII scrubbing (`scrub_malaysian_pii`) and evaluates whether an agreement compliant at `from_date` becomes non-compliant at `to_date` across both Act 709 PDPA gap rules and multi-regime `DeonticEnvelopeResolver` bounds (`ACT_854`, `BNM_RMIT`).
2. **Act 388 s. 63 Bilingual Divergence Critic (`src/lexgraph_lah/graph/bilingual_critic.py`):**
   - `audit_bilingual_pair` / `audit_bilingual_divergence` inspect paired BM and EN statutory `SourceSpan`s at `0` LLM tokens for `DEONTIC_MODALITY_MISMATCH` (`hendaklah`/`wajib` vs. `may`), `NUMERIC_DEADLINE_DISCREPANCY`, `PENALTY_CEILING_DISCREPANCY`, and `MISSING_SUBCLAUSE`, surfacing Act 388 s. 63 `authoritative_language` precedence and Practitioner/Rakyat explanations.
3. **REST APIs, 8-Tool MCP Catalog & UI Integration (`src/lexgraph_lah/api/routes.py`, `src/lexgraph_lah/mcp/tools.py`):**
   - REST endpoints: `GET`/`POST /api/v1/lineage/diff`, `POST /api/v1/lineage/delta-audit`, `GET /api/v1/crosswalk/{node_id}/divergence`, `POST /api/v1/crosswalk/divergence`.
   - MCP tools #7 & #8: `diff_statutory_versions` and `audit_bilingual_crosswalk`.
   - `/dashboard`: **Time-Travel Statutory Redline Explorer** with Cytoscape path highlighting and inline clause diff; `/demo`: Act 388 alignment/divergence badges inside the bilingual drawer adapting explanation density to the Practitioner/Rakyat persona toggle.
4. **v2 Determinism & FinOps Benchmark (`evals/run_benchmark.py`):**
   - Expands coverage to **20 scenarios x 3 trials (60 runs)** including `0.78` abstention gate rejection (`BENCH-15`), 5-way territorial isolation including Labuan [Act 704] (`BENCH-16`), pre-flight PII scrubbing (`BENCH-17`), bi-temporal `P.U. (A) 220/2024` commencement transitions (`BENCH-18`), zero-token lineage diff & delta-audit (`BENCH-19`), and Act 388 divergence detection (`BENCH-20`).

---

## 6. Track E: Security Firewall, East Malaysia Deontic Bounds, Portfolio Blast-Radius, SQLite WAL Attestation, JSON-RPC 2.0 MCP & `gemini-4-neon` FinOps Routing

### Goal
Harden document ingestion against adversarial `.docx`/`.pdf` indirect prompt injections, activate Sabah/Sarawak/Act 658 territorial deontic algebra, scale bi-temporal impact analysis across contract portfolios, persist tamper-evident cryptographic attestations in SQLite WAL, expose native JSON-RPC 2.0 MCP transports (`POST /mcp` and `--stdio`), and introduce tiered `gemini-4-neon` / `gemini-4-hydrogen` FinOps complexity routing with v3 benchmark verification.

### Architectural Design
1. **Zero-Token Adversarial OOXML/PDF Security Firewall (`src/lexgraph_lah/security/doc_firewall.py`):**
   - `scan_document_security` and `sanitize_docx_bytes` execute pre-AST sanitization across `.docx` OOXML parts (`<w:vanish/>`, `<w:webHidden/>`, `sz <= 2` half-pts, near-white `#F0F0F0`-`#FFFFFF` fonts, `word/vbaProject.bin`, `customXml`, suspicious `word/comments.xml`), `.pdf` streams (`3 Tr` invisible text rendering, micro/zero fonts, white fill colors, off-page `Tm`/`Td`), and EN/BM indirect prompt injection & statutory-spoofing overrides while preserving benign visible clauses and `<w:trackRevisions/>` exports intact.
2. **5-Territory Deontic Bounds & Act 658 (`deontic_solver.py`, `temporal_store.py`):**
   - Wires live `DeonticConstraint`s onto already-seeded nodes for Peninsular EA 1955 (`Act 265`, `45h`), Sabah Labour Ordinance (`Cap. 67`, `48h` + non-resident work permit), Sarawak Labour Ordinance (`Cap. 76`, `48h` + non-resident employment licence), Labuan FSA (`Act 704`), Contracts Act 1950 (`Act 136` s. 75 reasonable compensation cap), and Electronic Commerce Act 2006 [`Act 658` s. 7 EN+BM].
3. **Portfolio Gazette Blast-Radius Scanner (`src/lexgraph_lah/graph/portfolio_scanner.py`):**
   - `scan_portfolio_blast_radius` (`POST /api/v1/portfolio/blast-radius`, `/dashboard` panel, and `/demo` quick-trigger) evaluates up to 50 contracts across `from_date` -> `to_date` at `$0.00 USD / RM 0.00 MYR`, running pre-scan IPI defense, `evaluate_contract_delta_impact`, and territorial `DeonticEnvelopeResolver` bounds to produce deterministic severity rankings and PII-safe remediation summaries.
4. **Tamper-Evident SQLite WAL Attestation Ledger (`src/lexgraph_lah/security/attestation_ledger.py`):**
   - `AttestationLedger` (`:memory:` default or file-backed SQLite WAL) chains `ComplianceAttestationManifest` records and FinOps `TelemetrySummary` snapshots via SHA-256 `prev_chain_hash` -> `chain_hash` links, enabling cryptographic verification (`GET /api/v1/attestation/{manifest_id}`, `POST /api/v1/attestation/verify`) that detects single-byte document, manifest JSON, citation, snapshot, FinOps cost, or direct SQLite row tampering.
5. **11-Tool MCP Registry & JSON-RPC 2.0 Server (`mcp/tools.py`, `mcp/jsonrpc.py`):**
   - Adds `scan_document_security`, `scan_portfolio_blast_radius`, and `verify_compliance_attestation` (11 tools total) and exposes `initialize`, `notifications/initialized`, `ping`, `tools/list`, and `tools/call` over `POST /mcp` and `python -m lexgraph_lah.mcp.jsonrpc --stdio`.
6. **`gemini-4-neon` / `gemini-4-hydrogen` FinOps Tiering (`telemetry/cost_tracker.py`, `telemetry/tracer.py`, `agents/graph.py`):**
   - Adds `MODEL_PRICING_CATALOG` (`gemini-4-neon` `$3.00 / $15.00 / $0.15` cached per 1M; `gemini-4-hydrogen` `$0.50 / $2.50 / $0.05` cached per 1M) and `select_model_tier`, escalating counterfactual retries, multi-regime runs, AST traps, and security-flagged payloads to `gemini-4-neon`, emitting `model_tier` on `ComplianceSpanRecord` and OTel spans while preserving backward-compatible `settings` defaults.
7. **v3 Determinism Benchmark (`evals/run_benchmark.py`):**
   - Expands to **26 scenarios x 3 trials (78 runs)** adding `BENCH-21` (OOXML Hidden Clause Quarantine), `BENCH-22` (Bilingual IPI Neutralization + 11-Tool JSON-RPC 2.0), `BENCH-23` (Sabah vs. Peninsular Territorial Deontic Bounds + Act 136/658), `BENCH-24` (Sarawak & Labuan Territorial Isolation), `BENCH-25` (Portfolio Gazette Blast-Radius Ranking), and `BENCH-26` (SQLite WAL Attestation Tamper Verification + `gemini-4-neon` FinOps Routing).
