# Architecture Decision Records (`lexgraph-lah`)

This document captures the six core engineering architecture decisions governing `lexgraph-lah`.

---

## ADR-001: Neuro-Symbolic $O(V + E)$ Pre-Solvers Before Stochastic LLM Nodes

- **Status:** Accepted
- **Modules:** `src/lexgraph_lah/security/doc_firewall.py`, `src/lexgraph_lah/ingestion/contract_ast.py`, `src/lexgraph_lah/graph/deontic_solver.py`, `src/lexgraph_lah/agents/graph.py`
- **Context:** Contract compliance across overlapping Malaysian statutes requires deterministic enforcement of numeric bounds (e.g., `1h` BNM RMiT vs `6h` Act 854 vs `72h` PDPA Commissioner vs `7d` Data Subject), structural trap detection (`Notwithstanding` / `Walau apa pun` overrides, narrow definitions), and security sanitization. Relying on an LLM end-to-end inflates token burn, risks arithmetic/deadline hallucination, and exposes the model to hidden OOXML/PDF prompt injections.
- **Decision:** Run zero-token deterministic symbolic pipelines *before* and *after* any LLM invocation inside the LangGraph `StateGraph`:
  1. `doc_firewall.py` strips hidden OOXML runs, PDF invisible layers, bidi overrides, zero-width steganography, and homoglyphs.
  2. `contract_ast.py` constructs `ContractASTGraph` ($O(V + E)$ over clauses, schedules, definitions, and override traps).
  3. `deontic_solver.py` computes `CompositeDeonticEnvelope` across all active statutory constraints.
  4. `counterfactual_auditor_node` verifies verbatim quote substrings, temporal validity, citation existence, and shadow-override coverage (up to `MAX_RETRIES = 2`).
- **Consequences:** All quantitative deadlines, shadow overrides, track-changes diffs, and SLA cascades execute at `$0.00 USD` and deterministic `O(V + E)` latency, reserving LLM tokens strictly for natural-language clause synthesis when enabled.

---

## ADR-002: Bi-Temporal Knowledge Graph vs. Flat Vector RAG for Statutory Law

- **Status:** Accepted
- **Modules:** `src/lexgraph_lah/graph/temporal_store.py`, `src/lexgraph_lah/graph/diff_engine.py`, `src/lexgraph_lah/schemas/domain.py`
- **Context:** Malaysian statutory regimes phase in by specific Federal Gazette (`P.U. (A)` / `P.U. (B)`) dates (e.g., PDPA Act A1727 phased tranches on `2025-01-01`, `2025-04-01`, `2025-06-01`; Act 378 SDSAS and Act 53 MyInvois `>RM10,000` on `2026-01-01`). Flat vector stores mix pre-amendment and post-amendment clauses when querying historical contracts.
- **Decision:** Model statutes as versioned `StatutoryNode`s with `valid_from` / `valid_to`, `effective_from` / `effective_to`, `AMENDS` / `AMENDED_BY` / `REPEALS` / `REPEALED_BY` / `HAS_TRANSLATION` / `BM_EN_EQUIVALENT` edges backed by dual `InMemoryGraphBackend` and parameterized Cypher `Neo4jGraphBackend`.
- **Consequences:** Point-in-time queries strictly isolate active law on `as_of_date` (`0.00%` temporal contamination) and enable zero-token bi-temporal statutory diffs (`diff_statute_lineage`). Trade-off: statutory graph maintenance requires structured gazette ingestion (`gazette_ingestor.py`).

---

## ADR-003: Separating Deontic Modalities (`MANDATORY_STATUTE` vs. `VOLUNTARY_GUIDELINE` vs. `REGULATORY_CIRCULAR`)

- **Status:** Accepted
- **Modules:** `src/lexgraph_lah/schemas/domain.py`, `src/lexgraph_lah/graph/deontic_solver.py`, `src/lexgraph_lah/compliance/fiscal_aige_scanner.py`
- **Context:** Conflating advisory frameworks like MOSTI's National Guidelines on AI Governance & Ethics (`AIGE`, 2024) with statutory mandates like PDPA Act 709 or Cyber Security Act 854 causes false `CRITICAL` legal-violation verdicts, whereas ignoring AIGE hides enterprise AI governance risk. Similarly, conflating recipient duties (Commissioner `72h` vs Data Subject `7d` vs NACSA `6h`) erases legally distinct SLAs.
- **Decision:** Model `DeonticConstraint.modality` explicitly across `OBLIGATION`, `PROHIBITION`, `PERMISSION`, and `VOLUNTARY_GUIDELINE`, and separate `recipient_obligations` inside `CompositeDeonticEnvelope` alongside `voluntary_advisories`.
- **Consequences:** Voluntary AIGE gaps are surfaced as governance advisories rather than false statutory breaches, while multi-recipient notice deadlines remain non-lossy and auditable.

---

## ADR-004: Zero-Egress Reversible PII Vaulting with Per-Tenant AES-256-GCM AAD Binding

- **Status:** Accepted
- **Modules:** `src/lexgraph_lah/middleware/pii_scrubber.py`, `src/lexgraph_lah/hitl/review_store.py`
- **Context:** Contracts contain Malaysian MyKad/NRIC, Passport, Phone, Email, SSM, LHDN TIN, KWSP, PERKESO, and MY Bank/DuitNow identifiers. Sending raw PII to external LLM/embedding endpoints or leaking it across tenants in `.docx` rehydration or HITL exports violates Act 709 security principles.
- **Decision:** Scrub PII deterministically in `<50ms` prior to LLM, AST cache, or HITL persistence. Persist reversible mapping tokens in `EncryptedPIISessionStore` (`memory | sqlite | redis`) encrypted via **AES-256-GCM** with Authenticated Associated Data (AAD) cryptographically bound to `(tenant_id, audit_session_id)`.
- **Consequences:** No plaintext Malaysian PII leaves the trust boundary or appears in HITL JSONL eval exports, and cross-tenant ciphertext replay fails GCM tag verification deterministically.

---

## ADR-005: Hybrid `BM25F + Subword/Dense RRF` Retrieval and Calibrated `0.78` Abstention Gating

- **Status:** Accepted
- **Modules:** `src/lexgraph_lah/retrieval/hybrid_retriever.py`, `src/lexgraph_lah/graph/reranker.py`, `evals/calibration.py`
- **Context:** Pure lexical matching fails on euphemistic corporate phrasing (e.g., *"follow-the-sun global telemetry replication"* -> Act 709 s. 129), Bahasa Melayu morphological affixes (`pemindahan` / `memindahkan`), and OCR-degraded scans, while naive dense similarity risks accepting out-of-scope foreign law (e.g., Delaware or UK GDPR).
- **Decision:** Enforce bi-temporal (`as_of_date`) and 5-tier territorial (`Sabah`, `Sarawak`, `Labuan`, `Peninsular`, `Federal`) filtering **before** scoring, then fuse 6-field bilingual BM25F (`title`, `section`, `text_en`, `text_bm`, `obligations`, `synonyms`), `EmbeddingProvider` cosine similarity (`DeterministicSubwordEmbedder` zero-network default or `LiveHTTPEmbeddingAdapter`), and 1-hop graph neighbors via Reciprocal Rank Fusion (`RRF`, `k=60`), gated by a calibrated `0.78` abstention threshold.
- **Consequences:** `POST /api/v1/retrieval/explain` exposes full `bm25_score` / `vector_score` / `rrf_score` provenance, oblique/OCR Recall@3 reaches `>= 0.90`, and the `0.78` operating point achieves `0.00` False-Confidence Rate on foreign-law boundary cases.

---

## ADR-006: Scaling Bottlenecks & Evolution Path at `50,000+` Concurrent Contracts

- **Status:** Accepted (Roadmap & Production Pattern)
- **Modules:** `src/lexgraph_lah/graph/portfolio_scanner.py`, `src/lexgraph_lah/portfolio/worker.py`, `src/lexgraph_lah/compliance/clause_cache.py`
- **Context:** Single-process in-memory queues lose mid-batch progress on container OOM/restart and re-bill duplicate contract runs; SQLite WAL hits single-writer serialization under dozens of concurrent API replicas.
- **Decision:**
  1. **Idempotent Submission & Lease-Based Workers:** Use `Idempotency-Key` (tenant-scoped + SHA-256 payload fingerprint) on `POST /api/v1/portfolio/jobs`, atomic worker leases (`worker_id`, `lease_expires_at`, `heartbeat_at`), per-contract checkpoint tables (`portfolio_job_checkpoints`), stale-lease reaping, `DEAD_LETTER` transition + admin requeue, and horizontal `python -m lexgraph_lah.portfolio.worker` consumers.
  2. **Two-Tier `ClauseASTCache`:** Hash scrubbed AST + dependency edges + statutory graph digest in Redis (`CLAUSE_CACHE_BACKEND=redis`) so repeated boilerplate clauses across 50k contracts resolve in `$0.00 USD`.
  3. **Production Storage Tiering:** Partition portfolio jobs into PostgreSQL (`PORTFOLIO_JOB_STORE=postgres` with `FOR UPDATE SKIP LOCKED` at fleet scale), route read-heavy statutory traversals to Neo4j 5 read replicas (`GRAPH_BACKEND=neo4j`), and keep `EncryptedPIISessionStore` on Redis Cluster.
