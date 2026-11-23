# Changelog

All notable changes to `lexgraph-lah` are documented in this file using [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

## [0.4.0] - 2026-11-23

### Added
- **Bilingual Hybrid Retriever (`src/lexgraph_lah/retrieval/hybrid_retriever.py`, `agents/graph.py`, `temporal_store.py`, `routes.py`)**:
  - Added 6-field bilingual EN/BM field-weighted `BM25FIndex` (`title`, `section`, `text_en`, `text_bm`, `obligations`, `synonyms`) with Bahasa Melayu morphological affix/circumfix stemming (`stem_bm_token`), OCR noise normalization (`normalize_ocr_text`), and euphemistic legal concept expansion (`Act 709 s. 129`, `Act 873`, `MOSTI AIGE`, `Act 53`, `Act 378`, `BNM Outsourcing`).
  - Added `EmbeddingProvider` protocol with zero-network `DeterministicSubwordEmbedder` (`blake2b` subword + concept hashing) and configurable `LiveHTTPEmbeddingAdapter` (OpenAI / Gemini embeddings), fused with 1-hop graph neighborhood expansion via Reciprocal Rank Fusion (`RRF`, `k=60`) after strict pre-scoring bi-temporal and 5-tier territorial filtering.
  - Integrated hybrid retrieval fallback into `deontic_temporal_retriever_node` / `search_with_abstention` and exposed `POST /api/v1/retrieval/explain` (`viewer`/`auditor`/`admin`).
- **Statistical Calibration & Adversarial Oblique Stress Suite (`evals/calibration.py`, `evals/run_benchmark.py`, `docs/EVALUATION_AND_LIMITATIONS.md`)**:
  - Added 18-scenario `oblique_stress` suite spanning euphemistic EN/BM/Manglish clauses, OCR noise, hidden Malaysian nexus, and near-threshold foreign governing-law cases.
  - Computed `Recall@1/3/5`, `MRR`, Macro/Micro P/R/F1, `Abstention Precision`, `False-Confidence Rate`, `0.50..0.95` threshold sweep, `10-bin ECE`, and `Brier Score` via `--suite canonical|oblique_stress|all` and `--calibration-report`.
- **Crash-Recoverable Lease-Based Portfolio Queue, `Idempotency-Key` & `DLQ` (`portfolio_scanner.py`, `portfolio/worker.py`, `routes.py`, `auth.py`)**:
  - Extended `InMemoryPortfolioJobStore`, `SQLitePortfolioJobStore`, and `PostgresPortfolioJobStore` with tenant-scoped `Idempotency-Key` deduplication (`202` / `200` / `409 Conflict`), atomic worker leases/heartbeats, per-contract crash checkpoints (zero duplicate re-evaluation on mid-batch recovery), stale-lease reaping, and `DEAD_LETTER` transition after `max_attempts`.
  - Added standalone worker CLI `python -m lexgraph_lah.portfolio.worker --once | --poll-interval 2.0`, `GET /api/v1/portfolio/dlq` (`admin`), and `POST /api/v1/portfolio/jobs/{job_id}/requeue` (`admin`/`auditor`).
- **HITL Counsel Adjudication Flywheel & 1-Click Web UI Workbench (`src/lexgraph_lah/hitl/review_store.py`, `mcp/tools.py`, `routes.py`)**:
  - Added `POST /api/v1/hitl/reviews` (`auditor`/`admin`), `GET /api/v1/hitl/export-jsonl` (`admin`), MCP tool #14 `record_hitl_review`, and `evals/run_benchmark.py --extra-jsonl` ingestion with mandatory Malaysian PII scrubbing and Ed25519 attestation signing.
  - Upgraded `/demo` SPA with 4 1-click "Load Sample Scenario" presets, 2026 fiscal/AIGE regime chips, and per-finding interactive Accept/Modify/Reject/Escalate HITL controls.
- **Unicode Homoglyph/Bidi Firewall Hardening, Staff ADRs & README Top-Fold (`doc_firewall.py`, `docs/ARCHITECTURE_DECISIONS.md`, `README.md`)**:
  - Added `UNICODE_BIDI_OVERRIDE`, `ZERO_WIDTH_STEGANOGRAPHY`, and `UNICODE_HOMOGLYPH_SPOOFING` detection and canonical normalization across plain text, PDF text/hex streams, and OOXML body/tables/comments/customXml/footnotes.
  - Added `docs/ARCHITECTURE_DECISIONS.md` (ADR-001..006), `docs/EVALUATION_AND_LIMITATIONS.md`, and 60-Second Executive Architecture Summary in `README.md`.

## [0.3.0] - 2026-11-23

### Added
- **Counterparty OOXML Track-Changes & Comment-Thread Negotiation Engine (`doc_firewall.py`, `docx_redline_critic.py`, `routes.py`, `mcp/tools.py`)**:
  - Extended `doc_firewall.py` to inspect `word/comments.xml`, `word/commentsExtended.xml`, `word/footnotes.xml`, and `word/endnotes.xml` for bilingual EN/BM IPI, XML comments, statutory spoofing, hidden/vanished runs, and `DOCX_MAX_XML_PART_BYTES` per-part ceilings before AST parsing.
  - Added `src/lexgraph_lah/negotiation/docx_redline_critic.py` parsing `<w:ins>`, `<w:del>`, `<w:moveFrom>`, `<w:moveTo>`, and comment threads (`word/comments.xml`, `word/commentsExtended.xml`) into `CounterpartyRedlineDiff`, reconstructing PII-scrubbed baseline vs proposed clauses, running `DeonticEnvelopeResolver` + `ContractASTGraph`, and classifying deltas as `COMPLIANT_ACCEPT`, `DEONTIC_REGRESSION`, `COMMENT_CONFLICT`, or `NEUTRAL_EDIT` in `0` LLM tokens with Ed25519 attestation.
  - Exposed `POST /api/v1/negotiation/diff-docx` (multipart `.docx` or JSON, RBAC `auditor`/`admin`) and MCP tool `audit_counterparty_docx_redlines`.
- **2026 Malaysian Commercial Fiscal & AI Governance Statutory Pack (`temporal_store.py`, `fiscal_aige_scanner.py`, `deontic_solver.py`, `bilingual_router.py`, `contract_ast.py`, `diff_engine.py`)**:
  - Seeded bi-temporal bilingual EN/BM pairs (`135` total nodes, `520` total edges, all newly seeded pairs verified `ALIGNED` under Act 388 s. 63) across both `InMemoryGraphBackend` and parameterized Cypher (`Neo4jGraphBackend` including `$regime_code` & `$carve_out_metadata_json`):
    - **Stamp Act 1949 [Act 378] & SDSAS (eff. `2026-01-01`):** Section 52 evidentiary inadmissibility, 30-day self-assessment payment window, `RM300` -> `RM3,000/month` employment contract exemption transition, and `8%` foreign residential transfer tier.
    - **Income Tax Act 1967 [Act 53] s. 82C & s. 120(1)(d) (`MyInvois`):** Phased dates (`2024-08-01`..`2026-01-01`), `> RM10,000` single-tx consolidated e-invoice prohibition (including `<w:tbl>` `Jadual Pembayaran` schedule rules), `RM3,000,000` exemption update (`2026-08-30` w/ related/holding-company carve-out), `72h` UIN cancel/reject window, cross-border self-billed foreign imports, and `s. 120(1)(d)` penalties.
    - **MOSTI National Guidelines on AI Governance & Ethics (`AIGE`, eff. `2024-09-20`):** Modeled distinctly with `VOLUNTARY_GUIDELINE` deontic modality, 7 principles, HITL/AI audit trail controls, PDPA s. 9 / s. 129 cross-links, plus **BNM Outsourcing + RMiT** cryptographic key ownership (BYOK), sub-contractor prior-approval, and regulator right-of-audit enhancements.
- **Sub-Processor SLA Cascade Verifier & Multi-Regulator Incident Playbook (`sla_cascade.py`, `routes.py`, `mcp/tools.py`)**:
  - Added `verify_sla_cascade()` evaluating vendor/sub-processor breach windows across `DATA_USER_CONTROLLER`, `NCII_ENTITY`, `BNM_FINANCIAL_INSTITUTION`, and `PUBLIC_SECTOR_AGENCY_ACT_864`, flagging `SLA_CASCADE_BREACH` on impossible windows or `< 25%` operational triage buffers with exact slack/deficit hours and bilingual EN/BM replacement clauses.
  - Added `POST /api/v1/deontic/incident-playbook` and MCP tool `compile_incident_playbook` generating chronological UTC + `Asia/Kuala_Lumpur` deadline milestones with `Act 388 s. 54` computation-of-time / weekly-holiday rollover metadata and Ed25519 attestation.
- **Air-Gapped `.lexpack.zip` Evidence Bundles, Offline CLI Verifier & SSRF-Safe Signed Webhooks (`attestation/bundle.py`, `attestation/verify_cli.py`, `webhooks.py`, `portfolio_scanner.py`)**:
  - Exposed `GET /api/v1/attestation/{manifest_id}/bundle` (with tenant-isolated `include_docx=true&audit_session_id=...`) streaming deterministic `.lexpack.zip` archives and added zero-network verifier CLI `python -m lexgraph_lah.attestation.verify_cli --bundle <path> [--pubkey <pub.pem>]`.
  - Extended `POST /api/v1/portfolio/jobs` with durable backend persistence (`PORTFOLIO_JOB_STORE=memory|sqlite|postgres`), strict SSRF guards (`validate_webhook_url_ssrf` blocking loopback, RFC1918, metadata, non-HTTPS prod, and DNS rebinding), and dual-signed webhook delivery (`X-LexGraph-Signature-256` + `X-LexGraph-Ed25519`) with bounded 3-attempt exponential backoff.
- **Clause-AST Isomorphic Verdict Cache & Tenant FinOps Budget Guardrail (`clause_cache.py`, `cost_tracker.py`, `agents/graph.py`, `routes.py`)**:
  - Added zero-token `ClauseASTCache` (`CLAUSE_CACHE_BACKEND=memory|redis`, `cache_bypass=true`) computing canonical SHA-256 digests across normalized scrubbed clause ASTs, edges, dates, scopes, regimes, and statutory graph snapshots in `/compliance/check` and async portfolio jobs with OTel `lexgraph.cache_hit` telemetry.
  - Added per-tenant monthly MYR budget enforcement (`LEXGRAPH_TENANT_MONTHLY_BUDGET_MYR` + `LEXGRAPH_BUDGET_EXCEEDED_POLICY=deterministic_fallback|reject_429`) and `GET /api/v1/finops/tenant-usage` (`viewer`/`auditor`/`admin` own-tenant scoped).
- **36-Scenario Benchmark Expansion (`evals/run_benchmark.py`)**:
  - Expanded golden benchmark from 30 to 36 scenarios (`BENCH-31`..`BENCH-36`, `13` total MCP tools) achieving `100.00%` determinism consistency, `100.00%` cross-trial stability, `100.00%` verbatim grounding, `100.00%` abstention precision, `100.00%` temporal recall, and `0.00%` temporal contamination.

## [0.2.0] - 2026-11-22

### Added
- **2025–2026 Malaysian Statutory & Deontic Solver Expansion (`temporal_store.py`, `deontic_solver.py`, `diff_engine.py`, `bilingual_router.py`)**:
  - Full Cyber Security Act 2024 [Act 854] subsidiary suite: `P.U. (A) 219/2024` (annual risk assessment / biennial audit), `P.U. (A) 221/2024` (MSSP SOC & penetration testing licensing), `P.U. (A) 222/2024` (compounding of offences), and `Cyber Security (Exemption) Order 2025` (`P.U. (A) 47/2025`) carve-out metadata.
  - Complete PDPA (Amendment) Act 2024 [Act A1727] 3-phase commencement (`2025-01-01`, `2025-04-01`, `2025-06-01` via `P.U. (B) 522/2024`) plus 2025 PDPD Guidelines (`01/2025` DPO, `02/2025` DBN 72h Commissioner + 7d affected data subject + 2y register, `03/2025` CBPDT), biometric sensitive data classification, and distinct multi-recipient resolution in `DeonticEnvelopeResolver`.
  - Newly seeded 2025–2026 and companion statutes: **Data Sharing Act 2025 [Act 864]** (including s. 17(1) contractor extension), **Online Safety Act 2025 [Act 866]** + 2026 Risk Mitigation & Child Protection Codes (under-16 MyKad/passport verification, RM10M penalty ceiling), **Consumer Credit Act 2025 [Act 873]** (SKP BNPL licensing & Rule-of-78 prohibition), **Digital Signature Act 1997 [Act 562]**, and **Computer Crimes Act 1997 [Act 563]**.
  - Four new golden benchmark scenarios (`BENCH-27`..`BENCH-30`) expanding the evaluation dataset to 30 scenarios.
- **Persistent Graph Backend, Gazette CLI, OOXML Table AST & OCR Fallback (`temporal_store.py`, `gazette_ingestor.py`, `contract_ast.py`, `pii_scrubber.py`, `docker-compose.yml`)**:
  - Dual-backend `TemporalGraphStore` (`GRAPH_BACKEND=memory|neo4j`) with Neo4j 5 service in `docker-compose.yml` and idempotent JSON/XML `gazette_ingestor` CLI.
  - Structured OOXML `<w:tbl>` schedule/table parsing (`SCHEDULE` nodes with `table_rows`), new intra-contract edges (`SUBJECT_TO`, `INCORPORATES_SCHEDULE`, `SURVIVES_TERMINATION`), scanned PDF detection, and pluggable `OCRAdapter` (`OCR_PROVIDER=none|tesseract|gemini_vision`) with safe deterministic abstention metadata.
  - Expanded `<50ms` Malaysian PII masking covering LHDN TIN (`[TIN_MY_01]`), KWSP/EPF (`[KWSP_01]`), PERKESO/SOCSO (`[PERKESO_01]`), and MY Bank/DuitNow (`[BANK_MY_01]`).
- **Enterprise AuthN/RBAC, Multi-Worker PII Vault, Ed25519 Signed Attestation & Async Portfolio Jobs (`auth.py`, `doc_firewall.py`, `pii_scrubber.py`, `attestation_ledger.py`, `portfolio_scanner.py`, `routes.py`)**:
  - Configurable `AUTH_MODE=disabled|api_key|jwt` pure ASGI middleware with fail-closed `ENV=production` protection, HS256/EdDSA/RS256 JWT validation, `viewer`/`auditor`/`admin` RBAC across REST/SSE/`POST /mcp`, cross-tenant header verification, and sliding-window rate limiting.
  - OOXML `.docx` zip-bomb & archive path-traversal guards (`validate_zip_archive_safety`).
  - Cross-worker AES-256-GCM `EncryptedPIISessionStore` (memory, SQLite WAL, Redis) bound with tenant AAD (`(tenant_id, audit_session_id)`) for `/compliance/check` -> `/compliance/export-docx`.
  - Asymmetric **Ed25519** chain-tip signatures on `AttestationLedger` (with `GET /api/v1/attestation/public-key` & `PostgresAttestationBackend`).
  - Bounded-concurrency async portfolio jobs (`POST /api/v1/portfolio/jobs`, `GET /api/v1/portfolio/jobs/{job_id}`) supporting 500–2,000+ contracts and multipart `.zip` archives alongside precomputed statutory window context caching.
- **Production Model Aliasing, Live BNM FX Adapter & Live Evals (`cost_tracker.py`, `agents/graph.py`, `evals/run_benchmark.py`)**:
  - Configurable live model tier resolution (`LEXGRAPH_MODEL_FAST`, `LEXGRAPH_MODEL_REASONING`) with exponential backoff + structured validation, async 24h-cached BNM OpenAPI USD/MYR FX provider with `LEXGRAPH_USD_MYR_FALLBACK`, and `--mode live` metric persistence to `evals/results/`.
- **Repository Governance & Supply-Chain Security**:
  - Added `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `.github/dependabot.yml`, and `.github/workflows/security.yml`.

## [0.1.0] - 2026-06-01

### Added
- Initial release with PDPA 2010 [Act 709], Cyber Security Act 2024 [Act 854], BNM RMiT, Act 388 s. 63 bilingual divergence critic, 5-territory Malaysian statutes (`Act 265`, `Sabah Cap. 67`, `Sarawak Cap. 76`, `Labuan Act 704`, `Act 136`, `Act 658`), pre-AST OOXML/PDF security firewall, SHA-256 SQLite WAL attestation ledger, 11-tool JSON-RPC 2.0 MCP server, and 26-scenario `--mode mock` benchmark suite.
