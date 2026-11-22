# Changelog

All notable changes to `lexgraph-lah` are documented in this file using [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

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
