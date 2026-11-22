# `lexgraph-lah` — Deterministic Multi-Regime Legal Compliance, Counterfactual Redline & FinOps Engine

[![CI Pipeline](https://github.com/Kearskill/lexgraph-lah/actions/workflows/ci.yml/badge.svg)](https://github.com/Kearskill/lexgraph-lah/actions/workflows/ci.yml)
[![Security Audit](https://github.com/Kearskill/lexgraph-lah/actions/workflows/security.yml/badge.svg)](https://github.com/Kearskill/lexgraph-lah/actions/workflows/security.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-1C3C3C?logo=langchain&logoColor=white)](https://langchain-ai.github.io/langgraph/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

**`lexgraph-lah`** is a deterministic multi-agent regulatory compliance, bi-temporal statutory redline diffing, Act 388 bilingual divergence auditing, contract AST trap-detection, and Track-Changes `.docx` redline compiler engineered for overlapping 2025–2026 Malaysian statutory regimes:

- **PDPA 2010 [Act 709], PDPA (Amendment) Act 2024 [Act A1727] & 2025 PDPD Guidelines:** All three phased commencement tranches via `P.U. (B) 522/2024` (`2025-01-01`, `2025-04-01`, `2025-06-01`), including direct Data Processor s. 9 obligations (`RM1M / 3y`), biometric sensitive personal data, s. 129 adequacy/CBPDT Guidelines `No. 03/2025`, s. 43A data portability, mandatory DPO (`No. 01/2025`), **72-hour Commissioner breach notice**, **7-day affected data-subject notice**, and **2-year breach register** (`No. 02/2025`).
- **Cyber Security Act 2024 [Act 854] Full Subsidiary Suite:** `P.U. (A) 219/2024` (annual NCII risk assessment / biennial independent audit), `P.U. (A) 220/2024` (`6h` initial / `14d` full NCII incident reporting), `P.U. (A) 221/2024` (mandatory NACSA MSSP SOC & penetration testing licensing), `P.U. (A) 222/2024` (compounding of offences), and the **Cyber Security (Exemption) Order 2025** (`P.U. (A) 47/2025`) temporal carve-out metadata.
- **Bank Negara Malaysia RMiT** (`1h` critical incident notice, cloud exit plan & regulator audit rights).
- **Enacted 2025–2026 & Companion Malaysian Statutes:**
  - **Data Sharing Act 2025 [Act 864]** (eff. `2025-04-28`), including **s. 17(1)** extension of public-sector statutory duties to third-party contractors/vendors.
  - **Online Safety Act 2025 [Act 866]** (eff. `2026-01-01`) & **Risk Mitigation / Child Protection Codes** (eff. `2026-06-01`, under-16 MyKad/passport verification, RM10M non-compliance penalty ceiling).
  - **Consumer Credit Act 2025 [Act 873]** (eff. `2026-03-01`) & **SKP BNPL/Debt-Collector Licensing** (eff. `2026-06-01`, Rule-of-78 / flat-rate prohibition).
  - **Digital Signature Act 1997 [Act 562]** and **Computer Crimes Act 1997 [Act 563]**.
- **Interpretation Acts 1948 and 1967 [Act 388]** (`s. 63`) and 5-way East/West/Offshore territorial statutes (`Act 265`, `Sabah Cap. 67`, `Sarawak Cap. 76`, `Labuan Act 704`, `Act 136`, `Act 658`, `Act 574`).

---

## Core Capabilities

1. **Zero-Token Multi-Regime & Multi-Recipient Deontic Conflict Solver (`DeonticEnvelopeResolver`):**
   - Resolves point-in-time statutes and `P.U. (A)` / `P.U. (B)` gazettes in $O(V + E)$ (`0` LLM tokens), resolving both the strictest initial deadline AND distinct `recipient_obligations` (Commissioner `72h`, Affected Data Subject `7d`, NACSA `6h`/`14d`, BNM RMiT `1h`) without conflating recipients.
2. **Adversarial OOXML/PDF Firewall & Zip-Bomb Guards (`doc_firewall.py`):**
   - Zero-token inspection (`$0.00 USD`) of `.docx`, `.pdf`, and raw text **before** AST parsing: enforces `validate_zip_archive_safety` (uncompressed ceiling, streaming >64 KB compression ratio cap, max entry count, path-traversal blocking), quarantines `<w:vanish/>`, `<w:webHidden/>`, micro/near-white fonts, macros, `customXml`, PDF `3 Tr` / off-page `Tm`/`Td` layers, and bilingual EN/BM IPI/statutory-spoofing directives.
3. **Dual-Backend Temporal Graph Store & Gazette CLI (`temporal_store.py`, `gazette_ingestor.py`):**
   - Zero-dependency `InMemoryGraphBackend` (`GRAPH_BACKEND=memory`, seeding `107` statutory nodes and `397` edges) alongside parameterized Cypher `Neo4jGraphBackend` (`GRAPH_BACKEND=neo4j` against Neo4j 5), plus idempotent JSON/XML Federal Gazette validation & CLI ingestion.
4. **Structured OOXML Table Schedules, Scanned PDF OCR Fallback & Expanded PII Vault:**
   - Parses `<w:tbl>` schedules (`Jadual` / `Lampiran`) into structured `SCHEDULE` `ContractClauseNode`s with `table_rows` and intra-contract edges (`DEFINES_TERM`, `OVERRIDES_NOTWITHSTANDING`, `CROSS_REFERENCES`, `SUBJECT_TO`, `INCORPORATES_SCHEDULE`, `SURVIVES_TERMINATION`).
   - Detects low-text scanned PDFs and routes through pluggable `OCRAdapter` (`OCR_PROVIDER=none|tesseract|gemini_vision`, yielding deterministic abstention metadata when `none`).
   - `<50ms` pre-flight PII masking across MyKad/NRIC (`[MYKAD_01]`), Passport, Phone, Email, SSM, LHDN TIN (`[TIN_MY_01]`), KWSP/EPF (`[KWSP_01]`), PERKESO/SOCSO (`[PERKESO_01]`), and MY Bank/DuitNow (`[BANK_MY_01]`), persisted across workers using **AES-256-GCM** `EncryptedPIISessionStore` (`memory|sqlite|redis`) keyed with tenant AAD `(tenant_id, audit_session_id)`.
5. **Enterprise AuthN/RBAC, Ed25519 Signed Attestation & Async Portfolio Jobs:**
   - Pure ASGI `EnterpriseSecurityMiddleware` supporting `AUTH_MODE=disabled|api_key|jwt` (HS256 / EdDSA / RS256), fail-closed HTTP `503` when `ENV=production` and `AUTH_MODE=disabled`, `viewer`/`auditor`/`admin` RBAC across REST, SSE (`/compliance/stream`), and `POST /mcp`, anti-spoofing `X-Tenant-ID` enforcement, and per-tenant sliding-window rate limiting.
   - Append-only SHA-256 hash-chained `AttestationLedger` (SQLite WAL or PostgreSQL) with **Ed25519** chain-tip signing and public verification key endpoint (`GET /api/v1/attestation/public-key`).
   - Synchronous batch scanner (`POST /api/v1/portfolio/blast-radius`, `<= 50` contracts) and bounded-concurrency async portfolio job engine (`POST /api/v1/portfolio/jobs`, `GET /api/v1/portfolio/jobs/{job_id}`) supporting `500–2,000+` contracts or multipart `.zip` archives of `.docx`/`.pdf`/`.txt` files.
6. **Configurable Gemini Model Aliasing & Live Bank Negara Malaysia FX:**
   - Complexity-aware `select_model_tier` preserves `gemini-4-hydrogen`/`gemini-4-neon` in mock/offline CI while mapping `fast_tier` / `reasoning_tier` via `LEXGRAPH_MODEL_FAST` / `LEXGRAPH_MODEL_REASONING` in live mode with exponential backoff and Pydantic structured validation.
   - Optional async `BNMFXRateProvider` fetches `api.bnm.gov.my/public/exchange-rate` (cached for 24h) with deterministic offline fallback to `LEXGRAPH_USD_MYR_FALLBACK`.

---

## Quickstart

### Option 1: Local Development with `uv`

```bash
git clone https://github.com/Kearskill/lexgraph-lah.git
cd lexgraph-lah
cp .env.example .env
uv sync --all-extras --dev --frozen
uv run lexgraph-lah
```

### Option 2: Docker Compose

Base stack (API + Arize Phoenix + Neo4j 5):

```bash
cp .env.example .env
# In .env, set AUTH_API_KEYS_JSON or AUTH_MODE for production Docker defaults
docker compose up --build
```

Enterprise profile (adds **Redis 7** for cross-worker PII vault + **PostgreSQL 16** for multi-replica attestation ledger):

```bash
docker compose --profile enterprise up --build
```

### Gazette Ingestion CLI

```bash
uv run python -m lexgraph_lah.ingestion.gazette_ingestor \
  --input path/to/gazette.json \
  --backend memory
```

---

## API Contracts & MCP Tool Catalog

### REST, SSE & Async Portfolio Endpoints

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/compliance/check` | `POST` | Runs 5-node multi-regime audit (`audit_session_id` returned for cross-worker `.docx` re-hydration). |
| `/compliance/stream` | `POST` | Streams live SSE (`text/event-stream`) events (`node_update`, `abstention_gate`, `finops_tick`, `complete`). |
| `/compliance/upload` | `POST` | Multipart `.docx`, `.pdf`, or `.txt` upload with pre-AST firewall, `<w:tbl>` / OCR handling, and PII scrubbing. |
| `/compliance/export-docx` | `POST` | Streams Track-Changes `.docx` with cross-worker PII re-hydration (`audit_session_id`) and Ed25519 headers. |
| `/api/v1/deontic/envelope` | `GET` | Zero-token `DeonticEnvelopeResolver` returning strictest bounds and distinct `recipient_obligations`. |
| `/api/v1/lineage/diff` | `GET` / `POST` | Zero-token bi-temporal statutory diff across `AMENDED_BY` and `REPEALED_BY` chains. |
| `/api/v1/lineage/delta-audit` | `POST` | Zero-token Contract Delta-Audit detecting newly commenced statutory/gazette regressions. |
| `/api/v1/crosswalk/{node_id}/divergence` | `GET` / `POST` | Act 388 s. 63 Bilingual Divergence Critic across BM/EN `SourceSpan` nodes. |
| `/api/v1/compliance/scan` | `POST` | Deterministic pre-flight PII-scrubbed Act 709 gap scanner with Act 388 warnings. |
| `/api/v1/research/point-in-time` | `POST` | 4-stage bilingual point-in-time research with 7-tier court/statute breakdown. |
| `/api/v1/portfolio/blast-radius` | `POST` | Zero-token synchronous Gazette Blast-Radius Scanner (`<= 50` contracts). |
| `/api/v1/portfolio/jobs` | `POST` | Submits async portfolio job (`202 Accepted`) for `500–2,000+` contracts (JSON) or `.zip` archive upload. |
| `/api/v1/portfolio/jobs/{job_id}` | `GET` | Polls tenant-scoped async portfolio job progress (`QUEUED`/`RUNNING`/`COMPLETED`/`FAILED`). |
| `/api/v1/attestation/public-key` | `GET` | Returns Ed25519 PEM/raw public key and SHA-256 fingerprint for offline attestation verification. |
| `/api/v1/attestation/{manifest_id}` | `GET` | Retrieves an immutable hash-chained & Ed25519-signed `AttestationLedgerRecord`. |
| `/api/v1/attestation/verify` | `POST` | Cryptographically verifies digest, `as_of_date`, citations, SHA-256 chain, and Ed25519 signature. |
| `/api/v1/security/scan` | `POST` | Zero-token OOXML `.docx` / `.pdf` / raw-text IPI & zip-bomb firewall scanner. |
| `/mcp` | `POST` | Streamable HTTP JSON-RPC 2.0 MCP server (`11` tools; stdio via `python -m lexgraph_lah.mcp.jsonrpc --stdio`). |

---

## Testing, Evaluation & Determinism Benchmark

### 1. Run Quality Gates

```bash
uv run ruff check src tests evals
uv run mypy src
uv run pytest -q
```

### 2. Run the 30-Scenario Determinism & FinOps Benchmark

```bash
uv run python -m evals.run_benchmark --mode mock --trials 3
# Live Gemini evaluation (writes JSON & Markdown artifacts to evals/results/):
uv run python -m evals.run_benchmark --mode live --trials 3
```

| Metric | Observed (`--mode mock --trials 3`) | SLA Target | Status |
| :--- | :--- | :--- | :--- |
| **Scenarios x Trials** | `30 scenarios x 3 trials (90 runs)` | `>= 18 scenarios` | PASS |
| **Determinism Consistency (%)** | `100.00%` | `100.00%` | PASS |
| **Cross-Trial Verdict Stability (%)** | `100.00%` | `100.00%` | PASS |
| **Verdict Accuracy (%)** | `100.00%` | `>= 95.00%` | PASS |
| **Verbatim Citation Grounding (%)** | `100.00%` | `100.00%` | PASS |
| **Counterfactual Retry Recovery Rate (%)** | `100.00%` | `>= 95.00%` | PASS |
| **Citation Hallucinations Rejected** | `3` | `Audited` | PASS |
| **Abstention Precision (%)** | `100.00%` | `100.00%` | PASS |
| **Temporal Context Recall (%)** | `100.00%` | `100.00%` | PASS |
| **Temporal Contamination Rate (%)** | `0.00%` | `0.00%` | PASS |
| **Latency p50 / p95 (ms)** | `23.27 ms / 104.14 ms` | `< 5000.00 ms` | PASS |
| **Mean Tokens per Audit** | `572.8 tokens` | `< 15000 tokens` | PASS |
| **Mean Cost per Audit (USD & MYR)** | `$0.000144 USD / RM 0.000634 MYR` | `< $0.005000 USD` | PASS |

---

## Governance & License

- See [SECURITY.md](./SECURITY.md) for threat boundaries, PII handling, Ed25519 verification, and vulnerability disclosure.
- See [CONTRIBUTING.md](./CONTRIBUTING.md) for adding Malaysian statutes/`P.U.` gazettes and bilingual Act 388 test cases.
- See [CHANGELOG.md](./CHANGELOG.md) for release history.
- Released under the [MIT License](./LICENSE). Copyright (c) 2026 Kearney Leith Julius.
