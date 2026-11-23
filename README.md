# `lexgraph-lah` — Deterministic Multi-Regime Legal Compliance, Counterfactual Redline & FinOps Engine

[![CI Pipeline](https://github.com/Kearskill/lexgraph-lah/actions/workflows/ci.yml/badge.svg)](https://github.com/Kearskill/lexgraph-lah/actions/workflows/ci.yml)
[![Security Audit](https://github.com/Kearskill/lexgraph-lah/actions/workflows/security.yml/badge.svg)](https://github.com/Kearskill/lexgraph-lah/actions/workflows/security.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-1C3C3C?logo=langchain&logoColor=white)](https://langchain-ai.github.io/langgraph/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

## 60-Second Executive Architecture Summary

- **The Problem:** Auditing Malaysian commercial contracts across overlapping 2025–2026 statutes (`Act 709` PDPA A1727, `Act 854` Cyber Security, `BNM RMiT`, `Act 378` Stamp SDSAS, `Act 53` MyInvois `>RM10k`, `Act 873` Consumer Credit, `MOSTI AIGE`) breaks flat vector RAG: pre/post-amendment provisions leak across dates, stochastic LLMs fail numeric deadline arithmetic (`1h` vs `6h` vs `72h` vs `7d`), and hidden OOXML/PDF prompt injections or Unicode bidi overrides bypass naive parsers.
- **Neuro-Symbolic Unit Economics:** Deterministic $O(V + E)$ symbolic engines handle document firewalling, PII scrubbing (`<50ms`, AES-256-GCM AAD vault), Contract AST trap detection, deontic envelope solving, OOXML track-changes diffing, and SLA cascades at **`$0.00 USD` (`0` LLM tokens)**, keeping full multi-node benchmark audits at **`$0.000120 USD` (`RM 0.000528 MYR`)** mean spend with `ClauseASTCache` hits dropping repeat clauses to **`$0.00`**.
- **Zero Temporal Leakage & Calibrated Retrieval:** Bi-temporal (`as_of_date`) and 5-tier territorial (`Sabah`, `Sarawak`, `Labuan`, `Peninsular`, `Federal`) filters execute **before** bilingual `BM25F + Subword/Dense + RRF (k=60)` retrieval (`0.00%` temporal contamination, `0.78` calibrated abstention gate).
- **3-Line Zero-Config Quickstart:**
  ```bash
  uv sync --all-extras --dev --frozen && uv run lexgraph-lah
  # Open http://localhost:8000/demo -> click any 1-click "Load Sample Scenario" preset
  ```
- **Deep Dives:** [Staff Architecture Decisions (ADR-001..006)](./docs/ARCHITECTURE_DECISIONS.md) &bull; [Evaluation, Calibration (`ECE`/Brier/`Recall@K`) & Limitations](./docs/EVALUATION_AND_LIMITATIONS.md)

---

**`lexgraph-lah`** is a deterministic multi-agent regulatory compliance, bi-temporal statutory redline diffing, Act 388 bilingual divergence auditing, contract AST trap-detection, and Track-Changes `.docx` redline compiler engineered for overlapping 2025–2026 Malaysian statutory regimes:

- **PDPA 2010 [Act 709], PDPA (Amendment) Act 2024 [Act A1727] & 2025 PDPD Guidelines:** All three phased commencement tranches via `P.U. (B) 522/2024` (`2025-01-01`, `2025-04-01`, `2025-06-01`), including direct Data Processor s. 9 obligations (`RM1M / 3y`), biometric sensitive personal data, s. 129 adequacy/CBPDT Guidelines `No. 03/2025`, s. 43A data portability, mandatory DPO (`No. 01/2025`), **72-hour Commissioner breach notice**, **7-day affected data-subject notice**, and **2-year breach register** (`No. 02/2025`).
- **Cyber Security Act 2024 [Act 854] Full Subsidiary Suite:** `P.U. (A) 219/2024` (annual NCII risk assessment / biennial independent audit), `P.U. (A) 220/2024` (`6h` initial / `14d` full NCII incident reporting), `P.U. (A) 221/2024` (mandatory NACSA MSSP SOC & penetration testing licensing), `P.U. (A) 222/2024` (compounding of offences), and the **Cyber Security (Exemption) Order 2025** (`P.U. (A) 47/2025`) temporal carve-out metadata.
- **Bank Negara Malaysia RMiT** (`1h` critical incident notice, cloud exit plan & regulator audit rights).
- **Enacted 2025–2026 & Companion Malaysian Statutes:**
  - **Data Sharing Act 2025 [Act 864]** (eff. `2025-04-28`), including **s. 17(1)** extension of public-sector statutory duties to third-party contractors/vendors.
  - **Online Safety Act 2025 [Act 866]** (eff. `2026-01-01`) & **Risk Mitigation / Child Protection Codes** (eff. `2026-06-01`, under-16 MyKad/passport verification, RM10M non-compliance penalty ceiling).
  - **Consumer Credit Act 2025 [Act 873]** (eff. `2026-03-01`) & **SKP BNPL/Debt-Collector Licensing** (eff. `2026-06-01`, Rule-of-78 / flat-rate prohibition).
  - **Stamp Act 1949 [Act 378] & Tax Measures Act 2025 (SDSAS, eff. `2026-01-01`):** Section 52 evidentiary inadmissibility, 30-day SDSAS self-assessment return & payment window, employment contract stamp duty exemption threshold shift from `RM300` to `RM3,000/month`, and `8%` foreign residential property transfer duty tier.
  - **Income Tax Act 1967 [Act 53] s. 82C & s. 120(1)(d) (LHDN `MyInvois` e-Invoicing):** Phased commencement (`2024-08-01`, `2025-01-01`, `2025-07-01`, `2026-01-01`), `> RM10,000` single-transaction consolidated e-invoice prohibition (eff. `2026-01-01`), `RM3,000,000` annual revenue exemption update (eff. `2026-08-30` with related/holding-company non-exemption carve-out), `72-hour` UIN cancellation/rejection window, self-billed foreign import duties, `<w:tbl>` `Jadual Pembayaran` checks, and `s. 120(1)(d)` penalties (`RM200–RM20,000` / `6m`).
  - **MOSTI National Guidelines on AI Governance & Ethics (`AIGE`, eff. `2024-09-20`):** Modeled distinctly under `VOLUNTARY_GUIDELINE` deontic modality covering the 7 principles, human-in-the-loop oversight, AI audit trail retention, and PDPA `s. 9` / `s. 129` cross-links alongside **BNM Outsourcing + RMiT** cryptographic key ownership (BYOK), sub-contractor prior approval, and regulator right-of-audit mandates.
  - **Digital Signature Act 1997 [Act 562]** and **Computer Crimes Act 1997 [Act 563]**.
- **Interpretation Acts 1948 and 1967 [Act 388]** (`s. 54` computation of time & weekend/weekly-holiday rollover, `s. 63` bilingual prevalence) and 5-way East/West/Offshore territorial statutes (`Act 265`, `Sabah Cap. 67`, `Sarawak Cap. 76`, `Labuan Act 704`, `Act 136`, `Act 658`, `Act 574`).

---

## Core Capabilities

1. **Zero-Token Multi-Regime & Multi-Recipient Deontic Conflict Solver (`DeonticEnvelopeResolver`):**
   - Resolves point-in-time statutes and `P.U. (A)` / `P.U. (B)` gazettes in $O(V + E)$ (`0` LLM tokens), resolving both the strictest initial deadline AND distinct `recipient_obligations` (Commissioner `72h`, Affected Data Subject `7d`, NACSA `6h`/`14d`, BNM RMiT `1h`) without conflating recipients, while distinguishing mandatory statutory breaches from `VOLUNTARY_GUIDELINE` frameworks (MOSTI AIGE).
2. **Adversarial OOXML/PDF Firewall, Zip-Bomb Guards & Counterparty Track-Changes Critic (`doc_firewall.py`, `docx_redline_critic.py`):**
   - Zero-token inspection (`$0.00 USD`) of `.docx` (including `word/comments.xml`, `word/commentsExtended.xml`, `word/footnotes.xml`, `word/endnotes.xml`, and `DOCX_MAX_XML_PART_BYTES` per-part ceilings), `.pdf`, and raw text **before** AST parsing: enforces `validate_zip_archive_safety`, quarantines `<w:vanish/>`, `<w:webHidden/>`, micro/near-white fonts, macros, `customXml`, PDF `3 Tr` / off-page `Tm`/`Td` layers, and bilingual EN/BM IPI/statutory-spoofing directives.
   - Parses counterparty OOXML track-changes (`<w:ins>`, `<w:del>`, `<w:moveFrom>`, `<w:moveTo>`) and comment threads (`<w:commentRangeStart>`, `word/comments.xml`) into `CounterpartyRedlineDiff`, classifying baseline-vs-proposed clauses against `DeonticEnvelopeResolver` as `COMPLIANT_ACCEPT`, `DEONTIC_REGRESSION`, `COMMENT_CONFLICT`, or `NEUTRAL_EDIT` with PII vaulting and Ed25519 attestation in `0` LLM tokens.
3. **Dual-Backend Temporal Graph Store & Gazette CLI (`temporal_store.py`, `gazette_ingestor.py`):**
   - Zero-dependency `InMemoryGraphBackend` (`GRAPH_BACKEND=memory`, seeding `135` statutory nodes and `520` edges) alongside parameterized Cypher `Neo4jGraphBackend` (`GRAPH_BACKEND=neo4j` against Neo4j 5), plus idempotent JSON/XML Federal Gazette validation & CLI ingestion.
4. **Structured OOXML Table Schedules, Sub-Processor SLA Cascade Verifier, Incident Playbooks & Expanded PII Vault:**
   - Parses `<w:tbl>` schedules (`Jadual` / `Lampiran`) into structured `SCHEDULE` `ContractClauseNode`s with `table_rows` and evaluates 2026 Act 378/Act 53/AIGE/BNM Outsourcing rules in `0` tokens (`fiscal_aige_scanner.py`).
   - Verifies upstream-vs-downstream sub-processor notice windows across `DATA_USER_CONTROLLER`, `NCII_ENTITY`, `BNM_FINANCIAL_INSTITUTION`, and `PUBLIC_SECTOR_AGENCY_ACT_864` (`sla_cascade.py`), flagging `SLA_CASCADE_BREACH` on impossible windows or `< 25%` operational triage buffers, generating bilingual EN/BM redlines, and compiling chronological UTC + `Asia/Kuala_Lumpur` incident deadline playbooks with `Act 388 s. 54` metadata.
   - `<50ms` pre-flight PII masking across MyKad/NRIC (`[MYKAD_01]`), Passport, Phone, Email, SSM, LHDN TIN (`[TIN_MY_01]`), KWSP/EPF (`[KWSP_01]`), PERKESO/SOCSO (`[PERKESO_01]`), and MY Bank/DuitNow (`[BANK_MY_01]`), persisted across workers using **AES-256-GCM** `EncryptedPIISessionStore` (`memory|sqlite|redis`) keyed with tenant AAD `(tenant_id, audit_session_id)`.
5. **Enterprise AuthN/RBAC, Air-Gapped `.lexpack.zip` Bundles & Durable Signed Portfolio Webhooks:**
   - Pure ASGI `EnterpriseSecurityMiddleware` (`AUTH_MODE=disabled|api_key|jwt`), fail-closed HTTP `503` when `ENV=production` and `AUTH_MODE=disabled`, `viewer`/`auditor`/`admin` RBAC across REST, SSE (`/compliance/stream`), and `POST /mcp`, anti-spoofing `X-Tenant-ID` enforcement, and per-tenant sliding-window rate limiting.
   - Append-only SHA-256 hash-chained & **Ed25519**-signed `AttestationLedger` (SQLite WAL or PostgreSQL) plus deterministic `.lexpack.zip` air-gapped evidence bundle export (`GET /api/v1/attestation/{manifest_id}/bundle`) and offline CLI verifier (`python -m lexgraph_lah.attestation.verify_cli --bundle <path.lexpack.zip> [--pubkey <pub.pem>]`).
   - Durable portfolio jobs (`PORTFOLIO_JOB_STORE=memory|sqlite|postgres`) for `500–2,000+` contracts and `.zip` archives with SSRF-guarded (`validate_webhook_url_ssrf`) dual-signed webhooks (`X-LexGraph-Signature-256` HMAC-SHA256 + `X-LexGraph-Ed25519`) and bounded 3-attempt exponential backoff.
6. **Clause-AST Isomorphic Verdict Cache, Tenant FinOps Guardrails & Configurable Gemini / BNM FX:**
   - Zero-token `ClauseASTCache` (`CLAUSE_CACHE_BACKEND=memory|redis`, `cache_bypass=true` override) hashing PII-scrubbed clause ASTs, dependency edges, evaluation dates, territorial scopes, normalized regimes, and statutory graph digests across `/compliance/check` and async portfolio jobs with OpenTelemetry cache-hit telemetry.
   - Per-tenant MYR FinOps budget circuit-breaker (`LEXGRAPH_TENANT_MONTHLY_BUDGET_MYR` + `LEXGRAPH_BUDGET_EXCEEDED_POLICY=deterministic_fallback|reject_429` + `GET /api/v1/finops/tenant-usage`), complexity-aware `select_model_tier`, and 24h-cached live Bank Negara Malaysia USD/MYR FX rates.

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

### Offline Evidence Bundle Verifier CLI

```bash
uv run python -m lexgraph_lah.attestation.verify_cli \
  --bundle path/to/attestation.lexpack.zip \
  --pubkey path/to/public_key.pem
```

### Crash-Recoverable Portfolio Queue Worker CLI

```bash
uv run python -m lexgraph_lah.portfolio.worker --once
# Or run continuously with stale-lease reaping & per-contract checkpoints:
uv run python -m lexgraph_lah.portfolio.worker --poll-interval 2.0
```

---

## API Contracts & MCP Tool Catalog

### REST, SSE & Async Portfolio Endpoints

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/compliance/check` | `POST` | Runs 5-node multi-regime audit with Clause-AST cache lookup, tenant budget enforcement, and `audit_session_id` PII vaulting. |
| `/compliance/stream` | `POST` | Streams live SSE (`text/event-stream`) events (`node_update`, `abstention_gate`, `finops_tick`, `complete`). |
| `/compliance/upload` | `POST` | Multipart `.docx`, `.pdf`, or `.txt` upload with pre-AST firewall, `<w:tbl>` / OCR handling, and PII scrubbing. |
| `/compliance/export-docx` | `POST` | Streams Track-Changes `.docx` with cross-worker PII re-hydration (`audit_session_id`) and Ed25519 headers. |
| `/api/v1/negotiation/diff-docx` | `POST` | Zero-token counterparty OOXML track-changes & comment-thread negotiation critic returning `CounterpartyRedlineDiff` + attestation. |
| `/api/v1/deontic/envelope` | `GET` | Zero-token `DeonticEnvelopeResolver` returning strictest bounds, `VOLUNTARY_GUIDELINE` separation, and `recipient_obligations`. |
| `/api/v1/deontic/incident-playbook` | `POST` | Zero-token multi-regulator incident timeline compiler (`UTC` + `Asia/Kuala_Lumpur`, `Act 388 s. 54`) + SLA cascade warnings. |
| `/api/v1/lineage/diff` | `GET` / `POST` | Zero-token bi-temporal statutory diff across `AMENDED_BY` and `REPEALED_BY` chains. |
| `/api/v1/lineage/delta-audit` | `POST` | Zero-token Contract Delta-Audit detecting newly commenced statutory/gazette regressions. |
| `/api/v1/crosswalk/{node_id}/divergence` | `GET` / `POST` | Act 388 s. 63 Bilingual Divergence Critic across BM/EN `SourceSpan` nodes. |
| `/api/v1/compliance/scan` | `POST` | Deterministic pre-flight PII-scrubbed Act 709 gap scanner with Act 388 warnings. |
| `/api/v1/research/point-in-time` | `POST` | 4-stage bilingual point-in-time research with 7-tier court/statute breakdown. |
| `/api/v1/portfolio/blast-radius` | `POST` | Zero-token synchronous Gazette Blast-Radius Scanner (`<= 50` contracts). |
| `/api/v1/portfolio/jobs` | `POST` | Submits async portfolio job (`202` new / `200` `Idempotency-Key` replay / `409` conflict) with durable leases, checkpoints, & webhooks. |
| `/api/v1/portfolio/jobs/{job_id}` | `GET` | Polls tenant-scoped async portfolio job progress, lease metadata, `cache_hits`/`cache_misses`, and webhook telemetry. |
| `/api/v1/portfolio/dlq` | `GET` | Lists tenant-scoped `DEAD_LETTER` portfolio jobs (`admin` role only). |
| `/api/v1/portfolio/jobs/{job_id}/requeue` | `POST` | Requeues a `DEAD_LETTER` or `FAILED` portfolio job (`admin`/`auditor`). |
| `/api/v1/retrieval/search` | `GET` | Bilingual statutory span search with 5-tier authority reranking, territorial scope filter, and `0.78` abstention gate. |
| `/api/v1/retrieval/explain` | `POST` | Bilingual hybrid `BM25F + Subword/Dense + RRF (k=60)` retrieval explainability (`viewer`/`auditor`/`admin`). |
| `/api/v1/hitl/reviews` | `POST` | Records PII-scrubbed counsel HITL adjudication (`ACCEPT_REDLINE`, `MODIFY_REDLINE`, `REJECT_FALSE_POSITIVE`, `ESCALATE_TO_COUNSEL`) signed in Ed25519 ledger (`auditor`/`admin`). |
| `/api/v1/hitl/export-jsonl` | `GET` | Exports tenant-scoped PII-free counsel adjudications as deterministic JSONL golden regression cases (`admin`). |
| `/api/v1/attestation/public-key` | `GET` | Returns Ed25519 PEM/raw public key and SHA-256 fingerprint for offline attestation verification. |
| `/api/v1/attestation/{manifest_id}` | `GET` | Retrieves an immutable hash-chained & Ed25519-signed `AttestationLedgerRecord`. |
| `/api/v1/attestation/{manifest_id}/bundle` | `GET` | Streams a deterministic air-gapped `.lexpack.zip` evidence bundle (`include_docx=true` supports tenant-isolated DOCX attachment). |
| `/api/v1/attestation/verify` | `POST` | Cryptographically verifies digest, `as_of_date`, citations, SHA-256 chain, and Ed25519 signature. |
| `/api/v1/finops/tenant-usage` | `GET` | Returns tenant-scoped cumulative USD/MYR FinOps telemetry, cache hits, fallback runs, and budget guardrail status. |
| `/api/v1/security/scan` | `POST` | Zero-token OOXML `.docx` / `.pdf` / raw-text IPI, Unicode bidi/zero-width/homoglyph, `comments.xml`/`footnotes.xml`, and zip-bomb firewall scanner. |
| `/mcp` | `POST` | Streamable HTTP JSON-RPC 2.0 MCP server (`14` tools including `record_hitl_review`; stdio via `python -m lexgraph_lah.mcp.jsonrpc --stdio`). |

---

## Testing, Evaluation & Determinism Benchmark

### 1. Run Quality Gates

```bash
uv run ruff check src tests evals
uv run ruff format --check src tests evals
uv run mypy src tests evals
uv run pytest -q
```

### 2. Run the 36-Scenario Determinism, Oblique Stress & Calibration Benchmarks

```bash
uv run python -m evals.run_benchmark --mode mock --trials 3
# Oblique Stress + Calibration (ECE, Brier, Recall@K, MRR, 0.50..0.95 Sweep):
uv run python -m evals.run_benchmark --suite all --mode mock --trials 3 --calibration-report
# Include HITL-exported golden JSONL regression cases:
uv run python -m evals.run_benchmark --suite all --mode mock --trials 3 --extra-jsonl hitl_golden.jsonl
# Live Gemini evaluation (writes JSON & Markdown artifacts to evals/results/):
uv run python -m evals.run_benchmark --mode live --trials 3
```

| Metric | Observed (`--mode mock --trials 3`) | SLA Target | Status |
| :--- | :--- | :--- | :--- |
| **Scenarios x Trials** | `36 scenarios x 3 trials (108 runs)` | `>= 18 scenarios` | PASS |
| **Determinism Consistency (%)** | `100.00%` | `100.00%` | PASS |
| **Cross-Trial Verdict Stability (%)** | `100.00%` | `100.00%` | PASS |
| **Verdict Accuracy (%)** | `100.00%` | `>= 95.00%` | PASS |
| **Verbatim Citation Grounding (%)** | `100.00%` | `100.00%` | PASS |
| **Counterfactual Retry Recovery Rate (%)** | `100.00%` | `>= 95.00%` | PASS |
| **Citation Hallucinations Rejected** | `3` | `Audited` | PASS |
| **Abstention Precision (%)** | `100.00%` | `100.00%` | PASS |
| **Temporal Context Recall (%)** | `100.00%` | `100.00%` | PASS |
| **Temporal Contamination Rate (%)** | `0.00%` | `0.00%` | PASS |
| **Latency p50 / p95 (ms)** | `32.44 ms / 194.69 ms` | `< 5000.00 ms` | PASS |
| **Mean Tokens per Audit** | `477.4 tokens` | `< 15000 tokens` | PASS |
| **Mean Cost per Audit (USD & MYR)** | `$0.000120 USD / RM 0.000528 MYR` | `< $0.005000 USD` | PASS |

---

## Governance & License

- See [SECURITY.md](./SECURITY.md) for threat boundaries, PII handling, Ed25519 verification, and vulnerability disclosure.
- See [CONTRIBUTING.md](./CONTRIBUTING.md) for adding Malaysian statutes/`P.U.` gazettes and bilingual Act 388 test cases.
- See [CHANGELOG.md](./CHANGELOG.md) for release history.
- Released under the [MIT License](./LICENSE). Copyright (c) 2026 Kearney Leith Julius.
