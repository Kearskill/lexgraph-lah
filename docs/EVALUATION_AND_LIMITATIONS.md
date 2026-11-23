# Evaluation Methodology, Statistical Calibration & Known Limitations

`lexgraph-lah` intentionally separates **deterministic regression verification** from **statistical retrieval & calibration stress testing** so stakeholders can inspect both system invariants and realistic failure boundaries.

---

## 1. Suite Taxonomy (`--suite` & `--mode`)

| Command | Suite / Mode | Purpose | What It Tests |
| :--- | :--- | :--- | :--- |
| `uv run python -m evals.run_benchmark --mode mock --trials 3` | `--suite canonical` (`36` scenarios x `3` trials = `108` runs) | **Deterministic State-Machine & Statutory Regression Harness** | Verifies LangGraph routing, `DeonticEnvelopeResolver`, `ContractASTGraph` traps, counterfactual self-correction retries (rejecting injected hallucinated citations), `0.78` abstention, pre-flight PII scrubbing, Act 388 bilingual divergence, OOXML/PDF firewall, track-changes critic, SLA cascades, `.lexpack.zip` attestation, and FinOps guardrails. |
| `uv run python -m evals.run_benchmark --suite oblique_stress --calibration-report` | `--suite oblique_stress` (`18` scenarios) | **Adversarial Oblique, OCR & Calibration Stress Suite** | Evaluates `HybridStatutoryRetriever` (`BM25F + Subword/Vector + RRF k=60`) on euphemistic EN/BM/Manglish clauses with zero explicit statutory keywords, simulated OCR noise (`0`/`O`, `1`/`l`, spaced letters), hidden Malaysian nexus, and near-threshold foreign governing law (`Delaware`, `UK GDPR`, `Singapore Employment Act`, `EU AI Act`). |
| `uv run python -m evals.run_benchmark --suite all --mode mock --trials 3 --calibration-report` | `--suite all` | **Combined CI + Calibration Gate** | Runs all `36` canonical scenarios plus the `18`-scenario calibration report in one command. |
| `uv run python -m evals.run_benchmark --mode live --trials 3` | `--mode live` | **Live Stochastic Gemini + Live BNM FX Check** | Replaces mock LLM responses with real `GEMINI_API_KEY` calls (`LEXGRAPH_MODEL_FAST` / `LEXGRAPH_MODEL_REASONING`) and live Bank Negara Malaysia USD/MYR FX lookup, writing timestamped JSON/Markdown artifacts to `evals/results/`. |
| `uv run python -m evals.run_benchmark --extra-jsonl hitl.jsonl` | `--suite canonical` + HITL export | **Counsel Flywheel Regression Loop** | Appends PII-scrubbed golden cases exported from `GET /api/v1/hitl/export-jsonl` as live regression checks. |

> **Why `canonical` scores 100% in `--mode mock`:** `--mode mock` stubs the stochastic LLM node with fixed responses (including deliberate invalid citations on `BENCH-09` and `BENCH-11` to force counterfactual retry recovery) in order to verify that all *deterministic* symbolic layers—temporal gating, territorial isolation, deontic bounds, AST trap detection, PII redaction, and Ed25519 attestation—exhibit zero drift across trials. It is **not** a claim that an unassisted LLM achieves 100% accuracy in the wild; `--suite oblique_stress` and `--mode live` exist precisely to measure retrieval, calibration, and stochastic variability.

---

## 2. Calibration Methodology (`evals/calibration.py`)

`evals/calibration.py` computes rigorous IR, classification, and calibration metrics over the `18`-scenario `oblique_stress` suite:

1. **Retrieval Ranking Metrics (`in_scope` scenarios):**
   - **Recall@1 / Recall@3 / Recall@5** (Hit-Rate@K): fraction of queries where at least one ground-truth `StatutoryNode` ID appears within the top `K` RRF-ranked candidates after strict pre-scoring bi-temporal (`as_of_date`) and territorial filtering.
   - **Mean Reciprocal Rank (`MRR`):** average of $1 / \text{rank}_i$ of the first relevant statutory node.
2. **Classification & Abstention Metrics (at operating threshold $\tau = 0.78$):**
   - **Macro / Micro Precision, Recall, F1** and **Accuracy** over `in_scope` vs `out_of_scope` decisions.
   - **Abstention Precision:** $\text{TN} / (\text{TN} + \text{FN})$ — proportion of abstained queries that truly lacked Malaysian statutory grounding.
   - **False-Confidence Rate (`FCR`):** $\text{FP} / (\text{FP} + \text{TN})$ — proportion of out-of-scope / foreign-law queries mistakenly accepted above $\tau$.
3. **Probabilistic Calibration:**
   - **Expected Calibration Error (`ECE`, 10-bin):** partitions `[0.0, 1.0]` into 10 equal-width bins and computes $\sum_{m=1}^{10} \frac{|B_m|}{N} |\text{acc}(B_m) - \text{conf}(B_m)|$.
   - **Brier Score:** $\frac{1}{N} \sum_{i=1}^N (p_i - y_i)^2$ measuring squared probability error of `max_score`.
4. **Threshold Operating Curve (`0.50` to `0.95`, step `0.05`):**
   - Lower thresholds (`0.50`–`0.70`) admit foreign-law near-misses (e.g., Singapore Employment Act or EU AI Act clauses sharing generic terms like *"employment"*, *"overtime"*, or *"data"*), driving `False-Confidence Rate` up to `0.20`–`0.40`.
   - Raising $\tau$ past `0.80` begins rejecting valid OCR-degraded or oblique Bahasa Melayu clauses (`In-Scope Recall` drops from `1.00` to `0.92` -> `0.69`).
   - Operating at **`0.78`** maximizes `Macro F1` while preserving **`0.00` False-Confidence Rate** and **`1.00` In-Scope Recall** on the oblique stress suite.

---

## 3. Known Failure Boundaries & Concrete Mitigations

| Failure Boundary | Root Cause | Current Mitigation | Production Evolution |
| :--- | :--- | :--- | :--- |
| **Novel Corporate Euphemisms Unseen in Lexicon** | Offline `DeterministicSubwordEmbedder` uses hashed character/word n-grams + curated bilingual concept clusters rather than pretrained neural weights. | Extend `_CONCEPT_CLUSTERS` in `hybrid_retriever.py` via HITL counsel adjudications (`/api/v1/hitl/export-jsonl`). | Enable `EMBEDDING_PROVIDER=http` (`LiveHTTPEmbeddingAdapter`) with dense bilingual embeddings (Gemini / multilingual-e5) while preserving RRF + `0.78` calibration. |
| **Image-Only Scanned PDFs** | Default `OCR_PROVIDER=none` only reads PDF text streams (`Tj`/`TJ`) and flags low-text pages. | `detect_low_text_pdf_pages()` alerts operators deterministically before silent false passes. | Configure `OCR_PROVIDER=tesseract` or `OCR_PROVIDER=gemini_vision` for scanned gazettes and wet-ink contracts. |
| **Implicit Foreign Nexus Without Explicit Location Markers** | Jurisdiction dampening checks foreign-law markers against Malaysian nexus indicators (`Malaysia`, `RM`, `LHDN`, `Sabah`, etc.). | Clauses mentioning *any* Malaysian statutory/currency/geographic anchor bypass dampening cleanly. | Add entity-resolution lookup against tenant SSM/corporate registry metadata in `ContractASTGraph`. |
| **SQLite Single-Writer Lock Under Multi-Replica Burst** | SQLite WAL serializes writes within one node/volume. | Embedded async jobs + `PortfolioWorker` checkpoints resume cleanly after restarts. | Switch `PORTFOLIO_JOB_STORE=postgres`, `ATTESTATION_BACKEND=postgres`, `GRAPH_BACKEND=neo4j`, and `CLAUSE_CACHE_BACKEND=redis`. |
| **Voluntary vs Mandatory Ambiguity in Custom User Prompts** | Users occasionally prompt about MOSTI AIGE expecting statutory breach severity. | `DeonticEnvelopeResolver` isolates `voluntary_advisories` cleanly from mandatory bounds (`Act 709`, `Act 854`, `BNM RMiT`). | Counsel adjudications via HITL (`MODIFY_REDLINE` / `ESCALATE_TO_COUNSEL`) capture tenant-specific policy strictness. |
