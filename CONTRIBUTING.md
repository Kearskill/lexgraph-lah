# Contributing to `lexgraph-lah`

Thank you for helping strengthen deterministic Malaysian legal compliance tooling!

## Development Setup

```bash
cp .env.example .env
uv sync --all-extras --dev --frozen
```

---

## Adding Malaysian Statutes & Federal Gazette (`P.U. (A)` / `P.U. (B)`) Instruments

All statutory provisions must remain **strictly factual** and anchored to official Malaysian Acts or Federal Gazette publications (`lom.agc.gov.my` / `federalgazette.agc.gov.my`).

### Option 1: Seeding Built-In Statutory Corpus (`src/lexgraph_lah/graph/temporal_store.py`)
1. Construct a `StatutoryNode` with accurate bi-temporal fields:
   - `valid_from` / `valid_to` (matching statutory commencement / `P.U. (B)` appointment dates) and `gazette_date`.
   - `authority_tier` (`FEDERAL_STATUTE`, `SUBSIDIARY_LEGISLATION`, `REGULATORY_GUIDELINE`, etc.) and `territorial_scope` (`ALL_MALAYSIA`, `PENINSULAR_MALAYSIA`, `SABAH`, `SARAWAK`, `LABUAN`, `FEDERAL_TERRITORIES`).
   - Exact `source_spans` (`SourceSpan` with `span_id`, `citation`, `char_offset_start`, `char_offset_end`).
   - Structured `DeonticConstraint` items specifying `recipient` and `notice_stage` cleanly when distinct recipients apply (e.g., PDPA Commissioner `72h` vs. Affected Data Subject `7d` vs. NACSA `6h`/`14d`).
2. Add temporal edges (`AMENDED_BY`, `SUPERSEDED_BY`, `REPEALED_BY`, `CITES`) so `diff_statute_lineage` and `DeonticEnvelopeResolver` traverse amendments deterministically.

### Option 2: Idempotent Gazette Ingestion CLI (`src/lexgraph_lah/ingestion/gazette_ingestor.py`)
Validate and ingest new `P.U. (A)` or `P.U. (B)` JSON/XML instruments without touching core code:

```bash
uv run python -m lexgraph_lah.ingestion.gazette_ingestor \
  --input path/to/pua_instrument.json \
  --backend memory
```

Set `--backend neo4j` (with `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` configured) to synchronize into Neo4j 5.

---

## Authoring Act 388 s. 63 Bilingual EN/BM Test Cases

Under Malaysia's **Interpretation Acts 1948 and 1967 [Act 388], s. 63**, pair Bahasa Melayu (`normalized_language="bm"`) and English (`normalized_language="en"`) `StatutoryNode` provisions via `BILINGUAL_EQUIVALENT_OF` edges in `temporal_store.py` or test `audit_bilingual_divergence` directly:
- Keep authoritative Bahasa Melayu (`Seksyen`, `hendaklah`/`wajib`, `RM` ceilings, statutory durations) and English (`Section`, `shall`/`may`, numeric deadlines) faithful to authentic gazette wording.
- Add assertions checking both modality mismatches (`hendaklah` vs. `may`) and deadline / penalty ceiling parity in `tests/`.

---

## Quality Gates & Verification Checklist

Every pull request must keep existing public REST routes (`src/lexgraph_lah/api/routes.py`), 11 MCP tool schemas (`src/lexgraph_lah/mcp/tools.py`), and `--mode mock` benchmarks backward-compatible and pass:

```bash
uv run ruff check src tests evals
uv run mypy src
uv run pytest -q
uv run python -m evals.run_benchmark --mode mock --trials 3
```
