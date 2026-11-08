from datetime import date

from pydantic import BaseModel, Field

from lexgraph_lah.schemas.domain import ClauseAudit, RiskSeverity, StatutoryNode


class GoldenLegalScenario(BaseModel):
    """Synthetic golden benchmark case for deterministic Graph-RAG and compliance evaluation."""

    scenario_id: str
    description: str
    reference_date: date
    act_filter: str | None = None
    contract_text: str
    expected_active_statute_ids: set[str]
    forbidden_statute_ids: set[str] = Field(
        default_factory=set,
        description="Superseded, repealed, or post-dated statutes that MUST NOT leak into context.",
    )
    expected_clause_ids: set[str]
    simulated_llm_extractions: list[ClauseAudit]
    max_budget_usd: float = 0.005


class EvalMetrics(BaseModel):
    """Deterministic RAGAS/DeepEval-aligned legal evaluation metrics."""

    temporal_context_recall: float = Field(..., ge=0.0, le=1.0)
    temporal_contamination_rate: float = Field(..., ge=0.0, le=1.0)
    entity_clause_recall: float = Field(..., ge=0.0, le=1.0)
    verbatim_grounding_precision: float = Field(..., ge=0.0, le=1.0)


def evaluate_temporal_context(
    retrieved_statutes: list[StatutoryNode],
    expected_ids: set[str],
    forbidden_ids: set[str],
) -> tuple[float, float]:
    """
    Computes:
    1. Temporal Context Recall: fraction of `expected_ids` present in `retrieved_statutes`.
    2. Temporal Contamination Rate: fraction of `forbidden_ids` (post-dated amendments or
       repealed statutes) that leaked into `retrieved_statutes`.
    """
    retrieved_set = {s.node_id for s in retrieved_statutes}
    if not expected_ids:
        recall = 1.0
    else:
        recall = len(retrieved_set & expected_ids) / len(expected_ids)

    if not forbidden_ids:
        contamination = 0.0
    else:
        contamination = len(retrieved_set & forbidden_ids) / len(forbidden_ids)

    return round(recall, 4), round(contamination, 4)


def evaluate_entity_and_citation_grounding(
    extracted_clauses: list[ClauseAudit],
    raw_contract_text: str,
    expected_clause_ids: set[str],
) -> tuple[float, float]:
    """
    Computes:
    1. Entity/Clause Recall: fraction of `expected_clause_ids` identified in `extracted_clauses`.
    2. Verbatim Grounding Precision: fraction of extracted clauses whose `exact_quote` is a
       strict character-for-character substring of `raw_contract_text`.
    """
    extracted_ids = {c.clause_id for c in extracted_clauses}
    if not expected_clause_ids:
        clause_recall = 1.0
    else:
        clause_recall = len(extracted_ids & expected_clause_ids) / len(
            expected_clause_ids
        )

    if not extracted_clauses:
        grounding_precision = 1.0
    else:
        grounded_count = sum(
            1 for c in extracted_clauses if c.exact_quote in raw_contract_text
        )
        grounding_precision = grounded_count / len(extracted_clauses)

    return round(clause_recall, 4), round(grounding_precision, 4)


def get_golden_legal_scenarios() -> list[GoldenLegalScenario]:
    """
    Returns golden legal evaluation scenarios spanning pre-amendment (2024) and
    post-amendment (2026) statutory regimes.
    """
    return [
        GoldenLegalScenario(
            scenario_id="EVAL-2024-PDPA-BASELINE",
            description=(
                "2024 Master Data Processing Agreement evaluated under the 2010 PDPA baseline "
                "(prior to the 2025-01-01 mandatory 72-hour breach notification amendment)."
            ),
            reference_date=date(2024, 6, 15),
            act_filter="Personal Data Protection Act 2010",
            contract_text=(
                "SEC-4.1 Data Security: The Data Processor shall implement reasonable technical "
                "safeguards. SEC-4.2 Incident Reporting: The Data Processor may report security "
                "incidents within 14 business days at its sole discretion."
            ),
            expected_active_statute_ids={"PDPA-2010-SEC-9-V1", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V2"},
            expected_clause_ids={"SEC-4.2"},
            simulated_llm_extractions=[
                ClauseAudit(
                    clause_id="SEC-4.2",
                    category="Data Breach Notification",
                    exact_quote=(
                        "SEC-4.2 Incident Reporting: The Data Processor may report security "
                        "incidents within 14 business days at its sole discretion."
                    ),
                    severity=RiskSeverity.MEDIUM,
                    rationale=(
                        "Under PDPA 2010 Section 9 (V1), practical security steps are required "
                        "though the 72-hour statutory mandate was not yet in force on 2024-06-15."
                    ),
                    recommended_redline=(
                        "The Data Processor shall notify the Data User within 48 hours of any "
                        "suspected personal data breach."
                    ),
                    violated_statute_ids=["PDPA-2010-SEC-9-V1"],
                )
            ],
        ),
        GoldenLegalScenario(
            scenario_id="EVAL-2026-PDPA-AMENDMENT",
            description=(
                "2026 Cloud Services Agreement evaluated under the PDPA (Amendment) Act 2024 "
                "(effective 2025-01-01) where 72-hour breach notification and direct processor "
                "liability are mandatory."
            ),
            reference_date=date(2026, 2, 1),
            act_filter="Personal Data Protection Act 2010",
            contract_text=(
                "SEC-8.1 Processor Liability Exclusion: The Data Processor shall bear zero "
                "statutory liability for unauthorized data disclosure. SEC-8.2 Breach Notice: "
                "Notification of a personal data breach shall be provided within 10 days."
            ),
            expected_active_statute_ids={"PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V1"},
            expected_clause_ids={"SEC-8.1", "SEC-8.2"},
            simulated_llm_extractions=[
                ClauseAudit(
                    clause_id="SEC-8.1",
                    category="Statutory Liability",
                    exact_quote=(
                        "SEC-8.1 Processor Liability Exclusion: The Data Processor shall bear zero "
                        "statutory liability for unauthorized data disclosure."
                    ),
                    severity=RiskSeverity.CRITICAL,
                    rationale=(
                        "Directly contravenes PDPA 2024 Amendment (PDPA-2010-SEC-9-V2), which "
                        "imposes direct statutory Security Principle obligations on data processors."
                    ),
                    recommended_redline=(
                        "The Data Processor shall comply with all statutory obligations under "
                        "Section 9 of the Personal Data Protection Act 2010 (as amended)."
                    ),
                    violated_statute_ids=["PDPA-2010-SEC-9-V2"],
                ),
                ClauseAudit(
                    clause_id="SEC-8.2",
                    category="Data Breach Notification",
                    exact_quote=(
                        "SEC-8.2 Breach Notice: Notification of a personal data breach shall be "
                        "provided within 10 days."
                    ),
                    severity=RiskSeverity.HIGH,
                    rationale=(
                        "Violates the mandatory 72-hour Commissioner notification window under "
                        "Section 12B (PDPA-2010-SEC-9-V2)."
                    ),
                    recommended_redline=(
                        "Notification of a personal data breach shall be provided within 24 hours "
                        "to enable the Data User to meet the 72-hour statutory deadline."
                    ),
                    violated_statute_ids=["PDPA-2010-SEC-9-V2"],
                ),
            ],
        ),
    ]
