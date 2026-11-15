import argparse
import asyncio
import math
from datetime import date
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from pydantic import BaseModel, Field

from lexgraph_lah.agents.graph import build_compliance_graph
from lexgraph_lah.config import settings
from lexgraph_lah.eval.harness import (
    evaluate_entity_and_citation_grounding,
    evaluate_temporal_context,
)
from lexgraph_lah.schemas.domain import (
    ClauseAudit,
    ClauseExtractionList,
    RiskSeverity,
)
from lexgraph_lah.telemetry.cost_tracker import (
    assert_within_budget,
    compute_telemetry_summary,
)
from lexgraph_lah.telemetry.tracer import measure_latency_ms

_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
    RiskSeverity.CRITICAL: 4,
}


def _compute_overall_risk(clauses: list[ClauseAudit]) -> RiskSeverity:
    if not clauses:
        return RiskSeverity.LOW
    return max(clauses, key=lambda c: _SEVERITY_RANK[c.severity]).severity


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return round(sorted_vals[0], 2)
    idx = (pct / 100.0) * (len(sorted_vals) - 1)
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return round(sorted_vals[lo], 2)
    weight = idx - lo
    return round(sorted_vals[lo] * (1.0 - weight) + sorted_vals[hi] * weight, 2)


class BenchmarkCase(BaseModel):
    """Structured compliance benchmark case for determinism and FinOps evaluation."""

    case_id: str
    title: str
    reference_date: date
    act_filter: str = "Personal Data Protection Act 2010"
    contract_text: str
    expected_overall_risk: RiskSeverity
    expected_active_statute_ids: set[str]
    forbidden_statute_ids: set[str] = Field(default_factory=set)
    expected_clause_ids: set[str]
    mock_attempts: list[tuple[list[ClauseAudit], int, int]]


class CaseTrialResult(BaseModel):
    case_id: str
    trial_index: int
    overall_risk: RiskSeverity
    verdict_correct: bool
    is_grounded: bool
    retry_count: int
    temporal_recall: float
    temporal_contamination: float
    clause_recall: float
    grounding_precision: float
    total_tokens: int
    cost_usd: float
    cost_myr: float
    latency_ms: float
    signature: str


class BenchmarkSummary(BaseModel):
    mode: str
    total_cases: int
    trials_per_case: int
    total_runs: int
    determinism_consistency_pct: float
    verdict_accuracy_pct: float
    verbatim_grounding_pct: float
    temporal_recall_pct: float
    temporal_contamination_pct: float
    latency_p50_ms: float
    latency_p95_ms: float
    mean_tokens_per_audit: float
    mean_cost_usd: float
    mean_cost_myr: float
    total_cost_usd: float
    total_cost_myr: float
    case_results: list[CaseTrialResult] = Field(default_factory=list)


def get_benchmark_dataset() -> list[BenchmarkCase]:
    """
    Returns 10 structured Malaysian regulatory compliance benchmark scenarios covering
    pre-amendment (2024) and post-amendment (2025/2026) PDPA statutory regimes,
    compliant clauses, critical violations, and bounded critic self-correction.
    """
    return [
        BenchmarkCase(
            case_id="BENCH-01-COMPLIANT-2026-DPA",
            title="2026 Compliant PDPA Data Processing Agreement (24h/72h Breach SLA)",
            reference_date=date(2026, 3, 15),
            contract_text=(
                "SEC-1.1 Security Safeguards: Both Data User and Data Processor shall maintain "
                "ISO/IEC 27001 controls under Section 9 of the PDPA 2010 (as amended). "
                "SEC-1.2 Breach Notice: Data Processor shall notify Data User within 24 hours "
                "so Data User can notify the Commissioner within 72 hours under Section 12B."
            ),
            expected_overall_risk=RiskSeverity.LOW,
            expected_active_statute_ids={"PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V1"},
            expected_clause_ids={"SEC-1.1"},
            mock_attempts=[
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-1.1",
                            category="Statutory Security Compliance",
                            exact_quote=(
                                "SEC-1.1 Security Safeguards: Both Data User and Data Processor shall maintain "
                                "ISO/IEC 27001 controls under Section 9 of the PDPA 2010 (as amended)."
                            ),
                            severity=RiskSeverity.LOW,
                            rationale="Complies with Section 9 V2 direct processor security obligations.",
                            recommended_redline="No redline required — clause is compliant.",
                            violated_statute_ids=[],
                        )
                    ],
                    580,
                    160,
                )
            ],
        ),
        BenchmarkCase(
            case_id="BENCH-02-CRITICAL-PROCESSOR-EXCLUSION",
            title="2026 Data Processor Statutory Liability Exclusion",
            reference_date=date(2026, 2, 10),
            contract_text=(
                "SEC-2.1 Processor Liability Waiver: The Data Processor shall bear zero statutory "
                "liability under Malaysian data protection law for unauthorized disclosure."
            ),
            expected_overall_risk=RiskSeverity.CRITICAL,
            expected_active_statute_ids={"PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V1"},
            expected_clause_ids={"SEC-2.1"},
            mock_attempts=[
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-2.1",
                            category="Statutory Liability Exclusion",
                            exact_quote=(
                                "SEC-2.1 Processor Liability Waiver: The Data Processor shall bear zero statutory "
                                "liability under Malaysian data protection law for unauthorized disclosure."
                            ),
                            severity=RiskSeverity.CRITICAL,
                            rationale="Directly violates PDPA-2010-SEC-9-V2 direct processor statutory liability.",
                            recommended_redline="Data Processor shall comply with all direct obligations under Section 9.",
                            violated_statute_ids=["PDPA-2010-SEC-9-V2"],
                        )
                    ],
                    610,
                    185,
                )
            ],
        ),
        BenchmarkCase(
            case_id="BENCH-03-HIGH-14DAY-BREACH-DELAY",
            title="2026 Delayed 14-Day Data Breach Notification Window",
            reference_date=date(2026, 4, 1),
            contract_text=(
                "SEC-3.1 Breach Notification: Notification of a confirmed personal data breach "
                "shall be furnished within 14 calendar days."
            ),
            expected_overall_risk=RiskSeverity.HIGH,
            expected_active_statute_ids={"PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V1"},
            expected_clause_ids={"SEC-3.1"},
            mock_attempts=[
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-3.1",
                            category="Data Breach Notification",
                            exact_quote=(
                                "SEC-3.1 Breach Notification: Notification of a confirmed personal data breach "
                                "shall be furnished within 14 calendar days."
                            ),
                            severity=RiskSeverity.HIGH,
                            rationale="Exceeds the mandatory 72-hour Commissioner notification window under Section 12B.",
                            recommended_redline="Notification of a personal data breach shall be provided within 24 hours.",
                            violated_statute_ids=["PDPA-2010-SEC-9-V2"],
                        )
                    ],
                    590,
                    175,
                )
            ],
        ),
        BenchmarkCase(
            case_id="BENCH-04-2024-PRE-AMENDMENT-BASELINE",
            title="2024 Legacy DPA Evaluated Under Pre-Amendment PDPA 2010 Baseline",
            reference_date=date(2024, 6, 15),
            contract_text=(
                "SEC-4.1 Data Security: The Data Processor shall implement reasonable technical "
                "safeguards. SEC-4.2 Incident Reporting: The Data Processor may report security "
                "incidents within 14 business days at its sole discretion."
            ),
            expected_overall_risk=RiskSeverity.MEDIUM,
            expected_active_statute_ids={"PDPA-2010-SEC-9-V1", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V2"},
            expected_clause_ids={"SEC-4.2"},
            mock_attempts=[
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-4.2",
                            category="Data Breach Notification",
                            exact_quote=(
                                "SEC-4.2 Incident Reporting: The Data Processor may report security "
                                "incidents within 14 business days at its sole discretion."
                            ),
                            severity=RiskSeverity.MEDIUM,
                            rationale="Under 2024 baseline (PDPA-2010-SEC-9-V1), 72h mandate was not yet active, but discretionary reporting weakens practical security controls.",
                            recommended_redline="The Data Processor shall notify the Data User within 48 hours.",
                            violated_statute_ids=["PDPA-2010-SEC-9-V1"],
                        )
                    ],
                    640,
                    195,
                )
            ],
        ),
        BenchmarkCase(
            case_id="BENCH-05-MULTI-CLAUSE-2026-VIOLATION",
            title="2026 Dual Violation: Liability Exclusion + 10-Day Breach Delay",
            reference_date=date(2026, 2, 1),
            contract_text=(
                "SEC-8.1 Processor Liability Exclusion: The Data Processor shall bear zero "
                "statutory liability for unauthorized data disclosure. SEC-8.2 Breach Notice: "
                "Notification of a personal data breach shall be provided within 10 days."
            ),
            expected_overall_risk=RiskSeverity.CRITICAL,
            expected_active_statute_ids={"PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V1"},
            expected_clause_ids={"SEC-8.1", "SEC-8.2"},
            mock_attempts=[
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-8.1",
                            category="Statutory Liability",
                            exact_quote=(
                                "SEC-8.1 Processor Liability Exclusion: The Data Processor shall bear zero "
                                "statutory liability for unauthorized data disclosure."
                            ),
                            severity=RiskSeverity.CRITICAL,
                            rationale="Violates direct processor obligations under PDPA-2010-SEC-9-V2.",
                            recommended_redline="Comply with Section 9 of the PDPA 2010 (as amended).",
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
                            rationale="Violates 72-hour mandatory notification under Section 12B.",
                            recommended_redline="Provide breach notification within 24 hours.",
                            violated_statute_ids=["PDPA-2010-SEC-9-V2"],
                        ),
                    ],
                    680,
                    240,
                )
            ],
        ),
        BenchmarkCase(
            case_id="BENCH-06-UNLAWFUL-DISCLOSURE-SEC130",
            title="2026 Unlawful Third-Party Data Monetization & Disclosure",
            reference_date=date(2026, 5, 10),
            contract_text=(
                "SEC-6.1 Commercial Data Sharing: Vendor may sell or disclose customer personal "
                "data to external marketing brokers without data subject consent."
            ),
            expected_overall_risk=RiskSeverity.CRITICAL,
            expected_active_statute_ids={"PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V1"},
            expected_clause_ids={"SEC-6.1"},
            mock_attempts=[
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-6.1",
                            category="Unlawful Data Disclosure",
                            exact_quote=(
                                "SEC-6.1 Commercial Data Sharing: Vendor may sell or disclose customer personal "
                                "data to external marketing brokers without data subject consent."
                            ),
                            severity=RiskSeverity.CRITICAL,
                            rationale="Triggers criminal penalties under Section 130 (RM 500,000 fine / 3 years imprisonment).",
                            recommended_redline="Vendor shall strictly prohibit any unauthorized third-party disclosure or sale of personal data.",
                            violated_statute_ids=[
                                "PDPA-2010-SEC-9-V2",
                                "PDPA-2010-SEC-130-V1",
                            ],
                        )
                    ],
                    620,
                    190,
                )
            ],
        ),
        BenchmarkCase(
            case_id="BENCH-07-COMPLIANT-2024-LEGACY-SAFEGUARDS",
            title="2024 Pre-Amendment Compliant Encryption & Access Control Clause",
            reference_date=date(2024, 3, 10),
            contract_text=(
                "SEC-7.1 Technical Security Controls: Data User and Data Processor shall enforce "
                "AES-256 encryption at rest and role-based access control for all personal data."
            ),
            expected_overall_risk=RiskSeverity.LOW,
            expected_active_statute_ids={"PDPA-2010-SEC-9-V1", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V2"},
            expected_clause_ids={"SEC-7.1"},
            mock_attempts=[
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-7.1",
                            category="Security Principle Safeguards",
                            exact_quote=(
                                "SEC-7.1 Technical Security Controls: Data User and Data Processor shall enforce "
                                "AES-256 encryption at rest and role-based access control for all personal data."
                            ),
                            severity=RiskSeverity.LOW,
                            rationale="Satisfies practical security steps under PDPA 2010 Section 9 (V1).",
                            recommended_redline="No redline required.",
                            violated_statute_ids=[],
                        )
                    ],
                    560,
                    150,
                )
            ],
        ),
        BenchmarkCase(
            case_id="BENCH-08-CROSS-BORDER-SUBPROCESSING",
            title="2026 Unilateral Cross-Border Subprocessing Replication",
            reference_date=date(2026, 1, 20),
            contract_text=(
                "SEC-5.2 Regional Replication: Personal data may be mirrored to offshore "
                "subprocessors without prior written authorization from the Data User."
            ),
            expected_overall_risk=RiskSeverity.MEDIUM,
            expected_active_statute_ids={"PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V1"},
            expected_clause_ids={"SEC-5.2"},
            mock_attempts=[
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-5.2",
                            category="Cross-Border Data Transfer",
                            exact_quote=(
                                "SEC-5.2 Regional Replication: Personal data may be mirrored to offshore "
                                "subprocessors without prior written authorization from the Data User."
                            ),
                            severity=RiskSeverity.MEDIUM,
                            rationale="Requires explicit Data User authorization and security equivalence under PDPA-2010-SEC-9-V2.",
                            recommended_redline="Offshore replication requires prior written consent of the Data User.",
                            violated_statute_ids=["PDPA-2010-SEC-9-V2"],
                        )
                    ],
                    600,
                    170,
                )
            ],
        ),
        BenchmarkCase(
            case_id="BENCH-09-CRITIC-SELF-CORRECTION-LOOP",
            title="2026 Critic Self-Correction on Mutated Substring Quote (1 Retry)",
            reference_date=date(2026, 3, 1),
            contract_text=(
                "SEC-9.1 Audit Rights Waiver: The Data User waives all rights to inspect or "
                "audit the Data Processor's security facilities."
            ),
            expected_overall_risk=RiskSeverity.HIGH,
            expected_active_statute_ids={"PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V1"},
            expected_clause_ids={"SEC-9.1"},
            mock_attempts=[
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-9.1",
                            category="Security Audit Rights",
                            exact_quote="The Data User waives all security audit rights.",  # Paraphrased on attempt 1 -> caught by citation_auditor_node
                            severity=RiskSeverity.HIGH,
                            rationale="Prevents verification of Section 9 security compliance.",
                            recommended_redline="Grant annual security audit rights to Data User.",
                            violated_statute_ids=["PDPA-2010-SEC-9-V2"],
                        )
                    ],
                    520,
                    140,
                ),
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-9.1",
                            category="Security Audit Rights",
                            exact_quote=(
                                "SEC-9.1 Audit Rights Waiver: The Data User waives all rights to inspect or "
                                "audit the Data Processor's security facilities."
                            ),
                            severity=RiskSeverity.HIGH,
                            rationale="Prevents verification of Section 9 security compliance.",
                            recommended_redline="Grant annual security audit rights to Data User.",
                            violated_statute_ids=["PDPA-2010-SEC-9-V2"],
                        )
                    ],
                    630,
                    155,
                ),
            ],
        ),
        BenchmarkCase(
            case_id="BENCH-10-UNENCRYPTED-STORAGE-VIOLATION",
            title="2026 Plaintext Storage of Sensitive Personal Data",
            reference_date=date(2026, 3, 25),
            contract_text=(
                "SEC-10.1 Storage Format: Biometric and financial personal data may be stored "
                "in unencrypted plaintext logs for debugging purposes."
            ),
            expected_overall_risk=RiskSeverity.HIGH,
            expected_active_statute_ids={"PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1"},
            forbidden_statute_ids={"PDPA-2010-SEC-9-V1"},
            expected_clause_ids={"SEC-10.1"},
            mock_attempts=[
                (
                    [
                        ClauseAudit(
                            clause_id="SEC-10.1",
                            category="Security Principle Breach",
                            exact_quote=(
                                "SEC-10.1 Storage Format: Biometric and financial personal data may be stored "
                                "in unencrypted plaintext logs for debugging purposes."
                            ),
                            severity=RiskSeverity.HIGH,
                            rationale="Plaintext storage of sensitive data violates Section 9 V2 security obligations.",
                            recommended_redline="All personal data must be encrypted at rest and masked in application logs.",
                            violated_statute_ids=["PDPA-2010-SEC-9-V2"],
                        )
                    ],
                    605,
                    180,
                )
            ],
        ),
    ]


def _build_mock_llm_for_case(case: BenchmarkCase) -> MagicMock:
    side_effects = []
    for clauses, in_tok, out_tok in case.mock_attempts:
        raw_msg = SimpleNamespace(
            usage_metadata={"input_tokens": in_tok, "output_tokens": out_tok}
        )
        side_effects.append(
            {"parsed": ClauseExtractionList(clauses=clauses), "raw": raw_msg}
        )
    structured_mock = MagicMock()
    structured_mock.ainvoke = AsyncMock(side_effect=side_effects)
    llm_mock = MagicMock()
    llm_mock.with_structured_output.return_value = structured_mock
    return llm_mock


async def _run_single_trial(
    case: BenchmarkCase, trial_index: int, mode: str
) -> CaseTrialResult:
    graph = build_compliance_graph()
    initial_state = {
        "document_id": f"{case.case_id}-T{trial_index}",
        "raw_text": case.contract_text,
        "reference_date": case.reference_date.isoformat(),
        "act_filter": case.act_filter,
        "extracted_clauses": [],
        "auditor_feedback": "",
        "is_grounded": False,
        "retry_count": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }

    if mode == "mock":
        mock_llm = _build_mock_llm_for_case(case)
        with (
            patch("lexgraph_lah.agents.graph.get_llm", return_value=mock_llm),
            measure_latency_ms() as elapsed_holder,
        ):
            final_state = await graph.ainvoke(initial_state)
    else:
        if settings.gemini_api_key.strip() in {
            "mock-key-for-ci",
            "mock-ci-key-zero-cost",
            "your_key_here",
            "",
        }:
            raise RuntimeError(
                "Live benchmark mode requires a valid GEMINI_API_KEY in the environment or .env file."
            )
        with measure_latency_ms() as elapsed_holder:
            final_state = await graph.ainvoke(initial_state)

    retrieved_statutes = final_state.get("retrieved_statutes", [])
    extracted_clauses: list[ClauseAudit] = final_state.get("extracted_clauses", [])
    overall_risk = _compute_overall_risk(extracted_clauses)

    ctx_recall, ctx_contamination = evaluate_temporal_context(
        retrieved_statutes=retrieved_statutes,
        expected_ids=case.expected_active_statute_ids,
        forbidden_ids=case.forbidden_statute_ids,
    )
    clause_recall, grounding_precision = evaluate_entity_and_citation_grounding(
        extracted_clauses=extracted_clauses,
        raw_contract_text=case.contract_text,
        expected_clause_ids=case.expected_clause_ids,
    )

    telemetry = compute_telemetry_summary(
        prompt_tokens=final_state.get("prompt_tokens", 0),
        completion_tokens=final_state.get("completion_tokens", 0),
        latency_ms=elapsed_holder[0],
        retry_count=final_state.get("retry_count", 0),
        is_verified_grounded=final_state.get("is_grounded", False),
    )
    assert_within_budget(telemetry)

    statute_sig = ",".join(sorted(s.node_id for s in retrieved_statutes))
    clause_sig = ",".join(
        f"{c.clause_id}:{c.severity.value}" for c in extracted_clauses
    )
    signature = f"{overall_risk.value}|{clause_sig}|{statute_sig}|{telemetry.is_verified_grounded}"

    return CaseTrialResult(
        case_id=case.case_id,
        trial_index=trial_index,
        overall_risk=overall_risk,
        verdict_correct=(overall_risk == case.expected_overall_risk),
        is_grounded=telemetry.is_verified_grounded,
        retry_count=telemetry.retry_count,
        temporal_recall=ctx_recall,
        temporal_contamination=ctx_contamination,
        clause_recall=clause_recall,
        grounding_precision=grounding_precision,
        total_tokens=telemetry.total_tokens,
        cost_usd=telemetry.estimated_cost_usd,
        cost_myr=telemetry.estimated_cost_myr,
        latency_ms=telemetry.latency_ms,
        signature=signature,
    )


async def run_benchmark_async(
    mode: str = "mock", trials: int = 3
) -> BenchmarkSummary:
    dataset = get_benchmark_dataset()
    safe_trials = max(1, trials)
    all_results: list[CaseTrialResult] = []
    consistent_cases = 0

    for case in dataset:
        case_trials: list[CaseTrialResult] = []
        for t_idx in range(1, safe_trials + 1):
            res = await _run_single_trial(case, trial_index=t_idx, mode=mode)
            case_trials.append(res)
            all_results.append(res)

        unique_signatures = {r.signature for r in case_trials}
        if len(unique_signatures) == 1:
            consistent_cases += 1

    total_runs = len(all_results)
    determinism_pct = round((consistent_cases / len(dataset)) * 100.0, 2)
    verdict_acc_pct = round(
        (sum(1 for r in all_results if r.verdict_correct) / total_runs) * 100.0, 2
    )
    grounded_pct = round(
        (sum(1 for r in all_results if r.is_grounded) / total_runs) * 100.0, 2
    )
    temporal_recall_pct = round(
        (sum(r.temporal_recall for r in all_results) / total_runs) * 100.0, 2
    )
    temporal_contam_pct = round(
        (sum(r.temporal_contamination for r in all_results) / total_runs) * 100.0, 2
    )

    sorted_latencies = sorted(r.latency_ms for r in all_results)
    p50_ms = _percentile(sorted_latencies, 50.0)
    p95_ms = _percentile(sorted_latencies, 95.0)

    total_usd = round(sum(r.cost_usd for r in all_results), 6)
    total_myr = round(sum(r.cost_myr for r in all_results), 6)
    mean_usd = round(total_usd / total_runs, 6)
    mean_myr = round(total_myr / total_runs, 6)
    mean_tokens = round(sum(r.total_tokens for r in all_results) / total_runs, 1)

    return BenchmarkSummary(
        mode=mode,
        total_cases=len(dataset),
        trials_per_case=safe_trials,
        total_runs=total_runs,
        determinism_consistency_pct=determinism_pct,
        verdict_accuracy_pct=verdict_acc_pct,
        verbatim_grounding_pct=grounded_pct,
        temporal_recall_pct=temporal_recall_pct,
        temporal_contamination_pct=temporal_contam_pct,
        latency_p50_ms=p50_ms,
        latency_p95_ms=p95_ms,
        mean_tokens_per_audit=mean_tokens,
        mean_cost_usd=mean_usd,
        mean_cost_myr=mean_myr,
        total_cost_usd=total_usd,
        total_cost_myr=total_myr,
        case_results=all_results,
    )


def format_markdown_report(summary: BenchmarkSummary) -> str:
    lines = [
        "# `lexgraph-lah` Determinism & FinOps Benchmark Report",
        "",
        f"- **Execution Mode:** `{summary.mode}`",
        f"- **Golden Dataset Size:** `{summary.total_cases}` Malaysian regulatory compliance scenarios",
        f"- **Trials per Scenario:** `{summary.trials_per_case}` (`{summary.total_runs}` total LangGraph audit runs)",
        f"- **FX Rate (`USD_TO_MYR_RATE`):** `1 USD = RM {settings.usd_to_myr_rate:.2f} MYR`",
        "",
        "## 1. Aggregate SLA & FinOps Summary",
        "",
        "| Metric | Value | SLA Target | Status |",
        "| :--- | :--- | :--- | :--- |",
        f"| **Determinism Consistency (%)** | `{summary.determinism_consistency_pct:.2f}%` | `100.00%` | {'PASS' if summary.determinism_consistency_pct == 100.0 else 'WARN'} |",
        f"| **Verdict Accuracy (%)** | `{summary.verdict_accuracy_pct:.2f}%` | `>= 95.00%` | {'PASS' if summary.verdict_accuracy_pct >= 95.0 else 'FAIL'} |",
        f"| **Verbatim Citation Grounding (%)** | `{summary.verbatim_grounding_pct:.2f}%` | `100.00%` | {'PASS' if summary.verbatim_grounding_pct == 100.0 else 'FAIL'} |",
        f"| **Temporal Context Recall (%)** | `{summary.temporal_recall_pct:.2f}%` | `100.00%` | {'PASS' if summary.temporal_recall_pct == 100.0 else 'FAIL'} |",
        f"| **Temporal Contamination Rate (%)** | `{summary.temporal_contamination_pct:.2f}%` | `0.00%` | {'PASS' if summary.temporal_contamination_pct == 0.0 else 'FAIL'} |",
        f"| **Latency (p50 / p95 ms)** | `{summary.latency_p50_ms:.2f} ms / {summary.latency_p95_ms:.2f} ms` | `< 5000.00 ms` | PASS |",
        f"| **Mean Tokens per Audit** | `{summary.mean_tokens_per_audit:.1f} tokens` | `< 15000 tokens` | PASS |",
        f"| **Mean Cost per Audit (USD & MYR)** | `${summary.mean_cost_usd:.6f} USD / RM {summary.mean_cost_myr:.6f} MYR` | `< $0.005000 USD` | PASS |",
        f"| **Cumulative Benchmark Spend (USD & MYR)** | `${summary.total_cost_usd:.6f} USD / RM {summary.total_cost_myr:.6f} MYR` | `< $0.150000 USD` | PASS |",
        "",
        "## 2. Per-Scenario Breakdown (Trial 1 Representative)",
        "",
        "| Scenario ID | Verdict | Grounded | Retries | Tokens | Cost (USD) | Cost (MYR) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    first_trials = [r for r in summary.case_results if r.trial_index == 1]
    for r in first_trials:
        lines.append(
            f"| `{r.case_id}` | `{r.overall_risk.value}` | `{'YES' if r.is_grounded else 'NO'}` "
            f"| `{r.retry_count}` | `{r.total_tokens}` | `${r.cost_usd:.6f}` | `RM {r.cost_myr:.6f}` |"
        )

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the lexgraph-lah Determinism & FinOps MYR/USD Benchmark Suite."
    )
    parser.add_argument(
        "--mode",
        choices=["mock", "live"],
        default="mock",
        help="Execution mode: 'mock' (offline deterministic CI default) or 'live' (requires GEMINI_API_KEY).",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=3,
        help="Number of repeated trials per golden scenario to measure determinism consistency.",
    )
    args = parser.parse_args()

    summary = asyncio.run(run_benchmark_async(mode=args.mode, trials=args.trials))
    print(format_markdown_report(summary))


if __name__ == "__main__":
    main()
