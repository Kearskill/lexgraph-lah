"""
Statistical Calibration & Adversarial Oblique Evaluation Harness (`evals/calibration.py`).

Complements the 36-scenario deterministic state-machine regression suite (`--suite canonical`)
with an adversarial `oblique_stress` suite covering euphemistic corporate clauses,
Manglish/BM code-switching, simulated OCR noise, and near-threshold foreign-law boundary
cases, computing Retrieval (`Recall@1/3/5`, `MRR`), Classification/Abstention (`Macro/Micro F1`,
`False-Confidence Rate`, `0.50..0.95` threshold sweep), and Probabilistic Calibration
(`10-bin ECE`, `Brier Score`).
"""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, Field

from lexgraph_lah.retrieval.hybrid_retriever import (
    HybridStatutoryRetriever,
    default_hybrid_retriever,
)


class CalibrationSample(BaseModel):
    sample_id: str
    category: Literal[
        "oblique_euphemism_en",
        "oblique_bm_manglish",
        "ocr_noise",
        "near_threshold_ambiguity",
    ]
    title: str
    query: str
    as_of_date: date
    territorial_scope: str | None = None
    expected_in_scope: bool
    expected_node_ids: set[str] = Field(default_factory=set)
    forbidden_node_ids: set[str] = Field(default_factory=set)


class CalibrationBin(BaseModel):
    bin_index: int
    lower: float
    upper: float
    count: int
    avg_confidence: float
    empirical_accuracy: float
    gap: float


class ThresholdSweepPoint(BaseModel):
    threshold: float
    accuracy: float
    in_scope_precision: float
    in_scope_recall: float
    macro_f1: float
    abstention_precision: float
    false_confidence_rate: float


class SampleCalibrationResult(BaseModel):
    sample_id: str
    category: str
    expected_in_scope: bool
    predicted_in_scope: bool
    max_score: float
    top_node_id: str | None = None
    top_k_node_ids: list[str] = Field(default_factory=list)
    reciprocal_rank: float = 0.0
    hit_at_1: bool = False
    hit_at_3: bool = False
    hit_at_5: bool = False
    temporal_contaminated: bool = False


class CalibrationReport(BaseModel):
    suite: str = "oblique_stress"
    operating_threshold: float = 0.78
    total_samples: int
    in_scope_samples: int
    out_of_scope_samples: int
    recall_at_1: float
    recall_at_3: float
    recall_at_5: float
    mrr: float
    accuracy: float
    micro_precision: float
    micro_recall: float
    micro_f1: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    abstention_precision: float
    false_confidence_rate: float
    ece_10_bin: float
    brier_score: float
    temporal_contamination_rate: float
    bins: list[CalibrationBin] = Field(default_factory=list)
    threshold_sweep: list[ThresholdSweepPoint] = Field(default_factory=list)
    sample_results: list[SampleCalibrationResult] = Field(default_factory=list)


def compute_recall_at_k(
    expected_sets: list[set[str]],
    ranked_lists: list[list[str]],
    k: int,
) -> float:
    """Computes Hit-Rate / Recall@K across queries with non-empty ground-truth node sets."""
    pairs = [
        (exp, ranked)
        for exp, ranked in zip(expected_sets, ranked_lists, strict=True)
        if exp
    ]
    if not pairs:
        return 0.0
    hits = sum(1 for exp, ranked in pairs if bool(exp & set(ranked[:k])))
    return round(hits / len(pairs), 4)


def compute_mrr(
    expected_sets: list[set[str]],
    ranked_lists: list[list[str]],
) -> float:
    """Computes Mean Reciprocal Rank (MRR) across queries with non-empty ground-truth sets."""
    pairs = [
        (exp, ranked)
        for exp, ranked in zip(expected_sets, ranked_lists, strict=True)
        if exp
    ]
    if not pairs:
        return 0.0
    rr_total = 0.0
    for exp, ranked in pairs:
        rr = 0.0
        for idx, nid in enumerate(ranked, start=1):
            if nid in exp:
                rr = 1.0 / float(idx)
                break
        rr_total += rr
    return round(rr_total / len(pairs), 4)


def compute_ece(
    confidences: list[float],
    outcomes: list[float],
    *,
    n_bins: int = 10,
) -> tuple[float, list[CalibrationBin]]:
    """
    Computes Expected Calibration Error (ECE) over `n_bins` equal-width bins in `[0.0, 1.0]`.
    """
    if len(confidences) != len(outcomes):
        raise ValueError("confidences and outcomes must have identical length.")
    total = len(confidences)
    if total == 0:
        return 0.0, []

    bins_out: list[CalibrationBin] = []
    ece = 0.0
    for b_idx in range(n_bins):
        lo = round(b_idx / n_bins, 4)
        hi = round((b_idx + 1) / n_bins, 4)
        indices = [
            i
            for i, c in enumerate(confidences)
            if (lo <= c < hi) or (b_idx == n_bins - 1 and c == 1.0)
        ]
        cnt = len(indices)
        if cnt == 0:
            bins_out.append(
                CalibrationBin(
                    bin_index=b_idx,
                    lower=lo,
                    upper=hi,
                    count=0,
                    avg_confidence=0.0,
                    empirical_accuracy=0.0,
                    gap=0.0,
                )
            )
            continue
        avg_conf = sum(confidences[i] for i in indices) / cnt
        emp_acc = sum(outcomes[i] for i in indices) / cnt
        gap = abs(emp_acc - avg_conf)
        ece += (cnt / total) * gap
        bins_out.append(
            CalibrationBin(
                bin_index=b_idx,
                lower=lo,
                upper=hi,
                count=cnt,
                avg_confidence=round(avg_conf, 4),
                empirical_accuracy=round(emp_acc, 4),
                gap=round(gap, 4),
            )
        )
    return round(ece, 4), bins_out


def compute_brier_score(confidences: list[float], outcomes: list[float]) -> float:
    """Computes Brier Score `mean((p_i - y_i)^2)` in `[0.0, 1.0]`."""
    if len(confidences) != len(outcomes):
        raise ValueError("confidences and outcomes must have identical length.")
    if not confidences:
        return 0.0
    total = sum(
        (float(p) - float(y)) ** 2 for p, y in zip(confidences, outcomes, strict=True)
    )
    return round(total / len(confidences), 4)


def compute_classification_metrics(
    y_true: list[bool],
    y_pred: list[bool],
) -> dict[str, float]:
    """
    Computes binary in-scope vs abstention classification metrics:
      - accuracy, micro P/R/F1, macro P/R/F1
      - abstention_precision (`TN / (TN + FN)`)
      - false_confidence_rate (`FP / (FP + TN)`, i.e. OOD acceptance rate)
    """
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have identical length.")
    n = len(y_true)
    if n == 0:
        return {
            "accuracy": 0.0,
            "in_scope_precision": 0.0,
            "in_scope_recall": 0.0,
            "in_scope_f1": 0.0,
            "micro_precision": 0.0,
            "micro_recall": 0.0,
            "micro_f1": 0.0,
            "macro_precision": 0.0,
            "macro_recall": 0.0,
            "macro_f1": 0.0,
            "abstention_precision": 1.0,
            "false_confidence_rate": 0.0,
        }

    tp = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if yt and yp)
    fp = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if not yt and yp)
    fn = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if yt and not yp)
    tn = sum(1 for yt, yp in zip(y_true, y_pred, strict=True) if not yt and not yp)

    acc = (tp + tn) / n
    p_pos = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r_pos = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_pos = (2 * p_pos * r_pos / (p_pos + r_pos)) if (p_pos + r_pos) > 0 else 0.0

    p_neg = tn / (tn + fn) if (tn + fn) > 0 else 1.0
    r_neg = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1_neg = (2 * p_neg * r_neg / (p_neg + r_neg)) if (p_neg + r_neg) > 0 else 0.0

    macro_p = 0.5 * (p_pos + p_neg)
    macro_r = 0.5 * (r_pos + r_neg)
    macro_f1 = 0.5 * (f1_pos + f1_neg)
    fcr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": round(acc, 4),
        "in_scope_precision": round(p_pos, 4),
        "in_scope_recall": round(r_pos, 4),
        "in_scope_f1": round(f1_pos, 4),
        "micro_precision": round(acc, 4),
        "micro_recall": round(acc, 4),
        "micro_f1": round(acc, 4),
        "macro_precision": round(macro_p, 4),
        "macro_recall": round(macro_r, 4),
        "macro_f1": round(macro_f1, 4),
        "abstention_precision": round(p_neg, 4),
        "false_confidence_rate": round(fcr, 4),
    }


def compute_threshold_sweep(
    confidences: list[float],
    y_true: list[bool],
    *,
    start: float = 0.50,
    stop: float = 0.95,
    step: float = 0.05,
) -> list[ThresholdSweepPoint]:
    """Sweeps confidence thresholds to quantify the precision/recall/FCR operating curve."""
    points: list[ThresholdSweepPoint] = []
    cur = start
    while cur <= stop + 1e-9:
        thresh = round(cur, 2)
        y_pred = [c >= thresh for c in confidences]
        m = compute_classification_metrics(y_true, y_pred)
        points.append(
            ThresholdSweepPoint(
                threshold=thresh,
                accuracy=m["accuracy"],
                in_scope_precision=m["in_scope_precision"],
                in_scope_recall=m["in_scope_recall"],
                macro_f1=m["macro_f1"],
                abstention_precision=m["abstention_precision"],
                false_confidence_rate=m["false_confidence_rate"],
            )
        )
        cur += step
    return points


def get_oblique_stress_dataset() -> list[CalibrationSample]:
    """
    Returns 18 adversarial/oblique evaluation scenarios across euphemistic EN clauses,
    BM/Manglish code-switching, simulated OCR corruption, and near-threshold foreign-law
    ambiguity around the 0.78 abstention boundary.
    """
    return [
        # --- Oblique Euphemisms (EN, zero statutory keywords) ---
        CalibrationSample(
            sample_id="OBL-01-FOLLOW-THE-SUN-TELEMETRY",
            category="oblique_euphemism_en",
            title="Oblique Cross-Border Telemetry Replication -> Act 709 s. 129",
            query="Follow-the-sun global telemetry replication to regional support hubs outside Malaysia without explicit contractual safeguards.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "PDPA-2010-SEC-129-V2",
                "PDPA-2010-SEC-129-V2-BM",
                "PDPD-CBPDT-2025-03",
            },
            forbidden_node_ids={"PDPA-2010-SEC-129-V1"},
        ),
        CalibrationSample(
            sample_id="OBL-02-AI-RISK-SCORING-NO-HUMAN",
            category="oblique_euphemism_en",
            title="Automated Customer Risk Scoring Without Manual Review -> MOSTI AIGE / Act 873",
            query="Automated customer risk scoring without manual review or human escalation before credit rejection.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "MOSTI-AIGE-2024-PRINCIPLES-V1",
                "MOSTI-AIGE-2024-PRINCIPLES-V1-BM",
                "ACT-873-SEC-35-V1",
            },
        ),
        CalibrationSample(
            sample_id="OBL-03-DEFERRED-FEE-SPLITTING",
            category="oblique_euphemism_en",
            title="Discretionary Deferred Fee Splitting -> Act 873 BNPL",
            query="Discretionary deferred fee splitting at checkout over four monthly instalments using flat-rate financing charges.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "ACT-873-SEC-35-V1",
                "ACT-873-SEC-35-V1-BM",
                "ACT-873-SKP-LIC-V1",
            },
        ),
        CalibrationSample(
            sample_id="OBL-04-PROCESSOR-WASH-HANDS",
            category="oblique_euphemism_en",
            title="Euphemistic Processor Liability Disclaimer -> Act 709 s. 9(1A)",
            query="Infrastructure operator disclaims all security responsibility and shall bear zero statutory liability for client database compromise.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "PDPA-2010-SEC-9-V2",
                "PDPA-2010-SEC-9-V2-BM",
                "PDPA-2010-SEC-9-V2-SUB-1A",
            },
            forbidden_node_ids={"PDPA-2010-SEC-9-V1"},
        ),
        CalibrationSample(
            sample_id="OBL-05-CLOUD-KEY-CUSTODY-AUDIT",
            category="oblique_euphemism_en",
            title="Vendor Encryption Key Custody & Unapproved Sub-Contractors -> BNM Outsourcing",
            query="Vendor holds all cryptographic key ownership solely, appoints sub-contractors without prior approval, and restricts regulator audit access.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "BNM-OUTSOURCING-2019-V1",
                "BNM-OUTSOURCING-2019-V1-BM",
                "BNM-RMIT-SEC-10-32-V1",
            },
        ),
        # --- Oblique BM & Manglish Code-Switched ---
        CalibrationSample(
            sample_id="OBL-06-BM-OUTBOUND-MIRRORING",
            category="oblique_bm_manglish",
            title="BM Euphemistic Regional Support Hub Replication -> Act 709 s. 129",
            query="Semua rekod pelanggan disalin ke hab sokongan serantau di luar negara tanpa persetujuan bertulis.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "PDPA-2010-SEC-129-V2-BM",
                "PDPA-2010-SEC-129-V2",
                "PDPD-CBPDT-2025-03",
            },
        ),
        CalibrationSample(
            sample_id="OBL-07-MANGLISH-AUTO-SCORING",
            category="oblique_bm_manglish",
            title="Manglish AI Auto-Scoring Without Human Check -> MOSTI AIGE + Act 873",
            query="System buat auto-scoring guna AI tanpa human check untuk pelanggan skim bayaran ansuran tangguh.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "MOSTI-AIGE-2024-PRINCIPLES-V1",
                "MOSTI-AIGE-2024-PRINCIPLES-V1-BM",
                "ACT-873-SEC-35-V1",
            },
        ),
        CalibrationSample(
            sample_id="OBL-08-MANGLISH-MYINVOIS-BUNDLE",
            category="oblique_bm_manglish",
            title="BM/Manglish Consolidated Monthly Billing Over RM10k -> Act 53 MyInvois",
            query="Gabung semua invois bulanan lebih RM10,000 dalam satu bil e-invois disatukan pada hujung bulan.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "ACT-53-MYINVOIS-10K-V1",
                "ACT-53-MYINVOIS-10K-V1-BM",
                "ACT-53-SEC-82C-P1-V1",
            },
        ),
        CalibrationSample(
            sample_id="OBL-09-PRE2025-TEMPORAL-CROSSBORDER",
            category="oblique_bm_manglish",
            title="Pre-2025 Whitelist Regime Oblique Mirroring -> PDPA-2010-SEC-129-V1",
            query="Follow-the-sun global telemetry replication to regional support hubs outside Malaysia.",
            as_of_date=date(2024, 6, 15),
            expected_in_scope=True,
            expected_node_ids={
                "PDPA-2010-SEC-129-V1",
                "PDPA-2010-SEC-129-V1-BM",
            },
            forbidden_node_ids={"PDPA-2010-SEC-129-V2", "PDPA-2010-SEC-129-V2-BM"},
        ),
        # --- Simulated OCR Noise ---
        CalibrationSample(
            sample_id="OBL-10-OCR-BREACH-14D",
            category="ocr_noise",
            title="OCR Digit/Letter Swaps & Spaced Letters on Breach SLA",
            query="Sect10n 12B: n0tification of pers0nal data breach within 14 d a y s.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "PDPA-2010-SEC-12B-V1",
                "PDPA-2010-SEC-12B-V1-BM",
                "PDPD-DBN-2025-02",
            },
        ),
        CalibrationSample(
            sample_id="OBL-11-OCR-SABAH-OVERTIME",
            category="ocr_noise",
            title="OCR Corrupted Sabah Overtime Clause with Territorial Isolation",
            query="Empl0yees working in S a b a h sh1ft h0urs receive 1.5x 0vertime rates.",
            as_of_date=date(2026, 3, 15),
            territorial_scope="Sabah",
            expected_in_scope=True,
            expected_node_ids={
                "SABAH-CAP67-SEC-104-V1",
                "SABAH-CAP67-SEC-104-V1-BM",
            },
            forbidden_node_ids={"EA-1955-SEC-60A-V1", "SARAWAK-CAP76-SEC-105-V1"},
        ),
        CalibrationSample(
            sample_id="OBL-12-OCR-SDSAS-STAMP-DUTY",
            category="ocr_noise",
            title="OCR Corrupted Stamp Act 1949 SDSAS 30-Day Filing",
            query="Unstamped revenue 1nstrument under Act 378 flled after 3O d a y s under self-assessment stamp duty.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "ACT-378-SDSAS-2026-V1",
                "ACT-378-SDSAS-2026-V1-BM",
                "ACT-378-SEC-52-V1",
            },
        ),
        # --- Near-Threshold Ambiguity (Hidden MY Nexus vs Pure Foreign Law / OOD) ---
        CalibrationSample(
            sample_id="OBL-13-HIDDEN-MY-NEXUS",
            category="near_threshold_ambiguity",
            title="Hidden Kuala Lumpur Nexus Under Nominal Foreign Law Choice",
            query="Although governed nominally by foreign law, MyKad biometrics and payroll telemetry for Kuala Lumpur staff are mirrored to overseas regional support hubs.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=True,
            expected_node_ids={
                "PDPA-2010-SEC-129-V2",
                "PDPA-2010-SEC-129-V2-BM",
                "PDPA-2010-SEC-BIO-V1",
            },
        ),
        CalibrationSample(
            sample_id="OBL-14-OOD-DELAWARE-LLC",
            category="near_threshold_ambiguity",
            title="Out-of-Scope Delaware LLC & New York AAA Arbitration",
            query="This Software License Agreement is governed exclusively by the laws of the State of Delaware and disputes resolved by AAA arbitration in New York.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=False,
        ),
        CalibrationSample(
            sample_id="OBL-15-OOD-UK-GDPR-ICO",
            category="near_threshold_ambiguity",
            title="Out-of-Scope UK GDPR & UK ICO Data Protection Act 2018",
            query="Personal data of United Kingdom residents is processed solely under UK GDPR and reported to the UK Information Commissioner's Office under the Data Protection Act 2018.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=False,
        ),
        CalibrationSample(
            sample_id="OBL-16-OOD-PANTRY-INVOICE",
            category="near_threshold_ambiguity",
            title="Out-of-Scope Non-Regulatory Office Pantry Supply",
            query="Monthly supply of dark roast espresso beans, oat milk, and paper cups for the fifth-floor office pantry.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=False,
        ),
        CalibrationSample(
            sample_id="OBL-17-OOD-SINGAPORE-EMPLOYMENT",
            category="near_threshold_ambiguity",
            title="Out-of-Scope Singapore Employment Act Contract (Near-Threshold Boundary)",
            query="Standard executive employment contract governed by the Singapore Employment Act with overtime in SGD for Raffles Place staff.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=False,
        ),
        CalibrationSample(
            sample_id="OBL-18-OOD-EU-AI-ACT-VENDOR",
            category="near_threshold_ambiguity",
            title="Out-of-Scope EU AI Act Transparency Disclosure",
            query="European Union AI Act Article 52 algorithmic transparency disclosure for Brussels software with no local deployment.",
            as_of_date=date(2026, 3, 15),
            expected_in_scope=False,
        ),
    ]


def evaluate_oblique_stress_suite(
    *,
    retriever: HybridStatutoryRetriever | None = None,
    operating_threshold: float = 0.78,
    top_k: int = 5,
) -> CalibrationReport:
    """
    Executes the 16-scenario adversarial oblique stress suite against `HybridStatutoryRetriever`
    and computes retrieval (`Recall@1/3/5`, `MRR`), classification/abstention, threshold sweep,
    and calibration (`10-bin ECE`, `Brier Score`) metrics.
    """
    active_retriever = retriever or default_hybrid_retriever
    dataset = get_oblique_stress_dataset()

    expected_sets: list[set[str]] = []
    ranked_lists: list[list[str]] = []
    confidences: list[float] = []
    outcomes: list[float] = []
    y_true: list[bool] = []
    y_pred: list[bool] = []
    sample_results: list[SampleCalibrationResult] = []
    contaminated_count = 0

    for sample in dataset:
        resp = active_retriever.explain(
            query=sample.query,
            as_of_date=sample.as_of_date,
            territorial_scope=sample.territorial_scope,
            top_k=top_k,
            abstention_threshold=operating_threshold,
        )
        ranked_ids = [c.node_id for c in resp.candidates]
        max_sc = float(resp.max_score)
        pred_in_scope = max_sc >= operating_threshold and not resp.is_abstained

        rr = 0.0
        if sample.expected_node_ids:
            for idx, nid in enumerate(ranked_ids, start=1):
                if nid in sample.expected_node_ids:
                    rr = 1.0 / float(idx)
                    break

        hit1 = bool(sample.expected_node_ids & set(ranked_ids[:1]))
        hit3 = bool(sample.expected_node_ids & set(ranked_ids[:3]))
        hit5 = bool(sample.expected_node_ids & set(ranked_ids[:5]))

        contaminated = bool(sample.forbidden_node_ids & set(ranked_ids))
        if contaminated:
            contaminated_count += 1

        expected_sets.append(sample.expected_node_ids)
        ranked_lists.append(ranked_ids)
        confidences.append(max_sc)
        # Probabilistic calibration ground truth: whether sample genuinely belongs in scope (and retrieved top-k)
        outcomes.append(1.0 if (sample.expected_in_scope and hit5) else 0.0)
        y_true.append(sample.expected_in_scope)
        y_pred.append(pred_in_scope)

        sample_results.append(
            SampleCalibrationResult(
                sample_id=sample.sample_id,
                category=sample.category,
                expected_in_scope=sample.expected_in_scope,
                predicted_in_scope=pred_in_scope,
                max_score=max_sc,
                top_node_id=ranked_ids[0] if ranked_ids else None,
                top_k_node_ids=ranked_ids,
                reciprocal_rank=round(rr, 4),
                hit_at_1=hit1,
                hit_at_3=hit3,
                hit_at_5=hit5,
                temporal_contaminated=contaminated,
            )
        )

    r1 = compute_recall_at_k(expected_sets, ranked_lists, 1)
    r3 = compute_recall_at_k(expected_sets, ranked_lists, 3)
    r5 = compute_recall_at_k(expected_sets, ranked_lists, 5)
    mrr = compute_mrr(expected_sets, ranked_lists)

    cls_m = compute_classification_metrics(y_true, y_pred)
    ece, bins = compute_ece(confidences, outcomes, n_bins=10)
    brier = compute_brier_score(confidences, outcomes)
    sweep = compute_threshold_sweep(
        confidences, y_true, start=0.50, stop=0.95, step=0.05
    )

    in_scope_cnt = sum(1 for s in dataset if s.expected_in_scope)
    oos_cnt = len(dataset) - in_scope_cnt
    contam_rate = (
        round((contaminated_count / len(dataset)) * 100.0, 2) if dataset else 0.0
    )

    return CalibrationReport(
        suite="oblique_stress",
        operating_threshold=operating_threshold,
        total_samples=len(dataset),
        in_scope_samples=in_scope_cnt,
        out_of_scope_samples=oos_cnt,
        recall_at_1=r1,
        recall_at_3=r3,
        recall_at_5=r5,
        mrr=mrr,
        accuracy=cls_m["accuracy"],
        micro_precision=cls_m["micro_precision"],
        micro_recall=cls_m["micro_recall"],
        micro_f1=cls_m["micro_f1"],
        macro_precision=cls_m["macro_precision"],
        macro_recall=cls_m["macro_recall"],
        macro_f1=cls_m["macro_f1"],
        abstention_precision=cls_m["abstention_precision"],
        false_confidence_rate=cls_m["false_confidence_rate"],
        ece_10_bin=ece,
        brier_score=brier,
        temporal_contamination_rate=contam_rate,
        bins=bins,
        threshold_sweep=sweep,
        sample_results=sample_results,
    )


def format_calibration_markdown(report: CalibrationReport) -> str:
    """Formats a `CalibrationReport` into GitHub-flavored Markdown tables."""
    lines = [
        "## 3. Oblique Stress Retrieval & Probabilistic Calibration Report",
        "",
        f"- **Suite:** `{report.suite}` (`{report.total_samples}` scenarios: `{report.in_scope_samples}` in-scope oblique/BM/OCR + `{report.out_of_scope_samples}` out-of-scope boundary)",
        f"- **Operating Abstention Threshold:** `{report.operating_threshold:.2f}`",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Retrieval Recall@1 / Recall@3 / Recall@5** | `{report.recall_at_1:.4f}` / `{report.recall_at_3:.4f}` / `{report.recall_at_5:.4f}` |",
        f"| **Mean Reciprocal Rank (MRR)** | `{report.mrr:.4f}` |",
        f"| **Macro Precision / Recall / F1** | `{report.macro_precision:.4f}` / `{report.macro_recall:.4f}` / `{report.macro_f1:.4f}` |",
        f"| **Micro F1 / Accuracy** | `{report.micro_f1:.4f}` / `{report.accuracy:.4f}` |",
        f"| **Abstention Precision / False-Confidence Rate** | `{report.abstention_precision:.4f}` / `{report.false_confidence_rate:.4f}` |",
        f"| **Expected Calibration Error (ECE, 10-bin)** | `{report.ece_10_bin:.4f}` |",
        f"| **Brier Score** | `{report.brier_score:.4f}` |",
        f"| **Temporal/Territorial Contamination Rate** | `{report.temporal_contamination_rate:.2f}%` |",
        "",
        "### Confidence Threshold Sweep (`0.50` to `0.95`)",
        "",
        "| Threshold | Accuracy | In-Scope Recall | Macro F1 | Abstention Precision | False-Confidence Rate |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for pt in report.threshold_sweep:
        marker = (
            " **(OP)**" if abs(pt.threshold - report.operating_threshold) < 0.03 else ""
        )
        lines.append(
            f"| `{pt.threshold:.2f}`{marker} | `{pt.accuracy:.4f}` | `{pt.in_scope_recall:.4f}` | "
            f"`{pt.macro_f1:.4f}` | `{pt.abstention_precision:.4f}` | `{pt.false_confidence_rate:.4f}` |"
        )
    lines.extend(
        [
            "",
            "### Oblique Sample Results",
            "",
            "| Sample ID | Category | In-Scope (Exp/Pred) | Max Score | Top Node | Hit@3 |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for sr in report.sample_results:
        lines.append(
            f"| `{sr.sample_id}` | `{sr.category}` | `{sr.expected_in_scope}/{sr.predicted_in_scope}` | "
            f"`{sr.max_score:.4f}` | `{sr.top_node_id or 'NONE'}` | `{'YES' if sr.hit_at_3 else ('N/A' if not sr.expected_in_scope else 'NO')}` |"
        )
    return "\n".join(lines)
