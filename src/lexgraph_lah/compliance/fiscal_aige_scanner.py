"""
Zero-token deterministic compliance evaluator for 2026 Malaysian Commercial Fiscal
& AI Governance packs:
  - Stamp Act 1949 [Act 378] & Tax Measures Act 2025 (SDSAS, eff. 2026-01-01)
  - Income Tax Act 1967 [Act 53] s. 82C & s. 120(1)(d) (LHDN MyInvois)
  - MOSTI National Guidelines on AI Governance & Ethics (AIGE, eff. 2024-09-20; VOLUNTARY_GUIDELINE)
  - BNM Outsourcing Policy Document + RMiT (crypto key ownership & sub-contractor approval)
"""

from __future__ import annotations

import re
from datetime import date
from typing import TYPE_CHECKING

from lexgraph_lah.schemas.domain import (
    ClauseAudit,
    CompositeDeonticEnvelope,
    ContractASTGraph,
    ContractClauseNode,
    RiskSeverity,
)

if TYPE_CHECKING:
    from lexgraph_lah.graph.temporal_store import TemporalGraphStore

_RM_VAL_RE = re.compile(r"\bRM\s*([0-9][0-9,]*(?:\.\d+)?)\b", re.IGNORECASE)


def _span_ids(store: TemporalGraphStore, node_ids: list[str]) -> list[str]:
    out: list[str] = []
    for nid in node_ids:
        node = store.nodes.get(nid)
        if node:
            for sp in node.source_spans:
                if sp.span_id not in out:
                    out.append(sp.span_id)
    return out


def _active_filter(active_ids: set[str], candidates: list[str]) -> list[str]:
    if not active_ids:
        return candidates
    filtered = [c for c in candidates if c in active_ids]
    return filtered or candidates


def _max_rm_in_text(text: str) -> float | None:
    vals: list[float] = []
    for m in _RM_VAL_RE.finditer(text):
        try:
            vals.append(float(m.group(1).replace(",", "")))
        except ValueError:
            continue
    return max(vals) if vals else None


def _ordered_clauses_schedules_first(
    ast_graph: ContractASTGraph,
) -> list[ContractClauseNode]:
    schedules = [c for c in ast_graph.clauses if c.section_type == "SCHEDULE"]
    others = [c for c in ast_graph.clauses if c.section_type != "SCHEDULE"]
    return schedules + others


def evaluate_fiscal_aige_clauses(
    *,
    ast_graph: ContractASTGraph,
    envelope: CompositeDeonticEnvelope | None,
    as_of_date: date,
    store: TemporalGraphStore,
    active_statute_ids: set[str] | None = None,
) -> list[ClauseAudit]:
    """
    Evaluates a ContractASTGraph (including `<w:tbl>` `Jadual` / `Lampiran` tables) against
    Act 378 (Stamp Act SDSAS), Act 53 (MyInvois), MOSTI AIGE (`VOLUNTARY_GUIDELINE`),
    and BNM Outsourcing + RMiT enhancements in 0 LLM tokens.
    """
    regimes = set(envelope.regimes_evaluated if envelope else [])
    active_ids = active_statute_ids or (
        set(envelope.active_node_ids) if envelope else set()
    )
    ordered_clauses = _ordered_clauses_schedules_first(ast_graph)
    findings: list[ClauseAudit] = []
    fired_rules: set[str] = set()

    # ---------------------------------------------------------------------
    # 1. Stamp Act 1949 [Act 378] & SDSAS (eff. 2026-01-01)
    # ---------------------------------------------------------------------
    if "ACT_378" in regimes:
        has_stamp_clause = any(
            bool(c.extracted_metrics.get("stamp_duty_mentioned"))
            for c in ordered_clauses
        )
        for cnode in ordered_clauses:
            m = cnode.extracted_metrics
            low = cnode.text.lower()

            # 1a. Employment exemption threshold RM300 -> RM3,000/month (eff. 2026-01-01)
            claimed_exempt = m.get("stamp_duty_exempt_claimed_myr")
            if (
                as_of_date >= date(2026, 1, 1)
                and isinstance(claimed_exempt, (int, float))
                and claimed_exempt <= 300.0
                and any(
                    kw in low
                    for kw in ("employment", "salary", "wage", "pekerja", "gaji")
                )
                and "ACT378-EMP-3000" not in fired_rules
            ):
                v_ids = _active_filter(active_ids, ["ACT-378-EMP-EXEMPT-V2"])
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="Stamp Act Employment Exemption Threshold (2026)",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            "Clause states the superseded pre-2026 RM 300/month employment stamp duty "
                            "exemption threshold. Effective 2026-01-01 under Stamp Act 1949 [Act 378] "
                            "First Schedule Item 4, employment contracts up to RM 3,000/month are exempt."
                        ),
                        recommended_redline=(
                            "Employment contracts with monthly salary not exceeding RM 3,000 shall be "
                            "exempt from stamp duty pursuant to Stamp Act 1949 [Act 378] effective 1 January 2026."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("ACT378-EMP-3000")

            # 1b. SDSAS 30-day self-assessment return & payment window (eff. 2026-01-01)
            pay_days = m.get("stamp_duty_payment_days")
            if (
                as_of_date >= date(2026, 1, 1)
                and isinstance(pay_days, (int, float))
                and pay_days > 30.0
                and "ACT378-SDSAS-30D" not in fired_rules
            ):
                v_ids = _active_filter(active_ids, ["ACT-378-SDSAS-2026-V1"])
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="Stamp Duty Self-Assessment (SDSAS) 30-Day Window",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            f"Stamp duty assessment/payment window ({pay_days:g} days) exceeds the mandatory "
                            "30-day SDSAS self-assessment return and payment deadline effective 2026-01-01."
                        ),
                        recommended_redline=(
                            "The designated party shall file the LHDN SDSAS self-assessment stamp duty return "
                            "and remit assessed duty within 30 days from execution of this Agreement."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("ACT378-SDSAS-30D")

            # 1c. 8% foreign residential transfer tier (eff. 2026-01-01)
            f_pct = m.get("foreign_residential_stamp_duty_pct")
            if (
                as_of_date >= date(2026, 1, 1)
                and isinstance(f_pct, (int, float))
                and f_pct < 8.0
                and "ACT378-FOREIGN-8PCT" not in fired_rules
            ):
                v_ids = _active_filter(active_ids, ["ACT-378-FOREIGN-RES-8PCT-V1"])
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="Foreign Residential Transfer Stamp Duty Tier (8%)",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            f"Foreign residential property transfer cites {f_pct:g}% stamp duty, which understates "
                            "the 8% ad valorem tier effective 2026-01-01 under Stamp Act 1949 [Act 378]."
                        ),
                        recommended_redline=(
                            "Ad valorem stamp duty on foreign residential property transfers shall be assessed "
                            "and remitted at the 8% statutory tier under Stamp Act 1949 [Act 378] via SDSAS."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("ACT378-FOREIGN-8PCT")

            # 1d. Explicit exclusion/unstamped disclaimer -> s. 52 inadmissibility
            if (
                m.get("stamp_duty_excluded") is True
                and "ACT378-SEC52-OMIT" not in fired_rules
            ):
                v_ids = _active_filter(
                    active_ids,
                    ["ACT-378-SEC-52-V1"]
                    + (
                        ["ACT-378-SDSAS-2026-V1"]
                        if as_of_date >= date(2026, 1, 1)
                        else []
                    ),
                )
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="Stamp Act s. 52 Evidentiary Inadmissibility",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            "Disclaiming or omitting stamping renders the instrument inadmissible in evidence "
                            "under Stamp Act 1949 [Act 378] s. 52 and exposes parties to SDSAS penalties."
                        ),
                        recommended_redline=(
                            "Each chargeable instrument shall be duly stamped under Stamp Act 1949 [Act 378] "
                            "(with SDSAS return and payment completed within 30 days of execution) so it remains "
                            "admissible in evidence under Section 52."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("ACT378-SEC52-OMIT")

        # 1e. Commercial/SLA/employment contract omits stamp duty allocation entirely
        if (
            not has_stamp_clause
            and ordered_clauses
            and "ACT378-SEC52-OMIT" not in fired_rules
        ):
            target_c = ordered_clauses[0]
            v_ids = _active_filter(
                active_ids,
                ["ACT-378-SEC-52-V1"]
                + (["ACT-378-SDSAS-2026-V1"] if as_of_date >= date(2026, 1, 1) else []),
            )
            findings.append(
                ClauseAudit(
                    clause_id=target_c.clause_id,
                    category="Omitted Stamp Duty Allocation (Act 378 s. 52)",
                    exact_quote=target_c.text,
                    severity=RiskSeverity.MEDIUM,
                    rationale=(
                        "Agreement omits stamp duty allocation and stamping responsibility, creating "
                        "Section 52 evidentiary inadmissibility risk under Stamp Act 1949 [Act 378]."
                    ),
                    recommended_redline=(
                        "Stamp duty payable on this Agreement under Stamp Act 1949 [Act 378] shall be borne "
                        "by the designated party and duly stamped via LHDN SDSAS within 30 days of execution "
                        "to ensure evidentiary admissibility under Section 52."
                    ),
                    violated_statute_ids=v_ids,
                    source_span_ids=_span_ids(store, v_ids),
                    deontic_modality="OBLIGATION",
                )
            )
            fired_rules.add("ACT378-SEC52-OMIT")

    # ---------------------------------------------------------------------
    # 2. Income Tax Act 1967 [Act 53] s. 82C & s. 120(1)(d) — LHDN MyInvois
    # ---------------------------------------------------------------------
    if "ACT_53" in regimes:
        doc_has_consolidated = any(
            bool(c.extracted_metrics.get("myinvois_consolidated_billing"))
            for c in ordered_clauses
        )
        for cnode in ordered_clauses:
            m = cnode.extracted_metrics

            # 2a. > RM10,000 consolidated e-Invoice prohibition (eff. 2026-01-01)
            tx_amt = m.get("myinvois_max_single_tx_myr") or m.get("max_rm_amount")
            is_consol = bool(m.get("myinvois_consolidated_billing")) or (
                cnode.section_type == "SCHEDULE" and doc_has_consolidated
            )
            if (
                as_of_date >= date(2026, 1, 1)
                and is_consol
                and isinstance(tx_amt, (int, float))
                and tx_amt > 10_000.0
                and "ACT53-CONSOL-10K" not in fired_rules
            ):
                v_ids = _active_filter(
                    active_ids, ["ACT-53-MYINVOIS-10K-V1", "ACT-53-SEC-120-1D-V1"]
                )
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="LHDN MyInvois > RM10,000 Consolidated e-Invoice Trap",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            f"Billing clause/schedule specifies a single transaction of RM {tx_amt:,.2f} under "
                            "consolidated e-invoicing. Effective 2026-01-01, Income Tax Act 1967 [Act 53] s. 82C "
                            "prohibits consolidated e-invoices for single transactions > RM 10,000 (s. 120(1)(d) "
                            "penalties: RM 200-RM 20,000 fine / 6 months imprisonment)."
                        ),
                        recommended_redline=(
                            "Supplier shall issue an individual LHDN MyInvois validated e-Invoice with UIN "
                            "for every single transaction exceeding RM 10,000 (no consolidated e-invoicing), "
                            "with full TIN/SST/UBL validation cooperation under Act 53 s. 82C."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="PROHIBITION",
                    )
                )
                fired_rules.add("ACT53-CONSOL-10K")

            # 2b. Post-72h cancellation/rejection window trap
            cancel_h = m.get("myinvois_cancellation_hours")
            unilat = bool(m.get("myinvois_unilateral_post72h_cancel"))
            if (
                as_of_date >= date(2024, 8, 1)
                and ((isinstance(cancel_h, (int, float)) and cancel_h > 72.0) or unilat)
                and "ACT53-72H-CANCEL" not in fired_rules
            ):
                v_ids = _active_filter(active_ids, ["ACT-53-SEC-82C-P1-V1"])
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="MyInvois 72-Hour Cancellation / Rejection Window Breach",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            "Clause permits buyer rejection or unilateral supplier cancellation beyond "
                            "LHDN MyInvois's mandatory 72-hour post-UIN validation window under Act 53 s. 82C; "
                            "post-72h adjustments require validated credit/debit/refund note e-invoices."
                        ),
                        recommended_redline=(
                            "Any MyInvois buyer rejection or supplier cancellation shall be executed strictly "
                            "within 72 hours of UIN validation; adjustments thereafter shall be processed via "
                            "validated credit or debit note e-invoices under Act 53 s. 82C."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("ACT53-72H-CANCEL")

            # 2c. Missing TIN/SST/UBL validation cooperation
            if (
                as_of_date >= date(2024, 8, 1)
                and m.get("myinvois_validation_omitted") is True
                and "ACT53-UIN-COOP" not in fired_rules
            ):
                v_ids = _active_filter(
                    active_ids, ["ACT-53-SEC-82C-P1-V1", "ACT-53-SEC-120-1D-V1"]
                )
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="MyInvois UIN / TIN / SST / UBL Validation Omission",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            "Clause omits or refuses TIN, SST, UBL payload, or MyInvois UIN validation "
                            "cooperation required under Income Tax Act 1967 [Act 53] s. 82C and s. 120(1)(d)."
                        ),
                        recommended_redline=(
                            "Both parties shall timely exchange valid LHDN TIN, SST registration, and UBL 2.1 "
                            "mandatory fields to enable real-time MyInvois UIN validation under Act 53 s. 82C."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("ACT53-UIN-COOP")

            # 2d. Foreign supplier cross-border self-billed e-invoice omission
            if (
                as_of_date >= date(2024, 8, 1)
                and m.get("myinvois_self_billed_omitted") is True
                and "ACT53-SELF-BILLED" not in fired_rules
            ):
                v_ids = _active_filter(active_ids, ["ACT-53-SEC-82C-P1-V1"])
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="MyInvois Cross-Border Self-Billed e-Invoice Breach",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            "Disclaiming self-billed e-invoicing for cross-border foreign supplier imports "
                            "violates Malaysian buyer obligations under Income Tax Act 1967 [Act 53] s. 82C."
                        ),
                        recommended_redline=(
                            "For cross-border services or goods imported from a foreign supplier, the Malaysian "
                            "buyer shall issue a self-billed MyInvois e-invoice and foreign supplier shall supply "
                            "required billing details under Act 53 s. 82C."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("ACT53-SELF-BILLED")

            # 2e. RM3M threshold (eff. 2026-08-30) & related/holding-company carve-out
            claimed_rev_exempt = m.get("myinvois_claimed_exemption_myr")
            rel_flag = bool(m.get("myinvois_related_company_flag"))
            if (
                as_of_date >= date(2026, 8, 30)
                and rel_flag
                and claimed_rev_exempt is not None
                and "ACT53-RELATED-CARVEOUT" not in fired_rules
            ):
                v_ids = _active_filter(active_ids, ["ACT-53-MYINVOIS-EXEMPT-V2"])
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="MyInvois Related/Holding-Company Exemption Carve-Out",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            "Although the general annual MyInvois exemption threshold increased to RM 3,000,000 "
                            "effective 2026-08-30, subsidiaries, related companies, and entities linked to a holding "
                            "company exceeding RM 3,000,000 remain non-exempt under LHDN carve-out rules."
                        ),
                        recommended_redline=(
                            "A subsidiary or related company connected to a group/holding entity above RM 3,000,000 "
                            "annual revenue shall comply with full MyInvois e-Invoicing under Act 53 s. 82C."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("ACT53-RELATED-CARVEOUT")
            elif (
                date(2025, 1, 1) <= as_of_date < date(2026, 8, 30)
                and isinstance(claimed_rev_exempt, (int, float))
                and 500_000.0 < claimed_rev_exempt <= 3_000_000.0
                and "ACT53-EXEMPT-PRE-AUG26" not in fired_rules
            ):
                v_ids = _active_filter(active_ids, ["ACT-53-MYINVOIS-EXEMPT-V1"])
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="MyInvois Pre-2026-08-30 Exemption Threshold Exceeded",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            f"Prior to 2026-08-30, MyInvois micro-enterprise exemption applies only below RM 500,000 "
                            f"(claimed revenue RM {claimed_rev_exempt:,.2f} is NOT yet exempt on {as_of_date.isoformat()})."
                        ),
                        recommended_redline=(
                            "Entity shall issue LHDN MyInvois validated e-invoices until the RM 3,000,000 "
                            "revised exemption threshold takes effect on 30 August 2026."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("ACT53-EXEMPT-PRE-AUG26")

    # ---------------------------------------------------------------------
    # 3. MOSTI National Guidelines on AI Governance & Ethics (AIGE) — VOLUNTARY_GUIDELINE
    # ---------------------------------------------------------------------
    if "MOSTI_AIGE" in regimes and as_of_date >= date(2024, 9, 20):
        for cnode in ordered_clauses:
            m = cnode.extracted_metrics
            if m.get("aige_ai_system_present") and (
                m.get("aige_hitl_omitted") or m.get("aige_audit_trail_omitted")
            ):
                if "MOSTI-AIGE-GAP" in fired_rules:
                    continue
                v_ids = _active_filter(active_ids, ["MOSTI-AIGE-2024-PRINCIPLES-V1"])
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="MOSTI AIGE Voluntary AI Governance Gap",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.MEDIUM,
                        rationale=(
                            "Voluntary Governance Gap (NOT a mandatory statutory breach): AI deployment omits "
                            "human-in-the-loop/human-on-the-loop controls or AI decision audit trail retention "
                            "recommended under MOSTI AIGE (2024-09-20) 7 Principles and PDPA s. 9 / s. 129 cross-links."
                        ),
                        recommended_redline=(
                            "Supplier shall align AI operations with MOSTI AIGE 7 Responsible AI Principles "
                            "(voluntary benchmark), maintain human-in-the-loop oversight, retain explainable AI "
                            "decision audit trails, and comply with PDPA Act 709 ss. 9 & 129."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="VOLUNTARY_GUIDELINE",
                        is_voluntary_guideline=True,
                    )
                )
                fired_rules.add("MOSTI-AIGE-GAP")

    # ---------------------------------------------------------------------
    # 4. BNM Outsourcing + RMiT Enhancements (Crypto Key Ownership & Sub-Contractors)
    # ---------------------------------------------------------------------
    if "BNM_RMIT" in regimes:
        for cnode in ordered_clauses:
            m = cnode.extracted_metrics
            if (
                m.get("bnm_crypto_key_owned_by_vendor") is True
                and "BNM-CRYPTO-KEY" not in fired_rules
            ):
                v_ids = _active_filter(active_ids, ["BNM-OUTSOURCING-2019-V1"])
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="BNM Outsourcing & RMiT Cryptographic Key Ownership Breach",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.CRITICAL,
                        rationale=(
                            "Financial institution must retain exclusive cryptographic key ownership (BYOK) "
                            "and cannot cede sole key ownership to cloud/outsourced vendors under BNM Outsourcing + RMiT."
                        ),
                        recommended_redline=(
                            "Financial Institution shall retain exclusive ownership and lifecycle control of all "
                            "cryptographic encryption keys (BYOK/customer-managed keys) under BNM Outsourcing & RMiT."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("BNM-CRYPTO-KEY")

            if (
                m.get("bnm_subcontractor_unrestricted") is True
                or m.get("regulator_audit_access") is False
            ) and "BNM-SUBCONTRACTOR" not in fired_rules:
                v_ids = _active_filter(active_ids, ["BNM-OUTSOURCING-2019-V1"])
                findings.append(
                    ClauseAudit(
                        clause_id=cnode.clause_id,
                        category="BNM Outsourcing Sub-Contractor & Regulator Audit Rights Breach",
                        exact_quote=cnode.text,
                        severity=RiskSeverity.HIGH,
                        rationale=(
                            "Permitting material sub-contracting without prior written approval or excluding "
                            "BNM right-of-audit violates the BNM Outsourcing Policy Document."
                        ),
                        recommended_redline=(
                            "Vendor shall not sub-contract any material outsourced function without prior written "
                            "approval of Financial Institution and preservation of BNM right-of-audit."
                        ),
                        violated_statute_ids=v_ids,
                        source_span_ids=_span_ids(store, v_ids),
                        deontic_modality="OBLIGATION",
                    )
                )
                fired_rules.add("BNM-SUBCONTRACTOR")

    return findings
