"""
Zero-token Portfolio Gazette Blast-Radius Engine (`scan_portfolio_blast_radius`).

Evaluates batches of up to 50 contracts across bi-temporal statutory/P.U. gazette
windows (`from_date` -> `to_date`), ranking exposure by severity, newly broken clauses,
strictest territorial deontic bounds, and PII-safe delta remediation summaries.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from lexgraph_lah.graph.deontic_solver import DeonticEnvelopeResolver, normalize_regimes
from lexgraph_lah.graph.diff_engine import evaluate_contract_delta_impact
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    ContractDeltaAuditRequest,
    PortfolioBlastRadiusRequest,
    PortfolioBlastRadiusResponse,
    PortfolioContractImpact,
    RiskSeverity,
)
from lexgraph_lah.security.doc_firewall import scan_document_security
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import measure_latency_ms

if TYPE_CHECKING:
    from lexgraph_lah.graph.temporal_store import TemporalGraphStore

_RISK_SCORE_WEIGHT: dict[RiskSeverity, float] = {
    RiskSeverity.LOW: 0.0,
    RiskSeverity.MEDIUM: 15.0,
    RiskSeverity.HIGH: 30.0,
    RiskSeverity.CRITICAL: 45.0,
}


def scan_portfolio_blast_radius(
    req: PortfolioBlastRadiusRequest,
    store: TemporalGraphStore | None = None,
) -> PortfolioBlastRadiusResponse:
    """
    Deterministically scans a batch of contracts (1..50) against intervening
    Malaysian statutory amendments and P.U. gazette commencements ($0.00 USD / RM 0.00 MYR).
    """
    if req.from_date > req.to_date:
        raise ValueError(
            f"from_date ({req.from_date.isoformat()}) must be on or before to_date ({req.to_date.isoformat()})."
        )

    if store is None:
        from lexgraph_lah.graph.temporal_store import get_default_temporal_store

        store = get_default_temporal_store()

    resolver = DeonticEnvelopeResolver(store)

    with measure_latency_ms() as elapsed_holder:
        impacts: list[PortfolioContractImpact] = []
        all_gazettes: set[str] = set()
        all_statutes: set[str] = set()

        for contract in req.contracts:
            eff_scope = contract.territorial_scope or req.default_territorial_scope
            raw_regimes = (
                contract.regimes if contract.regimes is not None else req.regimes
            )
            eff_regimes = normalize_regimes(raw_regimes) if raw_regimes else None

            # Pre-scan against adversarial prompt injection before delta evaluation
            sec_report = scan_document_security(
                document_id=contract.document_id,
                raw_text=contract.raw_text,
            )
            clean_text = (
                sec_report.sanitized_text or "[ALL_ADVERSARIAL_CONTENT_QUARANTINED]"
                if sec_report.findings
                else (sec_report.sanitized_text or contract.raw_text)
            )

            delta = evaluate_contract_delta_impact(
                ContractDeltaAuditRequest(
                    document_id=contract.document_id,
                    raw_text=clean_text,
                    from_date=req.from_date,
                    to_date=req.to_date,
                    regimes=eff_regimes,
                    territorial_scope=eff_scope,
                    persona=req.persona,
                ),
                store=store,
            )

            envelope = resolver.resolve(
                regimes=eff_regimes or ["ACT_709"],
                as_of_date=req.to_date,
                territorial_scope=eff_scope,
            )
            bounds_summary: dict[str, Any] = {
                k: {
                    "operator": b.operator,
                    "strictest_value": b.strictest_value,
                    "unit": b.unit,
                    "dominating_regime": b.dominating_regime,
                    "dominating_node_id": b.dominating_node_id,
                    "dominating_citation": b.dominating_citation,
                }
                for k, b in envelope.resolved_bounds.items()
            }

            for g in delta.newly_commenced_gazettes:
                all_gazettes.add(g)
            for diff in delta.intervening_statutory_diffs:
                if diff.to_node_id:
                    all_statutes.add(diff.to_node_id)

            broken_rule_ids = [f.rule_id for f in delta.delta_findings]
            contract_gazettes: list[str] = []
            seen_cg: set[str] = set()
            for finding in delta.delta_findings:
                for sid in finding.triggering_statute_ids:
                    all_statutes.add(sid)
                for gz in finding.triggering_gazettes:
                    all_gazettes.add(gz)
                    if gz not in seen_cg:
                        seen_cg.add(gz)
                        contract_gazettes.append(gz)

            broken_count = len(delta.delta_findings)
            risk_pts = _RISK_SCORE_WEIGHT[delta.to_overall_risk]
            regression_pts = (
                30.0
                if delta.became_non_compliant
                else (15.0 if delta.compliance_regression_detected else 0.0)
            )
            clause_pts = min(25.0, float(broken_count) * 8.0)
            impact_score = round(
                min(100.0, risk_pts + regression_pts + clause_pts), 2
            )

            if broken_count > 0 or delta.became_non_compliant:
                bounds_hint = ", ".join(
                    f"{bk}: {bv['operator']} {bv['strictest_value']} {bv['unit']}".strip()
                    for bk, bv in sorted(bounds_summary.items())
                )
                rem_pract = (
                    f"[{contract.document_id}] Scope={eff_scope.value}; "
                    f"Risk={delta.from_overall_risk.value}->{delta.to_overall_risk.value}; "
                    f"Broken rules={', '.join(broken_rule_ids) or 'THRESHOLD_SHIFT'}. "
                    f"Tighten clauses to satisfy [{bounds_hint}]."
                )
                rem_rakyat = (
                    f"Contract '{contract.title or contract.document_id}' ({eff_scope.value}) "
                    f"needs updates for {broken_count} new rule(s) taking effect by "
                    f"{req.to_date.isoformat()}."
                )
            else:
                rem_pract = (
                    f"[{contract.document_id}] Scope={eff_scope.value}; no new statutory "
                    f"delta regressions between {req.from_date.isoformat()} and {req.to_date.isoformat()}."
                )
                rem_rakyat = (
                    f"Contract '{contract.title or contract.document_id}' remained unaffected by "
                    f"new rules between {req.from_date.isoformat()} and {req.to_date.isoformat()}."
                )

            impacts.append(
                PortfolioContractImpact(
                    document_id=contract.document_id,
                    title=contract.title,
                    territorial_scope=eff_scope,
                    rank=1,
                    impact_score=impact_score,
                    from_overall_risk=delta.from_overall_risk,
                    to_overall_risk=delta.to_overall_risk,
                    became_non_compliant=delta.became_non_compliant,
                    broken_clause_count=broken_count,
                    broken_rule_ids=broken_rule_ids,
                    triggering_gazettes=contract_gazettes,
                    strictest_deontic_bounds=bounds_summary,
                    pii_scrub=delta.pii_scrub,
                    remediation_summary_practitioner=rem_pract,
                    remediation_summary_rakyat=rem_rakyat,
                    delta_findings=delta.delta_findings,
                )
            )

        # Deterministic ranking: highest impact_score, newly non-compliant, most broken clauses
        impacts.sort(
            key=lambda item: (
                -item.impact_score,
                not item.became_non_compliant,
                -item.broken_clause_count,
                item.document_id,
            )
        )
        ranked = [
            item.model_copy(update={"rank": idx})
            for idx, item in enumerate(impacts, start=1)
        ]

        impacted_count = sum(
            1
            for item in ranked
            if item.became_non_compliant
            or item.broken_clause_count > 0
            or item.to_overall_risk != item.from_overall_risk
        )
        newly_non_compliant_count = sum(
            1 for item in ranked if item.became_non_compliant
        )

        sorted_gazettes = sorted(all_gazettes)
        sorted_statutes = sorted(all_statutes)

        exec_pract = (
            f"Scanned {len(ranked)} contract(s) across {req.from_date.isoformat()} -> "
            f"{req.to_date.isoformat()}. Impacted={impacted_count}, "
            f"Newly Non-Compliant={newly_non_compliant_count}. "
            f"Gazettes={', '.join(sorted_gazettes) or 'None'}."
        )
        exec_rakyat = (
            f"Checked {len(ranked)} agreements for legal updates between "
            f"{req.from_date.isoformat()} and {req.to_date.isoformat()}: "
            f"{newly_non_compliant_count} became non-compliant and require redline remediation."
        )

    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_holder[0],
        retry_count=0,
        is_verified_grounded=True,
    )

    return PortfolioBlastRadiusResponse(
        from_date=req.from_date,
        to_date=req.to_date,
        total_contracts_scanned=len(ranked),
        impacted_contracts_count=impacted_count,
        newly_non_compliant_count=newly_non_compliant_count,
        newly_commenced_gazettes=sorted_gazettes,
        affected_statute_ids=sorted_statutes,
        ranked_impacts=ranked,
        executive_summary_practitioner=exec_pract,
        executive_summary_rakyat=exec_rakyat,
        telemetry=telemetry,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )
