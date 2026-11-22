from datetime import date

import pytest

from lexgraph_lah.graph.deontic_solver import DeonticEnvelopeResolver, normalize_regimes
from lexgraph_lah.graph.diff_engine import evaluate_contract_delta_impact
from lexgraph_lah.graph.temporal_store import get_default_temporal_store
from lexgraph_lah.schemas.domain import (
    ContractDeltaAuditRequest,
    RiskSeverity,
    TemporalEdgeType,
)


def test_act854_subsidiary_suite_and_exemption_order_carve_out():
    """
    Verifies P.U. (A) 219/2024, 220/2024, 221/2024, 222/2024 and Cyber Security
    (Exemption) Order 2025 [P.U. (A) 47/2025] temporal carve-out metadata.
    """
    store = get_default_temporal_store()

    # Before 2024-08-26: Act 854 regulations inactive
    pre_csa = {
        n.node_id for n in store.query_point_in_time(as_of_date=date(2024, 8, 1))
    }
    assert "PUA-219-2024-REG-3" not in pre_csa
    assert "PUA-221-2024-REG-3" not in pre_csa
    assert "PUA-222-2024-REG-2" not in pre_csa

    # On 2024-09-01: 219, 220, 221, 222 active; P.U. (A) 47/2025 (eff. 2025-02-01) NOT yet active
    late_2024 = {
        n.node_id for n in store.query_point_in_time(as_of_date=date(2024, 9, 1))
    }
    assert {
        "PUA-219-2024-REG-3",
        "PUA-220-2024-REG-4",
        "PUA-221-2024-REG-3",
        "PUA-222-2024-REG-2",
        "CSA-2024-SEC-27-V1",
    } <= late_2024
    assert "PUA-47-2025-EXEMPT" not in late_2024

    # On 2025-02-01+: Exemption Order 2025 active with carve_out_metadata
    post_exempt = {
        n.node_id for n in store.query_point_in_time(as_of_date=date(2025, 3, 1))
    }
    assert "PUA-47-2025-EXEMPT" in post_exempt
    exempt_node = store.nodes["PUA-47-2025-EXEMPT"]
    assert exempt_node.gazette_date == date(2025, 1, 28)
    assert exempt_node.carve_out_metadata is not None
    assert exempt_node.carve_out_metadata["instrument"] == "P.U. (A) 47/2025"

    resolver = DeonticEnvelopeResolver(store)
    env = resolver.resolve(regimes=["ACT_854"], as_of_date=date(2026, 3, 15))
    assert (
        env.resolved_bounds["ncii_risk_assessment_max_interval_months"].strictest_value
        == 12.0
    )
    assert (
        env.resolved_bounds["ncii_independent_audit_max_interval_years"].strictest_value
        == 2.0
    )
    assert (
        env.resolved_bounds["mssp_soc_pentest_nacsa_license_required"].strictest_value
        is True
    )
    assert (
        env.resolved_bounds["csa_offence_compounding_max_fine_pct"].strictest_value
        == 50.0
    )


def test_pdpa_act_a1727_three_commencement_phases_and_multi_recipient_breach_duties():
    """
    Verifies Act A1727 3-phase commencement (2025-01-01, 2025-04-01, 2025-06-01)
    and ensures DeonticEnvelopeResolver resolves both strictest initial clock AND
    distinct recipient-specific obligations without conflating recipients.
    """
    store = get_default_temporal_store()
    resolver = DeonticEnvelopeResolver(store)

    # Phase 1 only (2025-02-01): Phase 2 & 3 not active yet
    p1_ids = {n.node_id for n in store.query_point_in_time(as_of_date=date(2025, 2, 1))}
    assert "PUB-522-2024-P1" in p1_ids
    assert "PDPA-2010-SEC-129-V1" in p1_ids
    assert "PDPA-2010-SEC-129-V2" not in p1_ids
    assert "PDPA-2010-SEC-4-BIOMETRIC-V1" not in p1_ids
    assert "PDPA-2010-SEC-43A-V1" not in p1_ids

    # Phase 2 active (2025-05-01): s. 9 P2 processor fine, biometric data, s. 129 V2, CBPDT 03/2025; Phase 3 still inactive
    p2_ids = {n.node_id for n in store.query_point_in_time(as_of_date=date(2025, 5, 1))}
    assert {
        "PUB-522-2024-P2",
        "PDPA-2010-SEC-9-P2-PROC",
        "PDPA-2010-SEC-4-BIOMETRIC-V1",
        "PDPA-2010-SEC-129-V2",
        "PDPD-CBPDT-2025-03",
    } <= p2_ids
    assert "PDPA-2010-SEC-129-V1" not in p2_ids
    assert "PDPA-2010-SEC-43A-V1" not in p2_ids
    assert "PDPD-DBN-2025-02" not in p2_ids

    # Phase 3 active (2025-06-15+): s. 43A Data Portability, DPO 01/2025, DBN 02/2025 (72h + 7d + 2y)
    p3_ids = {
        n.node_id for n in store.query_point_in_time(as_of_date=date(2025, 6, 15))
    }
    assert {
        "PUB-522-2024-P3",
        "PDPA-2010-SEC-43A-V1",
        "PDPD-DPO-2025-01",
        "PDPD-DBN-2025-02",
    } <= p3_ids

    # Multi-recipient breach envelope: BNM (1h) + NACSA (6h/14d) + PDPA Commissioner (72h) + Data Subject (7d)
    env = resolver.resolve(
        regimes=["ACT_709", "ACT_854", "BNM_RMIT"],
        as_of_date=date(2026, 3, 15),
    )
    assert env.resolved_bounds["incident_notice_max_hours"].strictest_value == 1.0
    assert (
        env.resolved_bounds["incident_notice_max_hours"].dominating_regime == "BNM_RMIT"
    )
    assert (
        env.resolved_bounds["data_subject_breach_notice_max_days"].strictest_value
        == 7.0
    )
    assert (
        env.resolved_bounds["breach_register_min_retention_years"].strictest_value
        == 2.0
    )

    # Recipient-specific duties remain distinct and unconflated
    assert "PDPA_COMMISSIONER:INITIAL_NOTICE" in env.recipient_obligations
    assert (
        env.recipient_obligations["PDPA_COMMISSIONER:INITIAL_NOTICE"].threshold_value
        == 72.0
    )
    assert "AFFECTED_DATA_SUBJECT:DATA_SUBJECT_NOTICE" in env.recipient_obligations
    assert (
        env.recipient_obligations[
            "AFFECTED_DATA_SUBJECT:DATA_SUBJECT_NOTICE"
        ].threshold_value
        == 7.0
    )
    assert "BNM_SUPERVISOR:INITIAL_NOTICE" in env.recipient_obligations
    assert (
        env.recipient_obligations["BNM_SUPERVISOR:INITIAL_NOTICE"].threshold_value
        == 1.0
    )
    assert "NACSA:INITIAL_NOTICE" in env.recipient_obligations
    assert env.recipient_obligations["NACSA:INITIAL_NOTICE"].threshold_value == 6.0
    assert "NACSA:FULL_REPORT" in env.recipient_obligations
    assert env.recipient_obligations["NACSA:FULL_REPORT"].threshold_value == 14.0


def test_2025_2026_statutes_act864_act866_act873_act562_act563_and_delta_audit():
    """
    Verifies Act 864 (eff. 2025-04-28), Act 866 (2026-01-01 & Codes 2026-06-01),
    Act 873 (2026-03-01 & SKP 2026-06-01), Act 562 & Act 563 cross-references,
    and Contract Delta-Audit regressions across these enactments.
    """
    assert normalize_regimes(["act 864", "onsa", "bnpl", "act 562", "act 563"]) == [
        "ACT_864",
        "ACT_866",
        "ACT_873",
        "ACT_562",
        "ACT_563",
    ]

    store = get_default_temporal_store()
    resolver = DeonticEnvelopeResolver(store)

    # Pre-2025-04-28: Act 864 inactive
    pre_864 = resolver.resolve(regimes=["ACT_864"], as_of_date=date(2025, 4, 1))
    assert "ACT-864-SEC-17-V1" not in pre_864.active_node_ids

    # Post-2025-04-28: Act 864 s. 17(1) active
    post_864 = resolver.resolve(regimes=["ACT_864"], as_of_date=date(2025, 5, 1))
    assert (
        post_864.resolved_bounds[
            "public_sector_third_party_data_protection"
        ].strictest_value
        is True
    )

    # Act 866 phased: 2026-02-01 (RM10M + MCMC 24h) vs 2026-06-15 (+ under-16 MyKad age verification)
    env_866_early = resolver.resolve(regimes=["ACT_866"], as_of_date=date(2026, 2, 1))
    assert (
        env_866_early.resolved_bounds["online_safety_max_penalty_myr"].strictest_value
        == 10_000_000.0
    )
    assert (
        env_866_early.recipient_obligations[
            "MCMC:HARMFUL_CONTENT_REPORT"
        ].threshold_value
        == 24.0
    )
    assert (
        "online_safety_under_16_age_verification" not in env_866_early.resolved_bounds
    )

    env_866_mid = resolver.resolve(regimes=["ACT_866"], as_of_date=date(2026, 6, 15))
    assert (
        env_866_mid.resolved_bounds[
            "online_safety_under_16_age_verification"
        ].strictest_value
        is True
    )

    # Act 873 phased: 2026-04-01 (Rule-of-78 forbidden) vs 2026-06-15 (+ SKP licensing)
    env_873_early = resolver.resolve(regimes=["ACT_873"], as_of_date=date(2026, 4, 1))
    assert "rule_of_78_interest_prohibition" in env_873_early.resolved_bounds
    assert "skp_non_bank_credit_license_required" not in env_873_early.resolved_bounds

    env_873_mid = resolver.resolve(regimes=["ACT_873"], as_of_date=date(2026, 6, 15))
    assert (
        env_873_mid.resolved_bounds[
            "skp_non_bank_credit_license_required"
        ].strictest_value
        is True
    )

    # Act 562 & Act 563 cross-references
    assert any(
        e.source_id == "ACT-658-SEC-7-V1"
        and e.target_id == "ACT-562-SEC-62-V1"
        and e.edge_type == TemporalEdgeType.CITES
        for e in store.edges
    )
    assert any(
        e.source_id == "CSA-2024-SEC-23-V1"
        and e.target_id == "ACT-563-SEC-3-V1"
        and e.edge_type == TemporalEdgeType.CITES
        for e in store.edges
    )

    # Contract Delta-Audit checks for MSSP licensing, Act 864 s. 17(1), Act 873 BNPL, and PDPA dual-recipient
    delta_mssp = evaluate_contract_delta_impact(
        ContractDeltaAuditRequest(
            document_id="D-MSSP",
            raw_text="Vendor provides managed SOC monitoring and penetration testing without NACSA licence.",
            from_date=date(2024, 6, 15),
            to_date=date(2026, 3, 15),
            regimes=["ACT_854"],
        ),
        store=store,
    )
    assert delta_mssp.became_non_compliant is True
    assert any(
        f.rule_id == "DELTA-ACT_854-PUA221-MSSP" for f in delta_mssp.delta_findings
    )

    delta_864 = evaluate_contract_delta_impact(
        ContractDeltaAuditRequest(
            document_id="D-864",
            raw_text="Vendor performing public-sector shared data migration disclaims all statutory duty under Act 864.",
            from_date=date(2025, 3, 1),
            to_date=date(2026, 3, 15),
            regimes=["ACT_864"],
        ),
        store=store,
    )
    assert delta_864.became_non_compliant is True
    assert any(
        f.rule_id == "DELTA-ACT_864-SEC17-VENDOR" for f in delta_864.delta_findings
    )

    delta_873 = evaluate_contract_delta_impact(
        ContractDeltaAuditRequest(
            document_id="D-873",
            raw_text="BNPL lender charges Rule-of-78 flat-rate interest and operates without SKP licence.",
            from_date=date(2026, 1, 15),
            to_date=date(2026, 7, 1),
            regimes=["ACT_873"],
        ),
        store=store,
    )
    assert delta_873.became_non_compliant is True
    assert delta_873.to_overall_risk == RiskSeverity.CRITICAL
    assert {
        "DELTA-ACT_873-RULE78",
        "DELTA-ACT_873-SKP-LIC",
    } <= {f.rule_id for f in delta_873.delta_findings}

    delta_pdpa_p3 = evaluate_contract_delta_impact(
        ContractDeltaAuditRequest(
            document_id="D-PDPA-P3",
            raw_text=(
                "Section 9 Security Principle: Processor applies encryption. "
                "Data User notifies Commissioner within 72 hours, notifies affected data subjects within 21 days, "
                "and maintains a breach register for 6 months."
            ),
            from_date=date(2025, 4, 15),
            to_date=date(2026, 3, 15),
            regimes=["ACT_709"],
        ),
        store=store,
    )
    assert {
        "DELTA-ACT709-P3-SUBJECT-7D",
        "DELTA-ACT709-P3-REGISTER-2Y",
    } <= {f.rule_id for f in delta_pdpa_p3.delta_findings}


@pytest.mark.asyncio
async def test_phase1_verification_sanity():
    from lexgraph_lah.agents.graph import build_compliance_graph

    graph = build_compliance_graph()
    out = await graph.ainvoke(
        {
            "document_id": "P1-BNPL-01",
            "raw_text": "SEC-35.1 BNPL: Non-bank BNPL lender applies Rule-of-78 flat-rate interest.",
            "reference_date": "2026-07-01",
            "regimes": ["ACT_873"],
            "extracted_clauses": [],
            "auditor_feedback": "",
            "is_grounded": False,
            "retry_count": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
        }
    )
    assert out["is_grounded"] is True
    assert out["extracted_clauses"][0].violated_statute_ids == ["ACT-873-SEC-35-V1"]
