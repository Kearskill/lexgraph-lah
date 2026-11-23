from __future__ import annotations

import io
import zipfile
from datetime import date

from lexgraph_lah.compliance.fiscal_aige_scanner import evaluate_fiscal_aige_clauses
from lexgraph_lah.graph.bilingual_critic import audit_bilingual_pair
from lexgraph_lah.graph.deontic_solver import DeonticEnvelopeResolver
from lexgraph_lah.graph.diff_engine import evaluate_contract_delta_impact
from lexgraph_lah.graph.temporal_store import (
    build_upsert_amendment_cypher,
    get_default_temporal_store,
)
from lexgraph_lah.ingestion.contract_ast import build_contract_ast
from lexgraph_lah.schemas.domain import ContractDeltaAuditRequest


def _make_docx_with_table(body_inner_xml: str) -> bytes:
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body_inner_xml}</w:body></w:document>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", doc_xml.encode("utf-8"))
    return buf.getvalue()


def test_act378_stamp_act_sdsas_2026_point_in_time_and_clauses():
    """
    Verifies Stamp Act 1949 [Act 378] & SDSAS 2026:
      - Employment stamp duty exemption shifts RM300 -> RM3,000/month eff. 2026-01-01
      - SDSAS 30-day return/payment window, s. 52 inadmissibility, 8% foreign residential tier
      - Delta-audit flags RM300 -> RM3,000 transition across 2025-12-31 -> 2026-03-15
    """
    store = get_default_temporal_store()
    resolver = DeonticEnvelopeResolver(store)

    env_2025 = resolver.resolve(regimes=["ACT_378"], as_of_date=date(2025, 12, 31))
    env_2026 = resolver.resolve(regimes=["ACT_378"], as_of_date=date(2026, 3, 15))
    assert (
        env_2025.resolved_bounds[
            "employment_stamp_duty_exempt_monthly_myr"
        ].strictest_value
        == 300.0
    )
    assert (
        env_2026.resolved_bounds[
            "employment_stamp_duty_exempt_monthly_myr"
        ].strictest_value
        == 3000.0
    )
    assert (
        env_2026.resolved_bounds["stamp_duty_payment_max_days"].strictest_value == 30.0
    )
    assert (
        env_2026.resolved_bounds[
            "foreign_residential_transfer_stamp_duty_pct"
        ].strictest_value
        == 8.0
    )

    text_bad = (
        "Clause 4 Employment Stamp Duty Exemption: Monthly salaries up to RM 300 qualify for "
        "employment stamp duty exemption. SDSAS stamp duty payment within 60 days. "
        "Foreign non-citizen residential transfer stamp duty shall be 4%."
    )
    ast_g, _ = build_contract_ast(document_id="ACT378-TEST", raw_text=text_bad)
    findings = evaluate_fiscal_aige_clauses(
        ast_graph=ast_g,
        envelope=env_2026,
        as_of_date=date(2026, 3, 15),
        store=store,
    )
    violated = {sid for f in findings for sid in f.violated_statute_ids}
    assert "ACT-378-EMP-EXEMPT-V2" in violated
    assert "ACT-378-SDSAS-2026-V1" in violated
    assert "ACT-378-FOREIGN-RES-8PCT-V1" in violated

    delta = evaluate_contract_delta_impact(
        ContractDeltaAuditRequest(
            document_id="ACT378-DELTA",
            raw_text="Clause 4 Employment Stamp Duty Exemption: Up to RM 300 monthly salary exempt.",
            from_date=date(2025, 12, 31),
            to_date=date(2026, 3, 15),
            regimes=["ACT_378"],
        ),
        store=store,
    )
    assert any(
        d.rule_id == "DELTA-ACT_378-EMP-EXEMPT-3000" for d in delta.delta_findings
    )
    assert delta.telemetry.total_tokens == 0


def test_act53_myinvois_tables_carveout_72h_and_penalties():
    """
    Verifies Income Tax Act 1967 [Act 53] s. 82C & s. 120(1)(d) MyInvois pack:
      - RM500k (2025) -> RM3M (2026-08-30) exemption shift + related/holding-company carve-out
      - <w:tbl> Jadual Pembayaran > RM10,000 consolidated billing prohibition
      - 72h cancel window, TIN/UBL validation omission, and cross-border self-billed import trap
    """
    store = get_default_temporal_store()
    resolver = DeonticEnvelopeResolver(store)

    env_aug29 = resolver.resolve(regimes=["ACT_53"], as_of_date=date(2026, 8, 29))
    env_sep01 = resolver.resolve(regimes=["ACT_53"], as_of_date=date(2026, 9, 1))
    assert (
        env_aug29.resolved_bounds[
            "myinvois_annual_revenue_exemption_myr"
        ].strictest_value
        == 500_000.0
    )
    assert (
        env_sep01.resolved_bounds[
            "myinvois_annual_revenue_exemption_myr"
        ].strictest_value
        == 3_000_000.0
    )
    assert (
        env_sep01.resolved_bounds[
            "myinvois_consolidated_max_single_tx_myr"
        ].strictest_value
        == 10_000.0
    )
    assert (
        env_sep01.resolved_bounds[
            "myinvois_cancellation_rejection_max_hours"
        ].strictest_value
        == 72.0
    )
    assert (
        env_sep01.resolved_bounds[
            "myinvois_non_compliance_max_fine_myr"
        ].strictest_value
        == 20_000.0
    )

    docx_bytes = _make_docx_with_table(
        "<w:p><w:r><w:t>Jadual Pembayaran</w:t></w:r></w:p>"
        "<w:tbl>"
        "<w:tr><w:tc><w:p><w:r><w:t>Deliverable</w:t></w:r></w:p></w:tc>"
        "<w:tc><w:p><w:r><w:t>Single Transaction Value</w:t></w:r></w:p></w:tc>"
        "<w:tc><w:p><w:r><w:t>e-Invoice Type</w:t></w:r></w:p></w:tc></w:tr>"
        "<w:tr><w:tc><w:p><w:r><w:t>Cloud Migration</w:t></w:r></w:p></w:tc>"
        "<w:tc><w:p><w:r><w:t>RM 25,000</w:t></w:r></w:p></w:tc>"
        "<w:tc><w:p><w:r><w:t>Consolidated monthly e-invoice</w:t></w:r></w:p></w:tc></w:tr>"
        "</w:tbl>"
        "<w:p><w:r><w:t>Clause 9 Billing: Supplier may cancel validated e-invoice after 72 hours, provides no TIN or UBL fields, waives self-billed foreign import e-invoices, and claims RM 3,000,000 exemption as a related subsidiary.</w:t></w:r></w:p>"
    )
    ast_g, _ = build_contract_ast(
        document_id="ACT53-TBL", file_bytes=docx_bytes, filename="myinvois_tbl.docx"
    )
    assert any(c.section_type == "SCHEDULE" and c.table_rows for c in ast_g.clauses)

    findings = evaluate_fiscal_aige_clauses(
        ast_graph=ast_g,
        envelope=env_sep01,
        as_of_date=date(2026, 9, 1),
        store=store,
    )
    cats = " | ".join(f.category for f in findings)
    violated = {sid for f in findings for sid in f.violated_statute_ids}
    assert "ACT-53-MYINVOIS-10K-V1" in violated
    assert "ACT-53-SEC-120-1D-V1" in violated
    assert "ACT-53-SEC-82C-P1-V1" in violated
    assert "ACT-53-MYINVOIS-EXEMPT-V2" in violated
    assert "72-Hour" in cats
    assert "Self-Billed" in cats


def test_aige_voluntary_modality_bnm_outsourcing_and_cypher_bilingual():
    """
    Verifies MOSTI AIGE VOLUNTARY_GUIDELINE separation from mandatory BNM Outsourcing
    breaches, Act 388 s. 63 alignment across all new EN/BM pairs, and parameterized
    Cypher output containing regime_code and carve_out_metadata_json.
    """
    store = get_default_temporal_store()
    resolver = DeonticEnvelopeResolver(store)
    env = resolver.resolve(
        regimes=["MOSTI_AIGE", "BNM_RMIT", "ACT_709"], as_of_date=date(2026, 3, 15)
    )
    assert (
        env.resolved_bounds["aige_seven_principles_alignment"].modality
        == "VOLUNTARY_GUIDELINE"
    )
    assert (
        env.resolved_bounds["bnm_crypto_key_ownership_fi_retained"].modality
        == "OBLIGATION"
    )

    text = (
        "Clause 11 AI & Outsourcing: The automated AI model operates without human oversight "
        "and with no AI audit trail. Vendor retains sole ownership of encryption keys and may "
        "sub-contract without prior approval while excluding BNM audit access."
    )
    ast_g, _ = build_contract_ast(document_id="AIGE-BNM-01", raw_text=text)
    findings = evaluate_fiscal_aige_clauses(
        ast_graph=ast_g,
        envelope=env,
        as_of_date=date(2026, 3, 15),
        store=store,
    )
    voluntary = [f for f in findings if f.is_voluntary_guideline]
    mandatory = [f for f in findings if not f.is_voluntary_guideline]
    assert len(voluntary) == 1
    assert voluntary[0].deontic_modality == "VOLUNTARY_GUIDELINE"
    assert "MOSTI-AIGE-2024-PRINCIPLES-V1" in voluntary[0].violated_statute_ids
    assert any("BNM-OUTSOURCING-2019-V1" in f.violated_statute_ids for f in mandatory)

    # All 13 newly seeded bilingual EN/BM pairs must be ALIGNED under Act 388 s. 63
    new_en_ids = [
        "ACT-388-SEC-54-V1",
        "ACT-378-SEC-52-V1",
        "ACT-378-SDSAS-2026-V1",
        "ACT-378-EMP-EXEMPT-V1",
        "ACT-378-EMP-EXEMPT-V2",
        "ACT-378-FOREIGN-RES-8PCT-V1",
        "ACT-53-SEC-82C-P1-V1",
        "ACT-53-MYINVOIS-10K-V1",
        "ACT-53-MYINVOIS-EXEMPT-V1",
        "ACT-53-MYINVOIS-EXEMPT-V2",
        "ACT-53-SEC-120-1D-V1",
        "MOSTI-AIGE-2024-PRINCIPLES-V1",
        "BNM-OUTSOURCING-2019-V1",
    ]
    for nid in new_en_ids:
        en_node = store.nodes[nid]
        assert en_node.translation_node_id is not None
        bm_node = store.nodes[en_node.translation_node_id]
        rep = audit_bilingual_pair(en_node=en_node, bm_node=bm_node)
        assert rep.alignment_status == "ALIGNED", f"{nid} drifted: {rep.issues}"

    cypher_payload = build_upsert_amendment_cypher(
        store.nodes["ACT-53-MYINVOIS-EXEMPT-V2"]
    )
    cypher_str = cypher_payload.query
    params = cypher_payload.params
    assert "$regime_code" in cypher_str
    assert "$carve_out_metadata_json" in cypher_str
    assert params["regime_code"] == "ACT_53"
    assert "related_company" in params["carve_out_metadata_json"]
