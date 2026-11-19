import re
import time
import uuid
from datetime import date

from lexgraph_lah.config import settings
from lexgraph_lah.graph.bilingual_critic import audit_bilingual_pair
from lexgraph_lah.graph.reranker import rerank_statutes_and_spans
from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    get_default_temporal_store,
)
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    AuthorityTier,
    BilingualClausePair,
    BilingualDivergenceReport,
    IRACAnalysis,
    PDPAComplianceScanRequest,
    PDPAComplianceScanResponse,
    PDPAGapItem,
    RakyatGuidance,
    RiskSeverity,
    SourceSpan,
    StatutoryNode,
    TerritorialScope,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import (
    ComplianceSpanRecord,
    measure_latency_ms,
    telemetry_registry,
)

_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
    RiskSeverity.CRITICAL: 4,
}


def _extract_matching_sentence(text: str, keywords: tuple[str, ...]) -> str:
    segments = [seg.strip() for seg in re.split(r"(?<=[.!?\n])\s+", text.strip()) if seg.strip()]
    for seg in segments:
        low = seg.lower()
        if any(kw in low for kw in keywords):
            return seg
    return segments[0] if segments else text.strip()


def _max_chunk_relevance(
    masked_text: str,
    active_nodes: list[StatutoryNode],
    threshold: float,
    territorial_scope: TerritorialScope,
) -> tuple[bool, float]:
    chunks = [
        c.strip()
        for c in re.split(r"(?<=[.!?\n;])\s+", masked_text.strip())
        if len(c.strip()) >= 8
    ]
    if not chunks:
        chunks = [masked_text.strip()]

    best_score = 0.0
    any_passed = False
    for chunk in chunks:
        abstained, max_score, _, _, _ = rerank_statutes_and_spans(
            query=chunk,
            nodes=active_nodes,
            abstention_threshold=threshold,
            territorial_scope=territorial_scope,
        )
        best_score = max(best_score, max_score)
        if not abstained:
            any_passed = True

    if not any_passed:
        abstained_full, full_score, _, _, _ = rerank_statutes_and_spans(
            query=masked_text,
            nodes=active_nodes,
            abstention_threshold=threshold,
            territorial_scope=territorial_scope,
        )
        best_score = max(best_score, full_score)
        if not abstained_full:
            any_passed = True

    return (not any_passed), round(best_score, 4)


def _spans_for_nodes(
    store: TemporalGraphStore,
    node_ids: list[str],
) -> tuple[list[str], list[SourceSpan]]:
    spans: list[SourceSpan] = []
    span_ids: list[str] = []
    for nid in node_ids:
        node = store.nodes.get(nid)
        if node:
            for sp in node.source_spans:
                if sp.span_id not in span_ids:
                    span_ids.append(sp.span_id)
                    spans.append(sp)
    return span_ids, spans


def _build_bilingual_provisions(
    store: TemporalGraphStore,
    node_ids: list[str],
    as_of_date: date | None = None,
) -> tuple[list[BilingualClausePair], list[BilingualDivergenceReport]]:
    pairs: list[BilingualClausePair] = []
    warnings: list[BilingualDivergenceReport] = []
    seen_keys: set[str] = set()
    for nid in node_ids:
        pair = store.get_bilingual_pair(nid)
        if pair:
            key = f"{pair.act_number}:{pair.section_code}"
            if key not in seen_keys:
                seen_keys.add(key)
                report = audit_bilingual_pair(
                    en_node=pair.en_node,
                    bm_node=pair.bm_node,
                    authoritative_node_id=pair.authoritative_node_id,
                    as_of_date=as_of_date,
                    provision_id=nid,
                    act_name=pair.act_name,
                    act_number=pair.act_number,
                    section_code=pair.section_code,
                )
                enriched = pair.model_copy(update={"divergence_report": report})
                pairs.append(enriched)
                if report.has_divergence:
                    warnings.append(report)
    return pairs, warnings


def build_persona_summaries(
    document_id: str,
    as_of_date: date,
    gaps: list[PDPAGapItem],
    overall_risk: RiskSeverity,
) -> tuple[IRACAnalysis, RakyatGuidance]:
    """Synthesizes top-level Practitioner (IRAC) and Rakyat Literacy Mode summaries."""
    non_compliant = [g for g in gaps if g.status != "COMPLIANT"]
    if not non_compliant:
        irac = IRACAnalysis(
            issue=f"Whether {document_id} complies with Act 709 (PDPA) obligations active on {as_of_date.isoformat()}.",
            rule="Personal Data Protection Act 2010 [Act 709] (as amended by Act A1727 & P.U. (A) 342/2024 where effective).",
            application="Evaluated clauses align with statutory Security, Consent, Disclosure, and Breach Notification controls.",
            conclusion=f"Overall Risk: {overall_risk.value}. No material statutory non-compliance gaps detected.",
        )
        rakyat = RakyatGuidance(
            plain_summary_en="Your document meets Malaysia's personal data protection checks for this date. No urgent compliance violations were found.",
            plain_summary_bm="Dokumen anda mematuhi semakan perlindungan data peribadi Malaysia bagi tarikh rujukan ini. Tiada pelanggaran berkanun utama dikesan.",
            gov_my_checklist=[
                "Keep a signed copy of your bilingual Bahasa Melayu and English Privacy Notice accessible to customers.",
                "Verify your Data Protection Officer (DPO) contact channel is updated on portal.pdp.gov.my (if applicable post-2025).",
                "Review vendor data processing agreements annually at pdp.gov.my.",
            ],
            official_portals=[
                "https://www.pdp.gov.my",
                "https://portal.pdp.gov.my",
                "https://lom.agc.gov.my",
            ],
        )
        return irac, rakyat

    cited_sections = ", ".join(g.section_ref for g in non_compliant)
    top_issues = "; ".join(f"{g.principle_name} ({g.severity.value})" for g in non_compliant)
    irac = IRACAnalysis(
        issue=f"Whether {document_id} exposes the Data User / Data Processor to statutory liability under {cited_sections} as of {as_of_date.isoformat()}.",
        rule=(
            "Personal Data Protection Act 2010 [Act 709] Part II Principles (ss. 6-12), "
            "Section 130 Unlawful Disclosure, and where effective (>= 2025-01-01), PDPA (Amendment) Act 2024 "
            "[Act A1727] ss. 9(1A), 12A, 12B & P.U. (A) 342/2024."
        ),
        application=f"Detected {len(non_compliant)} statutory gap(s): {top_issues}.",
        conclusion=f"Overall Risk: {overall_risk.value}. Immediate contractual redline and statutory remediation required prior to execution.",
    )
    rakyat = RakyatGuidance(
        plain_summary_en=(
            f"Warning ({overall_risk.value} Risk): This document has {len(non_compliant)} data protection "
            f"issue(s) under Malaysian law ({cited_sections}). For example, it may weaken security protection, "
            "delay breach alerts past the 72-hour legal limit, or omit clear consent/DPO safeguards."
        ),
        plain_summary_bm=(
            f"Amaran (Risiko {overall_risk.value}): Dokumen ini mempunyai {len(non_compliant)} jurang pematuhan "
            f"di bawah Akta 709 ({cited_sections}), seperti pengecualian liabiliti pemproses data atau kelewatan notis kebocoran data melebihi 72 jam."
        ),
        gov_my_checklist=[
            "Do NOT sign or publish clauses that waive processor security liability or permit selling personal data without consent.",
            "Update breach reporting timelines so the Commissioner (JPDP) can be notified within 72 hours via https://portal.pdp.gov.my.",
            "Provide a clear bilingual Privacy Notice (Bahasa Melayu & English) and appoint a DPO if required under Section 12A.",
            "Members of the public can lodge PDPA complaints or verify statutory rules at https://www.pdp.gov.my.",
        ],
        official_portals=[
            "https://www.pdp.gov.my",
            "https://portal.pdp.gov.my",
            "https://lom.agc.gov.my",
        ],
    )
    return irac, rakyat


def scan_pdpa_compliance(
    req: PDPAComplianceScanRequest,
    store: TemporalGraphStore | None = None,
    record_telemetry: bool = True,
) -> PDPAComplianceScanResponse:
    """
    Pre-flight PII-scrubbed Act 709 (PDPA) Compliance Gap Scanner returning strict
    Pydantic schema outputs mapped to Act 709 principles, bi-temporal effective dates,
    5-tier authorities, and verifiable SourceSpan IDs.
    """
    graph_store = store or get_default_temporal_store()
    effective_date = req.as_of_date or date.today()
    threshold = (
        req.abstention_threshold
        if req.abstention_threshold is not None
        else settings.abstention_threshold
    )

    with measure_latency_ms() as elapsed_holder:
        # 1. Pre-flight PII scrubbing BEFORE any retrieval, scoring, or downstream call
        pii_scrub = scrub_malaysian_pii(req.raw_text)
        safe_text = pii_scrub.masked_text
        low_text = safe_text.lower()

        # 2. Bi-temporal & territorial active statute lookup
        active_nodes = graph_store.query_point_in_time(
            as_of_date=effective_date,
            include_citations=True,
            include_translations=True,
            territorial_scope=req.territorial_scope,
        )

        # 3. Deterministic 0.78 Abstention Gate
        is_abstained, max_score = _max_chunk_relevance(
            masked_text=safe_text,
            active_nodes=active_nodes,
            threshold=threshold,
            territorial_scope=req.territorial_scope,
        )

        if is_abstained:
            telemetry = compute_telemetry_summary(
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=elapsed_holder[0],
                retry_count=0,
                is_verified_grounded=True,
                trace_id=f"scan-{uuid.uuid4().hex[:8]}",
            )
            return PDPAComplianceScanResponse(
                document_id=req.document_id,
                as_of_date=effective_date,
                territorial_scope=req.territorial_scope,
                persona=req.persona,
                is_abstained=True,
                abstention_reason=(
                    f"ABSTAINED: Document returned 0 verified Malaysian statutory SourceSpans "
                    f"above relevance threshold {threshold:.2f} (max_score={max_score:.4f})."
                ),
                max_relevance_score=max_score,
                overall_risk=RiskSeverity.LOW,
                compliance_score_pct=0.0,
                pii_scrub=pii_scrub,
                gaps=[],
                bilingual_provisions=[],
                irac_summary=None,
                rakyat_summary=None,
                disclaimer=DEFAULT_LEGAL_DISCLAIMER,
                telemetry=telemetry,
            )

        is_post_2025 = effective_date >= date(2025, 1, 1)
        sec9_node_id = "PDPA-2010-SEC-9-V2" if is_post_2025 else "PDPA-2010-SEC-9-V1"
        gaps: list[PDPAGapItem] = []
        implicated_node_ids: list[str] = [sec9_node_id, "PDPA-2010-SEC-130-V1"]

        # Rule 1: Security Principle & Processor Liability (Section 9)
        has_security_violation = any(
            kw in low_text
            for kw in (
                "zero statutory liability",
                "waive",
                "unencrypted",
                "plaintext",
                "waives all rights to inspect",
                "exclude",
            )
        )
        sec9_nodes = [sec9_node_id] + (
            ["PDPA-2010-SEC-9-V2-SUB-1A"] if is_post_2025 else []
        )
        sec9_span_ids, sec9_spans = _spans_for_nodes(graph_store, sec9_nodes)
        sec9_quote = _extract_matching_sentence(
            safe_text,
            ("security", "liability", "processor", "encryption", "plaintext", "keselamatan"),
        )
        if has_security_violation:
            gaps.append(
                PDPAGapItem(
                    rule_id="ACT709-SEC9-SECURITY",
                    principle_name="Security Principle & Processor Liability",
                    section_ref="Section 9 & 9(1A) [Act 709]" if is_post_2025 else "Section 9 [Act 709]",
                    status="NON_COMPLIANT",
                    severity=RiskSeverity.CRITICAL,
                    exact_quote=sec9_quote,
                    gap_description=(
                        "Clause excludes processor statutory liability or permits unencrypted/unsecured "
                        f"processing in breach of {sec9_node_id} (penalties up to RM 1,000,000)."
                        if is_post_2025
                        else "Clause weakens practical security safeguards required under PDPA 2010 Section 9 (V1)."
                    ),
                    remediation_action=(
                        "Remove liability waivers and require ISO/IEC 27001 technical safeguards, "
                        "encryption at rest, and direct Data Processor compliance with Section 9."
                    ),
                    source_span_ids=sec9_span_ids,
                    source_spans=sec9_spans,
                    authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
                    gazette_ref="Act A1727 / P.U. (B) 512/2024" if is_post_2025 else "Act 709",
                    irac=IRACAnalysis(
                        issue="Can a Data Processor exclude statutory security liability or store personal data in plaintext?",
                        rule=f"Act 709 {sec9_node_id}: Both Data Users and Data Processors must implement practical security safeguards.",
                        application=f"Quoted clause ('{sec9_quote}') purports to waive/undermine mandatory security obligations.",
                        conclusion="Non-compliant (CRITICAL). Clause is unenforceable against statutory liability and must be redlined.",
                    ),
                    rakyat_guidance=RakyatGuidance(
                        plain_summary_en="Companies handling your data cannot contract out of keeping your NRIC and personal records safe.",
                        plain_summary_bm="Syarikat atau vendor tidak boleh mengecualikan tanggungjawab mereka untuk melindungi data peribadi anda.",
                        gov_my_checklist=[
                            "Require encryption for NRIC, phone, and financial records.",
                            "Verify vendor accountability at https://www.pdp.gov.my.",
                        ],
                        official_portals=["https://www.pdp.gov.my"],
                    ),
                )
            )
        else:
            gaps.append(
                PDPAGapItem(
                    rule_id="ACT709-SEC9-SECURITY",
                    principle_name="Security Principle & Processor Liability",
                    section_ref="Section 9 [Act 709]",
                    status="COMPLIANT",
                    severity=RiskSeverity.LOW,
                    exact_quote=sec9_quote,
                    gap_description=f"Security obligations align with {sec9_node_id}.",
                    remediation_action="Maintain periodic security audits and encryption controls.",
                    source_span_ids=sec9_span_ids,
                    source_spans=sec9_spans,
                    authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
                    gazette_ref="Act A1727" if is_post_2025 else "Act 709",
                    irac=IRACAnalysis(
                        issue="Does the document uphold Act 709 Section 9 Security Principle controls?",
                        rule=f"Act 709 {sec9_node_id} mandates practical organizational and technical security safeguards.",
                        application="No liability exclusions or plaintext storage terms were detected.",
                        conclusion="Compliant with Section 9.",
                    ),
                    rakyat_guidance=RakyatGuidance(
                        plain_summary_en="Security requirements look aligned with Malaysian personal data rules.",
                        plain_summary_bm="Langkah keselamatan dokumen ini selaras dengan Prinsip Keselamatan Akta 709.",
                        gov_my_checklist=["Review security controls annually."],
                        official_portals=["https://www.pdp.gov.my"],
                    ),
                )
            )

        # Rule 2: Mandatory 72-Hour Data Breach Notification (Sec 12B + P.U. (A) 342/2024)
        if is_post_2025:
            implicated_node_ids.extend(["PDPA-2010-SEC-12B-V1", "PUA-342-2024-REG-3"])
            b_span_ids, b_spans = _spans_for_nodes(
                graph_store, ["PDPA-2010-SEC-12B-V1", "PUA-342-2024-REG-3"]
            )
            breach_quote = _extract_matching_sentence(
                safe_text, ("breach", "incident", "notify", "notification", "kebocoran", "pecah data")
            )
            delayed_breach = any(
                kw in low_text
                for kw in ("14 days", "10 days", "14 business days", "sole discretion", "without notice", "30 days")
            )
            has_72h = ("72 hours" in low_text or "24 hours" in low_text or "48 hours" in low_text or "72 jam" in low_text)
            if delayed_breach or ("breach" in low_text and not has_72h):
                gaps.append(
                    PDPAGapItem(
                        rule_id="ACT709-SEC12B-BREACH",
                        principle_name="Mandatory 72-Hour Data Breach Notification",
                        section_ref="Section 12B [Act 709] & Reg 3 [P.U. (A) 342/2024]",
                        status="NON_COMPLIANT",
                        severity=RiskSeverity.HIGH,
                        exact_quote=breach_quote,
                        gap_description=(
                            "Breach notification window exceeds or omits the mandatory 72-hour Commissioner "
                            "notification timeline under Section 12B and P.U. (A) 342/2024."
                        ),
                        remediation_action=(
                            "Mandate Data Processor notification within 24 hours so the Data User can notify "
                            "the Commissioner within 72 hours via portal.pdp.gov.my."
                        ),
                        source_span_ids=b_span_ids,
                        source_spans=b_spans,
                        authority_tier=AuthorityTier.TIER_4_SUBSIDIARY_LEGISLATION,
                        gazette_ref="P.U. (A) 342/2024",
                        irac=IRACAnalysis(
                            issue="Does the breach notification window comply with Section 12B and P.U. (A) 342/2024?",
                            rule="Section 12B [Act A1727] & P.U. (A) 342/2024 require Commissioner notification within 72 hours.",
                            application=f"Quoted clause ('{breach_quote}') delays or omits the 72-hour mandatory reporting window.",
                            conclusion="Non-compliant (HIGH). Revise SLA to <= 24h processor-to-user and <= 72h user-to-Commissioner.",
                        ),
                        rakyat_guidance=RakyatGuidance(
                            plain_summary_en="If your personal data is leaked, the company must alert Malaysia's PDPA Commissioner within 72 hours (3 days).",
                            plain_summary_bm="Jika berlaku kebocoran data peribadi, syarikat wajib melaporkan kepada Pesuruhjaya dalam masa 72 jam.",
                            gov_my_checklist=[
                                "Report confirmed data leaks within 72 hours at https://portal.pdp.gov.my.",
                                "Alert affected individuals promptly if there is risk of significant harm.",
                            ],
                            official_portals=["https://portal.pdp.gov.my"],
                        ),
                    )
                )
            elif has_72h:
                gaps.append(
                    PDPAGapItem(
                        rule_id="ACT709-SEC12B-BREACH",
                        principle_name="Mandatory 72-Hour Data Breach Notification",
                        section_ref="Section 12B [Act 709] & Reg 3 [P.U. (A) 342/2024]",
                        status="COMPLIANT",
                        severity=RiskSeverity.LOW,
                        exact_quote=breach_quote,
                        gap_description="Breach notification SLA meets the 72-hour statutory requirement.",
                        remediation_action="Keep incident response runbook aligned with P.U. (A) 342/2024 template.",
                        source_span_ids=b_span_ids,
                        source_spans=b_spans,
                        authority_tier=AuthorityTier.TIER_4_SUBSIDIARY_LEGISLATION,
                        gazette_ref="P.U. (A) 342/2024",
                        irac=IRACAnalysis(
                            issue="Does the breach SLA satisfy Section 12B?",
                            rule="Section 12B mandates 72-hour Commissioner notification.",
                            application="Clause prescribes <= 72-hour notification.",
                            conclusion="Compliant with Section 12B & P.U. (A) 342/2024.",
                        ),
                        rakyat_guidance=RakyatGuidance(
                            plain_summary_en="The 72-hour data leak notification requirement is properly included.",
                            plain_summary_bm="Tempoh pemberitahuan kebocoran data 72 jam telah dipatuhi.",
                            gov_my_checklist=["Keep JPDP breach portal credentials ready at https://portal.pdp.gov.my."],
                            official_portals=["https://portal.pdp.gov.my"],
                        ),
                    )
                )

        # Rule 3: General Principle / Consent & Disclosure (Sec 6, 8, 130)
        implicated_node_ids.extend(["PDPA-2010-SEC-6-V1", "PDPA-2010-SEC-8-V1"])
        dis_span_ids, dis_spans = _spans_for_nodes(
            graph_store, ["PDPA-2010-SEC-6-V1", "PDPA-2010-SEC-8-V1", "PDPA-2010-SEC-130-V1"]
        )
        dis_quote = _extract_matching_sentence(
            safe_text,
            ("sell", "marketing", "disclose", "disclosure", "cross-border", "offshore", "consent", "persetujuan", "penzahiran"),
        )
        unlawful_disclosure = any(
            kw in low_text
            for kw in (
                "without consent",
                "without data subject consent",
                "sell or disclose",
                "marketing brokers",
                "tanpa persetujuan",
            )
        )
        cross_border_gap = any(
            kw in low_text for kw in ("cross-border", "offshore", "mirrored to regional", "rentas sempadan")
        ) and "consent" not in low_text
        if unlawful_disclosure:
            gaps.append(
                PDPAGapItem(
                    rule_id="ACT709-SEC8-DISCLOSURE",
                    principle_name="General & Disclosure Principles (Consent & Section 130)",
                    section_ref="Sections 6, 8 & 130 [Act 709]",
                    status="NON_COMPLIANT",
                    severity=RiskSeverity.CRITICAL,
                    exact_quote=dis_quote,
                    gap_description="Unauthorized third-party disclosure or sale of personal data triggers Section 130 offences (RM 500,000 fine / 3 years imprisonment).",
                    remediation_action="Prohibit third-party sale/disclosure unless explicit written consent is obtained under Sections 6 and 8.",
                    source_span_ids=dis_span_ids,
                    source_spans=dis_spans,
                    authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
                    gazette_ref="Act 709",
                    irac=IRACAnalysis(
                        issue="May personal data be sold or disclosed to external brokers without data subject consent?",
                        rule="Sections 6, 8 & 130 of Act 709 prohibit non-consensual collection or third-party disclosure.",
                        application=f"Quoted text ('{dis_quote}') permits unauthorized third-party disclosure.",
                        conclusion="Non-compliant (CRITICAL). Triggers criminal liability under Section 130.",
                    ),
                    rakyat_guidance=RakyatGuidance(
                        plain_summary_en="Businesses cannot sell or share your personal details with marketers without your clear permission.",
                        plain_summary_bm="Perniagaan dilarang menjual atau berkongsi data peribadi anda tanpa persetujuan jelas anda.",
                        gov_my_checklist=["Withdraw marketing consent or report misuse at https://www.pdp.gov.my."],
                        official_portals=["https://www.pdp.gov.my"],
                    ),
                )
            )
        elif cross_border_gap:
            gaps.append(
                PDPAGapItem(
                    rule_id="ACT709-SEC8-DISCLOSURE",
                    principle_name="Disclosure & Cross-Border Safeguards",
                    section_ref="Sections 8 & 129 [Act 709]",
                    status="PARTIAL_GAP",
                    severity=RiskSeverity.MEDIUM,
                    exact_quote=dis_quote,
                    gap_description="Cross-border/regional data mirroring lacks explicit adequacy or data subject consent verification.",
                    remediation_action="Require explicit consent or equivalent statutory safeguards before offshore transfer.",
                    source_span_ids=dis_span_ids,
                    source_spans=dis_spans,
                    authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
                    gazette_ref="Act 709",
                    irac=IRACAnalysis(
                        issue="Are offshore subprocessing transfers adequately conditioned under Act 709?",
                        rule="Cross-border transfers require adequacy/equivalent protection or express data subject consent.",
                        application=f"Clause ('{dis_quote}') permits mirroring without express adequacy safeguards.",
                        conclusion="Partial Gap (MEDIUM). Add contractual adequacy and consent conditions.",
                    ),
                    rakyat_guidance=RakyatGuidance(
                        plain_summary_en="Sending your data outside Malaysia requires extra legal protection or your consent.",
                        plain_summary_bm="Pemindahan data ke luar Malaysia memerlukan perlindungan setara atau persetujuan anda.",
                        gov_my_checklist=["Confirm overseas storage safeguards in your privacy notice."],
                        official_portals=["https://www.pdp.gov.my"],
                    ),
                )
            )

        # Rule 4: Bilingual Notice & Choice Principle (Section 7)
        implicated_node_ids.append("PDPA-2010-SEC-7-V1")
        n_span_ids, n_spans = _spans_for_nodes(graph_store, ["PDPA-2010-SEC-7-V1"])
        notice_quote = _extract_matching_sentence(
            safe_text, ("notice", "notis", "privacy", "english", "bahasa melayu", "policy", "dasar")
        )
        has_bilingual_notice = ("bahasa melayu" in low_text or "malay" in low_text) and ("english" in low_text or "inggeris" in low_text)
        if ("privacy" in low_text or "policy" in low_text or "notice" in low_text) and not has_bilingual_notice:
            gaps.append(
                PDPAGapItem(
                    rule_id="ACT709-SEC7-NOTICE",
                    principle_name="Notice and Choice Principle (Bilingual BM & EN)",
                    section_ref="Section 7(3) [Act 709]",
                    status="PARTIAL_GAP",
                    severity=RiskSeverity.MEDIUM,
                    exact_quote=notice_quote,
                    gap_description="Section 7(3) requires written privacy notice in BOTH Bahasa Melayu and English; policy does not confirm bilingual availability.",
                    remediation_action="Publish the Privacy Notice in both Bahasa Melayu and English.",
                    source_span_ids=n_span_ids,
                    source_spans=n_spans,
                    authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
                    gazette_ref="Act 709",
                    irac=IRACAnalysis(
                        issue="Does the privacy notice satisfy Section 7(3) bilingual requirements?",
                        rule="Section 7(3) of Act 709 mandates notice in both the national language (BM) and English.",
                        application="Text does not specify dual BM and English notice delivery.",
                        conclusion="Partial Gap (MEDIUM). Provide synchronized BM & EN privacy notices.",
                    ),
                    rakyat_guidance=RakyatGuidance(
                        plain_summary_en="In Malaysia, privacy notices must be provided in both Bahasa Melayu and English so everyone understands.",
                        plain_summary_bm="Notis privasi di Malaysia wajib disediakan dalam Bahasa Melayu dan Bahasa Inggeris.",
                        gov_my_checklist=["Ensure both BM and English privacy notices are linked on your site."],
                        official_portals=["https://www.pdp.gov.my"],
                    ),
                )
            )

        # Rule 5: Retention, Integrity & Access Principles (Sections 10, 11, 12)
        if any(kw in low_text for kw in ("indefinitely", "forever", "never deleted", "permanently retained")):
            implicated_node_ids.append("PDPA-2010-SEC-10-V1")
            r_span_ids, r_spans = _spans_for_nodes(graph_store, ["PDPA-2010-SEC-10-V1"])
            r_quote = _extract_matching_sentence(safe_text, ("indefinitely", "forever", "retain", "deleted"))
            gaps.append(
                PDPAGapItem(
                    rule_id="ACT709-SEC10-RETENTION",
                    principle_name="Retention Principle",
                    section_ref="Section 10 [Act 709]",
                    status="NON_COMPLIANT",
                    severity=RiskSeverity.HIGH,
                    exact_quote=r_quote,
                    gap_description="Indefinite personal data retention violates Section 10 requirement to destroy data once purpose is fulfilled.",
                    remediation_action="Define explicit retention schedules and permanent deletion/anonymization workflows.",
                    source_span_ids=r_span_ids,
                    source_spans=r_spans,
                    authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
                    gazette_ref="Act 709",
                    irac=IRACAnalysis(
                        issue="Is indefinite retention of personal data lawful under Section 10?",
                        rule="Section 10 mandates personal data must not be kept longer than necessary.",
                        application=f"Quoted clause ('{r_quote}') permits indefinite storage.",
                        conclusion="Non-compliant (HIGH). Enforce bounded retention and deletion.",
                    ),
                    rakyat_guidance=RakyatGuidance(
                        plain_summary_en="Companies cannot keep your personal data forever after you stop using their service.",
                        plain_summary_bm="Syarikat tidak boleh menyimpan data peribadi anda selama-lamanya selepas tujuan tamat.",
                        gov_my_checklist=["Request deletion once an account or contract ends."],
                        official_portals=["https://www.pdp.gov.my"],
                    ),
                )
            )

        # Rule 6: Mandatory DPO Appointment (Sec 12A + JPDP Circular 01/2025, effective 2025-01-01)
        if is_post_2025:
            implicated_node_ids.extend(["PDPA-2010-SEC-12A-V1", "JPDP-CIRC-01-2025"])
            dpo_span_ids, dpo_spans = _spans_for_nodes(
                graph_store, ["PDPA-2010-SEC-12A-V1", "JPDP-CIRC-01-2025"]
            )
            has_dpo_mention = any(
                kw in low_text for kw in ("dpo", "data protection officer", "pegawai perlindungan data", "ppd")
            )
            no_dpo_explicit = any(
                kw in low_text for kw in ("no dpo", "without a dpo", "not appoint a dpo", "waive dpo")
            )
            dpo_quote = _extract_matching_sentence(
                safe_text, ("dpo", "data protection officer", "pegawai perlindungan data", "processor", "data")
            )
            if no_dpo_explicit or (not has_dpo_mention and len(gaps) > 0):
                gaps.append(
                    PDPAGapItem(
                        rule_id="ACT709-SEC12A-DPO",
                        principle_name="Data Protection Officer (DPO) Appointment",
                        section_ref="Section 12A [Act 709] & JPDP Circular 01/2025",
                        status="NON_COMPLIANT" if no_dpo_explicit else "PARTIAL_GAP",
                        severity=RiskSeverity.HIGH if no_dpo_explicit else RiskSeverity.MEDIUM,
                        exact_quote=dpo_quote,
                        gap_description=(
                            "Document omits or rejects appointment of a Data Protection Officer (DPO) "
                            "and JPDP registration required under Section 12A and JPDP Circular 01/2025."
                        ),
                        remediation_action=(
                            "Appoint a qualified DPO and submit registration details via https://portal.pdp.gov.my."
                        ),
                        source_span_ids=dpo_span_ids,
                        source_spans=dpo_spans,
                        authority_tier=AuthorityTier.TIER_5_AGENCY_CIRCULAR,
                        gazette_ref="JPDP Circular 01/2025",
                        irac=IRACAnalysis(
                            issue="Does the entity satisfy Section 12A DPO appointment obligations?",
                            rule="Section 12A [Act A1727] & JPDP Circular 01/2025 require DPO appointment and Commissioner notification.",
                            application="No compliant DPO designation/registration clause is present.",
                            conclusion="Gap identified. Designate DPO contact and register via portal.pdp.gov.my.",
                        ),
                        rakyat_guidance=RakyatGuidance(
                            plain_summary_en="Organizations processing large or sensitive data must designate a Data Protection Officer you can contact.",
                            plain_summary_bm="Organisasi perlu melantik Pegawai Perlindungan Data (DPO) untuk dihubungi jika ada isu privasi.",
                            gov_my_checklist=["Register DPO contact info via https://portal.pdp.gov.my."],
                            official_portals=["https://portal.pdp.gov.my"],
                        ),
                    )
                )

        overall_risk = (
            max(gaps, key=lambda g: _SEVERITY_RANK[g.severity]).severity
            if gaps
            else RiskSeverity.LOW
        )
        compliant_count = sum(1 for g in gaps if g.status == "COMPLIANT")
        compliance_score_pct = (
            round((compliant_count / len(gaps)) * 100.0, 2) if gaps else 100.0
        )

        bilingual_provisions, divergence_warnings = _build_bilingual_provisions(
            graph_store, implicated_node_ids, as_of_date=effective_date
        )
        irac_summary, rakyat_summary = build_persona_summaries(
            document_id=req.document_id,
            as_of_date=effective_date,
            gaps=gaps,
            overall_risk=overall_risk,
        )

    span_id = f"scan-{uuid.uuid4().hex[:8]}"
    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_holder[0],
        retry_count=0,
        is_verified_grounded=True,
        trace_id=span_id,
    )
    if record_telemetry:
        telemetry_registry.record_span(
            ComplianceSpanRecord(
                span_id=span_id,
                document_id=req.document_id,
                reference_date=effective_date.isoformat(),
                active_statute_count=len(active_nodes),
                telemetry=telemetry,
                timestamp_epoch=time.time(),
            )
        )

    return PDPAComplianceScanResponse(
        document_id=req.document_id,
        as_of_date=effective_date,
        territorial_scope=req.territorial_scope,
        persona=req.persona,
        is_abstained=False,
        abstention_reason=None,
        max_relevance_score=max_score,
        overall_risk=overall_risk,
        compliance_score_pct=compliance_score_pct,
        pii_scrub=pii_scrub,
        gaps=gaps,
        bilingual_provisions=bilingual_provisions,
        bilingual_divergence_warnings=divergence_warnings,
        irac_summary=irac_summary,
        rakyat_summary=rakyat_summary,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
        telemetry=telemetry,
    )
