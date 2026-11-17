import hashlib
import re
from datetime import date, timedelta
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

DEFAULT_LEGAL_DISCLAIMER = (
    "LEGAL INFORMATION NOTICE (NOT LEGAL ADVICE): lexgraph-lah provides automated statutory "
    "information retrieval and compliance gap analysis for Malaysian legislation. Outputs do "
    "not constitute legal advice or establish an advocate and solicitor relationship under the "
    "Legal Profession Act 1976 [Act 166]. Consult a qualified Malaysian Advocate & Solicitor "
    "before relying on these findings for formal regulatory or contractual decisions."
)


class RiskSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class StatutoryStatus(str, Enum):
    ACTIVE = "ACTIVE"
    AMENDED = "AMENDED"
    REPEALED = "REPEALED"


class TemporalEdgeType(str, Enum):
    VALID_FROM = "VALID_FROM"
    VALID_TO = "VALID_TO"
    AMENDED_BY = "AMENDED_BY"
    REPEALED_BY = "REPEALED_BY"
    CITES = "CITES"
    AMENDS = "AMENDS"
    REPEALS = "REPEALS"
    SUPERSEDED_BY = "SUPERSEDED_BY"
    PART_OF = "PART_OF"
    HAS_PART = "HAS_PART"
    HAS_CHAPTER = "HAS_CHAPTER"
    HAS_SECTION = "HAS_SECTION"
    HAS_SUBSECTION = "HAS_SUBSECTION"
    HAS_PROVISO = "HAS_PROVISO"
    HAS_ILLUSTRATION = "HAS_ILLUSTRATION"
    HAS_SOURCE_SPAN = "HAS_SOURCE_SPAN"
    HAS_TRANSLATION = "HAS_TRANSLATION"
    BM_EN_EQUIVALENT = "BM_EN_EQUIVALENT"
    AUTHORITATIVE_TEXT = "AUTHORITATIVE_TEXT"
    INTERPRETS = "INTERPRETS"
    APPLIES = "APPLIES"
    DISTINGUISHES = "DISTINGUISHES"
    OVERRULES = "OVERRULES"


class HierarchyLevel(str, Enum):
    ACT = "Act"
    PART = "Part"
    CHAPTER = "Chapter"
    SECTION = "Section"
    SUBSECTION = "Subsection"
    PROVISO = "Proviso"
    ILLUSTRATION = "Illustration"
    CASE = "Case"
    SOURCE_SPAN = "SourceSpan"


class AuthorityTier(int, Enum):
    """
    Malaysian 7-tier statutory & judicial authority hierarchy:
      1. Federal Constitution (Perlembagaan Persekutuan)
      2. Acts of Parliament (Laws of Malaysia / Akta) & State Enactments
      3. Subsidiary Legislation (P.U. (A), P.U. (B))
      4. Federal Court (Mahkamah Persekutuan)
      5. Court of Appeal (Mahkamah Rayuan)
      6. High Court (Mahkamah Tinggi Malaya & Sabah/Sarawak)
      7. Subordinate Courts & Statutory Tribunals
    """

    TIER_1_FEDERAL_CONSTITUTION = 1
    TIER_2_ACT_OF_PARLIAMENT = 2
    TIER_2_PRINCIPAL_ACT = 2  # noqa: PIE796 - backward-compatible alias
    TIER_3_SUBSIDIARY_LEGISLATION = 3
    TIER_3_ORDINANCE = 3  # noqa: PIE796 - backward-compatible alias
    TIER_4_FEDERAL_COURT = 4
    TIER_4_SUBSIDIARY_LEGISLATION = 4  # noqa: PIE796 - backward-compatible alias
    TIER_5_COURT_OF_APPEAL = 5
    TIER_5_AGENCY_CIRCULAR = 5  # noqa: PIE796 - backward-compatible alias
    TIER_6_HIGH_COURT = 6
    TIER_7_SUBORDINATE_COURT = 7
    TIER_7_STATUTORY_TRIBUNAL = 7  # noqa: PIE796 - intentional 7-tier synonym


class TerritorialScope(str, Enum):
    PENINSULAR_MALAYSIA = "Peninsular Malaysia"
    SABAH = "Sabah"
    SARAWAK = "Sarawak"
    FEDERAL_TERRITORIES = "Federal Territories"
    ALL_MALAYSIA = "All Malaysia"


class OutputPersona(str, Enum):
    PRACTITIONER = "PRACTITIONER"
    RAKYAT = "RAKYAT"


class SourceSpan(BaseModel):
    """Immutable verbatim provenance span mapped to an original gazetted statute or judgment."""

    model_config = ConfigDict(frozen=True)

    span_id: str = Field(..., description="Unique provenance span identifier")
    doc_id: str = Field(
        default="",
        description="Canonical source document identifier, e.g., act-709-en or mlj-2025-2-101",
    )
    source_uri: str = Field(
        default="",
        description="Canonical source URI (e.g., https://lom.agc.gov.my/ilims/...)",
    )
    act_number: str = Field(
        default="",
        description="Official Act/Gazette/Case identifier, e.g., Act 709, P.U. (A) 342/2024, [2025] 2 MLJ 101",
    )
    section_id: str = Field(
        default="",
        description="Canonical section/subsection/paragraph reference, e.g., SEC-9, SEKSYEN-9",
    )
    canonical_citation: str = Field(
        default="",
        description="Canonical Malaysian legal citation, e.g., Act 709 s. 9(1A) or [2025] 2 MLJ 101 (FC)",
    )
    language: str = Field(
        default="en", description="ISO/normalized statutory language ('ms', 'bm', or 'en')"
    )
    pdf_page: int = Field(default=1, ge=1, description="1-based page number in gazette PDF")
    start_char: int = Field(
        default=0, ge=0, description="0-based inclusive character start offset"
    )
    end_char: int = Field(
        default=1, ge=1, description="0-based exclusive character end offset"
    )
    char_offset_start: int = Field(
        default=0, ge=0, description="0-based inclusive character start offset (alias)"
    )
    char_offset_end: int = Field(
        default=1, ge=1, description="0-based exclusive character end offset (alias)"
    )
    content_sha256: str = Field(
        default="",
        description="SHA-256 cryptographic digest of the verified verbatim span text",
    )
    sha256_hash: str = Field(
        default="",
        description="SHA-256 cryptographic digest of the verified statutory span text (alias)",
    )
    text: str = Field(
        default="", description="Verbatim statutory span excerpt for side-by-side inspection"
    )

    @model_validator(mode="before")
    @classmethod
    def _sync_provenance_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)

        doc_id = d.get("doc_id") or d.get("act_number") or "MY-STATUTE"
        act_number = d.get("act_number") or doc_id
        d["doc_id"] = doc_id
        d["act_number"] = act_number

        section_id = d.get("section_id") or d.get("canonical_citation") or "SEC-1"
        d["section_id"] = section_id

        if not d.get("canonical_citation"):
            d["canonical_citation"] = f"{act_number} {section_id}".strip()
        if not d.get("source_uri"):
            slug = re.sub(r"[^a-z0-9]+", "-", str(doc_id).lower()).strip("-") or "statute"
            d["source_uri"] = f"https://lom.agc.gov.my/ilims/{slug}"

        if "start_char" in d and "char_offset_start" not in d:
            d["char_offset_start"] = d["start_char"]
        elif "char_offset_start" in d and "start_char" not in d:
            d["start_char"] = d["char_offset_start"]
        else:
            start_val = d.get("start_char", d.get("char_offset_start", 0))
            d["start_char"] = start_val
            d["char_offset_start"] = start_val

        if "end_char" in d and "char_offset_end" not in d:
            d["char_offset_end"] = d["end_char"]
        elif "char_offset_end" in d and "end_char" not in d:
            d["end_char"] = d["char_offset_end"]
        else:
            text_val = str(d.get("text", "")).strip()
            default_end = max(int(d["start_char"]) + 1, int(d["start_char"]) + len(text_val))
            end_val = d.get("end_char", d.get("char_offset_end", default_end))
            d["end_char"] = end_val
            d["char_offset_end"] = end_val

        digest = d.get("content_sha256") or d.get("sha256_hash") or ""
        if not digest:
            text_str = str(d.get("text", "")).strip()
            basis = (
                text_str
                if text_str
                else (
                    f"{act_number}:{section_id}:{d.get('language', 'en')}:"
                    f"{d.get('pdf_page', 1)}:{d['start_char']}:{d['end_char']}"
                )
            )
            digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
        d["content_sha256"] = digest
        d["sha256_hash"] = digest
        if not d.get("span_id"):
            d["span_id"] = f"SPAN-{digest[:12]}"
        return d

    @model_validator(mode="after")
    def _validate_offsets_and_hash(self) -> "SourceSpan":
        if self.char_offset_end <= self.char_offset_start or self.end_char <= self.start_char:
            raise ValueError(
                f"char_offset_end ({self.char_offset_end}) must be strictly greater than "
                f"char_offset_start ({self.char_offset_start})"
            )
        return self


class StatutoryNode(BaseModel):
    node_id: str = Field(
        ..., description="Unique versioned node ID, e.g., PDPA-2010-SEC-5-V1"
    )
    act_name: str = Field(
        ...,
        description="Canonical statute or case title, e.g., Personal Data Protection Act 2010",
    )
    section_code: str = Field(
        ..., description="Normalized section or case identifier, e.g., SEC-5"
    )
    version: int = Field(
        default=1, ge=1, description="Sequential legislative version number"
    )
    text: str = Field(..., description="Verbatim statutory provision or judicial extract text")
    valid_from: date = Field(..., description="Effective start date (inclusive)")
    valid_to: date | None = Field(
        default=None,
        description="Effective end date (exclusive), None if currently in force",
    )
    status: StatutoryStatus = Field(default=StatutoryStatus.ACTIVE)
    is_in_force: bool = Field(
        default=True,
        description="True when provision/authority is currently in force",
    )
    amendment_act_ref: str | None = Field(
        default=None,
        description="Amending Act / Akta Pindaan reference, e.g., Act A1727",
    )
    content_hash: str = Field(
        default="",
        description="SHA-256 hash of text for deduplication & semantic caching",
    )
    act_number: str = Field(
        default="Act 709",
        description="Malaysian Act number, Ordinance Cap., Constitution, P.U. Gazette ref, or Case Citation",
    )
    hierarchy_level: HierarchyLevel = Field(
        default=HierarchyLevel.SECTION,
        description="Structural hierarchy level (Act -> Part -> Chapter -> Section -> Subsection -> Proviso/Illustration / Case)",
    )
    parent_node_id: str | None = Field(
        default=None, description="Immediate structural parent node ID"
    )
    part_code: str | None = Field(default=None, description="Part / Bahagian identifier, e.g., PART-II")
    chapter_code: str | None = Field(default=None, description="Chapter / Bab identifier, e.g., CHAPTER-I")
    subsection_code: str | None = Field(
        default=None, description="Subsection identifier, e.g., (1A)"
    )
    language: str = Field(default="en", description="Provision language: 'ms', 'bm', or 'en'")
    authoritative_language: bool = Field(
        default=True,
        description="True when this node is the authoritative statutory text",
    )
    translation_node_id: str | None = Field(
        default=None,
        description="Paired translation node ID linked via BM_EN_EQUIVALENT / HAS_TRANSLATION",
    )
    effective_from: date | None = Field(
        default=None, description="Point-in-time inclusive effective_from date"
    )
    effective_to: date | None = Field(
        default=None, description="Point-in-time inclusive effective_to date (day before amendment takes effect)"
    )
    gazette_ref: str | None = Field(
        default=None,
        description="Federal Gazette reference, e.g., P.U. (A) 342/2024, P.U. (B) 512/2024",
    )
    authority_tier: AuthorityTier = Field(
        default=AuthorityTier.TIER_2_ACT_OF_PARLIAMENT,
        description="Malaysian 7-tier statutory & judicial authority rank (1=Federal Constitution .. 7=Subordinate Court)",
    )
    territorial_scope: list[TerritorialScope] = Field(
        default_factory=lambda: [TerritorialScope.ALL_MALAYSIA],
        description="Jurisdictions where this provision applies",
    )
    court_name: str | None = Field(
        default=None,
        description="Court name for judicial nodes (e.g., Federal Court (Mahkamah Persekutuan))",
    )
    case_citation: str | None = Field(
        default=None,
        description="Malaysian law report citation for judicial nodes (e.g., [2025] 2 MLJ 101 (FC))",
    )
    is_overruled: bool = Field(
        default=False,
        description="True when this judicial precedent has been overruled by a higher/later court",
    )
    source_spans: list[SourceSpan] = Field(
        default_factory=list,
        description="Strict SourceSpan provenance records backing this node",
    )

    @property
    def normalized_language(self) -> Literal["ms", "en"]:
        """Normalizes 'bm' / 'ms' to 'ms' and 'en' to 'en'."""
        return "ms" if self.language.lower() in {"bm", "ms"} else "en"

    @model_validator(mode="before")
    @classmethod
    def _sync_temporal_inputs(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)
        if not d.get("valid_from") and d.get("effective_from"):
            d["valid_from"] = d["effective_from"]
        if not d.get("effective_from") and d.get("valid_from"):
            d["effective_from"] = d["valid_from"]
        if d.get("valid_to") is None and d.get("effective_to") is not None:
            eff_to = d["effective_to"]
            if isinstance(eff_to, str):
                eff_to = date.fromisoformat(eff_to)
            d["valid_to"] = eff_to + timedelta(days=1)
        if not d.get("amendment_act_ref") and d.get("gazette_ref"):
            d["amendment_act_ref"] = d["gazette_ref"]
        if not d.get("gazette_ref") and d.get("amendment_act_ref"):
            d["gazette_ref"] = d["amendment_act_ref"]
        return d

    @model_validator(mode="after")
    def _populate_hash_and_validate_window(self) -> "StatutoryNode":
        if self.effective_from is None:
            self.effective_from = self.valid_from
        if self.effective_to is None and self.valid_to is not None:
            candidate_eff_to = self.valid_to - timedelta(days=1)
            self.effective_to = (
                candidate_eff_to if candidate_eff_to >= self.effective_from else self.valid_to
            )
        elif self.valid_to is None and self.effective_to is not None:
            self.valid_to = self.effective_to + timedelta(days=1)

        if self.valid_to is not None and self.valid_to <= self.valid_from:
            raise ValueError(
                f"valid_to ({self.valid_to}) must be strictly after valid_from ({self.valid_from})"
            )
        if self.status in {StatutoryStatus.AMENDED, StatutoryStatus.REPEALED}:
            self.is_in_force = False
        if not self.amendment_act_ref and self.gazette_ref:
            self.amendment_act_ref = self.gazette_ref
        if not self.gazette_ref and self.amendment_act_ref:
            self.gazette_ref = self.amendment_act_ref

        if not self.content_hash:
            self.content_hash = hashlib.sha256(
                self.text.strip().encode("utf-8")
            ).hexdigest()
        if not self.source_spans:
            clean_text = self.text.strip()
            citation = (
                self.case_citation
                or f"{self.act_number} {self.section_code}".strip()
            )
            self.source_spans = [
                SourceSpan(
                    span_id=f"SPAN-{self.node_id}",
                    doc_id=self.act_number,
                    act_number=self.act_number,
                    section_id=self.section_code,
                    canonical_citation=citation,
                    language=self.language,
                    pdf_page=1,
                    start_char=0,
                    end_char=max(1, len(clean_text)),
                    char_offset_start=0,
                    char_offset_end=max(1, len(clean_text)),
                    content_sha256=self.content_hash,
                    sha256_hash=self.content_hash,
                    text=self.text,
                )
            ]
        return self

    def is_active_on(self, as_of_date: date) -> bool:
        """Deterministic point-in-time validity check (effective_from <= as_of_date <= effective_to)."""
        eff_from = self.effective_from or self.valid_from
        if self.effective_to is not None:
            if self.valid_to is not None and self.effective_to < self.valid_to:
                return eff_from <= as_of_date <= self.effective_to
            return eff_from <= as_of_date <= self.effective_to
        return eff_from <= as_of_date and (
            self.valid_to is None or self.valid_to > as_of_date
        )


TemporalProvisionNode = StatutoryNode


class StatutoryEdge(BaseModel):
    source_id: str = Field(..., description="Origin StatutoryNode ID")
    target_id: str = Field(..., description="Destination StatutoryNode ID")
    edge_type: TemporalEdgeType
    effective_date: date = Field(
        ..., description="Date on which this relationship took legal effect"
    )
    gazette_ref: str | None = Field(
        default=None, description="Optional P.U. (A)/(B) or Amending Act citation"
    )


class ScoredSourceSpan(BaseModel):
    span: SourceSpan
    node_id: str
    act_name: str
    authority_tier: AuthorityTier
    authority_label: str
    territorial_scope: list[TerritorialScope]
    gazette_ref: str | None = None
    vector_score: float = Field(..., ge=0.0, le=1.0)
    authority_weight: float = Field(..., ge=0.0, le=1.0)
    final_score: float = Field(..., ge=0.0, le=1.0)
    bilingual_node_id: str | None = None


class BilingualClausePair(BaseModel):
    section_code: str
    act_name: str
    act_number: str
    en_node: StatutoryNode | None = None
    bm_node: StatutoryNode | None = None
    authoritative_node_id: str
    gazette_ref: str | None = None
    source_spans: list[SourceSpan] = Field(default_factory=list)


class RetrievalSearchResponse(BaseModel):
    query: str
    normalized_query: str
    detected_language: str
    as_of_date: date
    territorial_scope: str | None = None
    abstention_threshold: float
    is_abstained: bool
    abstention_reason: str | None = None
    max_relevance_score: float
    results: list[ScoredSourceSpan] = Field(default_factory=list)
    bilingual_pairs: list[BilingualClausePair] = Field(default_factory=list)


class PIIScrubSummary(BaseModel):
    original_length: int
    masked_text: str
    redaction_count: int
    placeholders: dict[str, str] = Field(default_factory=dict)
    entity_counts: dict[str, int] = Field(default_factory=dict)
    scrub_latency_ms: float


class IRACAnalysis(BaseModel):
    issue: str
    rule: str
    application: str
    conclusion: str


class RakyatGuidance(BaseModel):
    plain_summary_en: str
    plain_summary_bm: str
    gov_my_checklist: list[str] = Field(default_factory=list)
    official_portals: list[str] = Field(default_factory=list)


class PDPAGapItem(BaseModel):
    rule_id: str
    principle_name: str
    section_ref: str
    status: str = Field(..., description="COMPLIANT | NON_COMPLIANT | PARTIAL_GAP")
    severity: RiskSeverity
    exact_quote: str
    gap_description: str
    remediation_action: str
    source_span_ids: list[str] = Field(default_factory=list)
    source_spans: list[SourceSpan] = Field(default_factory=list)
    authority_tier: AuthorityTier = AuthorityTier.TIER_2_PRINCIPAL_ACT
    gazette_ref: str | None = None
    irac: IRACAnalysis
    rakyat_guidance: RakyatGuidance


class ClauseAudit(BaseModel):
    clause_id: str = Field(..., description="Section identifier, e.g., SEC-1.1")
    category: str = Field(
        ..., description="E.g., Indemnification, IP Ownership, Liability, Termination"
    )
    exact_quote: str = Field(
        ...,
        description="MUST be an exact, character-for-character verbatim substring from the source text.",
    )
    severity: RiskSeverity
    rationale: str = Field(
        ..., description="Concise explanation of the legal/financial exposure."
    )
    recommended_redline: str = Field(
        ..., description="Suggested safer replacement clause wording."
    )
    violated_statute_ids: list[str] = Field(
        default_factory=list,
        description="IDs of point-in-time StatutoryNodes violated or implicated by this clause.",
    )
    source_span_ids: list[str] = Field(
        default_factory=list,
        description="Verified SourceSpan IDs supporting this finding.",
    )


class ClauseExtractionList(BaseModel):
    clauses: list[ClauseAudit]


class TelemetrySummary(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int
    estimated_cost_usd: float
    estimated_cost_myr: float
    latency_ms: float
    retry_count: int
    is_verified_grounded: bool
    trace_id: str | None = None


class ContractAuditResponse(BaseModel):
    document_id: str
    reference_date: date | None = None
    overall_risk: RiskSeverity
    findings: list[ClauseAudit]
    active_statutes: list[StatutoryNode] = Field(default_factory=list)
    telemetry: TelemetrySummary
    is_abstained: bool = False
    abstention_reason: str | None = None
    persona: OutputPersona = OutputPersona.PRACTITIONER
    territorial_scope: TerritorialScope = TerritorialScope.ALL_MALAYSIA
    pii_scrub: PIIScrubSummary | None = None
    bilingual_provisions: list[BilingualClausePair] = Field(default_factory=list)
    irac_summary: IRACAnalysis | None = None
    rakyat_summary: RakyatGuidance | None = None
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


class ComplianceCheckRequest(BaseModel):
    document_id: str = Field(
        ..., min_length=1, description="Contract or policy identifier"
    )
    raw_text: str = Field(..., min_length=1, description="Full contract text to audit")
    reference_date: date | None = Field(
        default=None,
        description="Point-in-time audit date (YYYY-MM-DD); defaults to today if omitted.",
    )
    act_filter: str | None = Field(
        default=None,
        description="Optional canonical statute name filter, e.g., Personal Data Protection Act 2010",
    )
    territorial_scope: TerritorialScope | None = Field(
        default=None,
        description="Optional Malaysian territorial jurisdiction filter",
    )
    persona: OutputPersona = Field(
        default=OutputPersona.PRACTITIONER,
        description="Output mode: PRACTITIONER (IRAC) or RAKYAT (plain-language + gov.my steps)",
    )
    abstention_threshold: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Optional override for deterministic relevance abstention threshold (default 0.78)",
    )


class PDPAComplianceScanRequest(BaseModel):
    document_id: str = Field(default="PDPA-SCAN-001", min_length=1)
    raw_text: str = Field(..., min_length=1)
    as_of_date: date | None = Field(
        default=None,
        description="Point-in-time legislation date (YYYY-MM-DD); defaults to today.",
    )
    territorial_scope: TerritorialScope = Field(default=TerritorialScope.ALL_MALAYSIA)
    persona: OutputPersona = Field(default=OutputPersona.PRACTITIONER)
    abstention_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    rule_pack: str = Field(default="ACT_709_PDPA")


class PDPAComplianceScanResponse(BaseModel):
    document_id: str
    as_of_date: date
    territorial_scope: TerritorialScope
    persona: OutputPersona
    is_abstained: bool = False
    abstention_reason: str | None = None
    max_relevance_score: float = 1.0
    overall_risk: RiskSeverity
    compliance_score_pct: float = Field(..., ge=0.0, le=100.0)
    pii_scrub: PIIScrubSummary
    gaps: list[PDPAGapItem] = Field(default_factory=list)
    bilingual_provisions: list[BilingualClausePair] = Field(default_factory=list)
    irac_summary: IRACAnalysis | None = None
    rakyat_summary: RakyatGuidance | None = None
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER
    telemetry: TelemetrySummary


class GraphTopologyResponse(BaseModel):
    as_of_date: date | None = None
    nodes: list[StatutoryNode]
    edges: list[StatutoryEdge]
    cypher_query: str


class TelemetryMetricsResponse(BaseModel):
    total_runs: int
    total_tokens: int
    total_cost_usd: float
    total_cost_myr: float
    average_latency_ms: float
    grounded_rate: float
    spans: list[dict] = Field(default_factory=list)


class PointInTimeResearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Malaysian legal query in BM, EN, or mixed")
    as_of_date: date | None = Field(
        default=None,
        description="Point-in-time date (YYYY-MM-DD); defaults to current date",
    )
    language_mode: Literal["ms", "bm", "en", "bilingual"] = Field(
        default="bilingual",
        description="Preferred output/traversal mode: 'ms' (Bahasa Melayu), 'en' (English), or 'bilingual'",
    )
    include_repealed_lineage: bool = Field(
        default=True,
        description="Whether to include superseded/repealed versions in amendment_timeline",
    )
    territorial_scope: TerritorialScope | None = Field(
        default=None,
        description="Optional Malaysian territorial jurisdiction filter",
    )
    abstention_threshold: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Optional deterministic abstention threshold override",
    )


class AmendmentTimelineEntry(BaseModel):
    node_id: str
    act_name: str
    act_number: str
    section_code: str
    version: int
    language: str
    effective_from: date
    effective_to: date | None = None
    is_in_force: bool
    is_active_at_query_date: bool
    status: StatutoryStatus
    amendment_act_ref: str | None = None
    text: str
    source_spans: list[SourceSpan] = Field(default_factory=list)


class AuthorityBreakdownItem(BaseModel):
    node_id: str
    title: str
    canonical_citation: str
    hierarchy_level: HierarchyLevel
    authority_tier: AuthorityTier
    authority_label: str
    authority_weight: float = Field(..., ge=0.0, le=1.0)
    relevance_score: float = Field(..., ge=0.0, le=1.0)
    final_score: float
    language: str
    effective_from: date
    effective_to: date | None = None
    treatment_type: str | None = None
    is_overruled: bool = False
    overruled_by_node_id: str | None = None
    source_span_ids: list[str] = Field(default_factory=list)


class GroundedClaim(BaseModel):
    claim_id: str
    statement: str
    source_span_ids: list[str] = Field(..., min_length=1)
    node_ids: list[str] = Field(default_factory=list)
    authority_tier: AuthorityTier


class JudicialTreatmentItem(BaseModel):
    case_node_id: str
    case_title: str
    case_citation: str
    court_name: str
    authority_tier: AuthorityTier
    authority_label: str
    treatment_type: TemporalEdgeType
    target_node_id: str
    decision_date: date
    is_overruled: bool = False
    overruled_by_node_id: str | None = None
    extract_text: str
    source_spans: list[SourceSpan] = Field(default_factory=list)


class SubgraphVisualizationData(BaseModel):
    nodes: list[StatutoryNode] = Field(default_factory=list)
    edges: list[StatutoryEdge] = Field(default_factory=list)
    cypher_query: str = ""


class PointInTimeResearchResponse(BaseModel):
    status: Literal["grounded", "insufficient_evidence"]
    query: str
    normalized_query: str
    detected_language: str
    language_mode: Literal["ms", "en", "bilingual"]
    as_of_date: date
    include_repealed_lineage: bool
    is_abstained: bool = False
    refusal_reason: str | None = None
    answer: str
    claims: list[GroundedClaim] = Field(default_factory=list)
    citations: list[SourceSpan] = Field(default_factory=list)
    authority_breakdown: list[AuthorityBreakdownItem] = Field(default_factory=list)
    amendment_timeline: list[AmendmentTimelineEntry] = Field(default_factory=list)
    bilingual_crosswalk: list[BilingualClausePair] = Field(default_factory=list)
    judicial_treatments: list[JudicialTreatmentItem] = Field(default_factory=list)
    subgraph: SubgraphVisualizationData = Field(default_factory=SubgraphVisualizationData)
    telemetry: TelemetrySummary
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


class ProvisionLineageResponse(BaseModel):
    provision_id: str
    act_name: str
    act_number: str
    section_code: str
    as_of_date: date
    current_active_node_id: str | None = None
    amendment_timeline: list[AmendmentTimelineEntry] = Field(default_factory=list)
    bilingual_equivalent: BilingualClausePair | None = None
    judicial_treatments: list[JudicialTreatmentItem] = Field(default_factory=list)
    lineage_edges: list[StatutoryEdge] = Field(default_factory=list)
