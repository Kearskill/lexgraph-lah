import hashlib
from datetime import date
from enum import Enum

from pydantic import BaseModel, Field, model_validator

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
    HAS_PART = "HAS_PART"
    HAS_SECTION = "HAS_SECTION"
    HAS_SUBSECTION = "HAS_SUBSECTION"
    HAS_SOURCE_SPAN = "HAS_SOURCE_SPAN"
    HAS_TRANSLATION = "HAS_TRANSLATION"
    AUTHORITATIVE_TEXT = "AUTHORITATIVE_TEXT"


class HierarchyLevel(str, Enum):
    ACT = "Act"
    PART = "Part"
    SECTION = "Section"
    SUBSECTION = "Subsection"
    SOURCE_SPAN = "SourceSpan"


class AuthorityTier(int, Enum):
    TIER_1_FEDERAL_CONSTITUTION = 1
    TIER_2_PRINCIPAL_ACT = 2
    TIER_3_ORDINANCE = 3
    TIER_4_SUBSIDIARY_LEGISLATION = 4
    TIER_5_AGENCY_CIRCULAR = 5


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
    """Exact verifiable statutory provenance span mapped to original gazetted source."""

    span_id: str = Field(..., description="Unique provenance span identifier")
    act_number: str = Field(
        ...,
        description="Official Act/Gazette identifier, e.g., Act 709, P.U. (A) 342/2024, Cap. 67",
    )
    section_id: str = Field(
        ..., description="Canonical section/subsection reference, e.g., SEC-9, SEKSYEN-9"
    )
    language: str = Field(
        default="en", description="ISO/normalized statutory language ('en' or 'bm')"
    )
    pdf_page: int = Field(default=1, ge=1, description="1-based page number in gazette PDF")
    char_offset_start: int = Field(
        default=0, ge=0, description="0-based inclusive character start offset"
    )
    char_offset_end: int = Field(
        default=1, ge=1, description="0-based exclusive character end offset"
    )
    sha256_hash: str = Field(
        default="",
        description="SHA-256 cryptographic digest of the verified statutory span text",
    )
    text: str = Field(
        default="", description="Verbatim statutory span excerpt for side-by-side inspection"
    )

    @model_validator(mode="after")
    def _validate_offsets_and_hash(self) -> "SourceSpan":
        if self.char_offset_end <= self.char_offset_start:
            raise ValueError(
                f"char_offset_end ({self.char_offset_end}) must be strictly greater than "
                f"char_offset_start ({self.char_offset_start})"
            )
        if not self.sha256_hash:
            basis = (
                self.text.strip()
                if self.text.strip()
                else f"{self.act_number}:{self.section_id}:{self.language}:{self.pdf_page}:{self.char_offset_start}:{self.char_offset_end}"
            )
            self.sha256_hash = hashlib.sha256(basis.encode("utf-8")).hexdigest()
        return self


class StatutoryNode(BaseModel):
    node_id: str = Field(
        ..., description="Unique versioned node ID, e.g., PDPA-2010-SEC-5-V1"
    )
    act_name: str = Field(
        ...,
        description="Canonical statute name, e.g., Personal Data Protection Act 2010",
    )
    section_code: str = Field(
        ..., description="Normalized section identifier, e.g., SEC-5"
    )
    version: int = Field(
        default=1, ge=1, description="Sequential legislative version number"
    )
    text: str = Field(..., description="Verbatim statutory provision text")
    valid_from: date = Field(..., description="Effective start date (inclusive)")
    valid_to: date | None = Field(
        default=None,
        description="Effective end date (exclusive), None if currently in force",
    )
    status: StatutoryStatus = Field(default=StatutoryStatus.ACTIVE)
    content_hash: str = Field(
        default="",
        description="SHA-256 hash of text for deduplication & semantic caching",
    )
    act_number: str = Field(
        default="Act 709",
        description="Malaysian Act number, Ordinance Cap., Constitution, or P.U. Gazette ref",
    )
    hierarchy_level: HierarchyLevel = Field(
        default=HierarchyLevel.SECTION,
        description="Structural hierarchy level (Act -> Part -> Section -> Subsection -> SourceSpan)",
    )
    parent_node_id: str | None = Field(
        default=None, description="Immediate structural parent node ID"
    )
    part_code: str | None = Field(default=None, description="Part identifier, e.g., PART-II")
    subsection_code: str | None = Field(
        default=None, description="Subsection identifier, e.g., (1A)"
    )
    language: str = Field(default="en", description="Provision language: 'en' or 'bm'")
    authoritative_language: bool = Field(
        default=True,
        description="True when this node is the authoritative statutory text",
    )
    translation_node_id: str | None = Field(
        default=None,
        description="Paired translation node ID linked via HAS_TRANSLATION",
    )
    effective_from: date | None = Field(
        default=None, description="Bi-temporal effective_from date (synced with valid_from)"
    )
    effective_to: date | None = Field(
        default=None, description="Bi-temporal effective_to date (synced with valid_to)"
    )
    gazette_ref: str | None = Field(
        default=None,
        description="Federal Gazette reference, e.g., P.U. (A) 342/2024, P.U. (B) 512/2024",
    )
    authority_tier: AuthorityTier = Field(
        default=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        description="Malaysian 5-tier statutory authority rank (1=Federal Constitution .. 5=Circular)",
    )
    territorial_scope: list[TerritorialScope] = Field(
        default_factory=lambda: [TerritorialScope.ALL_MALAYSIA],
        description="Jurisdictions where this provision applies",
    )
    source_spans: list[SourceSpan] = Field(
        default_factory=list,
        description="Strict SourceSpan provenance records backing this node",
    )

    @model_validator(mode="after")
    def _populate_hash_and_validate_window(self) -> "StatutoryNode":
        if self.effective_from is None:
            self.effective_from = self.valid_from
        if self.effective_to is None and self.valid_to is not None:
            self.effective_to = self.valid_to
        elif self.valid_to is None and self.effective_to is not None:
            self.valid_to = self.effective_to

        if self.valid_to is not None and self.valid_to <= self.valid_from:
            raise ValueError(
                f"valid_to ({self.valid_to}) must be strictly after valid_from ({self.valid_from})"
            )
        if not self.content_hash:
            self.content_hash = hashlib.sha256(
                self.text.strip().encode("utf-8")
            ).hexdigest()
        if not self.source_spans:
            clean_text = self.text.strip()
            self.source_spans = [
                SourceSpan(
                    span_id=f"SPAN-{self.node_id}",
                    act_number=self.act_number,
                    section_id=self.section_code,
                    language=self.language,
                    pdf_page=1,
                    char_offset_start=0,
                    char_offset_end=max(1, len(clean_text)),
                    sha256_hash=self.content_hash,
                    text=self.text,
                )
            ]
        return self

    def is_active_on(self, as_of_date: date) -> bool:
        """Deterministic point-in-time validity check (zero LLM cost)."""
        eff_from = self.effective_from or self.valid_from
        eff_to = self.effective_to if self.effective_to is not None else self.valid_to
        return eff_from <= as_of_date and (eff_to is None or eff_to > as_of_date)


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
