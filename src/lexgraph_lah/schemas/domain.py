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
    GAZETTED_PENDING_COMMENCEMENT = "GAZETTED_PENDING_COMMENCEMENT"


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
    LABUAN = "Labuan"
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
        default="en",
        description="ISO/normalized statutory language ('ms', 'bm', or 'en')",
    )
    pdf_page: int = Field(
        default=1, ge=1, description="1-based page number in gazette PDF"
    )
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
        default="",
        description="Verbatim statutory span excerpt for side-by-side inspection",
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
            slug = (
                re.sub(r"[^a-z0-9]+", "-", str(doc_id).lower()).strip("-") or "statute"
            )
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
            default_end = max(
                int(d["start_char"]) + 1, int(d["start_char"]) + len(text_val)
            )
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
        if (
            self.char_offset_end <= self.char_offset_start
            or self.end_char <= self.start_char
        ):
            raise ValueError(
                f"char_offset_end ({self.char_offset_end}) must be strictly greater than "
                f"char_offset_start ({self.char_offset_start})"
            )
        return self


class TelemetrySummary(BaseModel):
    prompt_tokens: int = 0
    cached_prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int
    estimated_cost_usd: float
    estimated_cost_myr: float
    latency_ms: float
    retry_count: int
    is_verified_grounded: bool
    model_name: str | None = None
    trace_id: str | None = None
    cache_hit: bool = False


class DeonticModality(str, Enum):
    OBLIGATION = "OBLIGATION"
    PROHIBITION = "PROHIBITION"
    PERMISSION = "PERMISSION"
    VOLUNTARY_GUIDELINE = "VOLUNTARY_GUIDELINE"
    PRE_COMMENCEMENT_ADVISORY = "PRE_COMMENCEMENT_ADVISORY"


class DeonticOperator(str, Enum):
    LTE = "<="
    GTE = ">="
    EQ = "=="
    FORBIDDEN_CLAUSE = "FORBIDDEN_CLAUSE"


class DeonticConstraint(BaseModel):
    """Structured statutory deontic constraint attached to a statute or P.U. gazette node."""

    constraint_id: str = Field(default="", description="Unique constraint identifier")
    regime_id: str = Field(
        default="ACT_709",
        description="Canonical regime code, e.g., ACT_709, ACT_854, BNM_RMIT",
    )
    modality: Literal[
        "OBLIGATION",
        "PROHIBITION",
        "PERMISSION",
        "VOLUNTARY_GUIDELINE",
        "PRE_COMMENCEMENT_ADVISORY",
    ] = Field(default="OBLIGATION")
    metric_key: str = Field(
        ...,
        description=(
            "Normalized metric key, e.g., incident_notice_max_hours, "
            "full_report_max_days, cross_border_transfer_condition, "
            "processor_direct_liability, regulator_audit_access"
        ),
    )
    operator: Literal["<=", ">=", "==", "FORBIDDEN_CLAUSE"] = Field(default="<=")
    threshold_value: float | str | bool = Field(
        ..., description="Numeric bound, boolean mandate, or forbidden clause pattern"
    )
    unit: str = Field(default="", description="Optional unit such as 'hours' or 'days'")
    territorial_scope: list[TerritorialScope] = Field(
        default_factory=lambda: [TerritorialScope.ALL_MALAYSIA]
    )
    recipient: str | None = Field(
        default=None,
        description="Recipient authority or party for notice duties, e.g., PDPA_COMMISSIONER, AFFECTED_DATA_SUBJECT, NACSA, BNM_SUPERVISOR, MCMC",
    )
    notice_stage: str | None = Field(
        default=None,
        description="Notice stage discriminator, e.g., INITIAL_NOTICE, FULL_REPORT, DATA_SUBJECT_NOTICE, HARMFUL_CONTENT_REPORT",
    )
    description: str = Field(default="")


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
    text: str = Field(
        ..., description="Verbatim statutory provision or judicial extract text"
    )
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
    part_code: str | None = Field(
        default=None, description="Part / Bahagian identifier, e.g., PART-II"
    )
    chapter_code: str | None = Field(
        default=None, description="Chapter / Bab identifier, e.g., CHAPTER-I"
    )
    subsection_code: str | None = Field(
        default=None, description="Subsection identifier, e.g., (1A)"
    )
    language: str = Field(
        default="en", description="Provision language: 'ms', 'bm', or 'en'"
    )
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
        default=None,
        description="Point-in-time inclusive effective_to date (day before amendment takes effect)",
    )
    gazette_ref: str | None = Field(
        default=None,
        description="Federal Gazette reference, e.g., P.U. (A) 342/2024, P.U. (B) 512/2024",
    )
    gazette_date: date | None = Field(
        default=None,
        description="Official Federal Gazette publication date",
    )
    carve_out_metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional statutory exemption/carve-out metadata",
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
    regime_code: str = Field(
        default="ACT_709",
        description="Canonical regulatory regime code (e.g., ACT_709, ACT_854, BNM_RMIT)",
    )
    deontic_constraints: list[DeonticConstraint] = Field(
        default_factory=list,
        description="Structured deontic obligations, prohibitions, and permissions encoded by this provision",
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
                candidate_eff_to
                if candidate_eff_to >= self.effective_from
                else self.valid_to
            )
        elif self.valid_to is None and self.effective_to is not None:
            self.valid_to = self.effective_to + timedelta(days=1)

        if self.valid_to is not None and self.valid_to <= self.valid_from:
            raise ValueError(
                f"valid_to ({self.valid_to}) must be strictly after valid_from ({self.valid_from})"
            )
        if self.status in {
            StatutoryStatus.AMENDED,
            StatutoryStatus.REPEALED,
            StatutoryStatus.GAZETTED_PENDING_COMMENCEMENT,
        }:
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
                self.case_citation or f"{self.act_number} {self.section_code}".strip()
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

    def is_gazetted_pending_on(self, as_of_date: date) -> bool:
        """True when provision is gazetted as GAZETTED_PENDING_COMMENCEMENT and as_of_date precedes commencement."""
        if self.status != StatutoryStatus.GAZETTED_PENDING_COMMENCEMENT:
            return False
        if self.gazette_date is None:
            return False
        eff_from = self.effective_from or self.valid_from
        return self.gazette_date <= as_of_date < eff_from


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


class BilingualDivergenceIssue(BaseModel):
    issue_id: str
    divergence_type: Literal[
        "DEONTIC_MODALITY_MISMATCH",
        "NUMERIC_DEADLINE_DISCREPANCY",
        "PENALTY_CEILING_DISCREPANCY",
        "MISSING_SUBCLAUSE",
    ]
    severity: RiskSeverity
    en_excerpt: str
    bm_excerpt: str
    en_span_id: str | None = None
    bm_span_id: str | None = None
    authoritative_resolution: str
    practitioner_note: str
    rakyat_note: str


class BilingualDivergenceReport(BaseModel):
    provision_id: str
    act_name: str
    act_number: str
    section_code: str
    as_of_date: date
    authoritative_language: Literal["ms", "en"]
    authoritative_node_id: str
    act_388_authority_basis: str
    alignment_status: Literal["ALIGNED", "DIVERGENCE_DETECTED", "SINGLE_LANGUAGE_ONLY"]
    has_divergence: bool
    en_node_id: str | None = None
    bm_node_id: str | None = None
    en_source_spans: list[SourceSpan] = Field(default_factory=list)
    bm_source_spans: list[SourceSpan] = Field(default_factory=list)
    detected_en_modalities: list[str] = Field(default_factory=list)
    detected_bm_modalities: list[str] = Field(default_factory=list)
    issues: list[BilingualDivergenceIssue] = Field(default_factory=list)
    summary_practitioner: str
    summary_rakyat: str
    telemetry: TelemetrySummary
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


class BilingualDivergenceRequest(BaseModel):
    node_id: str | None = None
    as_of_date: date | None = None
    en_text: str | None = None
    bm_text: str | None = None
    authoritative_language: Literal["ms", "bm", "en"] | None = None
    act_name: str = ""
    act_number: str = ""
    section_code: str = ""


class BilingualClausePair(BaseModel):
    section_code: str
    act_name: str
    act_number: str
    en_node: StatutoryNode | None = None
    bm_node: StatutoryNode | None = None
    authoritative_node_id: str
    gazette_ref: str | None = None
    source_spans: list[SourceSpan] = Field(default_factory=list)
    divergence_report: BilingualDivergenceReport | None = None


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


class RegimeConstraintCandidate(BaseModel):
    regime_id: str
    node_id: str
    act_name: str
    act_number: str
    section_code: str
    gazette_ref: str | None = None
    authority_tier: AuthorityTier = AuthorityTier.TIER_2_ACT_OF_PARLIAMENT
    constraint: DeonticConstraint


class InterRegimeConflictDelta(BaseModel):
    metric_key: str
    winning_regime: str
    winning_node_id: str
    winning_bound: float | str | bool
    superseded_regime: str
    superseded_node_id: str
    superseded_bound: float | str | bool
    delta_summary: str


class ResolvedMetricBound(BaseModel):
    metric_key: str
    modality: Literal[
        "OBLIGATION",
        "PROHIBITION",
        "PERMISSION",
        "VOLUNTARY_GUIDELINE",
        "PRE_COMMENCEMENT_ADVISORY",
    ]
    operator: Literal["<=", ">=", "==", "FORBIDDEN_CLAUSE"]
    strictest_value: float | str | bool
    unit: str = ""
    dominating_regime: str
    dominating_node_id: str
    dominating_citation: str
    provenance_chain: list[RegimeConstraintCandidate] = Field(default_factory=list)


class RecipientNoticeObligation(BaseModel):
    """Distinct recipient-specific statutory notification obligation resolved without conflation."""

    recipient: str
    notice_stage: str = "INITIAL_NOTICE"
    regime_id: str
    node_id: str
    citation: str
    metric_key: str
    operator: Literal["<=", ">=", "==", "FORBIDDEN_CLAUSE"] = "<="
    threshold_value: float | str | bool
    unit: str = ""
    description: str = ""


class CompositeDeonticEnvelope(BaseModel):
    as_of_date: date
    territorial_scope: TerritorialScope = TerritorialScope.ALL_MALAYSIA
    regimes_evaluated: list[str] = Field(default_factory=list)
    active_node_ids: list[str] = Field(default_factory=list)
    pending_commencement_node_ids: list[str] = Field(default_factory=list)
    resolved_bounds: dict[str, ResolvedMetricBound] = Field(default_factory=dict)
    pre_commencement_advisories: dict[str, ResolvedMetricBound] = Field(
        default_factory=dict
    )
    recipient_obligations: dict[str, RecipientNoticeObligation] = Field(
        default_factory=dict
    )
    inter_regime_conflicts: list[InterRegimeConflictDelta] = Field(default_factory=list)
    envelope_hash: str = ""


class ContractEdgeType(str, Enum):
    DEFINES_TERM = "DEFINES_TERM"
    OVERRIDES_NOTWITHSTANDING = "OVERRIDES_NOTWITHSTANDING"
    CROSS_REFERENCES = "CROSS_REFERENCES"
    SUBJECT_TO = "SUBJECT_TO"
    INCORPORATES_SCHEDULE = "INCORPORATES_SCHEDULE"
    SURVIVES_TERMINATION = "SURVIVES_TERMINATION"


class ContractClauseNode(BaseModel):
    clause_id: str
    heading: str = ""
    section_type: Literal[
        "DEFINITION", "OPERATIVE", "PRIORITY_OVERRIDE", "SCHEDULE", "GENERAL"
    ] = "OPERATIVE"
    text: str
    paragraph_idx: int = 0
    pdf_page: int = 1
    start_char: int = 0
    end_char: int = 1
    source_span: SourceSpan
    defined_terms: list[str] = Field(default_factory=list)
    referenced_clauses: list[str] = Field(default_factory=list)
    extracted_metrics: dict[str, float | str | bool] = Field(default_factory=dict)
    table_rows: list[list[str]] = Field(default_factory=list)


class ContractDependencyEdge(BaseModel):
    source_clause_id: str
    target_clause_id: str
    edge_type: ContractEdgeType
    trigger_phrase: str = ""
    term_name: str | None = None
    is_hostile_trap: bool = False
    rationale: str = ""


class NarrowDefinitionTrap(BaseModel):
    term_name: str
    definition_clause_id: str
    target_clause_ids: list[str] = Field(default_factory=list)
    contract_definition: str
    statutory_conflict: str
    severity: RiskSeverity = RiskSeverity.HIGH


class ShadowOverrideTrap(BaseModel):
    overriding_clause_id: str
    target_clause_id: str
    trigger_phrase: str
    overriding_quote: str
    target_quote: str
    trap_description: str
    severity: RiskSeverity = RiskSeverity.CRITICAL


class ContractASTGraph(BaseModel):
    document_id: str
    source_format: Literal["text", "docx", "pdf"] = "text"
    scrubbed_text: str
    raw_sha256: str = ""
    clauses: list[ContractClauseNode] = Field(default_factory=list)
    edges: list[ContractDependencyEdge] = Field(default_factory=list)
    narrow_definition_traps: list[NarrowDefinitionTrap] = Field(default_factory=list)
    shadow_override_traps: list[ShadowOverrideTrap] = Field(default_factory=list)
    ocr_metadata: dict[str, Any] | None = None
    requires_ocr_abstention: bool = False


class DocumentSecurityFinding(BaseModel):
    finding_id: str
    category: Literal[
        "HIDDEN_OOXML_TEXT",
        "HIDDEN_FONT_SIZE",
        "NEAR_WHITE_TEXT",
        "SUSPICIOUS_CUSTOM_XML",
        "MACRO_OR_EMBEDDED",
        "HIDDEN_PDF_LAYER",
        "INDIRECT_PROMPT_INJECTION",
        "STATUTORY_SPOOF_OVERRIDE",
        "ZIP_BOMB_OR_MALFORMED_ARCHIVE",
        "UNICODE_BIDI_OVERRIDE",
        "ZERO_WIDTH_STEGANOGRAPHY",
        "UNICODE_HOMOGLYPH_SPOOFING",
    ]
    severity: RiskSeverity
    source_format: Literal["docx", "pdf", "text"]
    location: str
    excerpt: str
    rationale: str
    quarantined: bool = True


SecurityFinding = DocumentSecurityFinding


class DocumentSecurityReport(BaseModel):
    document_id: str
    source_format: Literal["docx", "pdf", "text"]
    passed: bool
    risk_level: RiskSeverity = RiskSeverity.LOW
    blocked_injection_count: int = 0
    quarantined_segments: list[str] = Field(default_factory=list)
    findings: list[DocumentSecurityFinding] = Field(default_factory=list)
    sanitized_text: str
    pii_scrub_applied: bool = True
    telemetry: TelemetrySummary


class ComplianceAttestationManifest(BaseModel):
    manifest_id: str = ""
    document_id: str
    input_doc_sha256: str
    graph_state_hash: str
    as_of_date: date
    regimes: list[str] = Field(default_factory=list)
    territorial_scope: str = TerritorialScope.ALL_MALAYSIA.value
    is_verified_grounded: bool = True
    retry_count: int = 0
    estimated_cost_usd: float = 0.0
    estimated_cost_myr: float = 0.0
    total_tokens: int = 0
    model_used: str | None = None
    trace_id: str | None = None
    citation_span_ids: list[str] = Field(default_factory=list)
    manifest_sha256: str = ""
    prev_chain_hash: str = ""
    chain_hash: str = ""
    signature_b64: str = ""
    signing_key_id: str = ""
    signature_algorithm: str = "Ed25519"


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
    overriding_clause_id: str | None = Field(
        default=None,
        description="Clause ID of any overriding 'Notwithstanding' / 'Walau apa pun' shadow trap.",
    )
    overriding_clause_quote: str | None = Field(
        default=None,
        description="Verbatim quote from the overriding shadow clause if applicable.",
    )
    addresses_shadow_override: bool = Field(
        default=False,
        description="True when recommended_redline explicitly neutralizes linked OVERRIDES_NOTWITHSTANDING traps.",
    )
    proposed_notice_hours: float | None = Field(
        default=None,
        description="Post-redline incident notice SLA in hours extracted for counterfactual verification.",
    )
    proposed_report_days: float | None = Field(
        default=None,
        description="Post-redline full regulatory report SLA in days extracted for counterfactual verification.",
    )
    satisfies_deontic_envelope: bool = Field(
        default=True,
        description="True when counterfactual redline simulation satisfies the strictest composite deontic envelope.",
    )
    deontic_modality: (
        Literal[
            "OBLIGATION",
            "PROHIBITION",
            "PERMISSION",
            "VOLUNTARY_GUIDELINE",
            "PRE_COMMENCEMENT_ADVISORY",
        ]
        | None
    ) = Field(
        default=None,
        description="Optional deontic modality discriminating mandatory statutory duties vs voluntary guidelines or pre-commencement advisories.",
    )
    is_voluntary_guideline: bool = Field(
        default=False,
        description="True when finding arises from a voluntary governance guideline (e.g. MOSTI AIGE) rather than mandatory statute.",
    )
    is_pre_commencement_advisory: bool = Field(
        default=False,
        description="True when finding arises from a gazetted statute pending Ministerial commencement (e.g. Act 882).",
    )
    playbook_rule_id: str | None = Field(
        default=None,
        description="Active tenant PrecedentPlaybookRule ID applied during deterministic audit.",
    )
    playbook_tier_applied: (
        Literal["TIER_1_PREFERRED", "TIER_2_FALLBACK", "TIER_3_STATUTORY_FLOOR"] | None
    ) = Field(
        default=None,
        description="Negotiation playbook tier applied to recommended_redline.",
    )


class ClauseExtractionList(BaseModel):
    clauses: list[ClauseAudit]


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
    regimes: list[str] = Field(default_factory=lambda: ["ACT_709"])
    language: str = "bilingual"
    executive_summary: str = ""
    pii_scrub: PIIScrubSummary | None = None
    bilingual_provisions: list[BilingualClausePair] = Field(default_factory=list)
    bilingual_divergence_warnings: list[BilingualDivergenceReport] = Field(
        default_factory=list
    )
    irac_summary: IRACAnalysis | None = None
    rakyat_summary: RakyatGuidance | None = None
    deontic_envelope: CompositeDeonticEnvelope | None = None
    contract_ast: ContractASTGraph | None = None
    attestation_manifest: ComplianceAttestationManifest | None = None
    security_findings: list[DocumentSecurityFinding] = Field(default_factory=list)
    security_report: DocumentSecurityReport | None = None
    audit_session_id: str | None = None
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
    as_of_date: date | None = Field(
        default=None,
        description="Optional alias for reference_date (YYYY-MM-DD).",
    )
    act_filter: str | None = Field(
        default=None,
        description="Optional canonical statute name filter, e.g., Personal Data Protection Act 2010",
    )
    regimes: list[str] | None = Field(
        default=None,
        description="Optional multi-regime selection e.g. ['ACT_709', 'ACT_854', 'BNM_RMIT']",
    )
    territorial_scope: TerritorialScope | None = Field(
        default=None,
        description="Optional Malaysian territorial jurisdiction filter",
    )
    persona: OutputPersona = Field(
        default=OutputPersona.PRACTITIONER,
        description="Output mode: PRACTITIONER (IRAC) or RAKYAT (plain-language + gov.my steps)",
    )
    language: Literal["bm", "ms", "en", "bilingual"] = Field(
        default="bilingual",
        description="Preferred output narrative language ('bm', 'ms', 'en', or 'bilingual')",
    )
    abstention_threshold: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Optional override for deterministic relevance abstention threshold (default 0.78)",
    )
    audit_session_id: str | None = Field(
        default=None,
        description="Optional client-supplied audit session ID for cross-worker PII vault re-hydration.",
    )
    cache_bypass: bool = Field(
        default=False,
        description="When true, bypasses the deterministic Clause-AST verdict cache.",
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
    bilingual_divergence_warnings: list[BilingualDivergenceReport] = Field(
        default_factory=list
    )
    irac_summary: IRACAnalysis | None = None
    rakyat_summary: RakyatGuidance | None = None
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER
    telemetry: TelemetrySummary


class GraphTopologyResponse(BaseModel):
    as_of_date: date | None = None
    nodes: list[StatutoryNode]
    edges: list[StatutoryEdge]
    cypher_query: str
    contract_nodes: list[dict[str, Any]] = Field(default_factory=list)
    contract_edges: list[dict[str, Any]] = Field(default_factory=list)
    deontic_envelope: CompositeDeonticEnvelope | None = None


class TelemetryMetricsResponse(BaseModel):
    total_runs: int
    total_tokens: int
    total_cost_usd: float
    total_cost_myr: float
    average_latency_ms: float
    grounded_rate: float
    spans: list[dict] = Field(default_factory=list)


class PointInTimeResearchRequest(BaseModel):
    query: str = Field(
        ..., min_length=1, description="Malaysian legal query in BM, EN, or mixed"
    )
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
    bilingual_divergence_warnings: list[BilingualDivergenceReport] = Field(
        default_factory=list
    )
    judicial_treatments: list[JudicialTreatmentItem] = Field(default_factory=list)
    subgraph: SubgraphVisualizationData = Field(
        default_factory=SubgraphVisualizationData
    )
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


class ClauseDiffSegment(BaseModel):
    change_type: Literal["ADDED", "REMOVED", "MODIFIED", "UNCHANGED"]
    from_text: str = ""
    to_text: str = ""
    from_span_id: str | None = None
    to_span_id: str | None = None


class StatutoryTransitionStep(BaseModel):
    source_node_id: str
    target_node_id: str
    edge_type: TemporalEdgeType
    effective_date: date
    gazette_ref: str | None = None


class StatutoryVersionDiff(BaseModel):
    provision_id: str
    act_name: str
    act_number: str
    section_code: str
    language: str
    from_date: date
    to_date: date
    change_status: Literal[
        "UNCHANGED",
        "AMENDED",
        "NEWLY_ENACTED",
        "REPEALED",
        "NOT_IN_FORCE",
    ]
    from_node_id: str | None = None
    to_node_id: str | None = None
    from_status: StatutoryStatus | None = None
    to_status: StatutoryStatus | None = None
    from_text: str = ""
    to_text: str = ""
    from_source_spans: list[SourceSpan] = Field(default_factory=list)
    to_source_spans: list[SourceSpan] = Field(default_factory=list)
    transition_dates: list[date] = Field(default_factory=list)
    transitions: list[StatutoryTransitionStep] = Field(default_factory=list)
    added_clauses: list[str] = Field(default_factory=list)
    removed_clauses: list[str] = Field(default_factory=list)
    modified_clauses: list[ClauseDiffSegment] = Field(default_factory=list)
    unified_redline: list[ClauseDiffSegment] = Field(default_factory=list)
    related_gazettes: list[str] = Field(default_factory=list)
    telemetry: TelemetrySummary
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


class StatutoryDiffRequest(BaseModel):
    provision_id: str = Field(..., min_length=1)
    from_date: date
    to_date: date


class ContractDeltaAuditRequest(BaseModel):
    document_id: str = Field(default="DELTA-AUDIT-001", min_length=1)
    raw_text: str = Field(..., min_length=1)
    from_date: date
    to_date: date
    act_filter: str | None = None
    regimes: list[str] | None = None
    territorial_scope: TerritorialScope = Field(default=TerritorialScope.ALL_MALAYSIA)
    persona: OutputPersona = Field(default=OutputPersona.PRACTITIONER)


class ContractDeltaFinding(BaseModel):
    rule_id: str
    section_ref: str
    impact_type: Literal[
        "NEWLY_NON_COMPLIANT",
        "SEVERITY_ESCALATED",
        "NEW_STATUTORY_MANDATE",
        "REMEDIATED_BY_REPEAL",
        "UNCHANGED",
    ]
    from_status: str
    to_status: str
    from_severity: RiskSeverity | None = None
    to_severity: RiskSeverity | None = None
    exact_quote: str
    triggering_statute_ids: list[str] = Field(default_factory=list)
    triggering_gazettes: list[str] = Field(default_factory=list)
    source_spans: list[SourceSpan] = Field(default_factory=list)
    explanation_practitioner: str
    explanation_rakyat: str


class ContractDeltaAuditResponse(BaseModel):
    document_id: str
    from_date: date
    to_date: date
    territorial_scope: TerritorialScope
    persona: OutputPersona
    from_overall_risk: RiskSeverity
    to_overall_risk: RiskSeverity
    became_non_compliant: bool
    compliance_regression_detected: bool
    pii_scrub: PIIScrubSummary
    intervening_statutory_diffs: list[StatutoryVersionDiff] = Field(
        default_factory=list
    )
    newly_commenced_gazettes: list[str] = Field(default_factory=list)
    delta_findings: list[ContractDeltaFinding] = Field(default_factory=list)
    summary_practitioner: str
    summary_rakyat: str
    telemetry: TelemetrySummary
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


class SecurityScanRequest(BaseModel):
    document_id: str = Field(default="SEC-SCAN-001", min_length=1)
    raw_text: str = Field(..., min_length=1)


class PortfolioContractInput(BaseModel):
    document_id: str = ""
    contract_id: str | None = None
    title: str | None = None
    raw_text: str = ""
    text: str | None = None
    territorial_scope: TerritorialScope | None = None
    regimes: list[str] | None = None
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _sync_contract_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)
        if not d.get("document_id") and d.get("contract_id"):
            d["document_id"] = d["contract_id"]
        if not d.get("contract_id") and d.get("document_id"):
            d["contract_id"] = d["document_id"]
        if not d.get("raw_text") and d.get("text"):
            d["raw_text"] = d["text"]
        if not d.get("text") and d.get("raw_text"):
            d["text"] = d["raw_text"]
        return d

    @model_validator(mode="after")
    def _validate_contract_fields(self) -> "PortfolioContractInput":
        if not self.document_id and self.contract_id:
            self.document_id = self.contract_id
        if not self.contract_id and self.document_id:
            self.contract_id = self.document_id
        if not self.raw_text and self.text:
            self.raw_text = self.text
        if not self.text and self.raw_text:
            self.text = self.raw_text
        if not self.document_id.strip():
            raise ValueError(
                "PortfolioContractInput requires non-empty document_id or contract_id."
            )
        if not self.raw_text.strip():
            raise ValueError(
                "PortfolioContractInput requires non-empty raw_text or text."
            )
        return self


class PortfolioBlastRadiusRequest(BaseModel):
    from_date: date
    to_date: date
    contracts: list[PortfolioContractInput] = Field(..., min_length=1, max_length=50)
    regimes: list[str] | None = None
    default_territorial_scope: TerritorialScope = Field(
        default=TerritorialScope.ALL_MALAYSIA
    )
    persona: OutputPersona = Field(default=OutputPersona.PRACTITIONER)


class PortfolioContractImpact(BaseModel):
    document_id: str
    contract_id: str | None = None
    title: str | None = None
    territorial_scope: TerritorialScope
    rank: int = 1
    impact_score: float = 0.0
    from_overall_risk: RiskSeverity
    to_overall_risk: RiskSeverity
    became_non_compliant: bool
    broken_clause_count: int = 0
    broken_rule_ids: list[str] = Field(default_factory=list)
    triggering_gazettes: list[str] = Field(default_factory=list)
    strictest_deontic_bounds: dict[str, Any] = Field(default_factory=dict)
    pii_scrub: PIIScrubSummary
    remediation_summary_practitioner: str
    remediation_summary_rakyat: str
    delta_findings: list[ContractDeltaFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def _sync_contract_id(self) -> "PortfolioContractImpact":
        self.contract_id = self.contract_id or self.document_id
        return self


class PortfolioBlastRadiusResponse(BaseModel):
    from_date: date
    to_date: date
    total_contracts_scanned: int
    impacted_contracts_count: int
    newly_non_compliant_count: int
    newly_commenced_gazettes: list[str] = Field(default_factory=list)
    affected_statute_ids: list[str] = Field(default_factory=list)
    ranked_impacts: list[PortfolioContractImpact] = Field(default_factory=list)
    executive_summary_practitioner: str
    executive_summary_rakyat: str
    telemetry: TelemetrySummary
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


class PortfolioAsyncJobRequest(BaseModel):
    from_date: date
    to_date: date
    contracts: list[PortfolioContractInput] = Field(..., min_length=1, max_length=2000)
    regimes: list[str] | None = None
    default_territorial_scope: TerritorialScope = Field(
        default=TerritorialScope.ALL_MALAYSIA
    )
    persona: OutputPersona = Field(default=OutputPersona.PRACTITIONER)
    max_workers: int = Field(default=4, ge=1, le=16)
    webhook_url: str | None = None
    cache_bypass: bool = False


class WebhookDeliveryStatus(BaseModel):
    webhook_url: str
    status: Literal["PENDING", "DELIVERED", "FAILED", "BLOCKED_SSRF"] = "PENDING"
    attempts: int = 0
    last_http_status: int | None = None
    last_error: str | None = None
    delivered_at: str | None = None
    signature_hmac_256: str | None = None
    signature_ed25519: str | None = None


class PortfolioJobStatusResponse(BaseModel):
    job_id: str
    tenant_id: str = "default-tenant"
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED", "DEAD_LETTER"]
    total_contracts: int = 0
    processed_contracts: int = 0
    max_workers: int = 4
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    webhook_url: str | None = None
    webhook_delivery: WebhookDeliveryStatus | None = None
    cache_hits: int = 0
    cache_misses: int = 0
    result: PortfolioBlastRadiusResponse | None = None
    idempotency_key: str | None = None
    payload_fingerprint: str | None = None
    worker_id: str | None = None
    lease_expires_at: str | None = None
    heartbeat_at: str | None = None
    attempt_count: int = 0
    max_attempts: int = 3
    last_error_code: str | None = None
    requeued_at: str | None = None


class PortfolioDLQListResponse(BaseModel):
    tenant_id: str
    total: int = 0
    jobs: list[PortfolioJobStatusResponse] = Field(default_factory=list)


class AttestationLedgerRecord(BaseModel):
    manifest_id: str
    document_id: str
    input_doc_sha256: str
    graph_state_hash: str
    as_of_date: date
    regimes: list[str] = Field(default_factory=list)
    territorial_scope: str = TerritorialScope.ALL_MALAYSIA.value
    is_verified_grounded: bool = True
    retry_count: int = 0
    estimated_cost_usd: float = 0.0
    estimated_cost_myr: float = 0.0
    total_tokens: int = 0
    model_used: str | None = None
    trace_id: str | None = None
    citation_span_ids: list[str] = Field(default_factory=list)
    manifest_sha256: str
    prev_chain_hash: str
    chain_hash: str
    signature_b64: str = ""
    signing_key_id: str = ""
    signature_algorithm: str = "Ed25519"
    recorded_at: str
    telemetry_snapshot: dict[str, Any] = Field(default_factory=dict)


class AttestationVerifyRequest(BaseModel):
    manifest_id: str | None = None
    raw_text: str | None = None
    expected_doc_sha256: str | None = None
    manifest: ComplianceAttestationManifest | None = None


class AttestationVerifyResponse(BaseModel):
    manifest_id: str
    verified: bool
    status: Literal["VERIFIED", "TAMPERED", "NOT_FOUND"]
    digest_matches: bool = False
    manifest_sha256_valid: bool = False
    chain_link_valid: bool = False
    ledger_chain_valid: bool = False
    signature_valid: bool = False
    signing_key_id: str | None = None
    signature_algorithm: str = "Ed25519"
    tamper_reasons: list[str] = Field(default_factory=list)
    record: AttestationLedgerRecord | None = None
    telemetry: TelemetrySummary
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


class AttestationPublicKeyResponse(BaseModel):
    key_id: str
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_pem: str
    public_key_b64: str
    fingerprint_sha256: str


# =============================================================================
# Deliverable 1: Counterparty OOXML Track-Changes & Comment-Thread Negotiation
# =============================================================================

RedlineClassification = Literal[
    "COMPLIANT_ACCEPT",
    "DEONTIC_REGRESSION",
    "COMMENT_CONFLICT",
    "NEUTRAL_EDIT",
]


class RedlineRevisionItem(BaseModel):
    revision_id: str = ""
    revision_type: Literal["INS", "DEL", "MOVE_FROM", "MOVE_TO", "REPLACE"]
    author: str = "counterparty"
    date: str = ""
    text: str = ""


class CommentAnnotation(BaseModel):
    comment_id: str
    author: str = "counterparty"
    date: str = ""
    text: str
    para_id: str | None = None
    parent_comment_id: str | None = None
    parent_para_id: str | None = None
    resolved: bool = False
    has_conflict: bool = False
    conflict_reason: str | None = None


class RedlineRevisionInput(BaseModel):
    clause_id: str = "SEC-1.0"
    baseline_text: str = ""
    proposed_text: str = ""
    author: str = "counterparty"
    date: str = ""
    revision_id: str = ""
    revision_type: Literal["INS", "DEL", "MOVE_FROM", "MOVE_TO", "REPLACE"] = "REPLACE"
    comments: list[CommentAnnotation] = Field(default_factory=list)


class CounterpartyRedlineJsonRequest(BaseModel):
    document_id: str = Field(default="NEG-REDLINE-001", min_length=1)
    as_of_date: date | None = None
    regimes: list[str] | None = None
    territorial_scope: TerritorialScope = Field(default=TerritorialScope.ALL_MALAYSIA)
    docx_base64: str | None = None
    filename: str | None = None
    baseline_text: str | None = None
    proposed_text: str | None = None
    revisions: list[RedlineRevisionInput] = Field(default_factory=list)
    comments: list[CommentAnnotation] = Field(default_factory=list)
    audit_session_id: str | None = None


class ClauseRedlineDelta(BaseModel):
    clause_id: str
    classification: RedlineClassification
    severity: RiskSeverity = RiskSeverity.LOW
    baseline_text: str
    proposed_text: str
    revisions: list[RedlineRevisionItem] = Field(default_factory=list)
    comments: list[CommentAnnotation] = Field(default_factory=list)
    breached_bounds: list[str] = Field(default_factory=list)
    violated_statute_ids: list[str] = Field(default_factory=list)
    source_span_ids: list[str] = Field(default_factory=list)
    rationale: str = ""
    recommended_counter_redline: str = ""


class CounterpartyRedlineDiff(BaseModel):
    document_id: str
    as_of_date: date
    territorial_scope: TerritorialScope = TerritorialScope.ALL_MALAYSIA
    regimes: list[str] = Field(default_factory=list)
    overall_risk: RiskSeverity = RiskSeverity.LOW
    baseline_clauses: list[ContractClauseNode] = Field(default_factory=list)
    proposed_clauses: list[ContractClauseNode] = Field(default_factory=list)
    clause_deltas: list[ClauseRedlineDelta] = Field(default_factory=list)
    regression_count: int = 0
    comment_conflict_count: int = 0
    compliant_accept_count: int = 0
    neutral_edit_count: int = 0
    deontic_envelope: CompositeDeonticEnvelope | None = None
    security_report: DocumentSecurityReport | None = None
    pii_scrub: PIIScrubSummary | None = None
    audit_session_id: str | None = None
    attestation_manifest: ComplianceAttestationManifest | None = None
    telemetry: TelemetrySummary
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


# =============================================================================
# Deliverable 3: Sub-Processor SLA Cascade Verifier & Incident Playbook
# =============================================================================

PartyRole = Literal[
    "DATA_USER_CONTROLLER",
    "NCII_ENTITY",
    "BNM_FINANCIAL_INSTITUTION",
    "PUBLIC_SECTOR_AGENCY_ACT_864",
]


class SLACascadeCheckItem(BaseModel):
    recipient: str
    notice_stage: str
    regime_id: str
    citation: str
    node_id: str
    vendor_notice_hours: float
    regulator_deadline_hours: float
    slack_hours: float
    deficit_hours: float
    triage_buffer_ratio: float
    min_required_buffer_hours: float
    recommended_max_vendor_hours: float
    status: Literal["COMPLIANT", "SLA_CASCADE_BREACH"]
    breach_reason: Literal["NONE", "IMPOSSIBLE_TIMELINE", "INSUFFICIENT_TRIAGE_BUFFER"]
    severity: RiskSeverity
    clause_id: str = "SEC-1.0"
    clause_excerpt: str = ""


class SLACascadeReport(BaseModel):
    document_id: str
    party_role: PartyRole
    as_of_date: date
    territorial_scope: TerritorialScope = TerritorialScope.ALL_MALAYSIA
    regimes: list[str] = Field(default_factory=list)
    extracted_vendor_notice_hours: float | None = None
    is_business_days_window: bool = False
    cascade_breach_detected: bool = False
    overall_risk: RiskSeverity = RiskSeverity.LOW
    checks: list[SLACascadeCheckItem] = Field(default_factory=list)
    recommended_redline_en: str = ""
    recommended_redline_bm: str = ""
    pii_scrub: PIIScrubSummary | None = None
    telemetry: TelemetrySummary
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


class IncidentTimelineMilestone(BaseModel):
    milestone_order: int
    recipient: str
    notice_stage: str
    regime_id: str
    node_id: str
    citation: str
    statutory_window_value: float
    statutory_window_unit: str
    deadline_utc: str
    deadline_myt: str
    hours_from_discovery: float
    act_388_s54_applied: bool = False
    act_388_s54_metadata: dict[str, Any] | None = None
    description: str = ""
    source_span_ids: list[str] = Field(default_factory=list)


class IncidentPlaybookRequest(BaseModel):
    document_id: str = Field(default="INCIDENT-PLAYBOOK-001", min_length=1)
    discovery_timestamp: str = Field(
        ...,
        min_length=10,
        description="ISO-8601 incident discovery timestamp, normalized to Asia/Kuala_Lumpur.",
    )
    party_role: PartyRole = Field(default="DATA_USER_CONTROLLER")
    triggered_regimes: list[str] = Field(
        default_factory=lambda: ["ACT_709", "ACT_854", "BNM_RMIT"]
    )
    territorial_scope: TerritorialScope = Field(default=TerritorialScope.ALL_MALAYSIA)
    as_of_date: date | None = None
    contract_text: str | None = None
    clauses: list[str] | None = None

    @model_validator(mode="before")
    @classmethod
    def _accept_regimes_alias(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)
        if "triggered_regimes" not in d and "regimes" in d:
            d["triggered_regimes"] = d["regimes"]
        return d


class IncidentPlaybookResponse(BaseModel):
    document_id: str
    party_role: PartyRole
    discovery_timestamp_utc: str
    discovery_timestamp_myt: str
    as_of_date: date
    territorial_scope: TerritorialScope
    triggered_regimes: list[str] = Field(default_factory=list)
    milestones: list[IncidentTimelineMilestone] = Field(default_factory=list)
    sla_cascade_report: SLACascadeReport | None = None
    sla_cascade_warnings: list[SLACascadeCheckItem] = Field(default_factory=list)
    recommended_redline_en: str = ""
    recommended_redline_bm: str = ""
    attestation_manifest: ComplianceAttestationManifest | None = None
    attestation_record: AttestationLedgerRecord | None = None
    telemetry: TelemetrySummary
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


# =============================================================================
# Deliverable 5: Tenant FinOps Monthly Usage & Budget Guardrail
# =============================================================================


class TenantFinOpsUsageResponse(BaseModel):
    tenant_id: str
    billing_month: str
    total_runs: int = 0
    cache_hit_runs: int = 0
    deterministic_fallback_runs: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cumulative_cost_usd: float = 0.0
    cumulative_cost_myr: float = 0.0
    monthly_budget_myr: float = 0.0
    remaining_budget_myr: float | None = None
    budget_exceeded: bool = False
    budget_policy: Literal["deterministic_fallback", "reject_429"] = (
        "deterministic_fallback"
    )
    fx_rate_used: float = 4.40
    fx_rate_source: str = "fallback"


# =============================================================================
# Phase 6: Bilingual Hybrid Retrieval Explainability & HITL Counsel Ledger
# =============================================================================


class RetrievalExplainRequest(BaseModel):
    query: str = Field(..., min_length=1)
    as_of_date: date | None = None
    territorial_scope: str | None = None
    top_k: int = Field(default=5, ge=1, le=25)
    abstention_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    regimes: list[str] | None = None


class RetrievalExplainCandidate(BaseModel):
    node_id: str
    act_name: str
    act_number: str
    section_code: str
    language: str
    bm25_score: float
    vector_score: float
    graph_boost_score: float = 0.0
    rrf_score: float
    calibrated_score: float
    temporal_valid: bool = True
    territorial_tier: Literal["Sabah", "Sarawak", "Labuan", "Peninsular", "Federal"]
    authority_tier: int
    matched_fields: list[str] = Field(default_factory=list)
    source_span_ids: list[str] = Field(default_factory=list)


class RetrievalExplainResponse(BaseModel):
    query: str
    detected_language: str
    as_of_date: date
    territorial_scope: str | None = None
    abstention_threshold: float
    is_abstained: bool
    abstention_reason: str | None = None
    max_score: float
    embedding_provider: str
    rrf_k: int = 60
    candidates: list[RetrievalExplainCandidate] = Field(default_factory=list)


HITLDecision = Literal[
    "ACCEPT_REDLINE",
    "MODIFY_REDLINE",
    "REJECT_FALSE_POSITIVE",
    "ESCALATE_TO_COUNSEL",
]


class HITLReviewRequest(BaseModel):
    audit_session_id: str | None = None
    manifest_id: str | None = None
    document_id: str = Field(default="HITL-DOC-001", min_length=1)
    clause_id: str = Field(..., min_length=1)
    decision: HITLDecision
    original_clause_text: str = Field(..., min_length=1)
    recommended_redline: str | None = None
    counsel_modified_text: str | None = None
    rationale: str = Field(..., min_length=1)
    statutory_node_ids: list[str] = Field(default_factory=list)
    regimes: list[str] = Field(default_factory=lambda: ["ACT_709"])
    as_of_date: date | None = None
    territorial_scope: str = TerritorialScope.ALL_MALAYSIA.value
    expected_overall_risk: RiskSeverity | None = None
    reviewer_id: str | None = None


class HITLReviewRecord(BaseModel):
    review_id: str
    tenant_id: str = "default-tenant"
    audit_session_id: str | None = None
    manifest_id: str | None = None
    document_id: str
    clause_id: str
    decision: HITLDecision
    scrubbed_clause_text: str
    scrubbed_recommended_redline: str | None = None
    scrubbed_counsel_modified_text: str | None = None
    scrubbed_rationale: str
    pii_redaction_count: int = 0
    statutory_node_ids: list[str] = Field(default_factory=list)
    regimes: list[str] = Field(default_factory=list)
    as_of_date: date
    territorial_scope: str
    expected_overall_risk: RiskSeverity
    reviewer_id: str
    attestation_manifest_id: str
    attestation_signature_b64: str
    attestation_chain_hash: str
    signing_key_id: str
    recorded_at: str


# =============================================================================
# Phase 7: Closed-Loop Counter-Redline .docx Compiler & Tenant Playbook Engine
# =============================================================================

CounselDisposition = Literal[
    "ACCEPT_COUNTERPARTY",
    "COUNTER_PROPOSE_FALLBACK",
    "REJECT_REVERT_BASELINE",
    "ESCALATE_COMMENT_ONLY",
]

PlaybookTier = Literal[
    "TIER_1_PREFERRED",
    "TIER_2_FALLBACK",
    "TIER_3_STATUTORY_FLOOR",
]


class ClauseDispositionOverride(BaseModel):
    clause_id: str
    disposition: CounselDisposition
    custom_text: str | None = None
    custom_comment: str | None = None
    playbook_tier: PlaybookTier = "TIER_2_FALLBACK"


class CounterRedlineCompileRequest(BaseModel):
    document_id: str = Field(default="COUNTER-REDLINE-001", min_length=1)
    audit_session_id: str | None = None
    docx_base64: str | None = None
    filename: str | None = None
    diff: CounterpartyRedlineDiff | None = None
    baseline_text: str | None = None
    proposed_text: str | None = None
    revisions: list[RedlineRevisionInput] = Field(default_factory=list)
    comments: list[CommentAnnotation] = Field(default_factory=list)
    dispositions: dict[str, CounselDisposition | ClauseDispositionOverride] = Field(
        default_factory=dict
    )
    counsel_author: str = Field(default="LexGraph Counsel")
    counsel_initials: str = Field(default="LGC")
    as_of_date: date | None = None
    regimes: list[str] | None = None
    territorial_scope: TerritorialScope = Field(default=TerritorialScope.ALL_MALAYSIA)
    rehydrate_pii: bool = True
    use_tenant_playbook: bool = True
    preferred_playbook_tier: PlaybookTier = "TIER_2_FALLBACK"


class CompiledClauseAction(BaseModel):
    clause_id: str
    classification: RedlineClassification
    disposition: CounselDisposition
    counter_text_source: Literal[
        "COUNTERPARTY_ACCEPTED",
        "COUNSEL_OVERRIDE",
        "TENANT_PLAYBOOK",
        "STATUTORY_REMEDIATION",
        "BASELINE_REVERT",
        "COMMENT_ONLY",
    ]
    playbook_rule_id: str | None = None
    playbook_tier: PlaybookTier | None = None
    comment_id: str | None = None
    cited_provisions: list[str] = Field(default_factory=list)
    emitted_del: bool = False
    emitted_ins: bool = False


class CounterRedlineCompileResult(BaseModel):
    document_id: str
    filename: str
    audit_session_id: str
    as_of_date: date
    regimes: list[str] = Field(default_factory=list)
    territorial_scope: TerritorialScope = TerritorialScope.ALL_MALAYSIA
    counsel_author: str
    in_place_ooxml_mutation: bool = False
    accepted_count: int = 0
    counter_proposed_count: int = 0
    reverted_count: int = 0
    escalated_count: int = 0
    comments_appended: int = 0
    rehydrated_pii_count: int = 0
    output_docx_sha256: str
    docx_base64: str
    clause_actions: list[CompiledClauseAction] = Field(default_factory=list)
    attestation_manifest: ComplianceAttestationManifest | None = None
    telemetry: TelemetrySummary
    disclaimer: str = DEFAULT_LEGAL_DISCLAIMER


class PrecedentPlaybookRule(BaseModel):
    rule_id: str
    tenant_id: str
    clause_archetype: str
    ast_fingerprint: str
    regimes: list[str] = Field(default_factory=list)
    territorial_scope: str = TerritorialScope.ALL_MALAYSIA.value
    as_of_date: date
    tier_1_preferred: str
    tier_2_fallback: str | None = None
    tier_3_statutory_floor: str
    statutory_floor_bounds: dict[str, Any] = Field(default_factory=dict)
    source_review_id: str | None = None
    source_decision: HITLDecision | None = None
    rationale: str = ""
    statutory_risk_waiver: bool = False
    waiver_rationale: str | None = None
    waiver_approved_by: str | None = None
    waiver_attestation_manifest_id: str | None = None
    attestation_manifest_id: str
    attestation_signature_b64: str = ""
    attestation_chain_hash: str = ""
    signing_key_id: str = ""
    created_by: str = "counsel"
    created_at: str
    updated_at: str


class PlaybookPromoteRequest(BaseModel):
    review_id: str | None = None
    clause_archetype: str | None = None
    original_clause_text: str | None = None
    tier_1_preferred: str | None = None
    tier_2_fallback: str | None = None
    regimes: list[str] | None = None
    territorial_scope: str | None = None
    as_of_date: date | None = None
    rationale: str = ""
    statutory_risk_waiver: bool = False
    waiver_rationale: str | None = None


class PlaybookListResponse(BaseModel):
    tenant_id: str
    playbook_digest: str
    total: int = 0
    rules: list[PrecedentPlaybookRule] = Field(default_factory=list)
