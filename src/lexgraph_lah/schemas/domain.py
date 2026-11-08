import hashlib
from datetime import date
from enum import Enum

from pydantic import BaseModel, Field, model_validator


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

    @model_validator(mode="after")
    def _populate_hash_and_validate_window(self) -> "StatutoryNode":
        if self.valid_to is not None and self.valid_to <= self.valid_from:
            raise ValueError(
                f"valid_to ({self.valid_to}) must be strictly after valid_from ({self.valid_from})"
            )
        if not self.content_hash:
            self.content_hash = hashlib.sha256(
                self.text.strip().encode("utf-8")
            ).hexdigest()
        return self

    def is_active_on(self, as_of_date: date) -> bool:
        """Deterministic point-in-time validity check (zero LLM cost)."""
        return self.valid_from <= as_of_date and (
            self.valid_to is None or self.valid_to > as_of_date
        )


class StatutoryEdge(BaseModel):
    source_id: str = Field(..., description="Origin StatutoryNode ID")
    target_id: str = Field(..., description="Destination StatutoryNode ID")
    edge_type: TemporalEdgeType
    effective_date: date = Field(
        ..., description="Date on which this relationship took legal effect"
    )


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


class ClauseExtractionList(BaseModel):
    clauses: list[ClauseAudit]


class TelemetrySummary(BaseModel):
    total_tokens: int
    estimated_cost_usd: float
    estimated_cost_myr: float
    latency_ms: float
    retry_count: int
    is_verified_grounded: bool


class ContractAuditResponse(BaseModel):
    document_id: str
    reference_date: date | None = None
    overall_risk: RiskSeverity
    findings: list[ClauseAudit]
    active_statutes: list[StatutoryNode] = Field(default_factory=list)
    telemetry: TelemetrySummary


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
