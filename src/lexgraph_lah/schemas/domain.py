from enum import Enum
from pydantic import BaseModel, Field


class RiskSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ClauseAudit(BaseModel):
    clause_id: str = Field(..., description="Section identifier, e.g., SEC-1.1")
    category: str = Field(..., description="E.g., Indemnification, IP Ownership, Liability, Termination")
    exact_quote: str = Field(
        ...,
        description="MUST be an exact, character-for-character verbatim substring from the source text.",
    )
    severity: RiskSeverity
    rationale: str = Field(..., description="Concise explanation of the legal/financial exposure.")
    recommended_redline: str = Field(..., description="Suggested safer replacement clause wording.")


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
    overall_risk: RiskSeverity
    findings: list[ClauseAudit]
    telemetry: TelemetrySummary
