from __future__ import annotations

import hashlib
import importlib
import json
import re
import sqlite3
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Protocol

from lexgraph_lah.config import settings
from lexgraph_lah.graph.deontic_solver import DeonticEnvelopeResolver, normalize_regimes
from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    get_default_temporal_store,
)
from lexgraph_lah.hitl.review_store import HITLReviewLedger, default_hitl_review_ledger
from lexgraph_lah.ingestion.contract_ast import (
    _extract_clause_metrics,
    extract_numeric_sla_from_text,
)
from lexgraph_lah.schemas.domain import (
    ComplianceAttestationManifest,
    CompositeDeonticEnvelope,
    HITLReviewRecord,
    PlaybookListResponse,
    PlaybookPromoteRequest,
    PlaybookTier,
    PrecedentPlaybookRule,
    TelemetrySummary,
    TerritorialScope,
)
from lexgraph_lah.security.attestation_ledger import (
    AttestationLedger,
    compute_manifest_sha256,
    default_attestation_ledger,
)

_DURATION_HOURS_OR_DAYS_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*[-\s]*(hours?|hrs?|jam|days?|hari)\b",
    re.IGNORECASE,
)

_WEEKLY_HOURS_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*[-\s]*(hours?|hrs?|jam)\s*(?:per\s+week|weekly|a\s+week|seminggu)",
    re.IGNORECASE,
)

_FORBIDDEN_BREACH_WAIVER_PHRASES: tuple[str, ...] = (
    "no breach notification",
    "waives breach notification",
    "no notice required",
    "need not notify the commissioner",
    "exempt from pdpa breach",
    "without notifying nacsa",
    "tanpa memaklumkan pesuruhjaya",
    "tiada notis pelanggaran diperlukan",
)


class StatutoryFloorViolationError(ValueError):
    """
    Raised when a tenant playbook promotion attempts to weaken or contravene a
    mandatory IN_FORCE statutory bound in DeonticEnvelopeResolver without an
    authorized admin statutory_risk_waiver.
    """

    def __init__(
        self,
        message: str,
        *,
        metric_key: str,
        proposed_value: float | str | bool | None,
        statutory_floor_value: float | str | bool | None,
        dominating_regime: str,
        dominating_citation: str,
        dominating_node_id: str,
        waiver_requires_admin: bool = True,
    ) -> None:
        super().__init__(message)
        self.code = "STATUTORY_FLOOR_VIOLATION"
        self.message = message
        self.metric_key = metric_key
        self.proposed_value = proposed_value
        self.statutory_floor_value = statutory_floor_value
        self.dominating_regime = dominating_regime
        self.dominating_citation = dominating_citation
        self.dominating_node_id = dominating_node_id
        self.waiver_requires_admin = waiver_requires_admin

    def to_detail_dict(self) -> dict[str, Any]:
        return {
            "error_code": self.code,
            "message": self.message,
            "metric_key": self.metric_key,
            "proposed_value": self.proposed_value,
            "statutory_floor_value": self.statutory_floor_value,
            "dominating_regime": self.dominating_regime,
            "dominating_citation": self.dominating_citation,
            "dominating_node_id": self.dominating_node_id,
            "waiver_requires_admin": self.waiver_requires_admin,
        }


def _sha256_hex(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def infer_clause_archetype(
    clause_text: str,
    *,
    metric_hints: dict[str, Any] | None = None,
    statute_ids: list[str] | None = None,
) -> str:
    """Deterministic AST + statutory classifier into normalized Malaysian clause archetypes."""
    low = (clause_text or "").lower()
    metrics = (
        metric_hints
        if metric_hints is not None
        else _extract_clause_metrics(clause_text)
    )
    stat_blob = " ".join(statute_ids or []).upper()

    if (
        "ACT-872" in stat_blob
        or metrics.get("gig_context_present")
        or metrics.get("gig_service_schedule_omitted")
        or metrics.get("gig_unilateral_algo_deactivation")
        or metrics.get("gig_tribunal_waiver")
        or metrics.get("gig_perkeso_omitted")
        or any(k in low for k in ("gig worker", "pekerja gig", "perkeso", "act 872"))
    ):
        return "gig_workers_act_872"

    if (
        "ACT-882" in stat_blob
        or metrics.get("gov_procurement_context_present")
        or metrics.get("gov_procurement_unauth_subcontract")
        or metrics.get("gov_procurement_tribunal_ouster")
        or any(
            k in low
            for k in (
                "government procurement",
                "perolehan kerajaan",
                "procurement appeal tribunal",
                "act 882",
            )
        )
    ):
        return "gov_procurement_act_882"

    if (
        "MOSTI-AIGE" in stat_blob
        or metrics.get("aige_ai_system_present")
        or any(
            k in low for k in ("mosti", "aige", "ai governance", "human-in-the-loop")
        )
    ):
        return "mosti_aige_ai_governance"

    if (
        "ACT-53" in stat_blob
        or "ACT-378" in stat_blob
        or metrics.get("myinvois_consolidated_claim") is not None
        or metrics.get("stamp_duty_payment_days") is not None
        or metrics.get("stamp_duty_excluded")
        or any(
            k in low
            for k in ("myinvois", "lhdn", "stamp duty", "sdsas", "act 53", "act 378")
        )
    ):
        return "fiscal_myinvois_and_stamp_duty"

    if (
        "BNM-" in stat_blob
        or metrics.get("bnm_crypto_key_owned_by_vendor")
        or metrics.get("bnm_subcontractor_unrestricted")
        or metrics.get("bnm_audit_right_excluded")
        or any(k in low for k in ("rmit", "bnm", "cryptographic key", "outsourcing"))
    ):
        return "bnm_rmit_incident_and_outsourcing"

    if "ACT-854" in stat_blob or any(
        k in low for k in ("ncii", "nacsa", "act 854", "220/2024", "cyber")
    ):
        return "ncii_cyber_incident_notice"

    if "ACT-864" in stat_blob or any(
        k in low for k in ("act 864", "data sharing", "perkongsian data", "s. 17(1)")
    ):
        return "data_sharing_public_agency_s17"

    if any(
        k in low
        for k in (
            "cross-border",
            "rentas sempadan",
            "transfer outside malaysia",
            "s. 129",
        )
    ):
        return "cross_border_data_transfer"

    if metrics.get("weekly_hours") is not None or any(
        k in low
        for k in (
            "working hours",
            "waktu kerja",
            "overtime",
            "act 265",
            "cap 67",
            "cap 76",
        )
    ):
        return "employment_working_hours_and_overtime"

    if "ACT-709" in stat_blob or any(
        k in low
        for k in (
            "breach",
            "pelanggaran data",
            "incident",
            "notify",
            "notifikasi",
            "pdpa",
            "commissioner",
            "pesuruhjaya",
        )
    ):
        return "pdpa_breach_notification"

    return "general_commercial_clause"


def compute_clause_ast_fingerprint(
    clause_text: str,
    *,
    clause_archetype: str | None = None,
    regimes: list[str] | None = None,
    territorial_scope: str = TerritorialScope.ALL_MALAYSIA.value,
) -> str:
    """
    Computes a stable Clause-AST structural fingerprint combining normalized structural
    AST metrics, clause archetype, canonical regime set, and territorial scope.
    """
    metrics = _extract_clause_metrics(clause_text or "")
    metric_keys_present = sorted(
        k for k, v in metrics.items() if v is not None and v is not False
    )
    archetype = clause_archetype or infer_clause_archetype(
        clause_text, metric_hints=metrics
    )
    normalized_tokens = re.sub(r"[^a-z0-9\s]", " ", (clause_text or "").lower())
    collapsed = re.sub(r"\s+", " ", normalized_tokens).strip()
    reg_list = normalize_regimes(regimes) if regimes else []
    payload = {
        "schema_v": 1,
        "archetype": archetype,
        "regimes": sorted(reg_list),
        "territorial_scope": str(territorial_scope),
        "metric_keys_present": metric_keys_present,
        "text_stem": collapsed[:240],
    }
    return _sha256_hex(payload)


def compute_statutory_floor_text(
    clause_archetype: str,
    envelope: CompositeDeonticEnvelope,
    *,
    as_of_date: date,
) -> tuple[str, dict[str, Any]]:
    """Builds the immutable TIER_3_STATUTORY_FLOOR position directly from DeonticEnvelopeResolver."""
    floor_bounds: dict[str, Any] = {}
    clauses: list[str] = []

    for metric_key in sorted(envelope.resolved_bounds.keys()):
        bound = envelope.resolved_bounds[metric_key]
        if bound.modality == "PRE_COMMENCEMENT_ADVISORY":
            continue
        floor_bounds[metric_key] = {
            "modality": bound.modality,
            "operator": bound.operator,
            "strictest_value": bound.strictest_value,
            "unit": bound.unit,
            "dominating_regime": bound.dominating_regime,
            "dominating_citation": bound.dominating_citation,
            "dominating_node_id": bound.dominating_node_id,
        }

    if "incident_notice_max_hours" in floor_bounds:
        b = floor_bounds["incident_notice_max_hours"]
        clauses.append(
            f"Mandatory initial breach notification <= {b['strictest_value']} {b['unit'] or 'hours'} "
            f"({b['dominating_citation']} / {b['dominating_regime']})"
        )
    if "max_weekly_work_hours" in floor_bounds:
        b = floor_bounds["max_weekly_work_hours"]
        clauses.append(
            f"Maximum statutory weekly working hours <= {b['strictest_value']} {b['unit'] or 'hours'} "
            f"({b['dominating_citation']})"
        )
    if "gig_mandatory_service_agreement_schedule" in floor_bounds:
        clauses.append(
            "Mandatory written service agreement schedule, algorithmic notice/review, Gig Workers Tribunal non-waiver & PERKESO remittance (Act 872)"
        )
    if "myinvois_consolidated_over_10k_prohibited" in floor_bounds:
        clauses.append(
            "Individual LHDN MyInvois validated e-invoice required for transactions exceeding RM 10,000 (Act 53 s. 82C)"
        )
    if "bnm_crypto_key_ownership_fi_retained" in floor_bounds:
        clauses.append(
            "Exclusive FI cryptographic key ownership, prior sub-contractor approval, and BNM right-of-audit (BNM Outsourcing & RMiT)"
        )

    if not clauses:
        for mk, b in list(floor_bounds.items())[:3]:
            clauses.append(
                f"{mk} {b['operator']} {b['strictest_value']} ({b['dominating_citation']})"
            )

    summary = (
        f"[TIER_3_STATUTORY_FLOOR as_of={as_of_date.isoformat()} archetype={clause_archetype}] "
        + (
            "; ".join(clauses)
            if clauses
            else "Maintain active Malaysian statutory compliance baseline."
        )
    )
    return summary, floor_bounds


def _extract_candidate_breach_hours(text: str) -> float | None:
    """Extracts breach notification delay in hours, supporting hyphenated '14-day' and BM 'hari/jam'."""
    notice_hours, _ = extract_numeric_sla_from_text(text)
    if notice_hours is not None:
        return notice_hours
    low = (text or "").lower()
    extracted: list[float] = []
    for m in _DURATION_HOURS_OR_DAYS_RE.finditer(low):
        val = float(m.group(1))
        unit = m.group(2).lower()
        window = low[max(0, m.start() - 48) : min(len(low), m.end() + 24)]
        if any(
            kw in window
            for kw in (
                "full report",
                "comprehensive report",
                "post-incident",
                "laporan penuh",
            )
        ):
            continue
        if unit in {"day", "days", "hari"}:
            extracted.append(val * 24.0)
        else:
            extracted.append(val)
    return min(extracted) if extracted else None


def validate_against_statutory_floor(
    candidate_text: str,
    *,
    clause_archetype: str,
    envelope: CompositeDeonticEnvelope,
) -> tuple[bool, StatutoryFloorViolationError | None]:
    """
    Verifies proposed house fallback / promotion text against mandatory IN_FORCE
    bounds resolved by DeonticEnvelopeResolver. PRE_COMMENCEMENT_ADVISORY and
    VOLUNTARY_GUIDELINE bounds do NOT trigger a hard statutory floor block.
    """
    text = (candidate_text or "").strip()
    if not text:
        return True, None

    low = text.lower()
    metrics = _extract_clause_metrics(text)
    bounds = envelope.resolved_bounds

    # 1. Breach / incident notification SLA upper bound (PDPA 72h, Act 854 6h, BNM RMiT 1h)
    notice_bound = bounds.get("incident_notice_max_hours")
    if (
        notice_bound is not None
        and notice_bound.modality
        not in {"VOLUNTARY_GUIDELINE", "PRE_COMMENCEMENT_ADVISORY"}
        and isinstance(notice_bound.strictest_value, (int, float))
        and not isinstance(notice_bound.strictest_value, bool)
    ):
        cand_hours = _extract_candidate_breach_hours(text)
        floor_h = float(notice_bound.strictest_value)
        if cand_hours is not None and cand_hours > floor_h:
            return False, StatutoryFloorViolationError(
                (
                    f"Proposed position specifies a {cand_hours:g}h notification window, violating the "
                    f"mandatory IN_FORCE {floor_h:g}h statutory floor ({notice_bound.dominating_citation} / "
                    f"{notice_bound.dominating_regime})."
                ),
                metric_key="incident_notice_max_hours",
                proposed_value=cand_hours,
                statutory_floor_value=floor_h,
                dominating_regime=notice_bound.dominating_regime,
                dominating_citation=notice_bound.dominating_citation,
                dominating_node_id=notice_bound.dominating_node_id,
            )
        if any(phrase in low for phrase in _FORBIDDEN_BREACH_WAIVER_PHRASES):
            return False, StatutoryFloorViolationError(
                (
                    f"Proposed position waives mandatory breach notification, violating "
                    f"{notice_bound.dominating_citation} ({notice_bound.dominating_regime})."
                ),
                metric_key="incident_notice_max_hours",
                proposed_value="NO_NOTIFICATION",
                statutory_floor_value=floor_h,
                dominating_regime=notice_bound.dominating_regime,
                dominating_citation=notice_bound.dominating_citation,
                dominating_node_id=notice_bound.dominating_node_id,
            )

    # 2. Maximum weekly working hours (Act 265 s. 60A <= 45h, Sabah Cap 67 / Sarawak Cap 76)
    hours_bound = bounds.get("max_weekly_work_hours")
    if (
        hours_bound is not None
        and hours_bound.modality
        not in {"VOLUNTARY_GUIDELINE", "PRE_COMMENCEMENT_ADVISORY"}
        and isinstance(hours_bound.strictest_value, (int, float))
        and not isinstance(hours_bound.strictest_value, bool)
    ):
        cand_weekly = metrics.get("weekly_hours")
        if cand_weekly is None:
            m_wk = _WEEKLY_HOURS_RE.search(low)
            if m_wk:
                cand_weekly = float(m_wk.group(1))
        floor_wk = float(hours_bound.strictest_value)
        if isinstance(cand_weekly, (int, float)) and cand_weekly > floor_wk:
            return False, StatutoryFloorViolationError(
                (
                    f"Proposed {cand_weekly:g}h/week working schedule exceeds the mandatory statutory "
                    f"ceiling of {floor_wk:g}h/week ({hours_bound.dominating_citation})."
                ),
                metric_key="max_weekly_work_hours",
                proposed_value=cand_weekly,
                statutory_floor_value=floor_wk,
                dominating_regime=hours_bound.dominating_regime,
                dominating_citation=hours_bound.dominating_citation,
                dominating_node_id=hours_bound.dominating_node_id,
            )

    # 3. Stamp Duty SDSAS 30-day window (Act 378)
    sd_bound = bounds.get("stamp_duty_payment_max_days")
    if (
        sd_bound is not None
        and sd_bound.modality
        not in {"VOLUNTARY_GUIDELINE", "PRE_COMMENCEMENT_ADVISORY"}
        and isinstance(sd_bound.strictest_value, (int, float))
        and not isinstance(sd_bound.strictest_value, bool)
    ):
        cand_sd = metrics.get("stamp_duty_payment_days")
        floor_sd = float(sd_bound.strictest_value)
        if isinstance(cand_sd, (int, float)) and cand_sd > floor_sd:
            return False, StatutoryFloorViolationError(
                (
                    f"Proposed stamp duty payment window ({cand_sd:g} days) exceeds mandatory SDSAS "
                    f"{floor_sd:g}-day limit ({sd_bound.dominating_citation})."
                ),
                metric_key="stamp_duty_payment_max_days",
                proposed_value=cand_sd,
                statutory_floor_value=floor_sd,
                dominating_regime=sd_bound.dominating_regime,
                dominating_citation=sd_bound.dominating_citation,
                dominating_node_id=sd_bound.dominating_node_id,
            )

    # 4. Forbidden structural / statutory waiver rules (only when IN_FORCE)
    forbidden_checks: tuple[tuple[str, bool, str], ...] = (
        (
            "gig_workers_tribunal_waiver_prohibited",
            bool(metrics.get("gig_tribunal_waiver")),
            "Clause purports to waive Gig Workers Tribunal recourse under Act 872 s. 25.",
        ),
        (
            "gig_unilateral_algorithmic_deactivation_prohibited",
            bool(metrics.get("gig_unilateral_algo_deactivation")),
            "Clause permits unilateral algorithmic deactivation/rate cuts prohibited under Act 872 s. 12.",
        ),
        (
            "gig_perkeso_deduction_remittance_required",
            bool(metrics.get("gig_perkeso_omitted")),
            "Clause omits mandatory PERKESO social security remittance under Act 872 s. 38.",
        ),
        (
            "gig_mandatory_service_agreement_schedule",
            bool(metrics.get("gig_service_schedule_omitted")),
            "Clause omits mandatory written service agreement schedule under Act 872 s. 4.",
        ),
        (
            "bnm_crypto_key_ownership_fi_retained",
            bool(metrics.get("bnm_crypto_key_owned_by_vendor")),
            "Clause vests cryptographic key ownership with vendor contrary to BNM RMiT / Outsourcing.",
        ),
        (
            "bnm_subcontractor_prior_approval_required",
            bool(metrics.get("bnm_subcontractor_unrestricted")),
            "Clause permits unrestricted sub-contracting without prior approval contrary to BNM Outsourcing.",
        ),
        (
            "regulator_audit_access",
            bool(metrics.get("bnm_audit_right_excluded")),
            "Clause excludes mandatory BNM/regulator right-of-audit.",
        ),
    )

    for mk, triggered, reason in forbidden_checks:
        b = bounds.get(mk)
        if (
            triggered
            and b is not None
            and b.modality not in {"VOLUNTARY_GUIDELINE", "PRE_COMMENCEMENT_ADVISORY"}
        ):
            return False, StatutoryFloorViolationError(
                f"{reason} ({b.dominating_citation} / {b.dominating_regime})",
                metric_key=mk,
                proposed_value="NON_COMPLIANT_CLAUSE",
                statutory_floor_value=b.strictest_value,
                dominating_regime=b.dominating_regime,
                dominating_citation=b.dominating_citation,
                dominating_node_id=b.dominating_node_id,
            )

    _ = clause_archetype
    return True, None


class PlaybookBackend(Protocol):
    """Persistence contract for tenant-isolated 3-tier Precedent Playbook rules."""

    def list_rules(self, *, tenant_id: str) -> list[PrecedentPlaybookRule]: ...

    def get_rule(
        self, rule_id: str, *, tenant_id: str
    ) -> PrecedentPlaybookRule | None: ...

    def upsert_rule(self, rule: PrecedentPlaybookRule) -> PrecedentPlaybookRule: ...

    def delete_tenant_rules(self, *, tenant_id: str) -> int: ...


class InMemoryPlaybookBackend:
    """Thread-safe in-memory storage strictly partitioned by tenant_id."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rules: dict[str, dict[str, PrecedentPlaybookRule]] = {}

    def list_rules(self, *, tenant_id: str) -> list[PrecedentPlaybookRule]:
        with self._lock:
            items = list(self._rules.get(tenant_id, {}).values())
        return sorted(items, key=lambda r: (r.updated_at, r.rule_id))

    def get_rule(self, rule_id: str, *, tenant_id: str) -> PrecedentPlaybookRule | None:
        with self._lock:
            return self._rules.get(tenant_id, {}).get(rule_id)

    def upsert_rule(self, rule: PrecedentPlaybookRule) -> PrecedentPlaybookRule:
        with self._lock:
            bucket = self._rules.setdefault(rule.tenant_id, {})
            bucket[rule.rule_id] = rule
        return rule

    def delete_tenant_rules(self, *, tenant_id: str) -> int:
        with self._lock:
            removed = self._rules.pop(tenant_id, {})
        return len(removed)


class SQLitePlaybookBackend:
    """SQLite WAL-mode persistence backend strictly partitioned by tenant_id."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        self._lock = threading.RLock()
        if self._db_path != ":memory:":
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS precedent_playbook_rules (
                rule_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                ast_fingerprint TEXT NOT NULL,
                clause_archetype TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, rule_id)
            )
            """
        )
        self._conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_playbook_tenant_fp
            ON precedent_playbook_rules(tenant_id, ast_fingerprint, clause_archetype)
            """
        )
        self._conn.commit()

    def list_rules(self, *, tenant_id: str) -> list[PrecedentPlaybookRule]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT payload_json
                FROM precedent_playbook_rules
                WHERE tenant_id = ?
                ORDER BY updated_at ASC, rule_id ASC
                """,
                (tenant_id,),
            ).fetchall()
        return [PrecedentPlaybookRule.model_validate_json(str(r[0])) for r in rows]

    def get_rule(self, rule_id: str, *, tenant_id: str) -> PrecedentPlaybookRule | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT payload_json
                FROM precedent_playbook_rules
                WHERE tenant_id = ? AND rule_id = ?
                LIMIT 1
                """,
                (tenant_id, rule_id),
            ).fetchone()
        if row is None:
            return None
        return PrecedentPlaybookRule.model_validate_json(str(row[0]))

    def upsert_rule(self, rule: PrecedentPlaybookRule) -> PrecedentPlaybookRule:
        payload_json = rule.model_dump_json()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO precedent_playbook_rules (
                    rule_id, tenant_id, ast_fingerprint, clause_archetype, updated_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, rule_id) DO UPDATE SET
                    ast_fingerprint = excluded.ast_fingerprint,
                    clause_archetype = excluded.clause_archetype,
                    updated_at = excluded.updated_at,
                    payload_json = excluded.payload_json
                """,
                (
                    rule.rule_id,
                    rule.tenant_id,
                    rule.ast_fingerprint,
                    rule.clause_archetype,
                    rule.updated_at,
                    payload_json,
                ),
            )
            self._conn.commit()
        return rule

    def delete_tenant_rules(self, *, tenant_id: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM precedent_playbook_rules WHERE tenant_id = ?",
                (tenant_id,),
            )
            self._conn.commit()
            return int(cur.rowcount or 0)


class PostgresPlaybookBackend:
    """
    Multi-replica PostgreSQL storage backend strictly partitioned by tenant_id.
    Accepts an injectable DB-API connection_factory for deterministic unit testing.
    """

    def __init__(
        self,
        dsn: str,
        *,
        connection_factory: Callable[[], Any] | None = None,
    ) -> None:
        self._dsn = dsn
        self._connection_factory = connection_factory
        self._lock = threading.RLock()
        self._conn: Any = None
        self._schema_ready = False

    def _get_conn(self) -> Any:
        if self._conn is None:
            if self._connection_factory is not None:
                self._conn = self._connection_factory()
            else:
                psycopg = importlib.import_module("psycopg")
                self._conn = psycopg.connect(self._dsn)
        if not self._schema_ready:
            cur = self._conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS precedent_playbook_rules (
                    rule_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    ast_fingerprint TEXT NOT NULL,
                    clause_archetype TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, rule_id)
                )
                """
            )
            self._conn.commit()
            self._schema_ready = True
        return self._conn

    def list_rules(self, *, tenant_id: str) -> list[PrecedentPlaybookRule]:
        with self._lock:
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT payload_json
                FROM precedent_playbook_rules
                WHERE tenant_id = %s
                ORDER BY updated_at ASC, rule_id ASC
                """,
                (tenant_id,),
            )
            rows = cur.fetchall()
        return [PrecedentPlaybookRule.model_validate_json(str(r[0])) for r in rows]

    def get_rule(self, rule_id: str, *, tenant_id: str) -> PrecedentPlaybookRule | None:
        with self._lock:
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT payload_json
                FROM precedent_playbook_rules
                WHERE tenant_id = %s AND rule_id = %s
                LIMIT 1
                """,
                (tenant_id, rule_id),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return PrecedentPlaybookRule.model_validate_json(str(row[0]))

    def upsert_rule(self, rule: PrecedentPlaybookRule) -> PrecedentPlaybookRule:
        payload_json = rule.model_dump_json()
        with self._lock:
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO precedent_playbook_rules (
                    rule_id, tenant_id, ast_fingerprint, clause_archetype, updated_at, payload_json
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, rule_id) DO UPDATE SET
                    ast_fingerprint = EXCLUDED.ast_fingerprint,
                    clause_archetype = EXCLUDED.clause_archetype,
                    updated_at = EXCLUDED.updated_at,
                    payload_json = EXCLUDED.payload_json
                """,
                (
                    rule.rule_id,
                    rule.tenant_id,
                    rule.ast_fingerprint,
                    rule.clause_archetype,
                    rule.updated_at,
                    payload_json,
                ),
            )
            conn.commit()
        return rule

    def delete_tenant_rules(self, *, tenant_id: str) -> int:
        with self._lock:
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM precedent_playbook_rules WHERE tenant_id = %s",
                (tenant_id,),
            )
            count = int(getattr(cur, "rowcount", 0) or 0)
            conn.commit()
        return count


def _build_default_playbook_backend() -> PlaybookBackend:
    mode = str(settings.playbook_store_backend).strip().lower()
    if mode == "postgres" and settings.playbook_postgres_dsn:
        return PostgresPlaybookBackend(settings.playbook_postgres_dsn)
    if mode == "sqlite":
        return SQLitePlaybookBackend(settings.playbook_db_path)
    return InMemoryPlaybookBackend()


class PrecedentPlaybookStore:
    """
    Tenant-isolated 3-Tier Counsel Precedent Playbook Manager backed by
    DeonticEnvelopeResolver statutory floor validation and Ed25519 AttestationLedger.
    """

    def __init__(
        self,
        *,
        backend: PlaybookBackend | None = None,
        review_ledger: HITLReviewLedger | None = None,
        store: TemporalGraphStore | None = None,
        attestation_ledger: AttestationLedger | None = None,
    ) -> None:
        self._backend = backend or _build_default_playbook_backend()
        self._review_ledger = review_ledger or default_hitl_review_ledger
        self._store = store or get_default_temporal_store()
        self._attestation_ledger = attestation_ledger or default_attestation_ledger

    def list_rules(self, *, tenant_id: str) -> PlaybookListResponse:
        rules = self._backend.list_rules(tenant_id=tenant_id)
        return PlaybookListResponse(
            tenant_id=tenant_id,
            playbook_digest=self.get_tenant_playbook_digest(tenant_id),
            total=len(rules),
            rules=rules,
        )

    def get_tenant_playbook_digest(self, tenant_id: str) -> str:
        rules = self._backend.list_rules(tenant_id=tenant_id)
        if not rules:
            return _sha256_hex({"tenant_id": tenant_id, "rules": []})
        basis = [
            {
                "rule_id": r.rule_id,
                "ast_fingerprint": r.ast_fingerprint,
                "tier_1_preferred": r.tier_1_preferred,
                "tier_2_fallback": r.tier_2_fallback,
                "tier_3_statutory_floor": r.tier_3_statutory_floor,
                "updated_at": r.updated_at,
                "attestation_chain_hash": r.attestation_chain_hash,
            }
            for r in rules
        ]
        return _sha256_hex({"tenant_id": tenant_id, "rules": basis})

    def _record_attestation(
        self,
        *,
        document_id: str,
        payload: dict[str, Any],
        envelope: CompositeDeonticEnvelope,
        as_of_date: date,
        regimes: list[str],
        territorial_scope: str,
        citation_span_ids: list[str],
        prefix: str = "PB",
    ) -> tuple[str, str, str, str]:
        manifest_id = f"{prefix}-{uuid.uuid4().hex[:12].upper()}"
        manifest = ComplianceAttestationManifest(
            manifest_id=manifest_id,
            document_id=document_id,
            input_doc_sha256=_sha256_hex(payload),
            graph_state_hash=envelope.envelope_hash,
            as_of_date=as_of_date,
            regimes=regimes,
            territorial_scope=territorial_scope,
            is_verified_grounded=True,
            retry_count=0,
            estimated_cost_usd=0.0,
            estimated_cost_myr=0.0,
            total_tokens=0,
            model_used="deterministic-playbook-zero-token",
            citation_span_ids=citation_span_ids,
        )
        manifest.manifest_sha256 = compute_manifest_sha256(manifest)
        rec = self._attestation_ledger.record(
            manifest,
            TelemetrySummary(
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                estimated_cost_usd=0.0,
                estimated_cost_myr=0.0,
                latency_ms=0.0,
                retry_count=0,
                is_verified_grounded=True,
                model_name="deterministic-playbook-zero-token",
                cache_hit=False,
            ),
        )
        return (
            manifest.manifest_id,
            rec.signature_b64,
            rec.chain_hash,
            rec.signing_key_id,
        )

    def promote_rule(
        self,
        *,
        tenant_id: str,
        request: PlaybookPromoteRequest,
        actor_id: str = "counsel",
        actor_role: str = "auditor",
    ) -> PrecedentPlaybookRule:
        review: HITLReviewRecord | None = None
        if request.review_id:
            review = self._review_ledger.get_review(
                request.review_id, tenant_id=tenant_id
            )
            if review is None:
                raise KeyError(
                    f"HITL review '{request.review_id}' not found for tenant '{tenant_id}'."
                )

        regimes = normalize_regimes(
            request.regimes
            or (review.regimes if review and review.regimes else ["ACT_709"])
        )
        scope_str = (
            request.territorial_scope
            or (review.territorial_scope if review else None)
            or TerritorialScope.ALL_MALAYSIA.value
        )
        as_of = request.as_of_date or (
            review.as_of_date if review else date(2026, 6, 15)
        )
        source_clause_text = (
            request.original_clause_text
            or (review.scrubbed_clause_text if review else None)
            or request.tier_1_preferred
            or request.tier_2_fallback
            or ""
        ).strip()
        if not source_clause_text:
            raise ValueError(
                "Either review_id, original_clause_text, tier_1_preferred, or tier_2_fallback must be provided."
            )

        tier_1 = (
            request.tier_1_preferred
            or (review.scrubbed_counsel_modified_text if review else None)
            or (review.scrubbed_recommended_redline if review else None)
            or source_clause_text
        ).strip()

        tier_2 = request.tier_2_fallback
        if tier_2 is None and review is not None:
            if review.decision == "MODIFY_REDLINE":
                tier_2 = (
                    review.scrubbed_counsel_modified_text
                    or review.scrubbed_recommended_redline
                    or source_clause_text
                ).strip()
            elif review.decision == "REJECT_FALSE_POSITIVE":
                tier_2 = source_clause_text
            elif review.decision == "ACCEPT_REDLINE":
                tier_2 = (review.scrubbed_recommended_redline or tier_1).strip()

        archetype = request.clause_archetype or infer_clause_archetype(
            source_clause_text,
            statute_ids=review.statutory_node_ids if review else None,
        )
        ast_fp = compute_clause_ast_fingerprint(
            source_clause_text,
            clause_archetype=archetype,
            regimes=regimes,
            territorial_scope=scope_str,
        )

        resolver = DeonticEnvelopeResolver(self._store)
        envelope = resolver.resolve(
            regimes=regimes,
            as_of_date=as_of,
            territorial_scope=scope_str,
        )
        floor_text, floor_bounds = compute_statutory_floor_text(
            archetype, envelope, as_of_date=as_of
        )

        # Validate EVERY proposed position against mandatory IN_FORCE statutory bounds.
        violation: StatutoryFloorViolationError | None = None
        texts_to_check: list[str] = [tier_1]
        if tier_2:
            texts_to_check.append(tier_2)
        if review and review.decision == "REJECT_FALSE_POSITIVE":
            texts_to_check.append(review.scrubbed_clause_text)

        for cand_text in texts_to_check:
            ok, err = validate_against_statutory_floor(
                cand_text,
                clause_archetype=archetype,
                envelope=envelope,
            )
            if not ok and err is not None:
                violation = err
                break

        waiver_manifest_id: str | None = None
        waiver_approved_by: str | None = None
        waiver_rationale_clean = (
            request.waiver_rationale or request.rationale or ""
        ).strip()

        if violation is not None:
            role_norm = str(actor_role).strip().lower()
            can_waive = (
                role_norm == "admin"
                and request.statutory_risk_waiver
                and bool(waiver_rationale_clean)
            )
            if not can_waive:
                if request.statutory_risk_waiver and role_norm != "admin":
                    raise StatutoryFloorViolationError(
                        (
                            f"{violation.message} Statutory risk waiver requires 'admin' role "
                            f"(current role: '{role_norm}')."
                        ),
                        metric_key=violation.metric_key,
                        proposed_value=violation.proposed_value,
                        statutory_floor_value=violation.statutory_floor_value,
                        dominating_regime=violation.dominating_regime,
                        dominating_citation=violation.dominating_citation,
                        dominating_node_id=violation.dominating_node_id,
                        waiver_requires_admin=True,
                    )
                raise violation

            w_mid, _, _, _ = self._record_attestation(
                document_id=f"STATUTORY_RISK_WAIVER:{tenant_id}:{archetype}",
                payload={
                    "event_type": "STATUTORY_RISK_WAIVER",
                    "tenant_id": tenant_id,
                    "actor_id": actor_id,
                    "actor_role": role_norm,
                    "metric_key": violation.metric_key,
                    "proposed_value": violation.proposed_value,
                    "statutory_floor_value": violation.statutory_floor_value,
                    "dominating_citation": violation.dominating_citation,
                    "waiver_rationale": waiver_rationale_clean,
                    "ast_fingerprint": ast_fp,
                },
                envelope=envelope,
                as_of_date=as_of,
                regimes=regimes,
                territorial_scope=scope_str,
                citation_span_ids=[violation.dominating_node_id],
                prefix="WAIVER",
            )
            waiver_manifest_id = w_mid
            waiver_approved_by = actor_id

        rule_id = f"PBR-{ast_fp[:12].upper()}"
        now_iso = datetime.now(UTC).isoformat()
        existing = self._backend.get_rule(rule_id, tenant_id=tenant_id)
        created_at = existing.created_at if existing else now_iso

        att_id, sig_b64, chain_hash, key_id = self._record_attestation(
            document_id=f"PLAYBOOK_PROMOTE:{tenant_id}:{rule_id}",
            payload={
                "event_type": "PLAYBOOK_PROMOTE",
                "rule_id": rule_id,
                "tenant_id": tenant_id,
                "clause_archetype": archetype,
                "ast_fingerprint": ast_fp,
                "tier_1_preferred": tier_1,
                "tier_2_fallback": tier_2,
                "tier_3_statutory_floor": floor_text,
                "statutory_risk_waiver": waiver_manifest_id is not None,
            },
            envelope=envelope,
            as_of_date=as_of,
            regimes=regimes,
            territorial_scope=scope_str,
            citation_span_ids=(
                list(review.statutory_node_ids)
                if review and review.statutory_node_ids
                else list(envelope.active_node_ids[:6])
            ),
            prefix="PB",
        )

        rule = PrecedentPlaybookRule(
            rule_id=rule_id,
            tenant_id=tenant_id,
            clause_archetype=archetype,
            ast_fingerprint=ast_fp,
            regimes=regimes,
            territorial_scope=scope_str,
            as_of_date=as_of,
            tier_1_preferred=tier_1,
            tier_2_fallback=tier_2,
            tier_3_statutory_floor=floor_text,
            statutory_floor_bounds=floor_bounds,
            source_review_id=review.review_id if review else None,
            source_decision=review.decision if review else None,
            rationale=(
                request.rationale
                or (review.scrubbed_rationale if review else "")
                or "Counsel-approved tenant negotiation precedent."
            ),
            statutory_risk_waiver=waiver_manifest_id is not None,
            waiver_rationale=waiver_rationale_clean if waiver_manifest_id else None,
            waiver_approved_by=waiver_approved_by,
            waiver_attestation_manifest_id=waiver_manifest_id,
            attestation_manifest_id=att_id,
            attestation_signature_b64=sig_b64,
            attestation_chain_hash=chain_hash,
            signing_key_id=key_id,
            created_by=actor_id,
            created_at=created_at,
            updated_at=now_iso,
        )
        return self._backend.upsert_rule(rule)

    def match_clause(
        self,
        *,
        tenant_id: str,
        clause_text: str,
        regimes: list[str] | None = None,
        territorial_scope: str = TerritorialScope.ALL_MALAYSIA.value,
        preferred_tier: PlaybookTier = "TIER_2_FALLBACK",
    ) -> PrecedentPlaybookRule | None:
        rules = self._backend.list_rules(tenant_id=tenant_id)
        if not rules:
            return None

        target_archetype = infer_clause_archetype(clause_text)
        target_fp = compute_clause_ast_fingerprint(
            clause_text,
            clause_archetype=target_archetype,
            regimes=regimes,
            territorial_scope=territorial_scope,
        )
        target_regimes = set(normalize_regimes(regimes)) if regimes else set()

        for rule in reversed(rules):
            if rule.ast_fingerprint == target_fp:
                return rule

        for rule in reversed(rules):
            if rule.clause_archetype != target_archetype:
                continue
            if rule.territorial_scope not in {
                territorial_scope,
                TerritorialScope.ALL_MALAYSIA.value,
            }:
                continue
            if (
                target_regimes
                and rule.regimes
                and not (target_regimes & set(rule.regimes))
            ):
                continue
            return rule

        _ = preferred_tier
        return None


default_precedent_playbook_store = PrecedentPlaybookStore()

__all__ = [
    "InMemoryPlaybookBackend",
    "PlaybookBackend",
    "PostgresPlaybookBackend",
    "PrecedentPlaybookStore",
    "SQLitePlaybookBackend",
    "StatutoryFloorViolationError",
    "compute_clause_ast_fingerprint",
    "compute_statutory_floor_text",
    "default_precedent_playbook_store",
    "infer_clause_archetype",
    "validate_against_statutory_floor",
]
