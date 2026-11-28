"""
Human-in-the-Loop (HITL) Counsel Adjudication Ledger & PII-Safe Golden Dataset Exporter.

Records practitioner clause-level reviews (`ACCEPT_REDLINE`, `MODIFY_REDLINE`,
`REJECT_FALSE_POSITIVE`, `ESCALATE_TO_COUNSEL`) linked to `audit_session_id` /
`manifest_id` with mandatory pre-persistence Malaysian PII scrubbing, Ed25519
cryptographic attestation via `AttestationLedger`, and deterministic JSONL export
loadable by `evals/run_benchmark.py --extra-jsonl`.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from lexgraph_lah.config import settings
from lexgraph_lah.graph.deontic_solver import normalize_regimes
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import (
    ComplianceAttestationManifest,
    HITLReviewRecord,
    HITLReviewRequest,
    RiskSeverity,
    TerritorialScope,
)
from lexgraph_lah.security.attestation_ledger import (
    AttestationLedger,
    default_attestation_ledger,
)


class HITLReviewLedger:
    """Thread-safe, tenant-scoped SQLite WAL ledger for counsel HITL adjudications."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        raw_path = str(db_path or settings.hitl_db_path or ":memory:")
        self._db_path = raw_path
        self._lock = threading.RLock()
        if raw_path != ":memory:":
            Path(raw_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(raw_path, check_same_thread=False)
        if raw_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hitl_reviews (
                review_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                audit_session_id TEXT,
                manifest_id TEXT,
                recorded_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hitl_reviews_tenant ON hitl_reviews (tenant_id, recorded_at)"
        )
        self._conn.commit()

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM hitl_reviews")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def record_review(
        self,
        req: HITLReviewRequest,
        *,
        tenant_id: str = "default-tenant",
        reviewer_subject: str | None = None,
        ledger: AttestationLedger | None = None,
    ) -> HITLReviewRecord:
        if (
            req.decision == "MODIFY_REDLINE"
            and not (req.counsel_modified_text or "").strip()
        ):
            raise ValueError(
                "MODIFY_REDLINE requires non-empty 'counsel_modified_text'."
            )

        # Zero unredacted PII may ever reach HITL training/eval persistence
        clause_scrub = scrub_malaysian_pii(req.original_clause_text)
        rationale_scrub = scrub_malaysian_pii(req.rationale)
        rec_redline_scrub = (
            scrub_malaysian_pii(req.recommended_redline)
            if req.recommended_redline is not None
            else None
        )
        mod_text_scrub = (
            scrub_malaysian_pii(req.counsel_modified_text)
            if req.counsel_modified_text is not None
            else None
        )
        total_redactions = (
            clause_scrub.redaction_count
            + rationale_scrub.redaction_count
            + (rec_redline_scrub.redaction_count if rec_redline_scrub else 0)
            + (mod_text_scrub.redaction_count if mod_text_scrub else 0)
        )

        eff_date = req.as_of_date or date.today()
        eff_regimes = normalize_regimes(req.regimes or ["ACT_709"])
        eff_risk = req.expected_overall_risk
        if eff_risk is None:
            if req.decision == "REJECT_FALSE_POSITIVE":
                eff_risk = RiskSeverity.LOW
            elif req.decision in {"MODIFY_REDLINE", "ESCALATE_TO_COUNSEL"}:
                eff_risk = RiskSeverity.MEDIUM
            else:
                eff_risk = RiskSeverity.HIGH

        review_id = f"HITL-{uuid.uuid4().hex[:10].upper()}"
        reviewer = (
            req.reviewer_id or reviewer_subject or "counsel"
        ).strip() or "counsel"
        recorded_at = datetime.now(UTC).isoformat()

        canonical_basis = json.dumps(
            {
                "review_id": review_id,
                "tenant_id": tenant_id,
                "audit_session_id": req.audit_session_id,
                "source_manifest_id": req.manifest_id,
                "document_id": req.document_id,
                "clause_id": req.clause_id,
                "decision": req.decision,
                "scrubbed_clause_text": clause_scrub.masked_text,
                "scrubbed_counsel_modified_text": (
                    mod_text_scrub.masked_text if mod_text_scrub else None
                ),
                "scrubbed_rationale": rationale_scrub.masked_text,
                "statutory_node_ids": sorted(set(req.statutory_node_ids)),
                "regimes": eff_regimes,
                "as_of_date": eff_date.isoformat(),
                "territorial_scope": req.territorial_scope,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        doc_sha = hashlib.sha256(canonical_basis.encode("utf-8")).hexdigest()
        active_ledger = ledger or default_attestation_ledger
        manifest = ComplianceAttestationManifest(
            document_id=f"{req.document_id}:{req.clause_id}:{review_id}",
            input_doc_sha256=doc_sha,
            graph_state_hash=hashlib.sha256(
                "|".join(sorted(set(req.statutory_node_ids))).encode("utf-8")
            ).hexdigest(),
            as_of_date=eff_date,
            regimes=eff_regimes,
            territorial_scope=req.territorial_scope
            or TerritorialScope.ALL_MALAYSIA.value,
            is_verified_grounded=True,
            retry_count=0,
            estimated_cost_usd=0.0,
            estimated_cost_myr=0.0,
            total_tokens=0,
            model_used="hitl-counsel-adjudication",
            citation_span_ids=sorted(set(req.statutory_node_ids)),
        )
        ledger_rec = active_ledger.record(manifest)

        record = HITLReviewRecord(
            review_id=review_id,
            tenant_id=tenant_id,
            audit_session_id=req.audit_session_id,
            manifest_id=req.manifest_id,
            document_id=req.document_id,
            clause_id=req.clause_id,
            decision=req.decision,
            scrubbed_clause_text=clause_scrub.masked_text,
            scrubbed_recommended_redline=(
                rec_redline_scrub.masked_text if rec_redline_scrub else None
            ),
            scrubbed_counsel_modified_text=(
                mod_text_scrub.masked_text if mod_text_scrub else None
            ),
            scrubbed_rationale=rationale_scrub.masked_text,
            pii_redaction_count=total_redactions,
            statutory_node_ids=list(dict.fromkeys(req.statutory_node_ids)),
            regimes=eff_regimes,
            as_of_date=eff_date,
            territorial_scope=req.territorial_scope,
            expected_overall_risk=eff_risk,
            reviewer_id=reviewer,
            attestation_manifest_id=ledger_rec.manifest_id,
            attestation_signature_b64=ledger_rec.signature_b64,
            attestation_chain_hash=ledger_rec.chain_hash,
            signing_key_id=ledger_rec.signing_key_id,
            recorded_at=recorded_at,
        )

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO hitl_reviews
                    (review_id, tenant_id, audit_session_id, manifest_id, recorded_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.review_id,
                    record.tenant_id,
                    record.audit_session_id,
                    record.manifest_id,
                    record.recorded_at,
                    record.model_dump_json(),
                ),
            )
            self._conn.commit()
        return record

    def list_reviews(self, *, tenant_id: str) -> list[HITLReviewRecord]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT payload_json
                FROM hitl_reviews
                WHERE tenant_id = ?
                ORDER BY recorded_at ASC, review_id ASC
                """,
                (tenant_id,),
            ).fetchall()
        return [HITLReviewRecord.model_validate_json(str(r[0])) for r in rows]

    def get_review(self, review_id: str, *, tenant_id: str) -> HITLReviewRecord | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT payload_json
                FROM hitl_reviews
                WHERE review_id = ? AND tenant_id = ?
                LIMIT 1
                """,
                (review_id, tenant_id),
            ).fetchone()
        if row is None:
            return None
        return HITLReviewRecord.model_validate_json(str(row[0]))

    def export_golden_jsonl(self, *, tenant_id: str) -> str:
        """
        Exports tenant-scoped HITL counsel adjudications as deterministic JSONL golden
        regression cases directly loadable via `evals/run_benchmark.py --extra-jsonl`.
        Every exported text field is verified PII-scrubbed prior to serialization.
        """
        records = self.list_reviews(tenant_id=tenant_id)
        lines: list[str] = []
        for rec in records:
            safe_clause = scrub_malaysian_pii(rec.scrubbed_clause_text).masked_text
            safe_redline = (
                scrub_malaysian_pii(rec.scrubbed_counsel_modified_text).masked_text
                if rec.scrubbed_counsel_modified_text is not None
                else (
                    scrub_malaysian_pii(rec.scrubbed_recommended_redline).masked_text
                    if rec.scrubbed_recommended_redline is not None
                    else None
                )
            )
            safe_rationale = scrub_malaysian_pii(rec.scrubbed_rationale).masked_text
            payload: dict[str, Any] = {
                "case_id": rec.review_id,
                "title": f"HITL {rec.decision} - {rec.document_id} ({rec.clause_id})",
                "reference_date": rec.as_of_date.isoformat(),
                "act_filter": None,
                "regimes": rec.regimes,
                "territorial_scope": rec.territorial_scope,
                "expect_abstained": False,
                "contract_text": safe_clause,
                "expected_overall_risk": rec.expected_overall_risk.value,
                "expected_active_statute_ids": sorted(rec.statutory_node_ids),
                "expected_clause_ids": (
                    [rec.clause_id] if rec.decision != "REJECT_FALSE_POSITIVE" else []
                ),
                "hitl_metadata": {
                    "review_id": rec.review_id,
                    "decision": rec.decision,
                    "audit_session_id": rec.audit_session_id,
                    "source_manifest_id": rec.manifest_id,
                    "attestation_manifest_id": rec.attestation_manifest_id,
                    "attestation_signature_b64": rec.attestation_signature_b64,
                    "recommended_or_modified_redline": safe_redline,
                    "rationale": safe_rationale,
                    "recorded_at": rec.recorded_at,
                },
            }
            lines.append(json.dumps(payload, sort_keys=True, ensure_ascii=False))
        return "\n".join(lines) + ("\n" if lines else "")


default_hitl_review_ledger = HITLReviewLedger()
