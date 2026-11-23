from __future__ import annotations

import json
from datetime import date

import pytest
from httpx import ASGITransport, AsyncClient

from lexgraph_lah.api.routes import _COMPLIANCE_CACHE
from lexgraph_lah.compliance.clause_cache import (
    ClauseASTCache,
    compute_clause_ast_digest,
    compute_regime_set_hash,
    compute_statutory_graph_digest,
    default_clause_cache,
)
from lexgraph_lah.config import settings
from lexgraph_lah.graph.portfolio_scanner import PortfolioJobManager
from lexgraph_lah.graph.temporal_store import get_default_temporal_store
from lexgraph_lah.ingestion.contract_ast import build_contract_ast
from lexgraph_lah.main import app
from lexgraph_lah.schemas.domain import (
    PortfolioAsyncJobRequest,
    PortfolioContractInput,
    TerritorialScope,
)
from lexgraph_lah.security.auth import (
    default_api_key_registry,
    default_rate_limiter,
    hash_api_key,
)
from lexgraph_lah.telemetry.cost_tracker import (
    compute_telemetry_summary,
    default_tenant_budget_tracker,
)


def test_clause_ast_digest_isomorphism_and_redis_backend():
    """
    Verifies Clause-AST canonical digest invariance across differing document_ids and raw
    Malaysian PII values, invalidation on as_of_date / territorial_scope / regimes changes,
    and Redis backend roundtrip using an in-memory Redis fake.
    """
    store = get_default_temporal_store()
    ast_a, _ = build_contract_ast(
        document_id="CONTRACT-A",
        raw_text=(
            "Section 9 Security: Processor for NRIC 880101-14-5678 and email a@corp.my "
            "shall notify within 4 hours."
        ),
    )
    ast_b, _ = build_contract_ast(
        document_id="CONTRACT-B",
        raw_text=(
            "Section 9 Security: Processor for NRIC 951212-10-9999 and email b@vendor.my "
            "shall notify within 4 hours."
        ),
    )
    reg_hash = compute_regime_set_hash(["ACT_709", "ACT_854"])
    reg_hash_alt = compute_regime_set_hash(["ACT_709"])
    stat_hash_2026 = compute_statutory_graph_digest(
        store, as_of_date=date(2026, 3, 15), regimes=["ACT_709", "ACT_854"]
    )
    stat_hash_2024 = compute_statutory_graph_digest(
        store, as_of_date=date(2024, 6, 15), regimes=["ACT_709", "ACT_854"]
    )

    d_a = compute_clause_ast_digest(
        ast_a,
        as_of_date=date(2026, 3, 15),
        territorial_scope=TerritorialScope.ALL_MALAYSIA,
        regime_set_hash=reg_hash,
        statutory_graph_digest=stat_hash_2026,
    )
    d_b = compute_clause_ast_digest(
        ast_b,
        as_of_date=date(2026, 3, 15),
        territorial_scope=TerritorialScope.ALL_MALAYSIA,
        regime_set_hash=reg_hash,
        statutory_graph_digest=stat_hash_2026,
    )
    assert d_a == d_b

    # Invalidation on as_of_date, scope, and regime set
    d_old = compute_clause_ast_digest(
        ast_a,
        as_of_date=date(2024, 6, 15),
        territorial_scope=TerritorialScope.ALL_MALAYSIA,
        regime_set_hash=reg_hash,
        statutory_graph_digest=stat_hash_2024,
    )
    d_sabah = compute_clause_ast_digest(
        ast_a,
        as_of_date=date(2026, 3, 15),
        territorial_scope=TerritorialScope.SABAH,
        regime_set_hash=reg_hash,
        statutory_graph_digest=stat_hash_2026,
    )
    d_reg = compute_clause_ast_digest(
        ast_a,
        as_of_date=date(2026, 3, 15),
        territorial_scope=TerritorialScope.ALL_MALAYSIA,
        regime_set_hash=reg_hash_alt,
        statutory_graph_digest=stat_hash_2026,
    )
    assert len({d_a, d_old, d_sabah, d_reg}) == 4

    # Redis backend smoke test
    class _FakeRedis:
        def __init__(self) -> None:
            self.data: dict[str, bytes] = {}

        def get(self, key: str) -> bytes | None:
            return self.data.get(key)

        def setex(self, key: str, time: int, value: str) -> None:
            self.data[key] = value.encode("utf-8")

        def set(self, key: str, value: str) -> None:
            self.data[key] = value.encode("utf-8")

        def delete(self, *keys: str) -> None:
            for k in keys:
                self.data.pop(k, None)

    rc = ClauseASTCache(backend="redis", redis_client=_FakeRedis(), ttl_seconds=60)
    rc.set(d_a, {"status": "cached-ok"})
    assert rc.get(d_b) == {"status": "cached-ok"}


@pytest.mark.asyncio
async def test_compliance_check_isomorphic_cache_bypass_and_finops_budget_guardrail(
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Verifies:
      - Isomorphic Clause-AST cache hit returns cache_hit=True, total_tokens=0, and does
        not leak PII placeholders across contracts/tenants
      - cache_bypass=true forces fresh evaluation
      - LEXGRAPH_TENANT_MONTHLY_BUDGET_MYR triggers both deterministic_fallback and reject_429
      - GET /api/v1/finops/tenant-usage allows viewer own-tenant (200) and blocks spoof (403)
      - PortfolioJobManager records cache_hits > 0 across isomorphic batch contracts.
    """
    _COMPLIANCE_CACHE.clear()
    default_clause_cache.clear()
    default_tenant_budget_tracker.reset()
    default_api_key_registry.clear()
    default_rate_limiter.reset()

    viewer_key = "fin_viewer_01"
    auditor_key = "fin_auditor_02"
    keys = {
        hash_api_key(viewer_key): {
            "tenant_id": "tenant-fin",
            "role": "viewer",
            "subject": "v1",
        },
        hash_api_key(auditor_key): {
            "tenant_id": "tenant-fin",
            "role": "auditor",
            "subject": "a1",
        },
    }
    monkeypatch.setattr(settings, "env", "test")
    monkeypatch.setattr(settings, "auth_mode", "api_key")
    monkeypatch.setattr(settings, "auth_api_keys_json", json.dumps(keys))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Miss on Contract A (NRIC 880101-14-5678)
        r1 = await client.post(
            "/compliance/check",
            headers={"X-API-Key": auditor_key},
            json={
                "document_id": "ISO-DOC-1",
                "raw_text": (
                    "Section 9 Security: Data User 880101-14-5678 bears zero statutory "
                    "liability and notifies within 10 days."
                ),
                "as_of_date": "2026-03-15",
            },
        )
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["telemetry"]["cache_hit"] is False

        # 2. Isomorphic HIT on Contract B (different document_id + different NRIC 990202-10-4321)
        r2 = await client.post(
            "/compliance/check",
            headers={"X-API-Key": auditor_key},
            json={
                "document_id": "ISO-DOC-2",
                "raw_text": (
                    "Section 9 Security: Data User 990202-10-4321 bears zero statutory "
                    "liability and notifies within 10 days."
                ),
                "as_of_date": "2026-03-15",
            },
        )
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["document_id"] == "ISO-DOC-2"
        assert d2["telemetry"]["cache_hit"] is True
        assert d2["telemetry"]["total_tokens"] == 0
        # Zero PII leak from ISO-DOC-1 into ISO-DOC-2 placeholders
        p2 = json.dumps(d2["pii_scrub"]["placeholders"])
        assert "880101-14-5678" not in p2
        assert "990202-10-4321" in p2

        # 3. cache_bypass=true skips cache hit
        r_bypass = await client.post(
            "/compliance/check",
            headers={"X-API-Key": auditor_key},
            json={
                "document_id": "ISO-DOC-3",
                "raw_text": (
                    "Section 9 Security: Data User 990202-10-4321 bears zero statutory "
                    "liability and notifies within 10 days."
                ),
                "as_of_date": "2026-03-15",
                "cache_bypass": True,
            },
        )
        assert r_bypass.status_code == 200
        assert r_bypass.json()["telemetry"]["cache_hit"] is False

        # 4. Budget exceedance -> deterministic_fallback
        default_tenant_budget_tracker.record_usage(
            tenant_id="tenant-fin",
            telemetry=compute_telemetry_summary(
                prompt_tokens=200_000,
                completion_tokens=50_000,
                latency_ms=5.0,
                retry_count=0,
                is_verified_grounded=True,
                model_name="gemini-4-neon",
            ),
        )
        monkeypatch.setattr(settings, "lexgraph_tenant_monthly_budget_myr", 0.01)
        monkeypatch.setattr(
            settings, "lexgraph_budget_exceeded_policy", "deterministic_fallback"
        )
        r_fb = await client.post(
            "/compliance/check",
            headers={"X-API-Key": auditor_key},
            json={
                "document_id": "BUDGET-FB",
                "raw_text": (
                    "Section 9 Security: Vendor bears zero statutory liability and waives "
                    "regulatory audit access for personal data."
                ),
                "as_of_date": "2026-03-15",
                "cache_bypass": True,
            },
        )
        assert r_fb.status_code == 200
        assert r_fb.json()["telemetry"]["total_tokens"] == 0

        # 5. Budget exceedance -> reject_429
        monkeypatch.setattr(settings, "lexgraph_budget_exceeded_policy", "reject_429")
        r_429 = await client.post(
            "/compliance/check",
            headers={"X-API-Key": auditor_key},
            json={
                "document_id": "BUDGET-429",
                "raw_text": (
                    "Section 9 Security: Fresh clause requiring PDPA safeguards within 24 hours."
                ),
                "as_of_date": "2026-03-15",
                "cache_bypass": True,
            },
        )
        assert r_429.status_code == 429

        # 6. GET /api/v1/finops/tenant-usage RBAC + anti-spoofing
        u_ok = await client.get(
            "/api/v1/finops/tenant-usage",
            headers={"X-API-Key": viewer_key},
        )
        assert u_ok.status_code == 200
        usage_data = u_ok.json()
        assert usage_data["tenant_id"] == "tenant-fin"
        assert usage_data["cache_hit_runs"] >= 1
        assert usage_data["deterministic_fallback_runs"] >= 1
        assert usage_data["budget_exceeded"] is True

        u_spoof = await client.get(
            "/api/v1/finops/tenant-usage?tenant_id=other-tenant",
            headers={"X-API-Key": viewer_key},
        )
        assert u_spoof.status_code == 403

    # 7. Portfolio cache_hits & cache_bypass
    port_cache = ClauseASTCache(backend="memory")
    mgr = PortfolioJobManager(clause_cache=port_cache)
    j1 = mgr.submit_job(
        PortfolioAsyncJobRequest(
            from_date=date(2024, 6, 15),
            to_date=date(2026, 3, 15),
            contracts=[
                PortfolioContractInput(
                    document_id="P-ISO-1",
                    raw_text="Section 12B: Vendor 900101-14-1111 notifies breach within 48 hours.",
                ),
                PortfolioContractInput(
                    document_id="P-ISO-2",
                    raw_text="Section 12B: Vendor 920202-10-2222 notifies breach within 48 hours.",
                ),
            ],
            max_workers=1,
        ),
        tenant_id="tenant-fin",
    )
    res1 = mgr.wait_for_job(j1.job_id, timeout=15.0)
    assert res1 is not None and res1.status == "COMPLETED"
    assert res1.cache_hits == 1
    assert res1.cache_misses == 1

    j2 = mgr.submit_job(
        PortfolioAsyncJobRequest(
            from_date=date(2024, 6, 15),
            to_date=date(2026, 3, 15),
            cache_bypass=True,
            contracts=[
                PortfolioContractInput(
                    document_id="P-ISO-3",
                    raw_text="Section 12B: Vendor 900101-14-1111 notifies breach within 48 hours.",
                ),
            ],
            max_workers=1,
        ),
        tenant_id="tenant-fin",
    )
    res2 = mgr.wait_for_job(j2.job_id, timeout=15.0)
    assert res2 is not None and res2.cache_hits == 0 and res2.cache_misses == 1
