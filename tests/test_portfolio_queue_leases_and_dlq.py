from __future__ import annotations

import json
import threading
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from lexgraph_lah.config import settings
from lexgraph_lah.graph.portfolio_scanner import (
    PortfolioJobManager,
    SQLitePortfolioJobStore,
    _evaluate_single_portfolio_contract_with_cache,
)
from lexgraph_lah.main import app
from lexgraph_lah.portfolio.worker import PortfolioWorker
from lexgraph_lah.portfolio.worker import main as worker_cli_main
from lexgraph_lah.schemas.domain import (
    PortfolioAsyncJobRequest,
    PortfolioContractInput,
    TerritorialScope,
)
from lexgraph_lah.security.auth import hash_api_key


@pytest.mark.asyncio
async def test_portfolio_idempotency_key_deduplication_and_409_conflict():
    transport = ASGITransport(app=app)
    payload_a = {
        "from_date": "2024-06-15",
        "to_date": "2026-03-15",
        "regimes": ["ACT_709", "ACT_854"],
        "contracts": [
            {
                "document_id": "IDEMP-01",
                "raw_text": "Section 12B Notice: Data breach notification within 48 hours.",
            }
        ],
    }
    payload_mutated = {
        "from_date": "2024-06-15",
        "to_date": "2026-03-15",
        "regimes": ["ACT_709", "ACT_854"],
        "contracts": [
            {
                "document_id": "IDEMP-01",
                "raw_text": "Section 12B Notice: Data breach notification within 14 days.",
            }
        ],
    }

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        r1 = await client.post(
            "/api/v1/portfolio/jobs",
            headers={"X-Tenant-ID": "tenant-idem-a", "Idempotency-Key": "idem-key-001"},
            json=payload_a,
        )
        assert r1.status_code == 202
        j1 = r1.json()
        assert j1["idempotency_key"] == "idem-key-001"

        # Identical retry returns 200 OK with the exact same job_id
        r2 = await client.post(
            "/api/v1/portfolio/jobs",
            headers={"X-Tenant-ID": "tenant-idem-a", "Idempotency-Key": "idem-key-001"},
            json=payload_a,
        )
        assert r2.status_code == 200
        assert r2.json()["job_id"] == j1["job_id"]

        # Same key + mutated payload within same tenant -> 409 Conflict
        r_conflict = await client.post(
            "/api/v1/portfolio/jobs",
            headers={"X-Tenant-ID": "tenant-idem-a", "Idempotency-Key": "idem-key-001"},
            json=payload_mutated,
        )
        assert r_conflict.status_code == 409

        # Different tenant reusing same Idempotency-Key succeeds independently with new job_id
        r_other = await client.post(
            "/api/v1/portfolio/jobs",
            headers={"X-Tenant-ID": "tenant-idem-b", "Idempotency-Key": "idem-key-001"},
            json=payload_mutated,
        )
        assert r_other.status_code == 202
        assert r_other.json()["job_id"] != j1["job_id"]


def test_portfolio_crash_stale_lease_recovery_mid_batch_zero_rebill(tmp_path: Path):
    db_file = tmp_path / "portfolio_crash.db"
    job_store = SQLitePortfolioJobStore(db_path=db_file)
    eval_lock = threading.Lock()
    eval_counts: dict[str, int] = {}

    def _counting_evaluator(**kwargs: Any) -> Any:
        contract = kwargs["contract"]
        cid = contract.contract_id or contract.document_id
        with eval_lock:
            eval_counts[cid] = eval_counts.get(cid, 0) + 1
        return _evaluate_single_portfolio_contract_with_cache(**kwargs)

    try:
        mgr = PortfolioJobManager(
            job_store=job_store,
            lease_seconds=10.0,
            max_attempts=3,
            worker_mode="external",
            contract_evaluator=_counting_evaluator,
        )
        req = PortfolioAsyncJobRequest(
            from_date=date(2024, 6, 15),
            to_date=date(2026, 3, 15),
            regimes=["ACT_709", "ACT_854"],
            max_workers=2,
            contracts=[
                PortfolioContractInput(
                    document_id=f"CKPT-{i}",
                    raw_text=f"Section 12B Notice: Contract {i} breach notification within 48 hours.",
                )
                for i in range(1, 5)
            ],
        )
        submitted = mgr.submit_job(req, tenant_id="tenant-crash", auto_dispatch=False)
        assert submitted.status == "QUEUED"

        # Worker 1 claims job at t0, completes CKPT-1 and CKPT-2, then simulates OOM crash
        t0 = datetime.now(UTC)
        claimed = job_store.claim_job_by_id(
            submitted.job_id, "worker-crashed", 10.0, now=t0
        )
        assert claimed is not None
        assert claimed.status == "RUNNING"
        assert claimed.attempt_count == 1

        from lexgraph_lah.graph.portfolio_scanner import (
            _build_window_cache,
            _window_cache_key,
        )
        from lexgraph_lah.graph.temporal_store import get_default_temporal_store

        store = get_default_temporal_store()
        win_cache = _build_window_cache(
            contracts=req.contracts[:2],
            from_date=req.from_date,
            to_date=req.to_date,
            default_regimes=req.regimes,
            default_territorial_scope=TerritorialScope.ALL_MALAYSIA,
            store=store,
        )
        for c in req.contracts[:2]:
            rk, es, _ = _window_cache_key(c, req.regimes, TerritorialScope.ALL_MALAYSIA)
            imp, gz, st, is_hit = _counting_evaluator(
                contract=c,
                from_date=req.from_date,
                to_date=req.to_date,
                default_regimes=req.regimes,
                default_territorial_scope=TerritorialScope.ALL_MALAYSIA,
                persona=req.persona,
                store=store,
                precomputed_window=win_cache[(rk, es)],
                clause_cache=mgr._clause_cache,
                cache_bypass=False,
                tenant_id="tenant-crash",
            )
            job_store.save_checkpoint(
                job_id=submitted.job_id,
                contract_id=c.document_id,
                impact=imp,
                gazettes=gz,
                statutes=st,
                is_hit=is_hit,
            )

        # Simulate container restart -> new store & manager instance + expired lease at t0 + 30s
        reopened_store = SQLitePortfolioJobStore(db_path=db_file)
        try:
            mgr_recovered = PortfolioJobManager(
                job_store=reopened_store,
                lease_seconds=30.0,
                max_attempts=3,
                worker_mode="external",
                contract_evaluator=_counting_evaluator,
            )
            worker2 = PortfolioWorker(
                mgr_recovered, worker_id="worker-survivor", lease_seconds=30.0
            )
            finished = worker2.run_once(now=t0 + timedelta(seconds=30))
            assert finished is not None
            assert finished.status == "COMPLETED"
            assert finished.attempt_count == 2
            assert finished.processed_contracts == 4
            assert finished.result is not None
            assert finished.result.total_contracts_scanned == 4
            # Checkpointed contracts CKPT-1 and CKPT-2 were NOT re-evaluated!
            assert eval_counts == {"CKPT-1": 1, "CKPT-2": 1, "CKPT-3": 1, "CKPT-4": 1}
        finally:
            reopened_store.close()
    finally:
        job_store.close()


@pytest.mark.asyncio
async def test_portfolio_dlq_transition_rbac_and_requeue_plus_worker_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from lexgraph_lah.api import routes as routes_mod
    from lexgraph_lah.graph import portfolio_scanner as ps_mod

    db_file = tmp_path / "dlq_jobs.db"
    store = SQLitePortfolioJobStore(db_path=db_file)

    should_fail = {"flag": True}

    def _flaky_evaluator(**kwargs: Any) -> Any:
        if should_fail["flag"]:
            raise RuntimeError("Simulated downstream transient worker failure")
        return _evaluate_single_portfolio_contract_with_cache(**kwargs)

    mgr = PortfolioJobManager(
        job_store=store,
        lease_seconds=15.0,
        max_attempts=2,
        worker_mode="external",
        contract_evaluator=_flaky_evaluator,
    )
    monkeypatch.setattr(routes_mod, "default_portfolio_job_manager", mgr)
    monkeypatch.setattr(ps_mod, "default_portfolio_job_manager", mgr)

    viewer_key = "lg_dlq_viewer"
    auditor_key = "lg_dlq_auditor"
    admin_key = "lg_dlq_admin"
    api_keys = {
        hash_api_key(viewer_key): {
            "tenant_id": "tenant-dlq",
            "role": "viewer",
            "subject": "v1",
        },
        hash_api_key(auditor_key): {
            "tenant_id": "tenant-dlq",
            "role": "auditor",
            "subject": "a1",
        },
        hash_api_key(admin_key): {
            "tenant_id": "tenant-dlq",
            "role": "admin",
            "subject": "adm1",
        },
    }
    monkeypatch.setattr(settings, "auth_mode", "api_key")
    monkeypatch.setattr(settings, "auth_api_keys_json", json.dumps(api_keys))

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            sub = await client.post(
                "/api/v1/portfolio/jobs",
                headers={"X-API-Key": auditor_key},
                json={
                    "from_date": "2024-06-15",
                    "to_date": "2026-03-15",
                    "contracts": [
                        {
                            "document_id": "DLQ-C1",
                            "raw_text": "Section 12B: Breach notified within 48 hours.",
                        }
                    ],
                },
            )
            assert sub.status_code == 202
            job_id = sub.json()["job_id"]

            # Exhaust max_attempts=2 -> transitions to DEAD_LETTER
            r_try1 = mgr.run_worker_once(worker_id="w-fail-1")
            assert r_try1 is not None and r_try1.status == "QUEUED"
            r_try2 = mgr.run_worker_once(worker_id="w-fail-2")
            assert r_try2 is not None and r_try2.status == "DEAD_LETTER"
            assert r_try2.last_error_code == "RuntimeError"

            # RBAC on GET /api/v1/portfolio/dlq -> admin only
            assert (
                await client.get(
                    "/api/v1/portfolio/dlq", headers={"X-API-Key": viewer_key}
                )
            ).status_code == 403
            assert (
                await client.get(
                    "/api/v1/portfolio/dlq", headers={"X-API-Key": auditor_key}
                )
            ).status_code == 403
            dlq_resp = await client.get(
                "/api/v1/portfolio/dlq", headers={"X-API-Key": admin_key}
            )
            assert dlq_resp.status_code == 200
            assert dlq_resp.json()["total"] == 1
            assert dlq_resp.json()["jobs"][0]["job_id"] == job_id

            # RBAC on POST /api/v1/portfolio/jobs/{job_id}/requeue -> admin/auditor allowed, viewer 403
            assert (
                await client.post(
                    f"/api/v1/portfolio/jobs/{job_id}/requeue",
                    headers={"X-API-Key": viewer_key},
                )
            ).status_code == 403

            should_fail["flag"] = False
            req_resp = await client.post(
                f"/api/v1/portfolio/jobs/{job_id}/requeue",
                headers={"X-API-Key": auditor_key},
            )
            assert req_resp.status_code == 200
            assert req_resp.json()["status"] == "QUEUED"
            assert req_resp.json()["attempt_count"] == 0

            # Run worker CLI `--once` to complete the requeued job
            rc = worker_cli_main(["--once", "--worker-id", "cli-smoke-01"])
            assert rc == 0

            done_resp = await client.get(
                f"/api/v1/portfolio/jobs/{job_id}",
                headers={"X-API-Key": viewer_key},
            )
            assert done_resp.status_code == 200
            assert done_resp.json()["status"] == "COMPLETED"
    finally:
        store.close()
