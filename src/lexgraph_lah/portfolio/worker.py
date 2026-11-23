"""
Standalone CLI Worker for Crash-Recoverable Lease-Based Portfolio Blast-Radius Jobs.

Usage:
    python -m lexgraph_lah.portfolio.worker --once
    python -m lexgraph_lah.portfolio.worker --poll-interval 2.0 --worker-id worker-01
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from lexgraph_lah.config import settings
from lexgraph_lah.graph import portfolio_scanner as _portfolio_scanner
from lexgraph_lah.graph.portfolio_scanner import (
    PortfolioJobManager,
    build_portfolio_job_store,
)
from lexgraph_lah.schemas.domain import PortfolioJobStatusResponse


class PortfolioWorker:
    """Horizontal worker polling durable portfolio queue with stale-lease reaping."""

    def __init__(
        self,
        manager: PortfolioJobManager | None = None,
        *,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
    ) -> None:
        self.manager = (
            manager
            if manager is not None
            else _portfolio_scanner.default_portfolio_job_manager
        )
        self.worker_id = (
            worker_id or f"lexgraph-worker-{uuid.uuid4().hex[:8]}"
        ).strip()
        self.lease_seconds = float(
            lease_seconds
            if lease_seconds is not None
            else settings.portfolio_job_lease_seconds
        )

    def run_once(
        self, *, now: datetime | None = None
    ) -> PortfolioJobStatusResponse | None:
        return self.manager.run_worker_once(
            worker_id=self.worker_id,
            lease_seconds=self.lease_seconds,
            now=now,
        )

    def run_loop(
        self,
        *,
        poll_interval: float = 2.0,
        max_iterations: int | None = None,
    ) -> int:
        processed = 0
        iterations = 0
        interval = max(0.05, float(poll_interval))
        while max_iterations is None or iterations < max_iterations:
            iterations += 1
            job = self.run_once()
            if job is not None:
                processed += 1
                continue
            if max_iterations is not None and iterations >= max_iterations:
                break
            time.sleep(interval)
        return processed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run lexgraph-lah crash-recoverable lease-based portfolio worker."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Reap stale leases, process at most one queued job, and exit.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Polling interval in seconds when running continuously (default: 2.0).",
    )
    parser.add_argument(
        "--worker-id",
        type=str,
        default=None,
        help="Explicit worker identifier for lease ownership.",
    )
    parser.add_argument(
        "--lease-seconds",
        type=float,
        default=settings.portfolio_job_lease_seconds,
        help="Atomic lease duration in seconds.",
    )
    parser.add_argument(
        "--store-backend",
        choices=["memory", "sqlite", "postgres"],
        default=None,
        help="Override PORTFOLIO_JOB_STORE backend.",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite DB path when --store-backend=sqlite.",
    )
    args = parser.parse_args(argv)

    if args.store_backend is not None or args.db_path is not None:
        job_store = build_portfolio_job_store(args.store_backend, db_path=args.db_path)
        mgr = PortfolioJobManager(job_store=job_store, lease_seconds=args.lease_seconds)
    else:
        mgr = _portfolio_scanner.default_portfolio_job_manager

    worker = PortfolioWorker(
        mgr,
        worker_id=args.worker_id,
        lease_seconds=args.lease_seconds,
    )
    if args.once:
        res = worker.run_once()
        if res is not None:
            print(
                f"[worker={worker.worker_id}] processed job {res.job_id} -> {res.status}"
            )
        else:
            print(f"[worker={worker.worker_id}] queue empty (0 jobs processed)")
        return 0

    try:
        worker.run_loop(poll_interval=args.poll_interval)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
