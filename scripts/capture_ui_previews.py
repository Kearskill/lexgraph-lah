"""Capture high-resolution UI preview screenshots across all workbench views."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from PIL import Image, ImageDraw
from playwright.sync_api import Page, sync_playwright

ROOT_DIR = Path(__file__).resolve().parent.parent
PREVIEW_DIR = ROOT_DIR / "docs" / "ui-preview"
HOST = "127.0.0.1"
PORT = 8765
BASE_URL = f"http://{HOST}:{PORT}"


def wait_for_health(timeout_seconds: float = 30.0) -> None:
    """Poll FastAPI /health endpoint until the server responds 200 OK."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/health", timeout=1.5) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(0.25)
    raise RuntimeError(
        f"Server did not become healthy at {BASE_URL}/health within {timeout_seconds}s"
    )


def wait_for_settled_fonts(page: Page) -> None:
    """Wait for network idle and document fonts to finish loading."""
    page.wait_for_load_state("networkidle")
    page.evaluate("() => document.fonts.ready")
    page.wait_for_timeout(300)


def create_composite_sheet(preview_dir: Path) -> Path:
    """Stitch the 4 desktop workspace screenshots into a 2x2 master overview PNG."""
    labels = [
        (
            "01-contract-redline-workbench.png",
            "01 / Contract & Redline Audit + Evidence Inspector",
        ),
        (
            "02-statutory-graph-lineage.png",
            "02 / Statutory Graph & Bi-Temporal Lineage",
        ),
        (
            "03-deontic-incident-playbook.png",
            "03 / Deontic Envelope & Incident Playbooks",
        ),
        (
            "04-portfolio-attestation-finops.png",
            "04 / Portfolio Blast-Radius, Ed25519 & FinOps",
        ),
    ]
    tiles: list[tuple[Image.Image, str]] = []
    for filename, title in labels:
        img = Image.open(preview_dir / filename).convert("RGB")
        # Downscale cleanly by 50% (from 3200x2000 Retina to 1600x1000) per quadrant
        resized = img.resize((1600, 1000), Image.Resampling.LANCZOS)
        tiles.append((resized, title))

    pad = 24
    header_h = 40
    tile_w, tile_h = 1600, 1000
    canvas_w = pad * 3 + tile_w * 2
    canvas_h = pad * 3 + (tile_h + header_h) * 2

    canvas = Image.new("RGB", (canvas_w, canvas_h), (248, 249, 250))
    draw = ImageDraw.Draw(canvas)

    positions = [
        (pad, pad),
        (pad * 2 + tile_w, pad),
        (pad, pad * 2 + tile_h + header_h),
        (pad * 2 + tile_w, pad * 2 + tile_h + header_h),
    ]
    for (tile, title), (x, y) in zip(tiles, positions, strict=True):
        draw.rectangle(
            [x - 1, y - 1, x + tile_w, y + header_h + tile_h],
            outline=(203, 213, 225),
            width=2,
        )
        draw.rectangle([x, y, x + tile_w - 1, y + header_h - 1], fill=(255, 255, 255))
        draw.text((x + 16, y + 13), title, fill=(15, 76, 129))
        canvas.paste(tile, (x, y + header_h))

    out_path = preview_dir / "00-full-overview-composite.png"
    canvas.save(out_path, format="PNG", optimize=True)
    return out_path


def capture_all() -> None:
    """Boot uvicorn transiently, render all workbench states, and save PNG previews."""
    PREVIEW_DIR.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("AUTH_MODE", "disabled")

    server_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "lexgraph_lah.main:app",
            "--host",
            HOST,
            "--port",
            str(PORT),
            "--log-level",
            "warning",
        ],
        cwd=str(ROOT_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        wait_for_health(timeout_seconds=30.0)

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                # Desktop Retina context (1600x1000 @ 2x)
                desktop_ctx = browser.new_context(
                    viewport={"width": 1600, "height": 1000},
                    device_scale_factor=2,
                )
                page = desktop_ctx.new_page()

                # 01: Contract & Redline Audit with Fixture 05 (PII + Traps + Crosswalk Inspector)
                page.goto(f"{BASE_URL}/", wait_until="domcontentloaded")
                page.wait_for_selector(
                    "#findingsContainer .finding-card", timeout=15000
                )
                page.select_option("#fixtureSelect", "05_multi_regime_shadow_override")
                page.click("#runAuditBtn")
                page.wait_for_function(
                    """() => {
                        const btn = document.getElementById('runAuditBtn');
                        const card = document.querySelector('#findingsContainer .finding-card');
                        const drawer = document.getElementById('drawerContent');
                        return btn && !btn.disabled && card && drawer && !drawer.querySelector('.skeleton-card');
                    }""",
                    timeout=15000,
                )
                page.evaluate(
                    """() => {
                        const pii = document.getElementById('piiScrubCard');
                        const ws = document.getElementById('worksurface');
                        if (pii && ws) {
                            ws.scrollTop = Math.max(0, pii.offsetTop - 12);
                        }
                    }"""
                )
                wait_for_settled_fonts(page)
                page.screenshot(
                    path=str(PREVIEW_DIR / "01-contract-redline-workbench.png")
                )

                # 02: Statutory Graph & Bi-Temporal Lineage
                page.click('.nav-item[data-view="graph"]')
                page.wait_for_function(
                    """() => window.__LEXGRAPH_CY_READY__ === true &&
                        document.querySelector('#timeTravelRedlineDiffBox .diff-line') !== null""",
                    timeout=20000,
                )
                page.evaluate(
                    """() => {
                        if (window.LAST_CY_INSTANCE) {
                            window.LAST_CY_INSTANCE.resize();
                            window.LAST_CY_INSTANCE.fit(undefined, 24);
                        }
                        if (typeof openBilingualDrawer === 'function') {
                            ACTIVE_CLAUSE_CONTEXT = null;
                            openBilingualDrawer('PDPA-2010-SEC-9-V2');
                        }
                        const ws = document.getElementById('worksurface');
                        if (ws) ws.scrollTop = 76;
                    }"""
                )
                wait_for_settled_fonts(page)
                page.wait_for_timeout(500)
                page.screenshot(
                    path=str(PREVIEW_DIR / "02-statutory-graph-lineage.png")
                )

                # 03: Deontic Envelope & Multi-Regulator Incident Playbook
                page.click('.nav-item[data-view="deontic"]')
                page.wait_for_selector("#playbookTimelineBody tr", timeout=15000)
                page.click('button[onclick="applyAllDeonticRegimesPreset()"]')
                page.wait_for_function(
                    """() => {
                        const btn = document.getElementById('runIncidentPlaybookBtn');
                        const rows = document.querySelectorAll('#playbookTimelineBody tr');
                        const matrixText = document.getElementById('deonticMatrixBody')?.innerText || '';
                        return btn && !btn.disabled && rows.length >= 3 && matrixText.includes('VOLUNTARY_GUIDELINE');
                    }""",
                    timeout=15000,
                )
                page.evaluate(
                    "() => { const ws = document.getElementById('worksurface'); if (ws) ws.scrollTop = 0; }"
                )
                wait_for_settled_fonts(page)
                page.screenshot(
                    path=str(PREVIEW_DIR / "03-deontic-incident-playbook.png")
                )

                # 04: Portfolio Blast-Radius, Ed25519 Attestation & FinOps
                page.click('.nav-item[data-view="portfolio"]')
                page.wait_for_selector("#portfolioBlastTableBody tr", timeout=15000)
                page.wait_for_selector("#spanTableBody tr", timeout=15000)
                page.click("#verifyAttestationBtn")
                page.wait_for_function(
                    """() => {
                        const badge = document.getElementById('attestVerifyStatusBadge');
                        const sec = document.getElementById('secScanBadge');
                        return badge && badge.textContent.trim() === 'VERIFIED' &&
                               sec && sec.textContent.trim() !== 'READY';
                    }""",
                    timeout=15000,
                )
                page.evaluate(
                    "() => { const ws = document.getElementById('worksurface'); if (ws) ws.scrollTop = 96; }"
                )
                wait_for_settled_fonts(page)
                page.screenshot(
                    path=str(PREVIEW_DIR / "04-portfolio-attestation-finops.png")
                )
                desktop_ctx.close()

                # 05: Mobile Responsive (390x844 @ 2x) with zero horizontal overflow check
                mobile_ctx = browser.new_context(
                    viewport={"width": 390, "height": 844},
                    device_scale_factor=2,
                )
                m_page = mobile_ctx.new_page()
                m_page.goto(f"{BASE_URL}/", wait_until="domcontentloaded")
                m_page.wait_for_selector(
                    "#findingsContainer .finding-card", timeout=15000
                )
                wait_for_settled_fonts(m_page)
                overflow = m_page.evaluate(
                    "() => ({ scrollW: document.documentElement.scrollWidth, innerW: window.innerWidth })"
                )
                if overflow["scrollW"] > overflow["innerW"]:
                    raise RuntimeError(
                        f"Mobile horizontal overflow detected: scrollWidth={overflow['scrollW']} > innerWidth={overflow['innerW']}"
                    )
                m_page.screenshot(path=str(PREVIEW_DIR / "05-mobile-responsive.png"))
                mobile_ctx.close()
            finally:
                browser.close()

        create_composite_sheet(PREVIEW_DIR)
        print("Captured all UI previews in", PREVIEW_DIR)
    finally:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait(timeout=5)


if __name__ == "__main__":
    capture_all()
