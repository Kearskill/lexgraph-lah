"""Template assembler for the unified 3-Zone Institutional Legal Workbench."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

WorkbenchView = Literal["audit", "graph", "deontic", "portfolio"]
_UI_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=8)
def _read_ui_asset(filename: str) -> str:
    """Reads a static UI template or asset relative to this package."""
    return (_UI_DIR / filename).read_text(encoding="utf-8")


@lru_cache(maxsize=4)
def render_workbench_html(initial_view: WorkbenchView = "audit") -> str:
    """
    Assembles the complete, self-contained Institutional Legal Workbench HTML
    by embedding design tokens, structural CSS, and modular ES2022 JS into
    `workbench.html` with zero external CSS build steps.
    """
    html_template = _read_ui_asset("workbench.html")
    tokens_css = _read_ui_asset("tokens.css")
    workbench_css = _read_ui_asset("workbench.css")
    workbench_js = _read_ui_asset("workbench.js")

    return (
        html_template.replace("{{TOKENS_CSS}}", tokens_css)
        .replace("{{WORKBENCH_CSS}}", workbench_css)
        .replace("{{WORKBENCH_JS}}", workbench_js)
        .replace("{{INITIAL_VIEW}}", initial_view)
    )
