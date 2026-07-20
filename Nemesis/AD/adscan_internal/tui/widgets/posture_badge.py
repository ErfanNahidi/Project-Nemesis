"""Posture badge widget — the headline KPI tile in the workbench right pane.

Shows the canonical 0-100 posture score with band label (Healthy /
Acceptable / Elevated / Critical) and color drawn from the ADscan brand
palette. Score is sourced from :mod:`adscan_core.posture_score` — never
recomputed locally.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static

from adscan_core.posture_score import PostureScore
from adscan_core.theme import ADSCAN_PRIMARY


def _band_color(label: str) -> str:
    """Return a brand-aligned color hex for a posture band label."""
    label_norm = label.strip().lower()
    if label_norm == "healthy":
        return "#3fb950"
    if label_norm == "acceptable":
        return ADSCAN_PRIMARY  # cyan — premium neutral
    if label_norm == "elevated":
        return "#d29922"
    return "#f85149"  # Critical


def _build_css() -> str:
    border = "#21262d"
    panel = "#161b22"
    return f"""
PostureBadge {{
    height: auto;
    background: {panel};
    border: solid {border};
    padding: 1 2;
    layout: vertical;
}}

PostureBadge #posture-eyebrow {{
    color: #8b949e;
    text-style: bold;
    content-align: center middle;
    width: 100%;
}}

PostureBadge #posture-score {{
    text-style: bold;
    content-align: center middle;
    width: 100%;
    padding: 1 0 0 0;
}}

PostureBadge #posture-band {{
    text-style: bold;
    content-align: center middle;
    width: 100%;
    padding: 0 0 1 0;
}}
"""


class PostureBadge(Widget):
    """Cyan-accented posture score chip.

    Render the 0-100 score, ``/100`` denominator and the band label
    (UPPERCASE eyebrow caps) in the band's color. The widget is a
    pure read-only renderer — pass a :class:`PostureScore` to
    :meth:`set_posture` to update.
    """

    CSS = _build_css()

    def __init__(
        self,
        posture: PostureScore | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._posture = posture

    def compose(self) -> ComposeResult:
        yield Static("POSTURE SCORE", id="posture-eyebrow")
        yield Static(self._score_markup(), id="posture-score")
        yield Static(self._band_markup(), id="posture-band")

    def set_posture(self, posture: PostureScore | None) -> None:
        """Replace the rendered posture and refresh both children."""
        self._posture = posture
        try:
            self.query_one("#posture-score", Static).update(self._score_markup())
            self.query_one("#posture-band", Static).update(self._band_markup())
        except Exception:  # noqa: BLE001 — widget may not yet be mounted
            pass

    # ── Render helpers ───────────────────────────────────────────────────────

    def _score_markup(self) -> str:
        if self._posture is None:
            return f"[bold {ADSCAN_PRIMARY}]--[/]  [dim]/100[/dim]"
        color = _band_color(self._posture.label)
        return f"[bold {color}]{self._posture.score:>3}[/]  [dim]/100[/dim]"

    def _band_markup(self) -> str:
        if self._posture is None:
            return "[dim]NO DATA[/dim]"
        color = _band_color(self._posture.label)
        return f"[bold {color}]{self._posture.label.upper()}[/]"
