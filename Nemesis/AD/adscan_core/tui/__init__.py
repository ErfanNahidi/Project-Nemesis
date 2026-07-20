"""Shared TUI primitives for ADscan.

Dependency-light helpers that wrap Rich for premium-grade, non-TTY-safe
behaviour. Everything in this package must remain importable from both the
host launcher and the in-container runtime.
"""

from __future__ import annotations

from adscan_core.tui.live_session import LiveSession, LiveSessionConfig
from adscan_core.tui.ntlm_sweep_dashboard import (
    NtlmSweepDashboard,
    render_ntlm_results_table,
)
from adscan_core.tui.progress_dashboard import (
    ProgressDashboard,
    ProgressDashboardConfig,
    format_eta,
)

__all__ = [
    "LiveSession",
    "LiveSessionConfig",
    "NtlmSweepDashboard",
    "ProgressDashboard",
    "ProgressDashboardConfig",
    "format_eta",
    "render_ntlm_results_table",
]
