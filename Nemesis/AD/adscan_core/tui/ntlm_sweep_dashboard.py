"""Live per-host NTLM auth-type classification dashboard.

A premium live surface for the NTLM auth-type sweep ("All reachable hosts"
scope). While the sweep fires concurrent coercion triggers at a single shared
listener, this dashboard shows — in near-real-time — which host authenticated
back with which NTLM type (NTLMv1 vs NTLMv2), the per-host classification being
the defensive downgrade-misconfiguration signal the sweep exists to surface.

This is a SIBLING of :class:`adscan_core.tui.progress_dashboard.ProgressDashboard`
(a count/rate/ETA bar): here the operator watches a per-host classification
TABLE filling in. It mirrors that class's :class:`LiveSession` lifecycle exactly
(``alt_screen=True`` + a ``summary`` callback that re-prints the final renderable
to scrollback, with ``redirect_io`` / ``defer_live_logs`` left at their defaults
so the per-host debug lines defer-flush after the alt-screen pops).

Rows are PRE-ALLOCATED — one per candidate host, all starting in the
``coercing`` state — and flipped in place as verdicts arrive, so the rendered
line count is stable from frame 1 (defense in depth, even though the canonical
``alt_screen=True`` config already contains growth inside the alt-buffer).

This module also exposes :func:`render_ntlm_results_table` — a STATIC,
review-grade results table that the sweep prints to scrollback after EVERY
multi-host run, regardless of scope or whether the live dashboard ran. The live
dashboard is the "monitor while it runs" surface (only worth an alt-screen
takeover above a host threshold); the results table is the "review the verdict"
surface, valuable at every scale.

The module is dependency-light: it imports only ``adscan_core`` primitives and
Rich. Do NOT import ``adscan_internal`` here. Every host / account rendered goes
through :func:`mark_sensitive` because the dashboard is mirrored to the
telemetry console via ``_TeeConsole`` — an unmasked host here would be an
exfiltration leak (see CLAUDE.md § Sensitive-Data).
"""

from __future__ import annotations

import itertools
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Mapping, Optional, Sequence

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.sensitive import mark_sensitive
from adscan_core.theme import (
    ADSCAN_PRIMARY,
    ADSCAN_PRIMARY_BRIGHT,
    COLOR_AMBER,
    COLOR_MUTED,
    COLOR_SAGE,
)
from adscan_core.tui.live_session import LiveSession, LiveSessionConfig

__all__ = ["NtlmSweepDashboard", "render_ntlm_results_table"]

# Braille spinner frames — the modern default per tui-design § 5. Shared with
# ProgressDashboard so the two surfaces feel like one product.
_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# Per-host row states. The string value doubles as the persisted/queryable
# state name; the rendering picks the colour + glyph from it.
_STATE_COERCING = "coercing"
_STATE_NTLMV1 = "NTLMv1"
_STATE_NTLMV2 = "NTLMv2"
_STATE_UNKNOWN = "unknown"


# ----------------------------------------------------------------------------
# Static review-grade results table (printed to scrollback after every sweep)
# ----------------------------------------------------------------------------

# Sort key so NTLMv1 (the actionable findings — relay targets) is listed FIRST,
# then NTLMv2, then unknown. Lower sorts earlier.
_RESULTS_SORT_ORDER = {_STATE_NTLMV1: 0, _STATE_NTLMV2: 1, _STATE_UNKNOWN: 2}


def _normalize_result_state(raw: object) -> str:
    """Coerce an arbitrary verdict value into one of the three render states."""

    value = str(raw or "").strip()
    if value == _STATE_NTLMV1:
        return _STATE_NTLMV1
    if value == _STATE_NTLMV2:
        return _STATE_NTLMV2
    return _STATE_UNKNOWN


def _result_state_cells(state: str) -> tuple[Text, Text]:
    """Return ``(status-glyph+auth, )`` styled cell for a results-row state.

    NTLMv1 is the actionable finding (a relay target), so it is highlighted in
    amber with a ``⚠``; NTLMv2 is the secure-but-crackable outcome in sage with
    ``✓``; unknown is muted with ``·``.
    """

    if state == _STATE_NTLMV1:
        return Text("⚠ NTLMv1", style=f"bold {COLOR_AMBER}")
    if state == _STATE_NTLMV2:
        return Text("✓ NTLMv2", style=COLOR_SAGE)
    return Text("· unknown", style=COLOR_MUTED)


def render_ntlm_results_table(
    rows: Sequence[Mapping[str, object]],
    summary: Mapping[str, object],
) -> RenderableType:
    """Build the static, review-grade NTLM auth-type sweep results table.

    This is the "review the verdict" surface, printed to scrollback after EVERY
    multi-host sweep (live or not, DC-only or all-reachable). It is a pure
    function of its inputs — no Live, no state — so the sweep can render it once
    at the end and the live-dashboard ``summary`` callback can reuse it.

    Args:
        rows: One mapping per swept host. Recognized keys (all optional except
            the host identity): ``ip``/``host`` (the coerced host, masked as an
            IP), ``auth_type``/``state`` (one of ``NTLMv1``/``NTLMv2``/anything
            else → ``unknown``), and ``captured_user``/``expected_account`` (the
            captured ``<host>$`` principal, masked as a user). Rows are sorted
            NTLMv1-first, then NTLMv2, then unknown.
        summary: The sweep summary dict. Recognized keys: ``domain`` (rendered
            masked in the title) and the integer counters ``ntlmv1_found``,
            ``ntlmv2_found``, ``coercion_unknown``, ``swept_count`` (used for the
            footer line; recomputed from ``rows`` when absent).

    Returns:
        A Rich :class:`~rich.panel.Panel` ready to hand to ``get_console().print``.
    """

    normalized: list[tuple[str, str, str]] = []
    for row in rows or ():
        host = str(row.get("ip") or row.get("host") or "").strip()
        if not host:
            continue
        state = _normalize_result_state(row.get("auth_type") or row.get("state"))
        captured = str(
            row.get("captured_user") or row.get("expected_account") or ""
        ).strip()
        normalized.append((host, state, captured))

    normalized.sort(key=lambda item: (_RESULTS_SORT_ORDER.get(item[1], 3), item[0]))

    table = Table(
        expand=True,
        border_style=COLOR_MUTED,
        header_style=f"bold {ADSCAN_PRIMARY}",
        padding=(0, 1),
    )
    table.add_column("Auth", no_wrap=True)
    table.add_column("Host", no_wrap=True)
    table.add_column("Captured-as", no_wrap=True, overflow="ellipsis")

    for host, state, captured in normalized:
        auth_cell = _result_state_cells(state)
        host_style = COLOR_AMBER if state == _STATE_NTLMV1 else ADSCAN_PRIMARY
        host_cell = Text(str(mark_sensitive(host, "ip")), style=host_style)
        if captured:
            captured_cell = Text(
                str(mark_sensitive(captured, "user")), style=COLOR_MUTED
            )
        else:
            captured_cell = Text("—", style=COLOR_MUTED)
        table.add_row(auth_cell, host_cell, captured_cell)

    swept = int(summary.get("swept_count") or len(normalized))
    ntlmv1 = int(
        summary.get("ntlmv1_found")
        if summary.get("ntlmv1_found") is not None
        else sum(1 for _, s, _ in normalized if s == _STATE_NTLMV1)
    )
    ntlmv2 = int(
        summary.get("ntlmv2_found")
        if summary.get("ntlmv2_found") is not None
        else sum(1 for _, s, _ in normalized if s == _STATE_NTLMV2)
    )
    unknown = int(
        summary.get("coercion_unknown")
        if summary.get("coercion_unknown") is not None
        else sum(1 for _, s, _ in normalized if s == _STATE_UNKNOWN)
    )

    footer = Text()
    footer.append(f"⚠ {ntlmv1} NTLMv1", style=f"bold {COLOR_AMBER}")
    footer.append("  ·  ")
    footer.append(f"✓ {ntlmv2} NTLMv2", style=COLOR_SAGE)
    footer.append("  ·  ")
    footer.append(f"{unknown} unknown", style=COLOR_MUTED)
    footer.append(f"   ({swept} swept)", style=COLOR_MUTED)

    domain = str(summary.get("domain") or "").strip()
    if domain:
        title = Text("🔐 NTLM Auth-Type Sweep · ", style=f"bold {ADSCAN_PRIMARY_BRIGHT}")
        title.append(str(mark_sensitive(domain, "domain")), style=f"bold {ADSCAN_PRIMARY_BRIGHT}")
        title.append(f" · {swept} hosts swept", style=f"bold {ADSCAN_PRIMARY_BRIGHT}")
    else:
        title = Text(
            f"🔐 NTLM Auth-Type Sweep · {swept} hosts swept",
            style=f"bold {ADSCAN_PRIMARY_BRIGHT}",
        )

    return Panel(
        Group(table, Text(""), footer),
        title=title,
        title_align="left",
        border_style=ADSCAN_PRIMARY,
        padding=(0, 1),
    )


@dataclass
class _HostRow:
    """Mutable per-host row, flipped in place as a verdict arrives.

    Attributes:
        ip: The coerced host IP (rendered masked as ``ip``).
        expected_account: The expected ``<host>$`` computer account, or ``""``
            when the hostname is unknown (those hosts cannot be positively
            attributed and stay ``coercing`` → ``unknown``).
        state: One of the ``_STATE_*`` constants.
        captured_as: The actual captured principal once a verdict lands, or
            ``""`` while still coercing / unattributed.
    """

    ip: str
    expected_account: str = ""
    state: str = _STATE_COERCING
    captured_as: str = ""


@dataclass
class NtlmSweepDashboard:
    """Live per-host NTLM auth-type classification table.

    Construct with the candidate host list (the hosts the sweep will coerce),
    drive it inside :meth:`live_session`, and call
    :meth:`update_from_observations` on every poll tick with the listener's
    drained observations plus the set of hosts whose trigger has completed.
    The dashboard recomputes each row's state from those inputs and renders a
    header summary line plus the per-host table.

    The dashboard is PRESENTATION-ONLY: it reads observations and renders. It
    never changes how captures are attributed or persisted — that logic lives
    in the sweep itself.
    """

    candidates: list[str]
    ip_to_account: Mapping[str, str] = field(default_factory=dict)
    title: str = "NTLM Auth-Type Sweep · live classification"
    refresh_per_second: int = 8

    _rows: dict[str, _HostRow] = field(default_factory=dict, init=False)
    _order: list[str] = field(default_factory=list, init=False)
    _completed: set[str] = field(default_factory=set, init=False)
    _spinner: Iterator[str] = field(init=False)
    _spinner_frame: str = field(init=False)
    _session: Optional[LiveSession] = field(default=None, init=False)

    def __post_init__(self) -> None:
        """Pre-allocate one ``coercing`` row per candidate host (stable shape)."""
        self._spinner = itertools.cycle(_SPINNER_FRAMES)
        self._spinner_frame = next(self._spinner)
        seen: set[str] = set()
        for ip in self.candidates:
            key = str(ip or "").strip()
            if not key or key in seen:
                continue
            seen.add(key)
            self._order.append(key)
            self._rows[key] = _HostRow(
                ip=key,
                expected_account=str(self.ip_to_account.get(key) or "").strip(),
            )

    # ------------------------------------------------------------------
    # Derived counts
    # ------------------------------------------------------------------

    @property
    def total(self) -> int:
        """Number of candidate hosts (pre-allocated rows)."""
        return len(self._order)

    @property
    def done(self) -> int:
        """Number of hosts whose trigger completed (verdict resolved)."""
        return len([ip for ip in self._order if ip in self._completed])

    @property
    def ntlmv1_count(self) -> int:
        return len([r for r in self._rows.values() if r.state == _STATE_NTLMV1])

    @property
    def ntlmv2_count(self) -> int:
        return len([r for r in self._rows.values() if r.state == _STATE_NTLMV2])

    @property
    def pending_count(self) -> int:
        return len([r for r in self._rows.values() if r.state == _STATE_COERCING])

    # ------------------------------------------------------------------
    # Drive API
    # ------------------------------------------------------------------

    def update_from_observations(
        self,
        observations: Iterable[object],
        completed_hosts: Iterable[str] | None = None,
    ) -> None:
        """Recompute row states from drained observations and push a frame.

        Args:
            observations: The listener's drained observations so far. Each is
                duck-typed for ``clean_user`` (the authenticating ``<host>$``
                account, used for attribution) and ``ntlm_version`` (the
                classified auth type). Unknown shapes are skipped defensively.
            completed_hosts: Hosts whose coercion trigger has completed. A
                completed host with no matching capture flips ``coercing`` →
                ``unknown`` (it reached the budget / never authenticated). Left
                ``None`` keeps the prior completed set.

        Cumulative semantics: observations and completed_hosts are the full
        snapshot so far, not deltas. A positive classification is sticky —
        never downgraded by a later poll.
        """
        if completed_hosts is not None:
            for ip in completed_hosts:
                key = str(ip or "").strip()
                if key:
                    self._completed.add(key)

        # Attribute each observation to its coerced host by computer account.
        account_to_ip = {
            row.expected_account.casefold(): row.ip
            for row in self._rows.values()
            if row.expected_account
        }
        for obs in observations or ():
            clean_user = str(getattr(obs, "clean_user", "") or "").strip()
            if not clean_user:
                continue
            ip = account_to_ip.get(clean_user.casefold())
            if not ip:
                continue
            row = self._rows.get(ip)
            if row is None:
                continue
            version = str(getattr(obs, "ntlm_version", "") or "").strip()
            if version not in (_STATE_NTLMV1, _STATE_NTLMV2):
                continue
            # First positive classification wins; never downgrade.
            if row.state in (_STATE_NTLMV1, _STATE_NTLMV2):
                continue
            row.state = version
            raw_user = str(getattr(obs, "raw_user", "") or "").strip()
            row.captured_as = raw_user or clean_user

        # A completed host with no positive verdict resolves to ``unknown``.
        for ip in self._completed:
            row = self._rows.get(ip)
            if row is not None and row.state == _STATE_COERCING:
                row.state = _STATE_UNKNOWN

        self._spinner_frame = next(self._spinner)
        self._push()

    def _push(self) -> None:
        """Push the current renderable to Live (best-effort, never raises)."""
        if self._session is not None:
            try:
                self._session.update(self.render())
            except Exception:  # noqa: BLE001 — a render error must never abort the sweep
                pass

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def render(self) -> RenderableType:
        """Build the current dashboard renderable (header line + per-host table)."""
        return Panel(
            Group(self._render_header(), self._render_table()),
            title=Text(self.title, style=f"bold {ADSCAN_PRIMARY_BRIGHT}"),
            title_align="left",
            border_style=ADSCAN_PRIMARY,
            padding=(0, 1),
        )

    def _render_header(self) -> RenderableType:
        """Progress + per-type counts summary line."""
        grid = Table.grid(expand=True, padding=(0, 2))
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right")

        progress = Text()
        progress.append(f"{self.done} / {self.total} hosts", style=ADSCAN_PRIMARY)

        counts = Text()
        counts.append(f"⚠ NTLMv1 {self.ntlmv1_count}", style=COLOR_AMBER)
        counts.append("   ")
        counts.append(f"✓ NTLMv2 {self.ntlmv2_count}", style=COLOR_SAGE)
        counts.append("   ")
        counts.append(
            f"{self._spinner_frame} pending {self.pending_count}", style=COLOR_MUTED
        )

        grid.add_row(progress, counts)
        return grid

    def _render_table(self) -> RenderableType:
        """The per-host classification table (pre-allocated, flipped in place)."""
        table = Table(
            expand=True,
            border_style=COLOR_MUTED,
            header_style=f"bold {ADSCAN_PRIMARY}",
            padding=(0, 1),
        )
        table.add_column("Host", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Auth", no_wrap=True)
        table.add_column("Captured-as", no_wrap=True, overflow="ellipsis")

        for ip in self._order:
            row = self._rows[ip]
            host_cell = Text(str(mark_sensitive(row.ip, "ip")), style=ADSCAN_PRIMARY)
            status_cell, auth_cell = self._render_state_cells(row)
            captured_cell = self._render_captured_cell(row)
            table.add_row(host_cell, status_cell, auth_cell, captured_cell)
        return table

    def _render_state_cells(self, row: _HostRow) -> tuple[Text, Text]:
        """Return ``(status, auth)`` cells coloured by the row state."""
        if row.state == _STATE_NTLMV1:
            return (
                Text("classified", style=COLOR_AMBER),
                Text("⚠ NTLMv1", style=COLOR_AMBER),
            )
        if row.state == _STATE_NTLMV2:
            return (
                Text("classified", style=COLOR_SAGE),
                Text("✓ NTLMv2", style=COLOR_SAGE),
            )
        if row.state == _STATE_UNKNOWN:
            return (
                Text("done", style=COLOR_MUTED),
                Text("· no callback", style=COLOR_MUTED),
            )
        # Coercing / pending.
        return (
            Text(f"{self._spinner_frame} coercing…", style=COLOR_MUTED),
            Text("—", style=COLOR_MUTED),
        )

    def _render_captured_cell(self, row: _HostRow) -> Text:
        """Render the captured principal (masked), or a muted placeholder."""
        if row.captured_as:
            return Text(
                str(mark_sensitive(row.captured_as, "user")), style=ADSCAN_PRIMARY
            )
        if row.expected_account:
            return Text(
                str(mark_sensitive(row.expected_account, "user")), style=COLOR_MUTED
            )
        return Text("—", style=COLOR_MUTED)

    # ------------------------------------------------------------------
    # Results-table snapshot (static, review-grade)
    # ------------------------------------------------------------------

    def results_rows(self) -> list[dict[str, str]]:
        """Snapshot the dashboard rows in the shape :func:`render_ntlm_results_table` reads.

        Lets the live-dashboard ``summary`` callback re-print the cleaner static
        results table (instead of re-printing the live dashboard) without the
        sweep having to thread its own per-host verdict map into the callback.
        """

        snapshot: list[dict[str, str]] = []
        for ip in self._order:
            row = self._rows[ip]
            snapshot.append(
                {
                    "ip": row.ip,
                    "auth_type": row.state,
                    "captured_user": row.captured_as or row.expected_account,
                }
            )
        return snapshot

    def results_summary(self, *, domain: str = "") -> dict[str, object]:
        """Snapshot the per-type counters for :func:`render_ntlm_results_table`."""

        return {
            "domain": domain,
            "swept_count": self.done,
            "ntlmv1_found": self.ntlmv1_count,
            "ntlmv2_found": self.ntlmv2_count,
            "coercion_unknown": len(
                [r for r in self._rows.values() if r.state == _STATE_UNKNOWN]
            ),
        }

    # ------------------------------------------------------------------
    # LiveSession lifecycle — mirrors ProgressDashboard exactly.
    # ------------------------------------------------------------------

    def _live_config(self) -> LiveSessionConfig:
        return LiveSessionConfig(
            refresh_per_second=self.refresh_per_second,
            alt_screen=True,
        )

    @contextmanager
    def live_session(
        self, *, summary=None
    ) -> Iterator["NtlmSweepDashboard"]:
        """Sync context manager: enters a LiveSession bound to this dashboard.

        On non-TTY / CI consoles :class:`LiveSession` falls back to inline
        logging automatically — the caller code is identical in both modes.

        Args:
            summary: Optional ``summary(console)`` callback handed to
                :class:`LiveSession` to re-print a final renderable to scrollback
                after the alt-screen pops. When ``None`` the dashboard re-prints
                itself (legacy behaviour); the sweep passes a callback that
                renders the cleaner static results table instead.
        """
        session = LiveSession(
            self.render(),
            config=self._live_config(),
            summary=summary if summary is not None else self._summary,
        )
        self._session = session
        with session:
            try:
                yield self
            finally:
                self._session = None

    def _summary(self, console: Console) -> None:
        """Re-print the final dashboard to scrollback after the alt-screen pops."""
        try:
            console.print(self.render())
        except Exception:  # noqa: BLE001 — summary must never break the flow
            pass
