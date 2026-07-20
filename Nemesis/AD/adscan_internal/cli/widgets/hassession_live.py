"""Premium live view for native HasSession (schtask_as) exploitation.

Renders one self-updating Rich panel that walks through every phase of
:func:`adscan_internal.services.exploitation.hassession_native.run_command_as_session_user`
— connect, auth, SID resolution, task registration, execution, output capture,
cleanup — with timing, target context, and the captured payload output.

The view degrades gracefully on non-TTY runs (CI, ``ADSCAN_NO_LIVE=1``) by
emitting one debug line per phase transition instead of redrawing.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from typing import Any

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from adscan_core.rich_output import print_info_verbose
from adscan_core.tui import LiveSession, LiveSessionConfig
from adscan_internal import get_console
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.exploitation.hassession_native import (
    PHASES,
    HasSessionResult,
    PhaseEvent,
)


_PHASE_LABELS: dict[str, str] = {
    "fingerprint": "AV / EDR fingerprint (Defender RTP, EDR pipes)",
    "connect": "TCP / SMB connect",
    "auth": "Authenticate executor",
    "resolve_sid": "Resolve session user → SID",
    "register_task": "Register hidden Task Scheduler job",
    "run_task": "Invoke task on demand",
    "wait_output": "Wait for stdout file",
    "read_output": "Read captured output",
    "cleanup": "Delete task + temp file",
}


@dataclass(slots=True)
class _PhaseRow:
    phase: str
    status: str = "pending"  # pending | running | ok | warn | fail
    started_at: float | None = None
    duration_ms: float | None = None
    detail: str = ""


@dataclass(slots=True)
class HasSessionLiveContext:
    """Static context shown in the panel header."""

    target_host: str
    target_ip: str
    session_user: str
    executor_user: str
    auth_kind: str  # "NTLM" | "Kerberos" | "auto"
    command_label: str  # short, redacted-friendly label, e.g. "net group … /add"


class HasSessionLiveView:
    """Self-updating Rich panel for one schtask_as native exploitation run."""

    def __init__(self, ctx: HasSessionLiveContext) -> None:
        self.ctx = ctx
        self._rows: dict[str, _PhaseRow] = {p: _PhaseRow(phase=p) for p in PHASES}
        self._console = get_console()
        self._started = time.monotonic()
        # alt_screen=False: the phase panel is small and intentionally
        # inline so the operator keeps it in scrollback alongside the
        # exploitation summary printed after the run.
        self._session: LiveSession | None = None
        self._is_tty = sys.stdout.isatty() and os.environ.get("ADSCAN_NO_LIVE") != "1"
        self._sid: str | None = None
        self._task_name: str | None = None
        self._captured: str = ""
        self._fingerprint: object | None = None  # HostFingerprint when available
        self._final: HasSessionResult | None = None

    # ---- context management -----------------------------------------------

    def __enter__(self) -> "HasSessionLiveView":
        if self._is_tty:
            self._session = LiveSession(
                self._render(),
                config=LiveSessionConfig(refresh_per_second=8, alt_screen=False),
            )
            self._session.__enter__()
        return self

    def __exit__(self, *_args: Any) -> None:
        if self._session is not None:
            try:
                self._session.update(self._render(), refresh=True)
            except Exception:  # noqa: BLE001
                pass
            self._session.__exit__(*_args)
            self._session = None

    # ---- public API --------------------------------------------------------

    def on_event(self, event: PhaseEvent) -> None:
        row = self._rows.get(event.phase)
        if row is None:
            return
        now = time.monotonic()
        if event.status == "start":
            row.status = "running"
            row.started_at = now
            row.detail = event.detail
        elif event.status == "ok":
            row.status = "ok"
            if row.started_at is None:
                row.started_at = now
            row.duration_ms = (now - row.started_at) * 1000
            if event.detail:
                row.detail = event.detail
            if event.phase == "resolve_sid" and event.detail:
                self._sid = event.detail
            if event.phase == "register_task" and event.detail:
                self._task_name = event.detail
            if event.phase == "read_output" and event.detail:
                self._captured = event.detail  # size hint
        elif event.status == "warn":
            row.status = "warn"
            if row.started_at is None:
                row.started_at = now
            row.duration_ms = (now - row.started_at) * 1000
            row.detail = event.detail
        elif event.status == "fail":
            row.status = "fail"
            if row.started_at is None:
                row.started_at = now
            row.duration_ms = (now - row.started_at) * 1000
            row.detail = event.detail

        self._refresh(event)

    def set_final(self, result: HasSessionResult) -> None:
        self._final = result
        if result.sid:
            self._sid = result.sid
        if result.task_name:
            self._task_name = result.task_name
        if result.fingerprint is not None:
            self._fingerprint = result.fingerprint
        if self._session is not None:
            try:
                self._session.update(self._render(), refresh=True)
            except Exception:  # noqa: BLE001
                pass

    def set_fingerprint(self, fp: object | None) -> None:
        """Inject a fingerprint result early so the panel renders the banner.

        Called by the CLI flow after the AV/EDR pre-check returns but before
        :func:`run_command_as_session_user` actually fires — gives the operator
        time to review the banner before confirming.
        """
        self._fingerprint = fp
        if self._session is not None:
            try:
                self._session.update(self._render(), refresh=True)
            except Exception:  # noqa: BLE001
                pass

    # ---- internals ---------------------------------------------------------

    def _refresh(self, event: PhaseEvent) -> None:
        if self._session is not None:
            self._session.update(self._render())
            return
        marked_host = mark_sensitive(self.ctx.target_host, "hostname")
        marked_user = mark_sensitive(self.ctx.session_user, "user")
        label = _PHASE_LABELS.get(event.phase, event.phase)
        if event.status == "start":
            print_info_verbose(f"[hassession-native] {marked_host} → {label} …")
        elif event.status == "ok":
            print_info_verbose(f"[hassession-native] {marked_host} ✓ {label}")
        elif event.status == "warn":
            print_info_verbose(
                f"[hassession-native] {marked_host} ⚠ {label}: {event.detail}"
            )
        elif event.status == "fail":
            print_info_verbose(
                f"[hassession-native] {marked_host} ✗ {label}: {event.detail} "
                f"(session user: {marked_user})"
            )

    def _render(self) -> RenderableType:
        renderables: list[RenderableType] = [self._header()]
        banner = self._fingerprint_banner()
        if banner is not None:
            renderables.append(Text())
            renderables.append(banner)
        renderables.append(Text())
        renderables.append(self._phase_table())
        renderables.append(self._footer())
        return Panel(
            Padding(Group(*renderables), (1, 2)),
            title="[bold]HasSession · native schtask_as · live[/bold]",
            border_style=self._panel_color(),
            expand=False,
        )

    def _panel_color(self) -> str:
        if self._final is not None:
            return "green" if self._final.success else "red"
        return "cyan"

    def _header(self) -> RenderableType:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", justify="right", no_wrap=True)
        grid.add_column(no_wrap=False)
        host_text = Text()
        host_text.append(mark_sensitive(self.ctx.target_host, "hostname"), style="bold")
        if self.ctx.target_ip and self.ctx.target_ip != self.ctx.target_host:
            host_text.append("  ")
            host_text.append(mark_sensitive(self.ctx.target_ip, "ip"), style="dim")
        grid.add_row("Target", host_text)
        grid.add_row(
            "Session user",
            Text(mark_sensitive(self.ctx.session_user, "user"), style="bold yellow"),
        )
        grid.add_row(
            "Executor",
            Text(
                f"{mark_sensitive(self.ctx.executor_user, 'user')}  "
                f"({self.ctx.auth_kind})",
            ),
        )
        grid.add_row("Payload", Text(self.ctx.command_label, style="cyan"))
        if self._sid:
            grid.add_row("Session SID", Text(mark_sensitive(self._sid, "user")))
        if self._task_name:
            grid.add_row("Task", Text(self._task_name, style="dim"))
        return grid

    def _fingerprint_banner(self) -> RenderableType | None:
        """Render the AV/EDR fingerprint summary as a coloured sub-panel.

        Three render modes:
          - **No fingerprint yet** → nothing rendered (panel stays clean).
          - **Clean host** (no active AV/EDR, Defender RTP off OR absent) →
            green sub-panel: "No active AV/EDR detected".
          - **Active AV/EDR or Defender RTP on** → yellow/red sub-panel
            with a per-product breakdown so the operator sees exactly what
            stands between the schtask and the payload.
        """
        fp = self._fingerprint
        if fp is None:
            return None

        # Soft-typed access — the live widget should not import the host
        # intelligence module for type safety; it consumes the duck-typed
        # surface (has_edr, has_av, defender_rtp, active_products).
        has_edr = bool(getattr(fp, "has_edr", False))
        has_av = bool(getattr(fp, "has_av", False))
        defender_rtp = bool(getattr(fp, "defender_rtp", True))
        active_products = list(getattr(fp, "active_products", []) or [])
        error = getattr(fp, "error", None)

        if error and not active_products:
            text = Text()
            text.append("⚠  AV/EDR fingerprint partial: ", style="bold yellow")
            text.append(str(error)[:140], style="dim")
            return Panel(text, border_style="yellow", expand=False, padding=(0, 1))

        is_high_risk = has_edr
        is_medium_risk = has_av or (defender_rtp and active_products)

        if is_high_risk:
            border = "red"
            icon, headline = "🛑", "EDR ACTIVE — schtask payload may be killed"
        elif is_medium_risk:
            border = "yellow"
            icon, headline = "⚠ ", "AV active — Defender may quarantine output"
        else:
            border = "green"
            icon, headline = "✓ ", "No active AV/EDR detected on target"

        body = Table.grid(padding=(0, 1))
        body.add_column(no_wrap=True)
        body.add_column(no_wrap=False)

        head_text = Text()
        head_text.append(f"{icon} ", style="bold")
        head_text.append(headline, style=f"bold {border}")
        body.add_row("", head_text)

        if active_products:
            for product in active_products:
                pname = str(getattr(product, "name", "unknown"))
                category = str(getattr(product, "category", "")).upper()
                status = str(getattr(product, "status_label", ""))
                rtp_off = not bool(getattr(product, "realtime_protection", True))
                line = Text()
                line.append(f"  {category:>3s}  ", style="dim")
                line.append(pname, style="bold")
                line.append("  ·  ", style="dim")
                line.append(status, style="yellow" if rtp_off else "red")
                body.add_row("", line)
        else:
            line = Text()
            line.append("  No products in catalog matched.  ", style="dim")
            line.append("Defender RTP=", style="dim")
            line.append(
                "ON" if defender_rtp else "OFF",
                style="red" if defender_rtp else "green",
            )
            body.add_row("", line)

        # Footer line — concise OPSEC tip.
        tip = Text()
        if is_high_risk:
            tip.append("  → ", style="dim")
            tip.append(
                "operator decision required: continue / cancel / switch to in-memory technique",
                style="dim",
            )
            body.add_row("", tip)
        elif is_medium_risk:
            tip.append("  → ", style="dim")
            tip.append(
                "consider AMSI/Defender exclusion path or stage payload via temp dir",
                style="dim",
            )
            body.add_row("", tip)

        return Panel(
            body,
            title="[bold]AV / EDR fingerprint[/bold]",
            border_style=border,
            expand=False,
            padding=(0, 1),
        )

    def _phase_table(self) -> RenderableType:
        table = Table.grid(padding=(0, 2))
        table.add_column(width=2)
        table.add_column(no_wrap=False)
        table.add_column(justify="right", style="dim", no_wrap=True)

        for phase in PHASES:
            row = self._rows[phase]
            icon = self._phase_icon(row)
            label = Text()
            label.append(_PHASE_LABELS.get(phase, phase))
            if row.detail and row.status in ("warn", "fail", "running"):
                label.append("  ")
                label.append(
                    row.detail if len(row.detail) <= 80 else row.detail[:77] + "…",
                    style="dim",
                )
            right = Text()
            if row.status == "ok" and row.duration_ms is not None:
                right.append(f"{row.duration_ms:0.0f}ms", style="green")
            elif row.status == "warn" and row.duration_ms is not None:
                right.append(f"{row.duration_ms:0.0f}ms", style="yellow")
            elif row.status == "fail" and row.duration_ms is not None:
                right.append(f"{row.duration_ms:0.0f}ms", style="red")
            elif row.status == "running":
                right.append("…", style="cyan")
            else:
                right.append("pending", style="dim")
            table.add_row(icon, label, right)
        return table

    @staticmethod
    def _phase_icon(row: _PhaseRow) -> RenderableType:
        if row.status == "running":
            return Spinner("dots", style="cyan")
        if row.status == "ok":
            return Text("✓", style="bold green")
        if row.status == "warn":
            return Text("!", style="bold yellow")
        if row.status == "fail":
            return Text("✗", style="bold red")
        return Text("·", style="dim")

    def _footer(self) -> RenderableType:
        elapsed = time.monotonic() - self._started
        text = Text()
        text.append("Elapsed ", style="dim")
        text.append(f"{elapsed:0.1f}s", style="bold")
        if self._final is not None:
            text.append("    ")
            if self._final.success:
                text.append("RESULT  ", style="dim")
                text.append("SUCCESS", style="bold green")
                if self._captured:
                    text.append(f"  · captured {self._captured}", style="dim")
            else:
                text.append("RESULT  ", style="dim")
                text.append("FAILED", style="bold red")
                if self._final.error:
                    err = self._final.error
                    if len(err) > 90:
                        err = err[:87] + "…"
                    text.append(f"  · {err}", style="dim")
        return text


__all__ = ["HasSessionLiveContext", "HasSessionLiveView"]
