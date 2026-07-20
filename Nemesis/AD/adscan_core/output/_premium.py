"""Premium CLI primitives — implements ``docs/cli_style.md`` §3.

Four operator-visible primitives that complete the operation lifecycle:

* :func:`print_kv_section`             — reusable detail rows.
* :func:`print_remediation_card`       — error + cause + suggested commands.
* :func:`print_empty_state`            — graceful zero-result rendering.
* :func:`print_operation_summary_footer` — closing card; the operation's JSON.

All four respect the global output mode (``human`` / ``json`` / ``quiet``).
The footer additionally emits the canonical JSON envelope so consumers
(``adscan_web``, agents, automation) parse one stable contract per operation.

Layered on top of, not parallel to, the existing primitives in
``_panels.py`` / ``_tables.py`` / ``_scan.py``. Sensitive values are masked
via the same auto-detection used by :func:`print_operation_header`.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.theme import ADSCAN_PRIMARY

from adscan_core.output._modes import (
    build_envelope,
    emit_json,
    is_human,
    suppress_rich,
)
from adscan_core.output._state import (
    _get_console,
    _get_telemetry_console,
    _mark_operation_details,
)
from adscan_core.output._log import _handle_spacing


# ---------------------------------------------------------------------------
# Status vocabulary — locked to docs/cli_style.md §4
# ---------------------------------------------------------------------------

_STATUS_STYLES: Dict[str, Dict[str, str]] = {
    "ok": {"icon": "✓", "color": "green", "border": "green"},
    "empty": {"icon": "○", "color": "yellow", "border": "yellow"},
    "partial": {"icon": "⚠", "color": "yellow", "border": "yellow"},
    "error": {"icon": "✗", "color": "red", "border": "red"},
}


def _status_style(status: str) -> Dict[str, str]:
    return _STATUS_STYLES.get(status, _STATUS_STYLES["ok"])


def _print(panel: Panel, *, kind: str = "panel") -> None:
    """Centralised render with telemetry mirror and spacing logic."""
    if suppress_rich():
        return
    console = _get_console()
    _get_telemetry_console()

    if _handle_spacing(kind, True, "auto"):
        console.print()

    console.print(panel)


# ---------------------------------------------------------------------------
# 3.2 — print_kv_section
# ---------------------------------------------------------------------------


def print_kv_section(
    title: Optional[str],
    kv: Mapping[str, Any],
    *,
    icon: Optional[str] = None,
    border_style: str = ADSCAN_PRIMARY,
) -> None:
    """Render a titled key-value detail block.

    Replaces every ad-hoc ``Table.grid()`` for kv detail rows. Sensitive values
    (domain, IP, user, hash, etc.) are auto-masked via the same heuristics as
    :func:`print_operation_header`.

    A ``None`` or empty ``title`` renders the kv table inline without a panel
    border — useful inside larger composite renderables.
    """
    if suppress_rich() or not kv:
        return

    marked = _mark_operation_details({k: str(v) for k, v in kv.items()})

    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", justify="right")
    table.add_column(style="white")
    for key, value in marked.items():
        table.add_row(f"{key}:", value)

    if not title:
        if suppress_rich():
            return
        console = _get_console()
        _get_telemetry_console()
        console.print(table)
        return

    header = Text()
    if icon:
        header.append(f"{icon} ", style="bold")
    header.append(title, style=f"bold {border_style}")

    panel = Panel(
        Group(header, Text(""), table),
        border_style=border_style,
        padding=(1, 2),
    )
    _print(panel, kind="kv_section")


# ---------------------------------------------------------------------------
# 3.3 — print_remediation_card
# ---------------------------------------------------------------------------


def print_remediation_card(
    error: str,
    cause: Optional[str] = None,
    commands: Optional[Sequence[str]] = None,
    *,
    title: str = "Remediation",
) -> None:
    """Render an error with a probable cause and 1-3 suggested next commands.

    Use whenever the failure has a known cause in the operator's playbook
    (auth denied, signing required, clock skew, NTLM blocked, …). For unknown
    failures fall back to :func:`print_error_context` or :func:`print_error`.
    """
    if suppress_rich():
        return

    body = Text()
    body.append("✗ ", style="bold red")
    body.append(error, style="bold red")

    sections: List[Any] = [body]

    if cause:
        cause_line = Text()
        cause_line.append("Likely cause: ", style="dim")
        cause_line.append(cause, style="white")
        sections.append(Text(""))
        sections.append(cause_line)

    if commands:
        sections.append(Text(""))
        sections.append(Text("Try:", style="bold dim"))
        sections.append(_build_command_grid(commands[:3]))

    panel = Panel(
        Group(*sections),
        title=f"[bold red]{title}[/bold red]",
        border_style="red",
        padding=(1, 2),
    )
    _print(panel, kind="remediation")


# ---------------------------------------------------------------------------
# 3.4 — print_empty_state
# ---------------------------------------------------------------------------


def print_empty_state(
    resource: str,
    *,
    cause: Optional[str] = None,
    suggestions: Optional[Sequence[str]] = None,
    icon: str = "○",
) -> None:
    """Render a graceful zero-result block. Never silent.

    ``resource`` should be the plural noun the operator was looking for —
    ``"SMB shares"``, ``"Kerberoastable accounts"``, ``"writable GPOs"``.
    """
    if suppress_rich():
        return

    header = Text()
    header.append(f"{icon} ", style="bold yellow")
    header.append(f"No {resource} found", style="bold yellow")

    sections: List[Any] = [header]

    if cause:
        cause_line = Text()
        cause_line.append("Likely cause: ", style="dim")
        cause_line.append(cause, style="white")
        sections.append(Text(""))
        sections.append(cause_line)

    if suggestions:
        sections.append(Text(""))
        sections.append(Text("Try:", style="bold dim"))
        for idx, suggestion in enumerate(suggestions[:3], 1):
            line = Text()
            line.append(f"  {idx}. ", style="dim")
            line.append(suggestion, style="white")
            sections.append(line)

    panel = Panel(
        Group(*sections),
        border_style="yellow",
        padding=(1, 2),
    )
    _print(panel, kind="empty_state")


# ---------------------------------------------------------------------------
# 3.5 — print_operation_summary_footer
# ---------------------------------------------------------------------------


def print_operation_summary_footer(
    operation: str,
    *,
    status: str = "ok",
    target: Optional[Mapping[str, Any]] = None,
    posture: Optional[Mapping[str, Any]] = None,
    findings: Optional[Mapping[str, Any] | List[Any]] = None,
    saved_to: Optional[Sequence[str]] = None,
    next_command: Optional[str] = None,
    duration_ms: Optional[int] = None,
    started_at: Optional[datetime] = None,
    error: Optional[Mapping[str, Any]] = None,
    extra: Optional[Mapping[str, Any]] = None,
    title: Optional[str] = None,
) -> None:
    """Required at the end of every operation.

    In ``human`` mode renders a status-coloured summary panel with finding
    counts, saved-to paths, and a next-step suggestion. In ``json`` /
    ``quiet`` modes emits the canonical JSON envelope and skips Rich.

    ``operation`` is the dotted-path identifier (``smb.shares``,
    ``ldap.users``, …) and is part of the public JSON contract.
    ``findings`` may be a dict of named counts (rendered as kv rows) or a
    list (rendered as a bare count).
    """
    payload = build_envelope(
        operation=operation,
        target=dict(target) if target else None,
        posture=dict(posture) if posture else None,
        status=status,
        started_at=started_at,
        duration_ms=duration_ms,
        findings=list(findings) if isinstance(findings, list) else (dict(findings) if findings else []),
        saved_to=list(saved_to) if saved_to else None,
        next_command=next_command,
        error=dict(error) if error else None,
        extra=dict(extra) if extra else None,
    )
    emit_json(payload)

    if not is_human():
        return

    style = _status_style(status)
    display_title = title or operation

    header = Text()
    header.append(f"{style['icon']} ", style=f"bold {style['color']}")
    header.append(display_title, style=f"bold {style['color']}")
    header.append(f"  ·  {status}", style="dim")

    sections: List[Any] = [header]

    counts_table = _build_findings_kv(findings)
    if counts_table is not None:
        sections.append(Text(""))
        sections.append(counts_table)

    if saved_to:
        sections.append(Text(""))
        saved_header = Text("Saved to:", style="bold dim")
        sections.append(saved_header)
        for path in saved_to:
            line = Text()
            line.append("  ", style="dim")
            line.append(path, style="white")
            sections.append(line)

    if next_command:
        sections.append(Text(""))
        sections.append(Text("Next:", style="bold dim"))
        sections.append(_build_command_grid([next_command], numbered=False))

    if duration_ms is not None:
        sections.append(Text(""))
        duration_line = Text()
        duration_line.append("Duration: ", style="dim")
        duration_line.append(_format_duration(duration_ms), style="white")
        sections.append(duration_line)

    panel = Panel(
        Group(*sections),
        border_style=style["border"],
        padding=(1, 2),
    )
    _print(panel, kind="footer")


def _build_command_grid(
    commands: Sequence[str],
    *,
    numbered: bool = True,
) -> Table:
    """Render bash commands as a tight grid: ``  N.  $ <cmd>``.

    Avoids ``Syntax`` blocks for short single-line commands because they
    insert a hard line break that breaks the indentation of the surrounding
    list. Inline styling keeps every command on one logical row.
    """
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="dim", justify="right", no_wrap=True)
    grid.add_column(style="dim", no_wrap=True)
    grid.add_column(style="bold cyan", overflow="fold")
    for idx, cmd in enumerate(commands, 1):
        prefix = f"  {idx}." if numbered else "  "
        grid.add_row(prefix, "$", cmd)
    return grid


def _build_findings_kv(
    findings: Optional[Mapping[str, Any] | List[Any]],
) -> Optional[Table]:
    if findings is None:
        return None
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", justify="right")
    table.add_column(style="white")
    if isinstance(findings, Mapping):
        if not findings:
            return None
        for key, value in findings.items():
            color = "green" if isinstance(value, int) and value > 0 else "dim"
            table.add_row(f"{key}:", f"[{color}]{value}[/{color}]")
        return table
    if isinstance(findings, list):
        if not findings:
            return None
        table.add_row("Findings:", f"[green]{len(findings)}[/green]")
        return table
    return None


def _format_duration(ms: int) -> str:
    if ms < 1_000:
        return f"{ms} ms"
    seconds = ms / 1_000.0
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, seconds = divmod(seconds, 60)
    return f"{int(minutes)}m {seconds:.0f}s"


# ---------------------------------------------------------------------------
# Operation timing helper — paired with the footer
# ---------------------------------------------------------------------------


class operation_timer:  # noqa: N801 — context-manager naming convention
    """Tiny ctx-manager for ``started_at`` + ``duration_ms``.

    Removes the boilerplate of capturing ``time.monotonic()`` at every
    operation entry. Pair with :func:`print_operation_summary_footer`.

    Example::

        with operation_timer() as t:
            do_work()
        print_operation_summary_footer(
            "smb.shares",
            duration_ms=t.duration_ms,
            started_at=t.started_at,
            ...,
        )
    """

    __slots__ = ("started_at", "_t0", "duration_ms")

    def __init__(self) -> None:
        self.started_at: Optional[datetime] = None
        self._t0: float = 0.0
        self.duration_ms: Optional[int] = None

    def __enter__(self) -> "operation_timer":
        self.started_at = datetime.now(timezone.utc)
        self._t0 = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.duration_ms = int((time.monotonic() - self._t0) * 1_000)


__all__ = [
    "print_kv_section",
    "print_remediation_card",
    "print_empty_state",
    "print_operation_summary_footer",
    "operation_timer",
]
