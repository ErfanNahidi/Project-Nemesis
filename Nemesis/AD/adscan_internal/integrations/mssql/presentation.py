"""Premium CLI presentation for the native MSSQL flow.

Renders the three signature cards of the MSSQL operator console:

* :func:`print_mssql_sweep_card` — privilege fingerprint after login.
* :func:`print_mssql_command_card` — evidence card after one
  ``xp_cmdshell`` invocation.
* :func:`print_mssql_pivot_chain` — linked-server pivot map.

Design rules — kept short on purpose so future contributors do not bend
them by accident:

1. **Two-line answer, then evidence.** Title line names the outcome.
   Subtitle (or first body line) names the canonical class. Everything
   else is detail.
2. **Severity through typography.** Crimson is reserved for confirmed
   choke points. Amber for "validation pending" or partial wins. Sage
   for confirmed wins that are not Tier 0. Muted for structural rows.
3. **Translate inline.** Canonical terms (``Tier 0 Foothold``,
   ``Compromise Enabler``) ship with a comma-separated business clause
   on the same line — no footnotes, no glossary lookups.
4. **Every card ends with ``next``.** Two or three concrete follow-ups
   with prerequisites already validated by the data we just gathered.

This module imports only from :mod:`adscan_core` (rich primitives) and
:mod:`adscan_internal.integrations.mssql.models`. It does not touch the
backend or the network — pure rendering against typed inputs.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from rich.box import ROUNDED
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.output._panels import print_panel
from adscan_core.rich_output import _get_console as _get_base_console
from adscan_core.theme import (
    COLOR_AMBER,
    COLOR_CRIMSON,
    COLOR_MUTED,
    COLOR_SAGE,
    COLOR_STEEL,
)
from adscan_internal.integrations.mssql.models import (
    CommandExecution,
    IntegrityHint,
    PivotChain,
    PivotHop,
    PrivilegeSweep,
    XpCmdshellStatus,
)
from adscan_internal.rich_output import mark_sensitive


# ---------------------------------------------------------------------------
# Visual primitives
# ---------------------------------------------------------------------------

_TICK = "✓"
_CROSS = "✗"
_DOT = "•"
_ARROW = "→"
_DIVIDER = "─"

_LABEL_WIDTH = 18

_NEXT_LABEL = Text(" next ", style=f"bold black on {COLOR_STEEL}")


def _muted(text: str) -> Text:
    return Text(text, style=COLOR_MUTED)


def _label(text: str) -> Text:
    return Text(text.ljust(_LABEL_WIDTH), style=COLOR_MUTED)


def _flag(value: bool, *, true_style: str = COLOR_SAGE) -> Text:
    """Render a boolean as a coloured tick or cross."""
    if value:
        return Text(_TICK, style=f"bold {true_style}")
    return Text(_CROSS, style=COLOR_MUTED)


def _xp_cmdshell_glyph(status: XpCmdshellStatus) -> Text:
    if status == XpCmdshellStatus.ENABLED:
        return Text(f"{_TICK} enabled", style=f"bold {COLOR_SAGE}")
    if status == XpCmdshellStatus.DISABLED:
        return Text(f"{_CROSS} disabled", style=COLOR_AMBER)
    return Text("? unknown", style=COLOR_MUTED)


def _section_divider(width: int = 64) -> Text:
    return Text(_DIVIDER * width, style=COLOR_MUTED)


def _command_block(command: str) -> Text:
    return Text(command, style=f"bold {COLOR_STEEL}")


def _kv_grid(rows: Iterable[tuple[str, Text | str]]) -> Table:
    """Build the canonical two-column key/value grid used by every card."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style=COLOR_MUTED, min_width=_LABEL_WIDTH)
    grid.add_column(justify="left")
    for label, value in rows:
        grid.add_row(
            label, value if isinstance(value, Text) else Text.from_markup(str(value))
        )
    return grid


def _next_steps(steps: Sequence[tuple[str, str]]) -> Group:
    """Render the trailing ``next`` block: list of (label, command) pairs."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style=COLOR_MUTED, min_width=14)
    grid.add_column(justify="left")
    for label, command in steps:
        grid.add_row(label, _command_block(command))
    header = Text.assemble(_NEXT_LABEL, "  ", _muted("recommended follow-ups"))
    return Group(header, Text(""), grid)


# ---------------------------------------------------------------------------
# Compromise classification — light wrapper around canonical model
# ---------------------------------------------------------------------------


def _compromise_label(sweep: PrivilegeSweep) -> tuple[str, str, str]:
    """Return (canonical_class, business_clause, border_style) for a sweep.

    Stays intentionally narrow: only the cases the MSSQL flow can confirm
    locally. Real graph-level classification happens elsewhere — this is
    the in-the-moment label the operator sees in the CLI.
    """
    if sweep.is_sysadmin and sweep.xp_cmdshell == XpCmdshellStatus.ENABLED:
        return (
            "Tier 0 Foothold",
            "OS execution unlocked, control pending demonstration",
            COLOR_CRIMSON,
        )
    if sweep.is_sysadmin:
        return (
            "Tier 0 Foothold",
            "sysadmin confirmed, xp_cmdshell pending",
            COLOR_AMBER,
        )
    if sweep.has_dbowner_privesc_candidate or sweep.has_impersonation_privesc:
        return (
            "Compromise Enabler",
            "privilege-escalation path available",
            COLOR_AMBER,
        )
    return (
        "Authenticated principal",
        "no escalation path detected from this surface",
        COLOR_STEEL,
    )


# ---------------------------------------------------------------------------
# Card 1 — privilege sweep
# ---------------------------------------------------------------------------


def print_mssql_sweep_card(sweep: PrivilegeSweep) -> None:
    """Print the privilege fingerprint card for one MSSQL login."""
    canonical, clause, border = _compromise_label(sweep)
    identity = sweep.identity

    privileges = _kv_grid(
        [
            (
                "sysadmin",
                Text.assemble(
                    _flag(sweep.is_sysadmin, true_style=COLOR_CRIMSON),
                    "  ",
                    _muted("server-level role membership"),
                ),
            ),
            (
                "xp_cmdshell",
                Text.assemble(
                    _xp_cmdshell_glyph(sweep.xp_cmdshell),
                    "  ",
                    _muted(
                        "advanced options on"
                        if sweep.show_advanced_options_enabled
                        else "advanced options off"
                    ),
                ),
            ),
            (
                "impersonate",
                Text.assemble(
                    _flag(sweep.has_impersonation_privesc, true_style=COLOR_AMBER),
                    "  ",
                    _muted(
                        f"{len(sweep.impersonable_principals)} principal(s)"
                        if sweep.impersonable_principals
                        else "none"
                    ),
                ),
            ),
            (
                "dbowner privesc",
                Text.assemble(
                    _flag(
                        sweep.has_dbowner_privesc_candidate,
                        true_style=COLOR_AMBER,
                    ),
                    "  ",
                    _muted(
                        f"{len(sweep.owned_databases)} owned, "
                        f"{len(sweep.trustworthy_databases_owned_by_sysadmin)} trustworthy"
                    ),
                ),
            ),
            (
                "linked servers",
                Text.assemble(
                    _flag(bool(sweep.linked_servers), true_style=COLOR_STEEL),
                    "  ",
                    _muted(
                        f"{len(sweep.linked_servers)} reachable"
                        if sweep.linked_servers
                        else "none"
                    ),
                ),
            ),
        ]
    )

    integrity_text = (
        sweep.integrity_hint.value
        if sweep.integrity_hint != IntegrityHint.UNKNOWN
        else "—"
    )
    effective = (
        f"{identity.original_login} {_ARROW} {identity.system_user}"
        if identity.has_execute_as_chain
        else identity.system_user or identity.login_name
    )
    summary = _kv_grid(
        [
            (
                "effective login",
                Text(effective, style=f"bold {COLOR_STEEL}"),
            ),
            ("integrity hint", _muted(integrity_text)),
            (
                "server",
                Text.assemble(
                    Text(identity.server_name or "—", style=COLOR_STEEL),
                    "  ",
                    _muted(identity.short_version),
                ),
            ),
            (
                "edition",
                _muted(identity.edition or "—"),
            ),
        ]
    )

    classification = Table.grid(padding=(0, 2))
    classification.add_column(
        justify="right", style=COLOR_MUTED, min_width=_LABEL_WIDTH
    )
    classification.add_column(justify="left")
    classification.add_row("class", Text(canonical, style=f"bold {border}"))
    classification.add_row("", _muted(clause))
    classification.add_row(
        "elapsed",
        _muted(f"{sweep.duration_seconds * 1000:.0f}ms · single round-trip"),
    )

    next_steps = _next_steps(_recommended_next_for_sweep(sweep))

    body = Group(
        summary,
        Text(""),
        _section_divider(),
        Text(""),
        privileges,
        Text(""),
        _section_divider(),
        Text(""),
        classification,
        Text(""),
        next_steps,
    )

    title = Text.assemble(
        ("MSSQL Sweep", f"bold {border}"),
        ("  ·  ", COLOR_MUTED),
        (
            mark_sensitive(
                identity.server_name or sweep.identity.login_name, "hostname"
            ),
            COLOR_STEEL,
        ),
        ("  ·  ", COLOR_MUTED),
        (mark_sensitive(identity.system_user, "user"), f"bold {COLOR_STEEL}"),
    )

    print_panel(
        body,
        title=title,
        border_style=border,
        box=ROUNDED,
        padding=(1, 2),
    )


def _recommended_next_for_sweep(sweep: PrivilegeSweep) -> tuple[tuple[str, str], ...]:
    """Pick 2-3 concrete follow-ups based on what the sweep actually proved."""
    server = sweep.identity.server_name or "<host>"
    steps: list[tuple[str, str]] = []
    if sweep.can_execute_os_commands:
        steps.append(("pop shell", f"adscan mssql pop {server}"))
    elif sweep.is_sysadmin:
        steps.append(("enable shell", f"adscan mssql enable-shell {server}"))
    if sweep.linked_servers:
        steps.append(("map pivots", f"adscan mssql pivot map {server}"))
    if sweep.has_impersonation_privesc:
        steps.append(("walk impersonation", f"adscan mssql impersonate {server}"))
    if not steps:
        steps.append(("re-run with creds", f"adscan mssql sweep {server} --user OTHER"))
    return tuple(steps[:3])


# ---------------------------------------------------------------------------
# Card 2 — xp_cmdshell evidence
# ---------------------------------------------------------------------------


def print_mssql_command_card(
    execution: CommandExecution,
    *,
    sweep: PrivilegeSweep | None = None,
) -> None:
    """Print the evidence card after one OS command via ``xp_cmdshell``."""
    if execution.is_terminal_win:
        border = COLOR_CRIMSON
        outcome_label = "SYSTEM-equivalent"
    elif execution.success:
        border = COLOR_SAGE
        outcome_label = "command executed"
    else:
        border = COLOR_AMBER
        outcome_label = "execution failed"

    identity_block = _kv_grid(
        [
            (
                "host",
                Text(mark_sensitive(execution.host, "hostname"), style=COLOR_STEEL),
            ),
            (
                "via",
                _muted(
                    f"linked server [bold {COLOR_STEEL}]{execution.via_linked_server}[/]"
                    if execution.via_linked_server
                    else "local xp_cmdshell"
                ),
            ),
            (
                "integrity",
                Text(
                    execution.integrity_hint.value,
                    style=(
                        f"bold {COLOR_CRIMSON}"
                        if execution.integrity_hint == IntegrityHint.SYSTEM
                        else COLOR_STEEL
                    ),
                ),
            ),
            (
                "elapsed",
                _muted(f"{execution.duration_seconds * 1000:.0f}ms"),
            ),
        ]
    )

    command_grid = Table.grid(padding=(0, 2))
    command_grid.add_column(justify="right", style=COLOR_MUTED, min_width=_LABEL_WIDTH)
    command_grid.add_column(justify="left", overflow="fold")
    command_grid.add_row(
        "command",
        Text(mark_sensitive(execution.command, "text"), style=f"bold {COLOR_STEEL}"),
    )
    command_grid.add_row("status", Text(outcome_label, style=f"bold {border}"))

    output_panel = _build_output_block(execution)

    promotion: Group | Text
    if execution.is_terminal_win:
        promotion = Group(
            Text.assemble(
                Text(" EDGE INSERTED ", style=f"bold black on {COLOR_CRIMSON}"),
                "  ",
                Text(
                    f"{execution.host} ─derived[xp_cmdshell]→ NT AUTHORITY\\SYSTEM",
                    style=f"bold {COLOR_CRIMSON}",
                ),
            ),
            _muted("PathState: theoretical → post_ex_in_progress · evidence captured"),
        )
    elif execution.success:
        promotion = _muted("PathState: foothold_obtained · awaiting privilege evidence")
    else:
        promotion = _muted(
            f"PathState: post_ex_failed · {execution.error_message or 'see stderr'}"
        )

    next_steps = _next_steps(_recommended_next_for_execution(execution, sweep))

    body = Group(
        identity_block,
        Text(""),
        _section_divider(),
        Text(""),
        command_grid,
        Text(""),
        output_panel,
        Text(""),
        _section_divider(),
        Text(""),
        promotion,
        Text(""),
        next_steps,
    )

    title = Text.assemble(
        ("Shell", f"bold {border}"),
        ("  ·  ", COLOR_MUTED),
        (mark_sensitive(execution.host, "hostname"), COLOR_STEEL),
        ("  ·  ", COLOR_MUTED),
        (
            "via " + execution.via_linked_server
            if execution.via_linked_server
            else "xp_cmdshell",
            COLOR_MUTED,
        ),
    )

    print_panel(
        body,
        title=title,
        border_style=border,
        box=ROUNDED,
        padding=(1, 2),
    )


def _build_output_block(execution: CommandExecution) -> Panel:
    """Render the captured stdout/stderr inside a sub-panel."""
    if execution.success and execution.stdout_lines:
        preview_lines = execution.stdout_lines[:8]
        body_lines = [
            Text(mark_sensitive(line, "text"), style=COLOR_STEEL)
            for line in preview_lines
        ]
        if len(execution.stdout_lines) > len(preview_lines):
            body_lines.append(
                _muted(
                    f"… {len(execution.stdout_lines) - len(preview_lines)} more "
                    "lines (re-run with --verbose)"
                )
            )
        body: Group = Group(*body_lines)
        sub_border = COLOR_MUTED
        sub_title = Text("output", style=COLOR_MUTED)
    elif not execution.success:
        body = Group(
            Text(
                mark_sensitive(
                    execution.error_message or execution.stderr or "(no stderr)",
                    "text",
                ),
                style=COLOR_AMBER,
            )
        )
        sub_border = COLOR_AMBER
        sub_title = Text("error", style=f"bold {COLOR_AMBER}")
    else:
        body = Group(_muted("(no output)"))
        sub_border = COLOR_MUTED
        sub_title = Text("output", style=COLOR_MUTED)
    return Panel(
        body,
        title=sub_title,
        title_align="left",
        border_style=sub_border,
        box=ROUNDED,
        padding=(0, 1),
    )


def _recommended_next_for_execution(
    execution: CommandExecution,
    sweep: PrivilegeSweep | None,
) -> tuple[tuple[str, str], ...]:
    server = execution.host
    steps: list[tuple[str, str]] = []
    if execution.is_terminal_win:
        # Credential extraction runs automatically after escalation — do not
        # surface a phantom `adscan loot` command (no such verb exists).
        steps.append(("escalate to SYSTEM", f"adscan mssql escalate {server}"))
    elif execution.success:
        steps.append(("escalate to SYSTEM", f"adscan mssql escalate {server}"))
        if sweep and sweep.linked_servers:
            steps.append(("walk pivots", f"adscan mssql pivot map {server}"))
    else:
        if sweep and not sweep.is_sysadmin:
            steps.append(
                ("re-run as sysadmin", f"adscan mssql sweep {server} --user sa")
            )
        steps.append(("inspect server log", f"adscan mssql sweep {server} --debug"))
    return tuple(steps[:3])


# ---------------------------------------------------------------------------
# Card 3 — pivot chain
# ---------------------------------------------------------------------------


def print_mssql_pivot_chain(chain: PivotChain) -> None:
    """Render the linked-server pivot map as an indented chain."""
    if not chain.hops:
        print_panel(
            Group(_muted("No linked servers reachable from this connection.")),
            title=Text("Pivot Chain", style=f"bold {COLOR_STEEL}"),
            border_style=COLOR_MUTED,
            box=ROUNDED,
        )
        return

    border = COLOR_CRIMSON if chain.reaches_sysadmin else COLOR_STEEL
    body_lines: list[Text | Table] = []
    for hop in chain.hops:
        body_lines.extend(_render_pivot_hop(hop))

    classification, clause = _classify_pivot_chain(chain)
    classification_grid = Table.grid(padding=(0, 2))
    classification_grid.add_column(
        justify="right", style=COLOR_MUTED, min_width=_LABEL_WIDTH
    )
    classification_grid.add_column(justify="left")
    classification_grid.add_row("class", Text(classification, style=f"bold {border}"))
    classification_grid.add_row("", _muted(clause))
    classification_grid.add_row(
        "discovery",
        _muted(f"{chain.discovery_seconds * 1000:.0f}ms"),
    )

    next_steps = _next_steps(_recommended_next_for_pivot(chain))

    body = Group(
        Text(""),
        *body_lines,
        Text(""),
        _section_divider(),
        Text(""),
        classification_grid,
        Text(""),
        next_steps,
    )

    title = Text.assemble(
        ("Pivot Chain", f"bold {border}"),
        ("  ·  ", COLOR_MUTED),
        (mark_sensitive(chain.entry_server, "hostname"), COLOR_STEEL),
        ("  ·  ", COLOR_MUTED),
        (f"{chain.length} hop(s)", COLOR_MUTED),
    )

    print_panel(
        body,
        title=title,
        border_style=border,
        box=ROUNDED,
        padding=(1, 2),
    )


def _render_pivot_hop(hop: PivotHop) -> list[Text]:
    indent = "    " * hop.hop_index
    connector = ""
    if hop.hop_index > 0:
        connector = "└─" + (
            f"[linked: {hop.incoming_link}]" if hop.incoming_link else ""
        )

    style = (
        f"bold {COLOR_CRIMSON}"
        if hop.is_terminal_win
        else (f"bold {COLOR_STEEL}" if hop.is_sysadmin else COLOR_MUTED)
    )

    lines: list[Text] = []
    if connector:
        lines.append(Text(f"{indent[:-2]}{connector}", style=COLOR_MUTED))
    server_line = Text.assemble(
        Text(indent, style=COLOR_MUTED),
        Text(mark_sensitive(hop.server_label, "hostname"), style=style),
        "   ",
        Text(
            f"effective: {mark_sensitive(hop.effective_login, 'user')}",
            style=COLOR_MUTED,
        ),
    )
    lines.append(server_line)
    flag_line = Text.assemble(
        Text(indent + "   ", style=COLOR_MUTED),
        _flag(hop.is_sysadmin, true_style=COLOR_CRIMSON),
        Text(" sysadmin   ", style=COLOR_MUTED),
        _xp_cmdshell_glyph(hop.xp_cmdshell),
    )
    lines.append(flag_line)
    return lines


def _classify_pivot_chain(chain: PivotChain) -> tuple[str, str]:
    if chain.length == 0:
        return ("No pivot", "no linked servers reachable")
    if chain.reaches_sysadmin:
        return (
            "Compromise Enabler",
            f"{chain.length}-hop path reaches sysadmin via linked-server chain",
        )
    if chain.length == 1:
        return ("Pivot ready", "linked server reachable, identity probed")
    return (
        "Pivot reconnaissance",
        f"{chain.length}-hop chain mapped, sysadmin not yet confirmed",
    )


def _recommended_next_for_pivot(chain: PivotChain) -> tuple[tuple[str, str], ...]:
    entry = chain.entry_server
    terminal = chain.terminal_hop
    steps: list[tuple[str, str]] = []
    if chain.reaches_sysadmin and terminal:
        steps.append(
            (
                "prove via shell",
                f"adscan mssql pop {entry} --pivot {terminal.server_label}",
            )
        )
    elif terminal and terminal.incoming_link:
        steps.append(
            (
                "fingerprint hop",
                f"adscan mssql sweep {entry} --pivot {terminal.server_label}",
            )
        )
    if chain.length > 1:
        steps.append(
            (
                "deep walk",
                f"adscan mssql pivot walk {entry} --max-hops 6",
            )
        )
    if not steps:
        steps.append(("re-run sweep", f"adscan mssql sweep {entry}"))
    return tuple(steps[:3])


# ---------------------------------------------------------------------------
# Inline status helpers
# ---------------------------------------------------------------------------


def print_query_progress(
    label: str,
    *,
    duration_ms: float,
    rows: int | None = None,
) -> None:
    """Print the single-line "▸ querying X … 312ms · 47 rows" status marker.

    Status lines are emitted only in verbose mode by the caller — this
    helper just renders the line; gating on ``--verbose`` happens upstream.
    """
    parts: list[str | tuple[str, str]] = [
        ("▸ ", COLOR_STEEL),
        (label, COLOR_STEEL),
        ("  …  ", COLOR_MUTED),
        (f"{duration_ms:.0f}ms", COLOR_MUTED),
    ]
    if rows is not None:
        parts.extend([("  ·  ", COLOR_MUTED), (f"{rows} rows", COLOR_MUTED)])
    text = Text()
    for part in parts:
        if isinstance(part, tuple):
            text.append(part[0], style=part[1])
        else:
            text.append(part)
    _get_base_console().print(text)


__all__ = [
    "print_mssql_sweep_card",
    "print_mssql_command_card",
    "print_mssql_pivot_chain",
    "print_query_progress",
]
