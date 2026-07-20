"""Operator-facing presentation helpers for native coercion."""

from __future__ import annotations

from adscan_internal import print_info, print_success, print_warning
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.coercion.core import CoercionRunResult


def print_coercion_summary(result: CoercionRunResult) -> None:
    """Render a premium Rich panel summarising a native coercion run."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from adscan_core.rich_output import get_console

    target = mark_sensitive(result.target.label, "hostname")

    if not result.results:
        print_info(f"Native coercion: no attempts executed against {target}.")
        return

    grid = Table(
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        show_edge=True,
        padding=(0, 1),
        expand=False,
    )
    grid.add_column("Method", style="cyan", no_wrap=True)
    grid.add_column("Protocol", style="dim", no_wrap=True)
    grid.add_column("Endpoint", style="dim")
    grid.add_column("Listener", style="dim")
    grid.add_column("Result", no_wrap=True)
    grid.add_column("Error", style="dim red")

    for attempt in result.results:
        # ``success`` is now reserved for a real, listener-confirmed capture
        # (which is a run-level fact, not a per-attempt one), so per-row state
        # reflects the heuristic ``probable_auth_triggered`` hint.
        if attempt.probable_auth_triggered:
            result_cell = "[bold yellow]~ probable[/]"
        elif attempt.error_code:
            result_cell = f"[dim]{attempt.error_code}[/]"
        else:
            result_cell = "[dim]–[/]"
        error_cell = (
            (attempt.error or "")[:80]
            if (attempt.error and not attempt.probable_auth_triggered)
            else ""
        )

        grid.add_row(
            attempt.method_name,
            attempt.protocol,
            attempt.endpoint.label if attempt.endpoint else "–",
            f"{attempt.listener.auth_type.upper()} {attempt.listener.host}",
            result_cell,
            error_cell,
        )

    if result.captured:
        header_style = "bold white on green"
        title_text = "  Coercion — Authentication Captured  "
    elif result.timed_out:
        header_style = "bold white on yellow"
        title_text = "  Coercion — Timed Out  "
    else:
        header_style = "bold white on dark_orange"
        title_text = "  Coercion — No Capture  "

    title = Text(title_text, style=header_style)
    panel = Panel(grid, title=title, border_style="dim", padding=(1, 1))
    get_console().print(panel)

    if result.captured:
        print_success(f"Coercion captured inbound authentication from {target}.")
    elif result.timed_out:
        print_warning(
            f"Coercion timed out against {target} — "
            "verify connectivity and that the listener IP is reachable from the target."
        )
    else:
        print_info(
            f"Coercion completed against {target}; no inbound authentication was captured."
        )
