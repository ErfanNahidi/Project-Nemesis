"""``adscan show timeline`` — render the workspace scan timeline.

Reads ``<workspace>/<domains_dir>/<domain>/timeline.jsonl`` (one row per
phase, written by :mod:`adscan_internal.services.scan_timeline`) and renders
a premium, scannable summary of one or more scan runs:

    * Per-run header with start time, total elapsed, status, run id.
    * Per-phase row with title, elapsed, status icon, and delta chips.
    * Optional ``--diff`` mode that picks two runs and renders side-by-side
      the phase-by-phase delta of metrics and elapsed time.

The renderer is intentionally read-only: it never modifies the workspace and
never re-executes any scan logic. Failure to read the JSONL surfaces as a
helpful one-line error rather than blowing up the shell.

Operationally this gives the pentester three things the previous CLI lacked:

    1. A receipt of "what happened" they can show clients without grepping logs.
    2. A precise read of which phase produced which finding (`+12 paths` lives
       in *Attack Paths Discovery*, not "somewhere in the scan").
    3. A regression-detection signal: ``adscan show timeline --diff`` against
       last week's run shows whether environment changes shifted the surface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adscan_core.rich_output import (
    get_console,
    mark_sensitive,
    print_error,
    print_info,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class _RunGroup:
    """One scan run: ordered list of phase rows sharing a ``run_id``."""

    run_id: str
    rows: list[dict[str, Any]] = field(default_factory=list)

    @property
    def started_at(self) -> str:
        return str(self.rows[0].get("started_at", "")) if self.rows else ""

    @property
    def ended_at(self) -> str:
        return str(self.rows[-1].get("ended_at", "")) if self.rows else ""

    @property
    def total_elapsed(self) -> float:
        return sum(float(r.get("elapsed_seconds") or 0.0) for r in self.rows)

    @property
    def has_failures(self) -> bool:
        return any(r.get("status") == "error" for r in self.rows)


# ---------------------------------------------------------------------------
# Public entry point — invoked from `LdapShell.do_show_timeline`
# ---------------------------------------------------------------------------


def run_show_timeline(
    shell: Any,
    *,
    domain: str | None = None,
    show_all: bool = False,
    diff: bool = False,
) -> None:
    """Render one or more scan runs from the workspace timeline.

    Args:
        shell: The active ``LdapShell`` (used for workspace path resolution
            and sensitive-value masking).
        domain: Domain to render. When ``None``, falls back to the shell's
            current default domain.
        show_all: When True, render every run found in the JSONL. When False
            (default), render only the most recent run.
        diff: When True, compare the two most recent runs side-by-side. The
            ``show_all`` flag is ignored in diff mode.
    """
    target_domain = _resolve_domain(shell, domain)
    if target_domain is None:
        return

    timeline_path = _timeline_path(shell, target_domain)
    if timeline_path is None or not timeline_path.is_file():
        print_info(
            f"No timeline yet for {mark_sensitive(target_domain, 'domain')}. "
            "Run `adscan enum` first to populate it."
        )
        return

    runs = _load_runs(timeline_path)
    if not runs:
        print_info(
            f"Timeline for {mark_sensitive(target_domain, 'domain')} is empty."
        )
        return

    if diff:
        _render_diff(runs, target_domain)
        return

    if show_all:
        _render_all_runs(runs, target_domain)
    else:
        _render_run(runs[-1], target_domain, run_index=len(runs))


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _resolve_domain(shell: Any, domain: str | None) -> str | None:
    if domain:
        return domain
    fallback = getattr(shell, "domain", None) or getattr(shell, "current_domain", None)
    if fallback:
        return str(fallback)
    print_error("No domain specified and no active domain on the shell. Pass `<domain>`.")
    return None


def _timeline_path(shell: Any, domain: str) -> Path | None:
    workspace_dir = getattr(shell, "current_workspace_dir", None)
    if not workspace_dir:
        print_error("No active workspace. Open one with `workspace use <name>`.")
        return None
    domains_dir = getattr(shell, "domains_dir", "domains")
    try:
        from adscan_internal.workspaces import domain_subpath
    except Exception:  # noqa: BLE001
        return None
    return Path(domain_subpath(workspace_dir, domains_dir, domain, "timeline.jsonl"))


def _load_runs(path: Path) -> list[_RunGroup]:
    """Parse the JSONL into ordered ``_RunGroup`` instances.

    Rows missing a ``run_id`` (legacy format) are grouped under a synthetic
    bucket so older timelines still render meaningfully — the diff command
    still requires real ``run_id`` values to be useful.
    """
    runs: dict[str, _RunGroup] = {}
    order: list[str] = []
    legacy_bucket = "_legacy_no_run_id"

    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            run_id = str(row.get("run_id") or legacy_bucket)
            if run_id not in runs:
                runs[run_id] = _RunGroup(run_id=run_id)
                order.append(run_id)
            runs[run_id].rows.append(row)
    except OSError as exc:
        print_error(f"Failed to read timeline: {exc}")
        return []

    return [runs[rid] for rid in order]


# ---------------------------------------------------------------------------
# Rendering — single run / all runs
# ---------------------------------------------------------------------------


def _render_run(run: _RunGroup, domain: str, *, run_index: int) -> None:
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    header = Text()
    header.append(f"  Run #{run_index}  ", style="bold cyan")
    header.append(run.run_id, style="dim")
    header.append("\n  Domain   ", style="bold")
    header.append(mark_sensitive(domain, "domain"), style="bold magenta")
    header.append("\n  Started  ", style="bold")
    header.append(_short_time(run.started_at), style="cyan")
    header.append("\n  Elapsed  ", style="bold")
    header.append(_format_seconds(run.total_elapsed), style="cyan")
    header.append("\n  Status   ", style="bold")
    if run.has_failures:
        header.append("✗ contains failed phases", style="bold red")
    else:
        header.append("✓ all phases ok", style="bold green")

    title = Text("📜  Scan Timeline", style="bold")
    get_console().print(Panel(header, title=title, title_align="left", border_style="cyan", padding=(1, 2)))

    table = Table(
        show_header=True,
        header_style="bold cyan",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Phase", style="bold", no_wrap=True)
    table.add_column("Status", justify="center", width=8)
    table.add_column("Elapsed", justify="right", width=10)
    table.add_column("Delta", overflow="fold")

    for i, row in enumerate(run.rows, start=1):
        status_cell = (
            Text("✓ ok", style="green")
            if row.get("status") == "ok"
            else Text("✗ err", style="bold red")
        )
        elapsed = Text(
            _format_seconds(float(row.get("elapsed_seconds") or 0)),
            style="cyan",
        )
        table.add_row(
            str(i),
            str(row.get("phase_title", row.get("phase_id", "?"))),
            status_cell,
            elapsed,
            _format_delta(row.get("delta", {})),
        )

    get_console().print(table)


def _render_all_runs(runs: list[_RunGroup], domain: str) -> None:
    print_info(
        f"Found {len(runs)} run(s) in the timeline for "
        f"{mark_sensitive(domain, 'domain')}."
    )
    for index, run in enumerate(runs, start=1):
        _render_run(run, domain, run_index=index)


# ---------------------------------------------------------------------------
# Rendering — diff between two runs
# ---------------------------------------------------------------------------


def _render_diff(runs: list[_RunGroup], domain: str) -> None:
    if len(runs) < 2:
        print_info(
            "Only one run found in the timeline; nothing to diff. "
            "Run `adscan enum` again to capture a second run."
        )
        return

    prev_run = runs[-2]
    curr_run = runs[-1]

    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    header = Text()
    header.append("  Domain   ", style="bold")
    header.append(mark_sensitive(domain, "domain"), style="bold magenta")
    header.append("\n  Previous ", style="bold")
    header.append(prev_run.run_id, style="dim")
    header.append("  ·  ", style="dim")
    header.append(_short_time(prev_run.started_at), style="cyan")
    header.append("\n  Current  ", style="bold")
    header.append(curr_run.run_id, style="dim")
    header.append("  ·  ", style="dim")
    header.append(_short_time(curr_run.started_at), style="cyan")

    get_console().print(
        Panel(
            header,
            title=Text("📊  Timeline Diff", style="bold"),
            title_align="left",
            border_style="magenta",
            padding=(1, 2),
        )
    )

    # Index curr by phase_id; missing/added phases still show.
    curr_by_phase = {row.get("phase_id"): row for row in curr_run.rows}
    prev_phase_ids = {row.get("phase_id") for row in prev_run.rows}

    table = Table(
        show_header=True,
        header_style="bold cyan",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("Phase", style="bold", no_wrap=True)
    table.add_column("Δ Elapsed", justify="right", width=12)
    table.add_column("Δ Nodes", justify="right", width=10)
    table.add_column("Δ Edges", justify="right", width=10)
    table.add_column("Δ Paths", justify="right", width=10)
    table.add_column("Δ Creds", justify="right", width=10)
    table.add_column("Notes")

    for prev in prev_run.rows:
        phase_id = prev.get("phase_id")
        curr = curr_by_phase.get(phase_id)
        if curr is None:
            table.add_row(
                str(prev.get("phase_title", phase_id)),
                "—", "—", "—", "—", "—",
                Text("dropped this run", style="yellow"),
            )
            continue

        elapsed_delta = (curr.get("elapsed_seconds") or 0) - (prev.get("elapsed_seconds") or 0)
        # Compare per-phase contributions (delta), not absolute end_metrics —
        # otherwise leftover graph state from a prior run misleadingly inflates
        # the contribution of unrelated phases like Topology & Trusts.
        prev_delta = prev.get("delta", {}) or {}
        curr_delta = curr.get("delta", {}) or {}

        notes = Text()
        if curr.get("status") == "error" and prev.get("status") == "ok":
            notes.append("regressed: now failing", style="bold red")
        elif curr.get("status") == "ok" and prev.get("status") == "error":
            notes.append("recovered", style="bold green")
        elif curr.get("status") == "error":
            notes.append("still failing", style="red")

        table.add_row(
            str(curr.get("phase_title", phase_id)),
            _format_signed_seconds(elapsed_delta),
            _format_signed_int(
                int(curr_delta.get("nodes") or 0) - int(prev_delta.get("nodes") or 0)
            ),
            _format_signed_int(
                int(curr_delta.get("edges") or 0) - int(prev_delta.get("edges") or 0)
            ),
            _format_signed_int(
                int(curr_delta.get("attack_paths") or 0)
                - int(prev_delta.get("attack_paths") or 0)
            ),
            _format_signed_int(
                int(curr_delta.get("credentials") or 0)
                - int(prev_delta.get("credentials") or 0)
            ),
            notes,
        )

    # Phases new in the current run (added since prev).
    for curr in curr_run.rows:
        if curr.get("phase_id") in prev_phase_ids:
            continue
        table.add_row(
            str(curr.get("phase_title", curr.get("phase_id"))),
            "—", "—", "—", "—", "—",
            Text("new this run", style="green"),
        )

    get_console().print(table)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _format_seconds(value: float) -> str:
    if value < 0.5:
        return f"{value*1000:.0f} ms"
    if value < 60:
        return f"{value:.1f} s"
    minutes, seconds = divmod(int(value), 60)
    return f"{minutes}m {seconds:02d}s"


def _format_signed_seconds(value: float) -> str:
    from rich.text import Text

    text = Text()
    if abs(value) < 0.05:
        text.append("≈ same", style="dim")
        return text  # type: ignore[return-value]
    sign = "+" if value > 0 else "−"
    style = "yellow" if value > 0 else "green"
    text.append(f"{sign}{_format_seconds(abs(value))}", style=style)
    return text  # type: ignore[return-value]


def _format_signed_int(value: int) -> str:
    from rich.text import Text

    text = Text()
    if value == 0:
        text.append("0", style="dim")
        return text  # type: ignore[return-value]
    sign = "+" if value > 0 else "−"
    style = "green" if value > 0 else "red"
    text.append(f"{sign}{abs(value)}", style=style)
    return text  # type: ignore[return-value]


def _format_delta(delta: dict[str, Any]) -> "Any":
    """Render a `+208 nodes  +1019 edges` style chip for a single row."""
    from rich.text import Text

    out = Text()
    chips: list[tuple[int, str, str]] = [
        (int(delta.get("nodes") or 0), "nodes", "blue"),
        (int(delta.get("edges") or 0), "edges", "blue"),
        (int(delta.get("attack_paths") or 0), "paths", "magenta"),
        (int(delta.get("credentials") or 0), "creds", "yellow"),
        (int(delta.get("enabled_users") or 0), "users", "cyan"),
        (int(delta.get("enabled_computers") or 0), "hosts", "cyan"),
    ]
    first = True
    for value, label, colour in chips:
        if value == 0:
            continue
        if not first:
            out.append("  ", style="dim")
        first = False
        sign = "+" if value > 0 else ""
        out.append(f"{sign}{value} ", style=f"bold {colour}")
        out.append(label, style="dim")
    if first:
        out.append("no change", style="dim")
    return out


def _short_time(iso: str) -> str:
    """Return ``YYYY-MM-DD HH:MM:SS`` UTC from an ISO-8601 string."""
    if not iso:
        return "?"
    return iso.replace("T", " ").split("+", 1)[0].split(".", 1)[0]
