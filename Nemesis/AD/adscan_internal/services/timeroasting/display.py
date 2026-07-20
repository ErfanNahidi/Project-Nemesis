"""Premium Rich CLI output for native Timeroasting.

Aesthetic: "Dead Clock" — industrial precision, amber urgency on terminal dark.
Every element earns its space: no decorative noise, maximum signal.

Layout:
  1. Pre-flight panel   — target, candidate count, rate
  2. Live progress bar  — ticking packets, captured count, pkt/s
  3. Results table      — per-hash row with tier, RID, truncated hash
  4. Hashcat advisory   — mode 31300, exact command, crack-speed note
"""

from __future__ import annotations

import time
from collections.abc import Callable

from adscan_core.tui import LiveSession, LiveSessionConfig
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from adscan_internal.rich_output import (
    mark_sensitive,
    print_panel,
    print_success,
    print_warning,
)
from adscan_internal.services.timeroasting.config import (
    TimeroastConfig,
    TimeroastHashResult,
    TimeroastRunResult,
)
from adscan_internal.services.timeroasting.runner import stream_timeroast

# Hashcat mode for MS-SNTP hashes
_HASHCAT_MODE = "31300"

# Tier display helpers
_TIER_STYLE: dict[str, str] = {
    "Tier Zero": "bold red",
    "High Value": "bold yellow",
    "Standard": "dim white",
}
_TIER_ZERO_LABEL = "[bold red]Tier Zero[/bold red]"
_HIGH_VALUE_LABEL = "[bold yellow]High Value[/bold yellow]"
_STANDARD_LABEL = "[dim]Standard[/dim]"


def _tier_label(value_tier: str) -> str:
    if value_tier == "Tier Zero":
        return _TIER_ZERO_LABEL
    if value_tier == "High Value":
        return _HIGH_VALUE_LABEL
    return _STANDARD_LABEL


def print_timeroast_preflight(
    *,
    dc_ip: str,
    domain: str,
    candidate_count: int,
    rate: int,
    timeout: float,
) -> None:
    """Pre-flight panel shown before roasting begins."""
    marked_dc = mark_sensitive(dc_ip, "ip")
    marked_domain = mark_sensitive(domain, "domain")

    lines = [
        f"[dim]Target DC[/dim]       [cyan]{marked_dc}[/cyan]  [dim]UDP/123[/dim]",
        f"[dim]Domain[/dim]          [cyan]{marked_domain}[/cyan]",
        f"[dim]Candidates[/dim]      [bold amber]{candidate_count}[/bold amber] machine account(s)",
        f"[dim]Rate[/dim]            {rate} packets/sec",
        f"[dim]Timeout[/dim]         {timeout:.0f}s after last response",
        "",
        "[dim]Protocol:[/dim] MS-SNTP (NTP/UDP) — DC signs response with RC4 key of each machine account.",
        "[dim]Crack:[/dim]    hashcat -m 31300  —  RC4/NT hash, cracks in minutes on consumer GPU.",
    ]
    print_panel(
        "\n".join(lines),
        title="[bold]Timeroasting[/bold]  [dim]MS-SNTP NTP hash capture[/dim]",
        border_style="yellow",
    )


async def run_timeroast_with_display(
    config: TimeroastConfig,
    *,
    candidates_by_rid: dict[int, object] | None = None,
    on_hash: Callable[[TimeroastHashResult], None] | None = None,
) -> TimeroastRunResult:
    """Run timeroasting with a live Rich progress display.

    Streams hashes as they arrive from the DC, updates a live progress bar,
    and collects all results into TimeroastRunResult.

    candidates_by_rid: optional map of RID→TimeroastCandidate for tier display.
    on_hash: optional callback called synchronously for each captured hash.
    """
    result = TimeroastRunResult(rids_attempted=len(config.rids))
    captured_rows: list[tuple[TimeroastHashResult, object | None]] = []

    total = len(config.rids)
    rate = config.rate

    progress = Progress(
        SpinnerColumn(spinner_name="dots", style="yellow"),
        TextColumn("[bold yellow]{task.description}[/bold yellow]"),
        BarColumn(bar_width=32, style="yellow", complete_style="bright_yellow"),
        MofNCompleteColumn(),
        TextColumn("[dim]·[/dim]"),
        TextColumn("[green]{task.fields[captured]}[/green][dim] captured[/dim]"),
        TextColumn("[dim]·[/dim]"),
        TextColumn("[dim]{task.fields[rate_str]}[/dim]"),
        TimeElapsedColumn(),
        expand=False,
    )

    task: TaskID = progress.add_task(
        "NTP probing",
        total=total,
        captured=0,
        rate_str=f"{rate} pkt/s",
    )

    sent = 0
    start_ts = time.monotonic()

    # alt_screen=False + transient=True: the progress bar stays inline
    # and self-erases when the session exits, matching the previous
    # behaviour of the lone ``rich.live.Live(progress, transient=True)``.
    _live_cfg = LiveSessionConfig(
        refresh_per_second=10,
        alt_screen=False,
        transient=True,
    )
    with LiveSession(progress, config=_live_cfg):
        try:
            async for hash_result in stream_timeroast(config):
                # Estimate packets sent based on elapsed time and rate
                elapsed = time.monotonic() - start_ts
                sent = min(int(elapsed * rate), total)
                progress.update(
                    task,
                    completed=sent,
                    captured=result.captured_count + 1,
                    rate_str=f"{rate} pkt/s",
                )

                result.hashes.append(hash_result)
                result.rids_responded += 1
                candidate = (candidates_by_rid or {}).get(hash_result.rid)
                captured_rows.append((hash_result, candidate))

                if on_hash:
                    on_hash(hash_result)

        except PermissionError as exc:
            result.error = (
                f"UDP socket permission denied — need root or CAP_NET_RAW: {exc}"
            )
        except OSError as exc:
            result.error = f"Network error reaching {config.dc_ip}:123 — {exc}"
        except Exception as exc:
            result.error = f"Timeroast failed: {exc}"

        # Final progress tick
        elapsed = time.monotonic() - start_ts
        progress.update(task, completed=total, rate_str=f"{elapsed:.1f}s elapsed")

    return result


def print_timeroast_results(
    result: TimeroastRunResult,
    *,
    candidates_by_rid: dict[int, object] | None = None,
    hash_file_path: str | None = None,
) -> None:
    """Print results table + hashcat advisory after roasting completes."""
    if result.error:
        from adscan_internal.rich_output import print_error

        print_error(f"Timeroast error: {result.error}")
        return

    if not result.hashes:
        print_warning(
            "No hashes captured. The DC did not respond to any NTP probe. "
            "Verify UDP/123 is reachable and the RIDs match existing accounts."
        )
        return

    _print_hash_table(result.hashes, candidates_by_rid=candidates_by_rid)
    _print_hashcat_advisory(
        captured=result.captured_count,
        hash_file_path=hash_file_path,
    )

    print_success(
        f"Timeroast complete — {result.captured_count} hash(es) captured "
        f"from {result.rids_attempted} candidate(s)."
    )


def _print_hash_table(
    hashes: list[TimeroastHashResult],
    *,
    candidates_by_rid: dict[int, object] | None = None,
) -> None:
    """Dense results table: Computer | Tier | RID | Hash (truncated)."""
    table = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        box=_compact_box(),
        padding=(0, 1),
        title="[bold yellow]⏱ Timeroast — Captured Hashes[/bold yellow]",
        title_style="",
    )
    table.add_column("Computer", style="white", no_wrap=True)
    table.add_column("Tier", no_wrap=True, justify="center")
    table.add_column("RID", style="magenta", justify="right", no_wrap=True)
    table.add_column("Hash", style="dim cyan", overflow="fold")

    cmap = candidates_by_rid or {}

    for h in hashes:
        candidate = cmap.get(h.rid)

        if candidate is not None:
            computer = mark_sensitive(
                getattr(candidate, "fqdn", "") or str(h.rid), "hostname"
            )
            tier = _tier_label(getattr(candidate, "value_tier", "Standard"))
        else:
            computer = f"RID:{h.rid}"
            tier = "[dim]—[/dim]"

        # Truncate hash for display: show first 16 chars of hash_hex
        hash_preview = f"$sntp-ms${h.hash_hex[:16]}…"

        table.add_row(computer, tier, str(h.rid), hash_preview)

    from adscan_internal.rich_output import print_table

    print_table(table)


def _print_hashcat_advisory(
    *,
    captured: int,
    hash_file_path: str | None = None,
) -> None:
    """Advisory panel with hashcat command and crack-speed context."""
    file_arg = (
        mark_sensitive(hash_file_path, "path")
        if hash_file_path
        else "[dim]<hash_file>[/dim]"
    )
    cmd = (
        f"[bold white]hashcat[/bold white] "
        f"[cyan]-m {_HASHCAT_MODE}[/cyan] "
        f"[dim]--username[/dim] "
        f"{file_arg} "
        f"[dim]wordlist.txt[/dim]"
    )

    lines = [
        f"[bold yellow]{captured} hash(es)[/bold yellow] ready for offline cracking.",
        "",
        f"  {cmd}",
        "",
        "[dim]Mode 31300 = MS-SNTP / Windows NTP Authenticator[/dim]",
        "[dim]RC4 (NT hash) — cracks in minutes on consumer GPU with common wordlists.[/dim]",
        "[dim]Default machine passwords (hostname, hostname$, short variations) often succeed.[/dim]",
    ]

    print_panel(
        "\n".join(lines),
        title="[bold]Hashcat[/bold]  [dim]mode 31300[/dim]",
        border_style="yellow",
    )


def _compact_box():
    """Minimal box style — horizontal rules only, no vertical chrome."""
    from rich.box import Box

    return Box(
        "    \n ── \n    \n    \n ── \n    \n    \n    \n",
    )
