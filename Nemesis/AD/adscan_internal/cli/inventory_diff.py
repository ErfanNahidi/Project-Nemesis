"""CLI handler for the ``inventory_diff`` shell command.

Render a structured diff of the current-vantage inventory for one domain
against a previous snapshot. The handler resolves the "before" snapshot from
``--since`` (relative or HH:MM or ISO-8601), ``--vs <snapshot_id>``, or — by
default — the snapshot immediately preceding the latest one.
"""

from __future__ import annotations

import shlex
from typing import Any

from adscan_core.rich_output import (
    print_error,
    print_info,
    print_instruction,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.inventory_timeline_service import (
    compute_inventory_diff,
    find_snapshot_at_or_before,
    is_timeline_enabled,
    list_snapshots,
    load_snapshot_payload,
    mark_diff_seen,
    parse_since_expression,
    render_inventory_diff,
)


def _parse_args(raw: str) -> tuple[str, str | None, str | None, bool] | None:
    """Return ``(domain, since_expr, vs_id, peek)`` or ``None`` on failure."""

    try:
        tokens = shlex.split(raw or "")
    except ValueError as exc:
        print_error(f"Could not parse inventory_diff arguments: {exc}")
        return None
    if not tokens:
        print_error(
            "Usage: inventory_diff <domain> [--since 1d|2h|30m|HH:MM|<ISO>] "
            "[--vs <snapshot_id>] [--peek]"
        )
        return None

    domain = tokens[0]
    since_expr: str | None = None
    vs_id: str | None = None
    peek = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--since" and index + 1 < len(tokens):
            since_expr = tokens[index + 1]
            index += 2
            continue
        if token == "--vs" and index + 1 < len(tokens):
            vs_id = tokens[index + 1]
            index += 2
            continue
        if token == "--peek":
            peek = True
            index += 1
            continue
        print_error(f"Unrecognized inventory_diff argument: {token}")
        return None
    return domain, since_expr, vs_id, peek


def run_inventory_diff_command(shell: Any, args: str) -> None:
    """Entry point invoked by ``do_inventory_diff`` on the shell."""

    parsed = _parse_args(str(args or ""))
    if parsed is None:
        return
    domain, since_expr, vs_id, peek = parsed

    domains_data = getattr(shell, "domains_data", {}) or {}
    if isinstance(domains_data, dict) and domain not in domains_data:
        print_error(
            f"Domain {mark_sensitive(domain, 'domain')} is not part of the active workspace."
        )
        return

    if not is_timeline_enabled(shell):
        print_info("Inventory timeline is disabled for this workspace type.")
        return

    entries = list_snapshots(shell, domain=domain)
    if not entries:
        print_info(
            f"No inventory snapshots recorded yet for {mark_sensitive(domain, 'domain')}."
        )
        print_instruction(
            f"Run `refresh_inventory {domain}` to capture the first snapshot."
        )
        return

    after_entry = entries[-1]
    if len(entries) == 1 and not vs_id and not since_expr:
        print_info(
            f"Only one snapshot exists for {mark_sensitive(domain, 'domain')}; nothing to diff."
        )
        print_instruction(
            f"Run `refresh_inventory {domain}` to capture additional snapshots over time."
        )
        return

    before_entry = None
    if vs_id:
        before_entry = next((item for item in entries if item.id == vs_id), None)
        if before_entry is None:
            print_error(
                f"No snapshot with id {mark_sensitive(vs_id, 'detail')} exists for "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return
    elif since_expr:
        when = parse_since_expression(since_expr)
        if when is None:
            print_error(
                f"Could not parse --since value: {mark_sensitive(since_expr, 'detail')}"
            )
            return
        before_entry = find_snapshot_at_or_before(shell, domain=domain, when=when)
        if before_entry is None:
            print_info(
                f"No snapshot exists at or before "
                f"{mark_sensitive(since_expr, 'detail')} for "
                f"{mark_sensitive(domain, 'domain')}; using the oldest available snapshot."
            )
            before_entry = entries[0] if entries[0].id != after_entry.id else None
    else:
        before_entry = entries[-2] if len(entries) >= 2 else None

    after_payload = load_snapshot_payload(
        shell, domain=domain, snapshot_id=after_entry.id
    )
    if not isinstance(after_payload, dict):
        print_error(
            f"Could not load snapshot payload {mark_sensitive(after_entry.id, 'detail')}."
        )
        return
    before_payload = (
        load_snapshot_payload(shell, domain=domain, snapshot_id=before_entry.id)
        if before_entry is not None
        else None
    )

    diff = compute_inventory_diff(
        domain=domain,
        before_payload=before_payload,
        before_id=before_entry.id if before_entry else None,
        before_at=before_entry.at if before_entry else None,
        after_payload=after_payload,
        after_id=after_entry.id,
        after_at=after_entry.at,
    )
    title = f"Inventory diff for {domain}"
    render_inventory_diff(shell, diff=diff, title=title)
    if not peek:
        mark_diff_seen(shell, domain=domain, snapshot_id=after_entry.id)


__all__ = ["run_inventory_diff_command"]
