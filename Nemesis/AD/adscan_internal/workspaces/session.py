from __future__ import annotations

from typing import Any

from adscan_internal.workspaces.manager import resolve_workspace_paths


def activate_workspace(shell: Any, *, workspaces_dir: str, workspace_name: str) -> str:
    """Set the active workspace fields on the shell.

    This helper only mutates in-memory state. It does not perform any I/O or
    call `load_workspace_data()` so the CLI can decide when to apply side-effects.

    Args:
        shell: CLI shell instance (adscan.PentestShell).
        workspaces_dir: Root directory containing all workspaces.
        workspace_name: Workspace folder name.

    Returns:
        Absolute workspace directory path.
    """
    paths = resolve_workspace_paths(workspaces_dir, workspace_name)
    shell.current_workspace = workspace_name
    shell.current_workspace_dir = paths.root

    # Initialise the environment change ledger for the newly activated workspace.
    # Wrapped in a broad except so a ledger failure never blocks workspace activation.
    try:
        from adscan_internal.services.environment_change_ledger import EnvironmentChangeLedger

        shell.environment_change_ledger = EnvironmentChangeLedger(paths.root)
    except Exception:  # noqa: BLE001 — best-effort, must not break activation
        shell.environment_change_ledger = None

    shell.acl_cleanup_actions: list[dict] = []

    return paths.root


__all__ = [
    "activate_workspace",
]
