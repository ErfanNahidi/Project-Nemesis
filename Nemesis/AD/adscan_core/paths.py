"""Path helpers shared across launcher and runtime.

These helpers resolve user-owned directories under ADSCAN_HOME (sudo-safe),
matching the established project convention:
- Base: `~/.adscan` (or ADSCAN_HOME override)
- Subdirs: workspaces/, logs/, run/, state/
"""

from __future__ import annotations

import os
from pathlib import Path

from adscan_core.path_utils import (
    expand_effective_user_path,
    get_adscan_home,
    get_adscan_state_dir,
)


def get_adscan_home_dir() -> Path:
    """Return the ADscan home directory (sudo-safe)."""
    return get_adscan_home()


def get_workspaces_dir() -> Path:
    return get_adscan_home_dir() / "workspaces"


def get_logs_dir() -> Path:
    return get_adscan_home_dir() / "logs"


def get_run_dir() -> Path:
    return get_adscan_home_dir() / "run"


def get_sessions_dir() -> Path:
    """Per-launcher session directories under ``run/sessions/``.

    Each launcher process owns a unique sub-directory here that holds its
    private host-helper socket. The whole sub-directory is bind-mounted
    into the container at ``/run/adscan`` so multiple launchers never
    fight over a fixed socket path.
    """
    return get_run_dir() / "sessions"


def get_locks_dir() -> Path:
    """File-lock directory for per-workspace / install / resolver locks."""
    return get_run_dir() / "locks"


def get_resolver_locks_dir() -> Path:
    """Lock directory for atomic loopback-IP claims (in-container Unbound)."""
    return get_locks_dir() / "resolvers"


def get_state_dir() -> Path:
    explicit = os.getenv("ADSCAN_STATE_DIR", "").strip()
    if explicit:
        return Path(expand_effective_user_path(explicit))
    return get_adscan_state_dir()
