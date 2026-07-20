"""Scanner registry — name → factory.

Why a registry instead of importing scanners directly:

* Methods (truncation_bisect, toggle_ablation) and the CLI runner take
  a scanner *name* (``"defender"``, ``"crowdstrike"``…) and ask the
  registry for an instance.  Adding a new EDR is then a one-file change
  (``scanners/<edr>.py``) plus a single :func:`register` call — no caller
  ever imports the concrete class.
* Catalogs and run records reference scanners by name; the registry
  guarantees the name → implementation mapping is the single source of
  truth across the framework.

Factories receive a free-form ``config`` dict (parsed from CLI args or
catalog YAML) and a :class:`Workspace` for log capture, and return a
:class:`Scanner`.  Keeping the factory contract loose lets each scanner
declare its own auth/connection schema without leaking through this module.
"""

from __future__ import annotations

from typing import Any, Callable, Dict

from avlab.core.workspace import Workspace
from avlab.scanners.base import Scanner

ScannerFactory = Callable[[Dict[str, Any], Workspace], Scanner]

_REGISTRY: Dict[str, ScannerFactory] = {}


def register(name: str, factory: ScannerFactory) -> None:
    """Add a scanner factory under ``name``. Idempotent on re-registration."""
    _REGISTRY[name] = factory


def create(name: str, config: Dict[str, Any], workspace: Workspace) -> Scanner:
    """Build a configured scanner instance, or raise ``KeyError``."""
    try:
        factory = _REGISTRY[name]
    except KeyError as exc:
        known = ", ".join(sorted(_REGISTRY)) or "(none registered)"
        raise KeyError(f"unknown scanner {name!r}; known: {known}") from exc
    return factory(config, workspace)


def known_scanners() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


# ---------------------------------------------------------------------------
# Built-in registrations
# ---------------------------------------------------------------------------


def _defender_factory(config: Dict[str, Any], workspace: Workspace) -> Scanner:
    from avlab.scanners.defender import DefenderScanner, DefenderTarget, ScanMode

    raw_mode = config.get("scan_mode", "rtp").lower()
    mode = ScanMode.RTP if raw_mode == "rtp" else ScanMode.MPCMDRUN
    target = DefenderTarget(
        host=config["host"],
        domain=config["domain"],
        username=config["username"],
        password=config["password"],
        port=int(config.get("port", 1433)),
        remote_dir=config.get("remote_dir", r"C:\avlab"),
        scan_mode=mode,
        rtp_wait_seconds=int(config.get("rtp_wait_seconds", 3)),
        smb_username=config.get("smb_username", ""),
        smb_password=config.get("smb_password", ""),
    )
    return DefenderScanner(target=target, workspace=workspace)


register("defender", _defender_factory)


__all__ = ["register", "create", "known_scanners", "ScannerFactory"]
