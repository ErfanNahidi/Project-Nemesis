"""Tier (LITE vs PRO) detection — single source of truth.

ADscan ships in two tiers:

- **LITE**: open-source community engine. ``adscan_internal.pro`` is absent.
- **PRO**: closed-source. Adds the client deliverable kit.

This module exposes a tiny, dependency-light API that every other module
should consult instead of importing ``adscan_internal.pro`` directly:

- :func:`is_pro` — True when the PRO package is importable.
- :func:`tier_name` — "PRO" or "LITE".

Both calls are cached after the first lookup so callers do not pay an
import-resolution cost on every render.

Compatibility note:
    LITE/runtime code MUST NOT import ``adscan_internal.pro`` directly.
    Use :func:`is_pro` instead — the import is performed defensively here
    and any failure is treated as "LITE".
"""

from __future__ import annotations

from functools import lru_cache


@lru_cache(maxsize=1)
def is_pro() -> bool:
    """Return ``True`` when the PRO runtime is available.

    Detection is by import probe: if ``adscan_internal.pro`` can be
    imported, we are PRO. Any failure (ImportError, ModuleNotFoundError,
    or any unexpected error during import) yields ``False`` — the LITE
    default is always safe.

    The result is cached for the lifetime of the process. Tests that
    need to flip the value must clear the cache via
    ``is_pro.cache_clear()``.
    """
    try:
        import importlib

        importlib.import_module("adscan_internal.pro")
        return True
    except Exception:  # noqa: BLE001 — any failure means "not PRO"
        return False


@lru_cache(maxsize=1)
def tier_name() -> str:
    """Return ``"PRO"`` or ``"LITE"`` based on :func:`is_pro`."""
    return "PRO" if is_pro() else "LITE"


__all__ = ("is_pro", "tier_name")
