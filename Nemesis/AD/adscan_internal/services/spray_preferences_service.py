# adscan_internal/services/spray_preferences_service.py
"""Persistent operator preferences for lockout-free variation spraying.

Stored under ``spray_variations`` in ``~/.adscan/config.json`` (the
same file used by other ADscan operator preferences).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adscan_core.paths import get_adscan_home

PRODUCT_DEFAULT_BUDGET: int = 50_000
_DEFAULT_MAX_TIER: int = 1
_CONFIG_KEY = "spray_variations"


@dataclass(frozen=True)
class SprayVariationPreferences:
    """Operator preferences for the lockout-free variation spray prompt.

    Attributes:
        budget: Maximum number of Kerberos authentications per run.
        auto_accept: When True, skip the interactive prompt entirely and
            use saved values directly.
        max_tier_default: Default variation tier shown in the prompt
            (1, 2, or 3).
    """

    budget: int = PRODUCT_DEFAULT_BUDGET
    auto_accept: bool = False
    max_tier_default: int = _DEFAULT_MAX_TIER


def _default_config_path() -> Path:
    return Path(get_adscan_home()) / "config.json"


def load_spray_variation_preferences(
    *,
    config_path: Path | None = None,
) -> SprayVariationPreferences:
    """Load spray-variation preferences from ``config.json``.

    Returns defaults when the file is missing, unreadable, or lacks the
    ``spray_variations`` key.  Never raises.
    """
    path = config_path or _default_config_path()
    try:
        with open(path, encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return SprayVariationPreferences()

    block = data.get(_CONFIG_KEY)
    if not isinstance(block, dict):
        return SprayVariationPreferences()

    return SprayVariationPreferences(
        budget=int(block.get("budget", PRODUCT_DEFAULT_BUDGET)),
        auto_accept=bool(block.get("auto_accept", False)),
        max_tier_default=int(block.get("max_tier_default", _DEFAULT_MAX_TIER)),
    )


def save_spray_variation_preferences(
    prefs: SprayVariationPreferences,
    *,
    config_path: Path | None = None,
) -> None:
    """Persist spray-variation preferences to ``config.json``.

    Merges into the existing file, preserving all other keys.
    Creates the file if absent.  Never raises (errors are silently
    swallowed so a preference-save failure never interrupts a spray).
    """
    path = config_path or _default_config_path()
    try:
        try:
            with open(path, encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}

        data[_CONFIG_KEY] = {
            "budget": prefs.budget,
            "auto_accept": prefs.auto_accept,
            "max_tier_default": prefs.max_tier_default,
        }
        os.makedirs(path.parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:  # noqa: BLE001
        pass
