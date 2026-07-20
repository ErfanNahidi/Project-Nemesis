from __future__ import annotations

import time
from typing import Any

STALE_DAYS_DEFAULT: int = 180
_WIN_EPOCH_OFFSET = 116444736000000000


def _props(node: dict[str, Any]) -> dict[str, Any]:
    return node.get("properties") or {}


def is_enabled(node: dict[str, Any]) -> bool:
    v = _props(node).get("enabled")
    return bool(v) if v is not None else True


def domain_matches(node: dict[str, Any], domain: str) -> bool:
    return str(_props(node).get("domain") or "").upper() == domain.upper()


def has_flag(node: dict[str, Any], flag: str) -> bool:
    return bool(_props(node).get(flag))


def is_stale(node: dict[str, Any], stale_days: int = STALE_DAYS_DEFAULT) -> bool:
    last_logon = _props(node).get("lastlogon")
    if not last_logon:
        return False
    try:
        filetime = int(last_logon)
        if filetime == 0:
            return True
        epoch_s = (filetime - _WIN_EPOCH_OFFSET) * 100 / 1_000_000_000
        return epoch_s < time.time() - stale_days * 86400
    except (TypeError, ValueError):
        return False
