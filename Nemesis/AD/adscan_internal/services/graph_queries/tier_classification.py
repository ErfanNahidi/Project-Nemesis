from __future__ import annotations

from typing import Any

from adscan_internal.services.privileged_group_classifier import is_tier_zero_target_sid


def _props(node: dict[str, Any]) -> dict[str, Any]:
    return node.get("properties") or {}


def is_tier0(node: dict[str, Any]) -> bool:
    if node.get("isTierZero"):
        return True
    if _props(node).get("isTierZero"):
        return True
    tags = _props(node).get("system_tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return any(str(t).strip().lower() == "admin_tier_0" for t in tags)


def is_high_value(node: dict[str, Any]) -> bool:
    return bool(node.get("highvalue") or _props(node).get("highvalue"))


def is_tier0_or_high_value(node: dict[str, Any]) -> bool:
    return is_tier0(node) or is_high_value(node)


def classify_tier0_by_rid(sid: str) -> bool:
    return is_tier_zero_target_sid(sid)
