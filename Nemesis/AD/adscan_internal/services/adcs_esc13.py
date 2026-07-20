"""Helpers for ADCS ESC13 linked issuance-policy group metadata."""

from __future__ import annotations

import re
from typing import Any


def normalize_esc13_effective_group_name(value: object) -> str | None:
    """Normalize an ESC13 linked group reference into a group lookup name.

    Args:
        value: Group reference from Certipy. It may be a SAM/name, label, or DN.

    Returns:
        A group name suitable for BloodHound lookup and operator display.
    """
    text = str(value or "").strip()
    if not text:
        return None
    dn_match = re.match(r"^\s*CN=([^,]+)", text, flags=re.IGNORECASE)
    if dn_match:
        return (
            dn_match.group(1)
            .replace(r"\,", ",")
            .replace(r"\+", "+")
            .replace(r"\\", "\\")
            .strip()
            or None
        )
    return text


def extract_esc13_effective_group_from_text(value: object) -> str | None:
    """Extract a likely ESC13 linked group name from Certipy text metadata.

    Args:
        value: Certipy vulnerability text or metadata value.

    Returns:
        The linked group name when a recognizable pattern is present.
    """
    text = str(value or "").strip()
    if not text:
        return None
    patterns = (
        r"(?:linked|mapped|authorized|privileged)\s+group\s*[:=]\s*['\"]?([^'\";,.\n]+)",
        r"group\s*['\"]([^'\"]+)['\"]",
        r"group\s*[:=]\s*['\"]?([^'\";,.\n]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if not match:
            continue
        candidate = match.group(1).strip()
        if candidate:
            return normalize_esc13_effective_group_name(candidate)
    return None


def extract_esc13_effective_group_from_template_entry(
    entry: dict[str, Any],
) -> str | None:
    """Return a best-effort linked group for an ESC13 Certipy template entry.

    Args:
        entry: Certipy JSON certificate-template entry.

    Returns:
        The group linked through the issuance policy OID when Certipy exposed it.
    """
    direct_keys = (
        "Linked Group",
        "Linked Groups",
        "Policy Group",
        "Policy Groups",
        "Issuance Policy Group",
        "Issuance Policy Groups",
        "Effective Group",
        "Effective Groups",
    )
    for key in direct_keys:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return normalize_esc13_effective_group_name(value)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    return normalize_esc13_effective_group_name(item)
                if isinstance(item, dict):
                    name = item.get("name") or item.get("group") or item.get("label")
                    if isinstance(name, str) and name.strip():
                        return normalize_esc13_effective_group_name(name)

    vulnerabilities = entry.get("[!] Vulnerabilities")
    if isinstance(vulnerabilities, dict):
        for key, value in vulnerabilities.items():
            if str(key).strip().upper() != "ESC13":
                continue
            extracted = extract_esc13_effective_group_from_text(value)
            if extracted:
                return extracted
    return None
