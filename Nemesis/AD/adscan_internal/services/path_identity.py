"""Canonical attack-path identity helpers.

This module is the single source of truth for **identifying** an attack
path independently of how it is rendered. It computes the stable
``signature`` (string) and the public-facing short ``id`` (``P-XXXXXXXX``)
that every surface — CLI, report, web, post-ex sidecar — must use to
refer to the same path.

History: these helpers used to live in
``adscan_internal/pro/reporting/attack_path_narratives``. They were
moved here in Phase 6 because identity is a *service* concern that a
post-exploitation orchestrator must consume without dragging the entire
PRO reporting stack. The narratives module re-exports the names for
backward compatibility — do not add new identity logic there.
"""

from __future__ import annotations

import hashlib
from typing import Any


def attack_path_signature(path: dict[str, Any]) -> str:
    """Build a stable signature for an attack path.

    The signature is order-sensitive (nodes + relations) so two paths
    that touch the same set of objects via different routes hash to
    distinct identifiers. We deliberately fall back to ``source->target``
    or the path title when ``nodes`` is missing so legacy summaries from
    older materializer runs still produce a stable id.
    """
    nodes = path.get("nodes") if isinstance(path.get("nodes"), list) else []
    relations = path.get("relations") if isinstance(path.get("relations"), list) else []
    node_sig = ",".join(str(node) for node in nodes if node)
    rel_sig = ",".join(str(rel) for rel in relations if rel)
    if not node_sig:
        source = path.get("source") or ""
        target = path.get("target") or ""
        if source and target:
            node_sig = f"{source}->{target}"
        else:
            node_sig = str(path.get("title") or "Attack Path")
    return f"{node_sig}|{rel_sig}"


def attack_path_id(path: dict[str, Any]) -> str:
    """Return a stable short id (``P-XXXXXXXX``) for an attack path."""
    signature = attack_path_signature(path)
    digest = hashlib.sha1(  # noqa: S324 — non-security identity hash
        signature.encode("utf-8"), usedforsecurity=False
    ).hexdigest()
    return f"P-{digest[:8].upper()}"


__all__ = ["attack_path_id", "attack_path_signature"]
