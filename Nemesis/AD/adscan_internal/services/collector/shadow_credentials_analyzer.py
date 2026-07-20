"""Detect AD objects that already have msDS-KeyCredentialLink entries (shadow credentials)."""

from __future__ import annotations

from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    ShadowCredentialFinding,
)

_SHADOW_CRED_KINDS = {"User", "Computer"}


def analyze_shadow_credentials(
    result: CollectionResult,
) -> list[ShadowCredentialFinding]:
    """Find nodes with existing msDS-KeyCredentialLink entries.

    Also writes a HasShadowCredentials self-loop edge for each finding so that
    intelligence.py can surface them via the tactical findings display.
    """
    findings: list[ShadowCredentialFinding] = []
    for node in result.nodes.values():
        if node.kind not in _SHADOW_CRED_KINDS:
            continue
        key_count = int(node.properties.get("shadow_cred_count") or 0)
        if key_count <= 0:
            continue
        findings.append(
            ShadowCredentialFinding(
                object_id=node.object_id,
                samaccountname=node.samaccountname,
                kind=node.kind,
                distinguished_name=node.distinguished_name,
                key_count=key_count,
            )
        )
        result.add_edge(
            CollectorEdge(
                source_object_id=node.object_id,
                target_object_id=node.object_id,
                relation="HasShadowCredentials",
                source="ldap",
                method="msDS-KeyCredentialLink",
            )
        )
    return findings


__all__ = ["analyze_shadow_credentials"]
