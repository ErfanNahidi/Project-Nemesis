"""ESC11 — ICPR RPC accepts plaintext requests (NTLM relay surface).

Probe-driven: needs ``enforce_encrypt_icertrequest`` from CA registry. Without
probe data no edges are emitted.

The edge source is the Domain Users group SID (``{domain_sid}-513``) passed by
the collector, so the edge resolves to a real graph node and surfaces correctly
in tactical findings.  If ``domain_users_sid`` is unavailable we skip emission
rather than using a synthetic placeholder that cannot be resolved by the graph
display layer.
"""

from __future__ import annotations

from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc11(
    *,
    ca_node: CollectorNode,
    domain: str,
    enforce_encrypt_icertrequest: bool = False,
    domain_users_sid: str | None = None,
) -> list[CollectorEdge]:
    if enforce_encrypt_icertrequest:
        return []
    if ca_node.kind != "EnterpriseCA":
        return []

    source_oid = domain_users_sid
    if not source_oid:
        return []

    return [
        CollectorEdge(
            source_object_id=source_oid,
            target_object_id=ca_node.object_id,
            relation="ADCSESC11",
            source="adcs_detector",
            method="adcs",
            notes={"requires": "domain_credentials_with_ntlm"},
        )
    ]
