"""ESC7 — non-Tier0 principal has CA management rights on an Enterprise CA.

Native ACLParser collapses ManageCA / ManageCertificates extended rights into
``GenericAll`` / ``WriteDACL`` / ``WriteOwner`` / ``AllExtendedRights`` — all
equivalent or stronger than the documented ESC7 rights. We treat any such
principal as ESC7-vulnerable.
"""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._common import (
    ca_acl_edges_with_management,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc7(
    *,
    ca_node: CollectorNode,
    ca_acl_edges: list[CollectorEdge],
    domain: str,
) -> list[CollectorEdge]:
    if ca_node.kind != "EnterpriseCA":
        return []
    edges: list[CollectorEdge] = []
    seen: set[str] = set()
    for acl_edge in ca_acl_edges_with_management(ca_acl_edges):
        sid = acl_edge.source_object_id
        if not sid or sid in seen:
            continue
        seen.add(sid)
        edges.append(
            CollectorEdge(
                source_object_id=sid,
                target_object_id=ca_node.object_id,
                relation="ADCSESC7",
                source="adcs_detector",
                method="adcs",
            )
        )
    return edges
