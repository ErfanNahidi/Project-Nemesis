"""ESC13 — template with issuance policy OID linked to a group + low-priv enroll.

Each issuance-policy OID is resolved against the forest-wide
``msDS-OIDToGroupLink`` map collected from ``msPKI-Enterprise-Oid`` objects.
When a template carries at least one OID linked to a group, the detector
emits an ``ADCSESC13`` edge with ``linked_group_dn`` populated so the
persistence layer can re-emit a compromise-centric edge to that group.

When no OID resolves to a group (older snapshots or environments without
``msDS-OIDToGroupLink`` set), the detector still emits the raw edge with
``requires_oid_resolution=True`` so operators see the misconfiguration.
"""

from __future__ import annotations

from adscan_core.rich_output import print_info_debug

from adscan_internal.services.collector.adcs_detectors._common import (
    get_enroll_principal_sids,
    template_certificate_policies,
    template_int_property,
)
from adscan_internal.services.collector.adcs_detectors.constants import (
    PEND_ALL_REQUESTS,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc13(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
    oid_to_group_dn: dict[str, str] | None = None,
) -> list[CollectorEdge]:
    if template_node.kind != "CertTemplate":
        return []
    policies = template_certificate_policies(template_node)
    if not policies:
        return []
    if (
        template_int_property(
            template_node, "mspki_enrollment_flag", "msPKI-Enrollment-Flag"
        )
        & PEND_ALL_REQUESTS
    ):
        return []
    if (
        template_int_property(template_node, "mspki_ra_signature", "msPKI-RA-Signature")
        > 0
    ):
        return []

    oid_map = oid_to_group_dn or {}
    linked_groups: list[dict[str, str]] = []
    for policy in policies:
        group_dn = oid_map.get(str(policy).strip())
        if group_dn:
            linked_groups.append({"oid": str(policy), "group_dn": group_dn})

    edges: list[CollectorEdge] = []
    for sid in get_enroll_principal_sids(template_acl_edges):
        notes: dict[str, object] = {"issuance_policies": list(policies)}
        if linked_groups:
            # First match is sufficient — one ESC13 edge per template/source.
            notes["linked_group_dn"] = linked_groups[0]["group_dn"]
            notes["linked_oid"] = linked_groups[0]["oid"]
            notes["linked_groups"] = list(linked_groups)
        else:
            notes["requires_oid_resolution"] = True
            unresolved = [str(p) for p in policies]
            print_info_debug(
                f"[esc13-detector] template {template_node.name!r}: "
                f"OID(s) {unresolved} not in oid_to_group_dn map — "
                f"emitting requires_oid_resolution edge (no group link found)"
            )
        edges.append(
            CollectorEdge(
                source_object_id=sid,
                target_object_id=template_node.object_id,
                relation="ADCSESC13",
                source="adcs_detector",
                method="adcs",
                notes=notes,
            )
        )
    return edges
