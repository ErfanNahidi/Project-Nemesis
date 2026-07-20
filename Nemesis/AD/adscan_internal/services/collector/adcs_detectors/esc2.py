"""ESC2 — Any Purpose EKU (or no EKU) + low-priv enroll + no manager approval."""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._common import (
    get_enroll_principal_sids,
    make_adcs_edge,
    template_eku_list,
    template_int_property,
)
from adscan_internal.services.collector.adcs_detectors.constants import (
    EKU_ANY_PURPOSE,
    PEND_ALL_REQUESTS,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc2(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
) -> list[CollectorEdge]:
    """Return ADCSESC2 edges for a vulnerable template, else empty list.

    Conditions:
      * Template kind is CertTemplate
      * EKU list contains "2.5.29.37.0" (Any Purpose) OR is empty
      * msPKI-Enrollment-Flag does NOT have PEND_ALL_REQUESTS
      * msPKI-RA-Signature == 0
      * At least one principal holds an enrollment-capable ACL right
    """
    if template_node.kind != "CertTemplate":
        return []

    ekus = template_eku_list(template_node)
    has_any_purpose = (not ekus) or (EKU_ANY_PURPOSE in ekus)
    if not has_any_purpose:
        return []

    enrollment_flag = template_int_property(
        template_node, "mspki_enrollment_flag", "msPKI-Enrollment-Flag"
    )
    if enrollment_flag & PEND_ALL_REQUESTS:
        return []

    ra_signature = template_int_property(
        template_node, "mspki_ra_signature", "msPKI-RA-Signature"
    )
    if ra_signature > 0:
        return []

    return [
        make_adcs_edge(principal_sid=sid, template_node=template_node, esc="2")
        for sid in get_enroll_principal_sids(template_acl_edges)
    ]
