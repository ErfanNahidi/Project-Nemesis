"""ESC9 — CT_FLAG_NO_SECURITY_EXTENSION + ClientAuth EKU + low-priv enroll."""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._common import (
    get_enroll_principal_sids,
    has_client_auth_or_no_eku,
    make_adcs_edge,
    template_eku_list,
    template_int_property,
)
from adscan_internal.services.collector.adcs_detectors.constants import (
    NO_SECURITY_EXTENSION,
    PEND_ALL_REQUESTS,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc9(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
) -> list[CollectorEdge]:
    """Return ADCSESC9 edges when the template enables UPN/DNS spoof on weak binding.

    Conditions:
      * Template kind is CertTemplate
      * msPKI-Enrollment-Flag has CT_FLAG_NO_SECURITY_EXTENSION bit (0x80000)
      * msPKI-Enrollment-Flag does NOT have PEND_ALL_REQUESTS
      * msPKI-RA-Signature == 0
      * EKU grants client auth (or empty / any purpose)
      * At least one principal holds an enrollment-capable ACL right
    """
    if template_node.kind != "CertTemplate":
        return []

    enrollment_flag = template_int_property(
        template_node, "mspki_enrollment_flag", "msPKI-Enrollment-Flag"
    )
    if not (enrollment_flag & NO_SECURITY_EXTENSION):
        return []
    if enrollment_flag & PEND_ALL_REQUESTS:
        return []

    ra_signature = template_int_property(
        template_node, "mspki_ra_signature", "msPKI-RA-Signature"
    )
    if ra_signature > 0:
        return []

    if not has_client_auth_or_no_eku(template_eku_list(template_node)):
        return []

    return [
        make_adcs_edge(principal_sid=sid, template_node=template_node, esc="9")
        for sid in get_enroll_principal_sids(template_acl_edges)
    ]
