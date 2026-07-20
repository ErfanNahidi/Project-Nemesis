"""ESC6 — CA EDITF_ATTRIBUTESUBJECTALTNAME2 + low-priv enroll on auth template.

Requires probe-derived ``ca_editf_san2_enabled`` (from CA registry). Without
probe data the detector emits no edges so missing inputs never produce false
positives.
"""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._common import (
    get_enroll_principal_sids,
    make_adcs_edge,
    template_has_authentication_eku,
    template_int_property,
)
from adscan_internal.services.collector.adcs_detectors.constants import (
    PEND_ALL_REQUESTS,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc6(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
    ca_editf_san2_enabled: bool = False,
) -> list[CollectorEdge]:
    if not ca_editf_san2_enabled:
        return []
    if template_node.kind != "CertTemplate":
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
    if not template_has_authentication_eku(template_node):
        return []
    return [
        make_adcs_edge(principal_sid=sid, template_node=template_node, esc="6")
        for sid in get_enroll_principal_sids(template_acl_edges)
    ]
