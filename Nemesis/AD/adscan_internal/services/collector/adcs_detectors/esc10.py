"""ESC10 — weak certificate mapping on DC + low-priv enroll on auth template.

Probe-driven: needs ``cert_mapping_methods`` and
``strong_cert_binding_enforced`` from DC registry probes. Without probe data
no edges are emitted.
"""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._common import (
    get_enroll_principal_sids,
    make_adcs_edge,
    template_has_authentication_eku,
    template_int_property,
)
from adscan_internal.services.collector.adcs_detectors.constants import (
    CERT_MAPPING_UPN,
    PEND_ALL_REQUESTS,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc10(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
    cert_mapping_methods: int = 0,
    strong_cert_binding_enforced: bool = False,
) -> list[CollectorEdge]:
    if not (cert_mapping_methods & CERT_MAPPING_UPN):
        return []
    if strong_cert_binding_enforced:
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
        make_adcs_edge(principal_sid=sid, template_node=template_node, esc="10")
        for sid in get_enroll_principal_sids(template_acl_edges)
    ]
