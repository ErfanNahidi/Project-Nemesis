"""ESC14 — weak SAN-based mapping on auth template + low-priv enroll.

Per-user ``altSecurityIdentities`` write analysis is deferred (requires per-
property ACL granularity which the native ACLParser collapses to Generic*).
This phase implements the template-side half: any auth template that requires
SAN-based UPN/Email mapping, has no manager approval, and exposes enrollment
to a non-Tier0 principal becomes an ESC14 source.
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
    SUBJECT_ALT_REQUIRE_EMAIL,
    SUBJECT_ALT_REQUIRE_UPN,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc14(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
) -> list[CollectorEdge]:
    if template_node.kind != "CertTemplate":
        return []
    name_flag = template_int_property(
        template_node,
        "mspki_certificate_name_flag",
        "msPKI-Certificate-Name-Flag",
    )
    if not (name_flag & (SUBJECT_ALT_REQUIRE_UPN | SUBJECT_ALT_REQUIRE_EMAIL)):
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
        make_adcs_edge(principal_sid=sid, template_node=template_node, esc="14")
        for sid in get_enroll_principal_sids(template_acl_edges)
    ]
