"""ESC3 — Enrollment Agent template (agent half + target half)."""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._common import (
    get_enroll_principal_sids,
    has_client_auth_or_no_eku,
    make_adcs_edge,
    template_application_policies,
    template_eku_list,
    template_int_property,
)
from adscan_internal.services.collector.adcs_detectors.constants import (
    EKU_CERT_REQUEST_AGENT,
    PEND_ALL_REQUESTS,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc3_agent(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
) -> list[CollectorEdge]:
    """ESC3 agent template: Cert Request Agent EKU + low-priv enroll + no approval."""
    if template_node.kind != "CertTemplate":
        return []

    ekus = template_eku_list(template_node)
    if EKU_CERT_REQUEST_AGENT not in ekus:
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
        make_adcs_edge(principal_sid=sid, template_node=template_node, esc="3")
        for sid in get_enroll_principal_sids(template_acl_edges)
    ]


def detect_esc3_target(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
) -> list[CollectorEdge]:
    """ESC3 target template: ClientAuth EKU + accepts EnrollOnBehalfOf chain.

    Conditions:
      * Has client auth EKU (or no EKU / any purpose)
      * No manager approval (PEND_ALL_REQUESTS not set)
      * msPKI-RA-Signature >= 1 (one or more co-signatures required)
      * msPKI-Certificate-Application-Policy includes Cert Request Agent OID
        (or template is schema V1, which implicitly accepts agent requests)
      * At least one principal can enroll
    """
    if template_node.kind != "CertTemplate":
        return []

    if not has_client_auth_or_no_eku(template_eku_list(template_node)):
        return []

    enrollment_flag = template_int_property(
        template_node, "mspki_enrollment_flag", "msPKI-Enrollment-Flag"
    )
    if enrollment_flag & PEND_ALL_REQUESTS:
        return []

    ra_signature = template_int_property(
        template_node, "mspki_ra_signature", "msPKI-RA-Signature"
    )
    schema_version = template_int_property(
        template_node, "mspki_template_schema_version", "msPKI-Template-Schema-Version"
    )
    app_policies = template_application_policies(template_node)

    accepts_agent = (EKU_CERT_REQUEST_AGENT in app_policies and ra_signature >= 1) or (
        schema_version == 1 and ra_signature >= 1
    )

    if not accepts_agent:
        return []

    return [
        make_adcs_edge(principal_sid=sid, template_node=template_node, esc="3")
        for sid in get_enroll_principal_sids(template_acl_edges)
    ]


def detect_esc3(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
) -> list[CollectorEdge]:
    """Combined ESC3 detector — runs agent and target halves and merges results."""
    edges: list[CollectorEdge] = []
    seen: set[tuple[str, str, str]] = set()
    for half in (detect_esc3_agent, detect_esc3_target):
        for edge in half(
            template_node=template_node,
            template_acl_edges=template_acl_edges,
            domain=domain,
        ):
            key = (edge.source_object_id, edge.target_object_id, edge.relation)
            if key in seen:
                continue
            seen.add(key)
            edges.append(edge)
    return edges
