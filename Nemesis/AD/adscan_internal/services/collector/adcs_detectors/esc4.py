"""ESC4 — Write access on a CertTemplate object.

A principal with GenericWrite / GenericAll / WriteDACL / WriteOwner / Owns
on a certificate template can modify its attributes (e.g. enable
ENROLLEE_SUPPLIES_SUBJECT), effectively turning it into ESC1.

References:
  https://posts.specterops.io/certified-pre-owned-d95910965cd2  (ESC4)
  https://mayfly277.github.io/posts/GOADv2-pwning-part6/         (khal.drogo → ESC4 template)
"""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._common import make_adcs_edge
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode

# Write-level ACL relations on a CertTemplate that allow modifying its attributes.
# AllExtendedRights grants extended rights (Enroll/AutoEnroll) but NOT property
# write access, so it is intentionally excluded here.
_ESC4_WRITE_RELATIONS: frozenset[str] = frozenset(
    {
        "GenericAll",
        "GenericWrite",
        "WriteDACL",
        "WriteOwner",
        "Owns",
    }
)


def detect_esc4(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
    **_: object,
) -> list[CollectorEdge]:
    """Return ADCSESC4 edges for principals with write access on a CertTemplate.

    Condition: any principal holds a write-equivalent ACL right on the template
    object (GenericAll / GenericWrite / WriteDACL / WriteOwner / Owns).
    No template flag checks needed — write access alone is sufficient to
    escalate the template to ESC1 conditions.
    """
    if template_node.kind != "CertTemplate":
        return []

    seen: set[str] = set()
    edges: list[CollectorEdge] = []
    for acl_edge in template_acl_edges:
        if acl_edge.relation not in _ESC4_WRITE_RELATIONS:
            continue
        sid = acl_edge.source_object_id
        if not sid or sid in seen:
            continue
        seen.add(sid)
        edges.append(
            make_adcs_edge(principal_sid=sid, template_node=template_node, esc="4")
        )
    return edges
