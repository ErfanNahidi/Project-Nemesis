"""ESC5 — Write access on PKI container objects (misconfigured PKI ACL).

A principal with write-level access on high-level PKI AD objects can
compromise the entire PKI infrastructure:
  - NTAuthStore  : controls which CAs are trusted for smart-card / client auth
  - RootCA       : trusted root certificate store
  - AIACA        : Authority Information Access CA (AIA) objects
  - EnterpriseCA : write beyond ManageCA (ESC7 covers ManageCA specifically;
                   ESC5 covers GenericAll / WriteDACL / WriteOwner that allow
                   arbitrary CA config modification)

GOAD coverage: khal.drogo → local admin on braavos (the CA server). Local
admin access requires SMB detection (out of scope for the LDAP collector);
the LDAP-detectable ESC5 surface is write on the PKI container objects above.

References:
  https://posts.specterops.io/certified-pre-owned-d95910965cd2  (ESC5)
  https://mayfly277.github.io/posts/ADCS-part14/                 (ESC5 in GOAD)
"""

from __future__ import annotations

from adscan_internal.services.collector.models import CollectorEdge, CollectorNode

_ESC5_TARGET_KINDS: frozenset[str] = frozenset(
    {"NTAuthStore", "RootCA", "AIACA", "EnterpriseCA"}
)

# Write-level relations that allow PKI object manipulation.
# Includes WriteOwner/WriteDACL because taking ownership → self-grant write.
_ESC5_WRITE_RELATIONS: frozenset[str] = frozenset(
    {
        "GenericAll",
        "GenericWrite",
        "WriteDACL",
        "WriteOwner",
        "Owns",
    }
)


def detect_esc5(
    *,
    pki_node: CollectorNode,
    pki_acl_edges: list[CollectorEdge],
    domain: str,
) -> list[CollectorEdge]:
    """Return ADCSESC5 edges for principals with write access on a PKI container node.

    Covers NTAuthStore, RootCA, AIACA, and EnterpriseCA objects (the latter
    complementing ESC7 which targets ManageCA-level rights specifically).
    """
    if pki_node.kind not in _ESC5_TARGET_KINDS:
        return []

    seen: set[str] = set()
    edges: list[CollectorEdge] = []
    for acl_edge in pki_acl_edges:
        if acl_edge.relation not in _ESC5_WRITE_RELATIONS:
            continue
        sid = acl_edge.source_object_id
        if not sid or sid in seen:
            continue
        seen.add(sid)
        edges.append(
            CollectorEdge(
                source_object_id=sid,
                target_object_id=pki_node.object_id,
                relation="ADCSESC5",
                source="adcs_detector",
                method="adcs",
            )
        )
    return edges
