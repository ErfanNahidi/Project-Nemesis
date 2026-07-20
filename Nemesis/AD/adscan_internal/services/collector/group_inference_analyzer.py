"""Infer CanRDP and CanPSRemote edges from domain builtin group membership.

Windows Active Directory creates domain-local builtin groups in the
``CN=Builtin`` container.  By default (and via the domain join process),
these groups map to the corresponding local groups on domain-joined computers:

  CN=Remote Desktop Users,CN=Builtin     → local BUILTIN\\Remote Desktop Users
  CN=Remote Management Users,CN=Builtin  → local BUILTIN\\Remote Management Users

Membership in these domain-level groups is visible in LDAP, allowing us to
infer group-level CanRDP / CanPSRemote even when running with low-priv
credentials that cannot open the SAMR pipe on each target computer. Individual
users reach those edges through the existing MemberOf graph relation, preserving
the chain ``User -> MemberOf -> Builtin Group -> CanRDP/CanPSRemote -> Host``.

All inferred edges carry ``source="ldap"`` and ``method="group_inferred"``
so callers and the attack-graph UX can distinguish them from SAMR-confirmed
edges.  Tier-zero source filtering (DA / EA) is handled downstream by
``attack_graph_service._edge_has_tier0_source`` as with all actionable edges.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from adscan_internal import print_info_debug, print_info_verbose
from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    CollectorNode,
    is_collectable_computer_host,
)

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Builtin group → edge relation mapping
# ---------------------------------------------------------------------------

# Canonical CN prefix (case-insensitive match against distinguished_name)
_BUILTIN_INFERENCE_GROUPS: dict[str, str] = {
    "remote desktop users": "CanRDP",
    "remote management users": "CanPSRemote",
}

_COLLECTABLE_COMPUTERS_SCOPE_ID_PREFIX = "ADSCAN-SCOPE-COLLECTABLE-COMPUTERS"


def _collectable_computers_scope_id(domain: str) -> str:
    """Return the stable synthetic object id for the collectable-computers scope."""
    domain_key = str(domain or "").strip().upper() or "UNKNOWN"
    return f"{_COLLECTABLE_COMPUTERS_SCOPE_ID_PREFIX}-{domain_key}"


def _ensure_collectable_computers_scope_node(
    result: CollectionResult,
    *,
    target_count: int,
) -> str:
    """Ensure the synthetic target node used to compress host-wide access edges."""
    object_id = _collectable_computers_scope_id(result.domain)
    if object_id.upper() not in result.nodes:
        result.add_node(
            CollectorNode(
                object_id=object_id,
                kind="Group",
                name=f"Collectable Computers@{result.domain.upper()}",
                domain=result.domain,
                properties={
                    "synthetic": True,
                    "synthetic_source": "group_inference_target_scope",
                    "scope_kind": "collectable_computers",
                    "target_selector": "all_collectable_computers",
                    "expanded_count": target_count,
                },
            )
        )
    return object_id


def _dn_builtin_name(distinguished_name: str) -> str | None:
    """Extract the CN name from a CN=Builtin group DN, or None if not a builtin group.

    Matches e.g.:
      CN=Remote Desktop Users,CN=Builtin,DC=essos,DC=local
      CN=Usuarios de escritorio remoto,CN=Builtin,DC=corp,DC=local  (localised)
    """
    dn_upper = distinguished_name.upper()
    if ",CN=BUILTIN," not in dn_upper:
        return None
    parts = distinguished_name.split(",")
    if not parts:
        return None
    first = parts[0].strip()
    if not first.upper().startswith("CN="):
        return None
    return first[3:].strip()


def _relation_for_builtin_group(dn: str) -> str | None:
    """Return the relation to infer for a CN=Builtin group, or None."""
    cn_name = _dn_builtin_name(dn)
    if cn_name is None:
        return None
    cn_lower = cn_name.lower()
    # Exact match first
    if cn_lower in _BUILTIN_INFERENCE_GROUPS:
        return _BUILTIN_INFERENCE_GROUPS[cn_lower]
    # Substring match to handle locale variants
    # e.g. "Usuarios de escritorio remoto" contains "escritorio remoto" ~ "remote desktop"
    for key, relation in _BUILTIN_INFERENCE_GROUPS.items():
        if _fuzzy_match(cn_lower, key):
            return relation
    return None


def _fuzzy_match(cn_lower: str, key: str) -> bool:
    """Loose heuristic for localised group name variants."""
    # Check for keyword overlap that unambiguously identifies the group
    if key == "remote desktop users":
        return any(
            kw in cn_lower for kw in ("desktop", "escritorio", "bureau", "remotos")
        )
    if key == "remote management users":
        return any(kw in cn_lower for kw in ("management", "administração", "gestion"))
    return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def analyze_group_inferences(result: CollectionResult) -> int:
    """Create group-level CanRDP / CanPSRemote edges for CN=Builtin groups.

    Returns the number of edges created.
    """
    # Index MemberOf edges: group_oid → [member_oid, ...]
    group_to_members: dict[str, list[str]] = {}
    for edge in result.edges:
        if edge.relation != "MemberOf":
            continue
        g = edge.target_object_id.upper()
        group_to_members.setdefault(g, []).append(edge.source_object_id.upper())

    computers = [n for n in result.nodes.values() if is_collectable_computer_host(n)]
    if not computers:
        return 0

    created = 0

    for node in list(result.nodes.values()):
        if node.kind != "Group":
            continue
        dn = str(node.distinguished_name or "")
        if not dn:
            continue
        relation = _relation_for_builtin_group(dn)
        if relation is None:
            continue

        members = group_to_members.get(str(node.object_id or "").upper(), [])
        if not members:
            continue

        print_info_debug(
            f"[group-inference] {relation} from {node.name!r} ({len(members)} members) "
            f"→ {len(computers)} computers"
        )

        group_oid = str(node.object_id or "").upper()
        if not group_oid:
            continue

        target_scope_oid = _ensure_collectable_computers_scope_node(
            result,
            target_count=len(computers),
        )
        already_inferred = any(
            e.relation == relation
            and e.source_object_id.upper() == group_oid
            and e.target_object_id.upper() == target_scope_oid.upper()
            and e.source == "ldap"
            and e.method == "group_inferred"
            for e in result.edges
        )
        if already_inferred:
            continue
        result.add_edge(
            CollectorEdge(
                source_object_id=group_oid,
                target_object_id=target_scope_oid,
                relation=relation,
                source="ldap",
                method="group_inferred",
                notes={
                    "target_selector": "all_collectable_computers",
                    "expanded_count": len(computers),
                },
            )
        )
        created += 1

    if created:
        print_info_verbose(
            f"[group-inference] inferred {created} edge(s) "
            f"(CanRDP + CanPSRemote from CN=Builtin groups)"
        )
    return created
