"""Effective-token rights derivation for compound AD permissions.

Windows evaluates DACLs by unioning rights across every SID in a principal's
authentication token (self + transitive group memberships + kind-implicit
well-known SIDs added by the LSA / KDC). ADscan must mirror this semantics
to correctly derive compound-right edges (DCSync, LAPS read, GMSA read,
compound ACL writes) when the required rights are distributed across
multiple SIDs in the default DACL of the target object.

The canonical example: in a default AD domain object DACL, ``GetChanges``
sits on ``Enterprise Domain Controllers (S-1-5-9)`` while ``GetChangesAll``
sits on ``Domain Controllers (-516)``. Neither group SID alone has the pair,
but a DC machine account is implicitly in both (S-1-5-9 added by the KDC,
-516 via explicit MemberOf), so its effective token unions both rights and
DCSync is authorised.

Public API:

- :class:`AllOf`, :class:`AnyOf`, type alias ``RightSpec`` — declarative
  algebra for compound-right requirements.
- :data:`DCSYNC` — canonical DCSync spec.
- :func:`compute_effective_token_sids` — build a principal's token.
- :func:`implicit_well_known_sids_for_principal` — kind-implicit SIDs.
- :func:`evaluate_compound_right` — check a spec against a principal's
  effective rights on a target object.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Union

# ── Right name constants ──────────────────────────────────────────────────
GET_CHANGES = "GetChanges"
GET_CHANGES_ALL = "GetChangesAll"
ALL_EXTENDED_RIGHTS = "AllExtendedRights"

# ── Well-known SIDs ───────────────────────────────────────────────────────
SID_EVERYONE = "S-1-1-0"
SID_AUTHENTICATED_USERS = "S-1-5-11"
SID_ENTERPRISE_DOMAIN_CONTROLLERS = "S-1-5-9"
SID_BUILTIN_USERS = "S-1-5-32-545"

# Domain Controllers (-516) and Read-Only Domain Controllers (-498) are the
# RIDs of groups whose members are all DC machine accounts. Group nodes with
# these RIDs receive S-1-5-9 in their effective token (BloodHound-style:
# "any member of this group can do X").
_DC_GROUP_RIDS: frozenset[int] = frozenset({516, 498})

# UAC bit set on DC machine accounts (SERVER_TRUST_ACCOUNT).
# https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
_UAC_SERVER_TRUST_ACCOUNT = 0x2000


# ── Compound right specs ──────────────────────────────────────────────────
@dataclass(frozen=True)
class AllOf:
    """All listed rights must be present in the principal's effective rights."""

    rights: tuple[str, ...]


@dataclass(frozen=True)
class AnyOf:
    """At least one alternative spec must be satisfied."""

    alternatives: tuple["RightSpec", ...]


# A right spec is either a leaf (single right name), an AllOf conjunction,
# or an AnyOf disjunction. Recursive composition is supported.
RightSpec = Union[str, AllOf, AnyOf]


# Canonical DCSync spec: (GetChanges AND GetChangesAll) OR AllExtendedRights.
DCSYNC: RightSpec = AnyOf(
    (
        AllOf((GET_CHANGES, GET_CHANGES_ALL)),
        ALL_EXTENDED_RIGHTS,
    )
)


# ── Private helpers ───────────────────────────────────────────────────────

def _node_properties(node: Any) -> Mapping[str, Any]:
    """Return the principal's properties dict, or an empty mapping if absent."""
    props = getattr(node, "properties", None)
    if isinstance(props, Mapping):
        return props
    return {}


def _is_dc_via_uac(node: Any) -> bool:
    """True if the Computer node has the SERVER_TRUST_ACCOUNT UAC bit set."""
    props = _node_properties(node)
    raw = props.get("useraccountcontrol", props.get("userAccountControl", 0))
    try:
        return bool(int(raw) & _UAC_SERVER_TRUST_ACCOUNT)
    except (ValueError, TypeError):
        return False


def _group_rid(node: Any) -> int | None:
    """Extract the RID from a group's domain SID (last numeric component)."""
    sid = str(getattr(node, "object_id", "") or "")
    if not sid.startswith("S-1-5-21-"):
        return None
    parts = sid.rsplit("-", 1)
    if len(parts) != 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _sid_is_dc_group(sid: str) -> bool:
    """True if a SID corresponds to a Domain Controllers (516) or RODC (498) group."""
    if not sid.startswith("S-1-5-21-"):
        return False
    parts = sid.rsplit("-", 1)
    if len(parts) != 2:
        return False
    try:
        return int(parts[1]) in _DC_GROUP_RIDS
    except ValueError:
        return False


def _bfs_memberof(start_sid: str, edges: Iterable[Any]) -> set[str]:
    """BFS over MemberOf edges from ``start_sid``, cycle-safe.

    Returns all group SIDs (uppercased) reachable from ``start_sid`` via
    MemberOf edges. The starting SID itself is NOT included.
    """
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        if str(getattr(edge, "relation", "") or "") != "MemberOf":
            continue
        src = str(getattr(edge, "source_object_id", "") or "").upper()
        dst = str(getattr(edge, "target_object_id", "") or "").upper()
        if not src or not dst:
            continue
        adjacency.setdefault(src, set()).add(dst)

    start_upper = start_sid.upper()
    visited: set[str] = set()
    queue: list[str] = list(adjacency.get(start_upper, set()))
    while queue:
        current = queue.pop()
        if current in visited:
            continue
        visited.add(current)
        for nxt in adjacency.get(current, ()):
            if nxt not in visited:
                queue.append(nxt)
    return visited


def _spec_satisfied_by(spec: RightSpec, rights: set[str]) -> bool:
    """Recursively evaluate ``spec`` against a set of effective rights."""
    if isinstance(spec, str):
        return spec in rights
    if isinstance(spec, AllOf):
        return all(_spec_satisfied_by(r, rights) for r in spec.rights)
    if isinstance(spec, AnyOf):
        return any(_spec_satisfied_by(alt, rights) for alt in spec.alternatives)
    raise TypeError(f"Unknown RightSpec: {type(spec).__name__}")


# ── Public API ────────────────────────────────────────────────────────────

def implicit_well_known_sids_for_principal(node: Any) -> frozenset[str]:
    """SIDs the LSA / KDC adds to a principal's token based on kind/props.

    Rules (ordered, additive):
      * Everyone (S-1-1-0) and Authenticated Users (S-1-5-11) — always added
        for any AD-authenticatable principal kind.
      * BUILTIN\\Users (S-1-5-32-545) — added for User principals.
      * Enterprise Domain Controllers (S-1-5-9) — added for DC machine
        accounts (Computer with SERVER_TRUST_ACCOUNT UAC bit) and for
        Group nodes whose RID is 516 or 498 (members are all DCs by
        AD schema).
    """
    sids: set[str] = {SID_EVERYONE, SID_AUTHENTICATED_USERS}
    kind = str(getattr(node, "kind", "") or "")

    if kind == "User":
        sids.add(SID_BUILTIN_USERS)
    elif kind == "Computer":
        if _is_dc_via_uac(node):
            sids.add(SID_ENTERPRISE_DOMAIN_CONTROLLERS)
    elif kind == "Group":
        rid = _group_rid(node)
        if rid is not None and rid in _DC_GROUP_RIDS:
            sids.add(SID_ENTERPRISE_DOMAIN_CONTROLLERS)

    return frozenset(sids)


def compute_intrinsic_token_sids(
    principal_object_id: str,
    *,
    nodes: Mapping[str, Any],
) -> frozenset[str]:
    """Compute the *intrinsic* token — self + kind-implicit well-known SIDs only.

    No transitive MemberOf BFS. Use this for compound-right derivation where
    the graph edge should reflect the literal ACE on the principal's own SID,
    not the union of rights reachable via group membership chains.

    Rationale: deriving DCSync (or any compound right) on a principal that has
    zero direct ACE rights — only transitive MemberOf access — violates the
    "one edge = one permission" invariant and produces redundant graph edges
    that obscure the canonical kill chain.  The MemberOf edges already exist
    in the graph; path-finding will traverse them naturally:

        Domain Admins → MemberOf → Administrators → DCSync → Domain

    ...rather than the short-cut denormalized path:

        Domain Admins → DCSync → Domain  ← wrong; no direct ACE

    The exception is the split-rights case (GOAD-essos pattern), where the
    rights are split across two *implicit* SIDs (S-1-5-9 + -516 for Domain
    Controllers): neither comes from MemberOf, so the principal IS the union
    point and the derived edge is correct.
    """
    principal_upper = principal_object_id.upper()
    token: set[str] = {principal_object_id}

    principal_node = nodes.get(principal_upper)
    if principal_node is not None:
        token.update(implicit_well_known_sids_for_principal(principal_node))

    return frozenset(token)


def compute_effective_token_sids(
    principal_object_id: str,
    *,
    nodes: Mapping[str, Any],
    edges: Iterable[Any],
    memberships_index: Mapping[str, set[str]] | None = None,
) -> frozenset[str]:
    """Compute the effective Kerberos/NTLM token SIDs for a principal.

    Composition (additive):
      1. The principal's own SID.
      2. Transitive MemberOf — every group reachable by walking MemberOf
         edges from the principal upward (BFS, cycle-safe). When
         ``memberships_index`` is provided, its value for the principal
         short-circuits the BFS.
      3. Implicit well-known SIDs added by the LSA / KDC, derived from
         the principal's kind and properties.
      4. S-1-5-9 (Enterprise Domain Controllers) when any SID in the
         token (after step 2) corresponds to a DC group (RID 516 / 498).
         This handles "Computer is a DC because it's MemberOf -516"
         without requiring the UAC flag to also be set.
    """
    principal_upper = principal_object_id.upper()
    token: set[str] = {principal_object_id}

    # (2) Transitive MemberOf.
    if memberships_index is not None:
        token.update(memberships_index.get(principal_upper, set()))
    else:
        token.update(_bfs_memberof(principal_upper, edges))

    # (3) Kind-implicit well-known SIDs.
    principal_node = nodes.get(principal_upper)
    if principal_node is not None:
        token.update(implicit_well_known_sids_for_principal(principal_node))

    # (4) S-1-5-9 promotion via DC-group membership.
    if SID_ENTERPRISE_DOMAIN_CONTROLLERS not in token:
        for sid in list(token):
            if _sid_is_dc_group(sid):
                token.add(SID_ENTERPRISE_DOMAIN_CONTROLLERS)
                break

    return frozenset(token)


def evaluate_compound_right(
    principal_object_id: str,
    target_object_id: str,
    spec: RightSpec,
    *,
    rights_index: Mapping[tuple[str, str], frozenset[str]],
    effective_token: Mapping[str, frozenset[str]] | None = None,
    nodes: Mapping[str, Any] | None = None,
    edges: Iterable[Any] | None = None,
) -> bool:
    """Check whether the principal's effective token covers ``spec`` on the target.

    Resolves the principal's token from ``effective_token``, falling back to
    computing it from ``nodes``+``edges`` if not provided. Returns False if
    neither source is available. Raises ``TypeError`` for unknown spec types.
    """
    token: frozenset[str] | None = None
    if effective_token is not None:
        token = effective_token.get(principal_object_id)
        if token is None:
            token = effective_token.get(principal_object_id.upper())
    if token is None:
        if nodes is None or edges is None:
            return False
        token = compute_effective_token_sids(
            principal_object_id, nodes=nodes, edges=edges,
        )

    target_upper = target_object_id.upper()
    union_rights: set[str] = set()
    for sid in token:
        rights = rights_index.get((target_upper, sid.upper()))
        if rights:
            union_rights.update(rights)

    return _spec_satisfied_by(spec, union_rights)
