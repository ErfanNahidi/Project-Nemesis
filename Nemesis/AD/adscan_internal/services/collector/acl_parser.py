from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from adscan_internal import telemetry
from adscan_internal.rich_output import print_info_debug, print_warning_debug
from adscan_internal.services.collector.models import CollectorEdge, NodeKind

if TYPE_CHECKING:
    from adscan_internal.services.ldap_transport_service import ADscanLDAPConnection

_ADS_RIGHT_DS_SELF = 0x00000008          # Validated Write — "Self" (e.g. Self-Membership on group)
_ADS_RIGHT_DS_WRITE_PROP = 0x20
_ADS_RIGHT_DS_READ_PROP = 0x10
_ADS_RIGHT_GENERIC_ALL = 0x10000000
_ADS_RIGHT_GENERIC_WRITE = 0x40000000
_ADS_RIGHT_WRITE_DACL = 0x00040000
_ADS_RIGHT_WRITE_OWNER = 0x00080000
_ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
_FULL_CONTROL_MASK = 0x000F01FF

_ACCESS_ALLOWED_ACE_TYPE = 0x00
_ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05

# AceFlags bits (MS-DTYP §2.4.4.1)
_ACE_INHERIT_ONLY = 0x08

# ACCESS_ALLOWED_OBJECT_ACE.Flags bits (MS-DTYP §2.4.4.4)
_ACE_OBJECT_TYPE_PRESENT = 0x01

GENERIC_ACL_RIGHTS: dict[int, str] = {
    _ADS_RIGHT_GENERIC_ALL: "GenericAll",
    _FULL_CONTROL_MASK: "GenericAll",
    _ADS_RIGHT_GENERIC_WRITE: "GenericWrite",
    _ADS_RIGHT_WRITE_DACL: "WriteDACL",
    _ADS_RIGHT_WRITE_OWNER: "WriteOwner",
    _ADS_RIGHT_DS_CONTROL_ACCESS: "AllExtendedRights",
}

WRITE_PROPERTY_GUID_TO_RELATION: dict[str, str] = {
    "scriptPath": "WriteLogonScript",
    "msDS-RevealOnDemandGroup": "ManageRODCPrp",
    "msDS-NeverRevealGroup": "ManageRODCPrp",
    "member": "AddMember",
    "servicePrincipalName": "WriteSPN",
    "msDS-KeyCredentialLink": "AddKeyCredentialLink",
}

# READ_PROP grants on these LAPS attributes ARE the real read authority — the DC
# returns the cleartext/encrypted local-admin password to any principal the DACL
# grants READ_PROP on the attribute, so these mappings are correct and load-bearing.
#
# Deliberately EXCLUDED: "msDS-ManagedPassword" (gMSA). A DACL READ_PROP grant on
# the gMSA managed-password attribute is INERT — the DC returns the confidential
# managed password ONLY to principals listed in msDS-GroupMSAMembership
# (PrincipalsAllowedToRetrieveManagedPassword), regardless of the DACL. Mapping it
# here produced a phantom "Everyone (S-1-1-0) --ReadGMSAPassword--> <gMSA>" edge
# (the gMSA DACL grants S-1-1-0 READ_PROP on the attribute, but Everyone can never
# actually read it). The genuine ReadGMSAPassword edge is parsed from the
# msDS-GroupMSAMembership security descriptor in
# ldap_collector._parse_gmsa_membership_sd, so this exclusion loses no real edge.
# Do NOT re-add msDS-ManagedPassword here.
READ_PROPERTY_GUID_TO_RELATION: dict[str, str] = {
    "ms-Mcs-AdmPwd": "ReadLAPSPassword",
    "msLAPS-Password": "ReadLAPSPassword",
    "msLAPS-EncryptedPassword": "ReadLAPSPassword",
}

# Well-known property-set GUIDs. Granted via DS_WRITE_PROP on the property set.
# These are stable Windows constants — no LDAP schema lookup needed.
PROPERTY_SET_GUID_TO_RELATION: dict[str, str] = {
    "4c164200-20c0-11d0-a768-00aa006e0529": "WriteAccountRestrictions",  # User-Account-Restrictions
}

# Well-known extended-right GUIDs (CN=Extended-Rights,CN=Configuration).
# Granted via DS_CONTROL_ACCESS on an OBJECT_ACE. Stable across all AD environments.
EXTENDED_RIGHT_GUID_TO_RELATION: dict[str, str] = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddSelf",  # Self-Membership
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",  # Certificate-Enrollment
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll",  # Certificate-AutoEnrollment
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "GetChanges",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "GetChangesAll",
    "89e95b76-444d-4c62-991a-0facbeda640c": "GetChangesInFilteredSet",
}

# Validated-write GUIDs for DS_SELF (0x8) ACEs.
# DS_SELF + one of these GUIDs means the trustee can perform the named validated
# write against their own identity only — distinct from DS_WRITE_PROP (AddMember)
# which grants unrestricted writes.  AD encodes the Self-Membership validated
# write via the *same* GUID as the `member` attribute (bf9679c0-…) but with
# the DS_SELF bit instead of DS_WRITE_PROP.  This is a deliberate AD design:
# the GUID distinguishes *which* attribute; the mask bit determines *who* can
# be written (self only vs anyone).
SELF_WRITE_GUID_TO_RELATION: dict[str, str] = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddSelf",  # member — Self-Membership
}

PROPERTY_GUID_TO_RELATION: dict[str, str] = {
    **WRITE_PROPERTY_GUID_TO_RELATION,
    **READ_PROPERTY_GUID_TO_RELATION,
}


# Each non-generic relation is only meaningful on a restricted set of target
# kinds. Inherited / property-set ACEs on parent containers (Domain, OU,
# Container) carry GUIDs for ``ForceChangePassword`` / ``AddMember`` etc.
# whose semantic is "applicable to child objects of class X" — but the parser
# materializes them as edges to the parent. Without this filter, the graph
# ends up with nonsense like ``EWP -ForceChangePassword-> Domain`` which is
# not a real attack step (you can't reset the Domain's password) and pollutes
# attack-path UX. Generic edges (GenericAll/Write, WriteDACL, WriteOwner)
# remain valid on every target kind.
_RELATION_VALID_TARGET_KINDS: dict[str, frozenset[str]] = {
    "ForceChangePassword": frozenset({"User", "Computer"}),
    "AddMember": frozenset({"Group"}),
    "AddSelf": frozenset({"Group"}),
    "AddKeyCredentialLink": frozenset({"User", "Computer"}),
    "WriteSPN": frozenset({"User", "Computer"}),
    "ReadLAPSPassword": frozenset({"Computer"}),
    "ReadGMSAPassword": frozenset({"User", "Computer"}),
    "WriteAccountRestrictions": frozenset({"User", "Computer"}),
    "WriteLogonScript": frozenset({"User", "Computer"}),
    "ManageRODCPrp": frozenset({"Computer"}),
    "Enroll": frozenset({"CertTemplate"}),
    "AutoEnroll": frozenset({"CertTemplate"}),
    "GetChanges": frozenset({"Domain"}),
    "GetChangesAll": frozenset({"Domain"}),
    "GetChangesInFilteredSet": frozenset({"Domain"}),
}


def _relation_valid_for_target(relation: str, target_kind: str) -> bool:
    """Return True when ``relation`` makes operational sense on ``target_kind``.

    Generic relations (GenericAll, GenericWrite, WriteDACL, WriteOwner,
    AllExtendedRights, Owns) are valid on any object class. Specialized
    relations are restricted via :data:`_RELATION_VALID_TARGET_KINDS`.
    """
    valid = _RELATION_VALID_TARGET_KINDS.get(relation)
    if valid is None:
        return True
    return str(target_kind or "") in valid


class ACLParser:
    """Parse nTSecurityDescriptor bytes into CollectorEdge instances."""

    def __init__(self, domain: str, connection: ADscanLDAPConnection | None) -> None:
        self.domain = domain
        self._connection = connection
        self._guid_cache: dict[str, str | None] = {}

    def parse_sd(
        self,
        sd_bytes: bytes,
        target_object_id: str,
        target_kind: NodeKind,
    ) -> list[CollectorEdge]:
        if not sd_bytes:
            return []
        try:
            from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR  # type: ignore
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning_debug(f"[acl_parser] winacl unavailable: {exc}")
            return []

        try:
            sd = SECURITY_DESCRIPTOR.from_bytes(sd_bytes)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_info_debug(f"[acl_parser] Failed to parse SD: {exc}")
            return []

        dacl = getattr(sd, "Dacl", None)
        if not dacl:
            return []

        write_property_guid_map = self._build_property_guid_map(
            WRITE_PROPERTY_GUID_TO_RELATION
        )
        read_property_guid_map = self._build_property_guid_map(
            READ_PROPERTY_GUID_TO_RELATION
        )
        # SELF_WRITE_GUID_TO_RELATION uses stable Windows GUIDs — no schema
        # lookup needed; they are the same across all AD versions.
        self_write_guid_map = {k: v for k, v in SELF_WRITE_GUID_TO_RELATION.items()}
        edges: list[CollectorEdge] = []

        for ace in getattr(dacl, "aces", []) or []:
            ace_type = self._ace_type(ace)
            if ace_type not in (
                _ACCESS_ALLOWED_ACE_TYPE,
                _ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            ):
                continue

            # INHERIT_ONLY ACEs do not apply to the object that holds them —
            # only to their child objects via inheritance. Materializing them
            # as direct edges produces phantom GenericAll/WriteDACL on the
            # parent (typical false positive on Domain/OU objects).
            ace_flags = self._ace_flags(ace)
            if ace_flags & _ACE_INHERIT_ONLY:
                continue

            trustee = self._trustee_sid(ace)
            if not trustee or trustee == target_object_id:
                continue

            mask = self._ace_mask(ace)
            if mask is None:
                continue

            if ace_type == _ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                obj_guid = self._object_type_guid(ace)
                # ACE_OBJECT_TYPE_PRESENT means the mask is RESTRICTED to the
                # specific schema element identified by ``ObjectType``. The
                # ACE does NOT grant generic rights over the whole object —
                # treating it as such is the canonical RustHound-CE issue #33
                # (Exchange schema GUIDs surfacing as ``GenericAll`` on the
                # Domain root). We therefore look up the GUID against our
                # closed catalogs; anything outside them must be skipped, not
                # downgraded to a generic relation.
                object_type_present = bool(
                    self._ace_object_flags(ace) & _ACE_OBJECT_TYPE_PRESENT
                ) or bool(obj_guid)
                if object_type_present:
                    property_relation = self._classify_object_ace(
                        mask=mask,
                        obj_guid=obj_guid or "",
                        write_property_guid_map=write_property_guid_map,
                        read_property_guid_map=read_property_guid_map,
                        self_write_guid_map=self_write_guid_map,
                    )
                    if property_relation and _relation_valid_for_target(
                        property_relation, str(target_kind)
                    ):
                        edges.append(
                            CollectorEdge(
                                source_object_id=trustee,
                                target_object_id=target_object_id,
                                relation=property_relation,
                                source="acl_parser",
                                method="acl",
                            )
                        )
                    # Whether the GUID matched a known relation or not, the
                    # ACE is scoped to that GUID — never fall through to the
                    # generic-relation branch.
                    continue

            relation = self._generic_relation(mask)
            if relation:
                edges.append(
                    CollectorEdge(
                        source_object_id=trustee,
                        target_object_id=target_object_id,
                        relation=relation,
                        source="acl_parser",
                        method="acl",
                    )
                )
                continue

        return edges

    def _classify_object_ace(
        self,
        *,
        mask: int,
        obj_guid: str,
        write_property_guid_map: dict[str, str],
        read_property_guid_map: dict[str, str],
        self_write_guid_map: dict[str, str] | None = None,
    ) -> str | None:
        """Classify an OBJECT_ACE whose mask is scoped to ``obj_guid``.

        Returns the canonical relation name when the GUID is one we know how
        to map (extended-right grants like DCSync, write-property grants like
        AddMember, read-property grants like ReadLAPSPassword, well-known
        property sets, or validated-write Self grants like AddSelf).
        Returns ``None`` for any GUID outside those catalogs — including
        Exchange schema GUIDs and other vendor extensions whose scope cannot
        be reduced to a domain-control edge.

        The ``DS_SELF`` (0x8) branch handles validated-write "Self" ACEs.
        AD uses the *same GUID* for the `member` attribute (schemaIDGUID) and
        the Self-Membership extended right (rightsGUID), but distinguishes
        them via the mask bit:
          - DS_SELF (0x8)         → AddSelf  (trustee can only add themselves)
          - DS_WRITE_PROP (0x20)  → AddMember (trustee can add anyone)
          - DS_CONTROL_ACCESS (0x100) on ext-right GUID → AddSelf (alternative form)
        """
        if not obj_guid:
            return None
        # DS_SELF (validated-write Self): trustee can write their own identity
        # into the attribute — the canonical "Self-Membership" grant on groups.
        if mask & _ADS_RIGHT_DS_SELF:
            smap = self_write_guid_map or SELF_WRITE_GUID_TO_RELATION
            relation = smap.get(obj_guid)
            if relation:
                return relation
        if mask & _ADS_RIGHT_DS_CONTROL_ACCESS:
            relation = EXTENDED_RIGHT_GUID_TO_RELATION.get(obj_guid)
            if relation:
                return relation
        if mask & _ADS_RIGHT_DS_WRITE_PROP:
            relation = write_property_guid_map.get(obj_guid)
            if relation:
                return relation
            relation = PROPERTY_SET_GUID_TO_RELATION.get(obj_guid)
            if relation:
                return relation
        if mask & (
            _ADS_RIGHT_DS_READ_PROP
            | _ADS_RIGHT_DS_CONTROL_ACCESS
            | _ADS_RIGHT_GENERIC_ALL
        ):
            relation = read_property_guid_map.get(obj_guid)
            if relation:
                return relation
        return None

    def _generic_relation(self, mask: int) -> str | None:
        """Map an unscoped mask (whole-object ACE) to a relation name.

        Only called for ACEs that grant rights over the entire object — i.e.
        ``ACCESS_ALLOWED_ACE`` and ``ACCESS_ALLOWED_OBJECT_ACE`` whose
        ``ObjectType`` is absent. Object ACEs scoped to a specific schema
        GUID are routed through :meth:`_classify_object_ace` instead and
        never reach this method.
        """
        if mask & _ADS_RIGHT_GENERIC_ALL:
            return "GenericAll"
        if mask == _FULL_CONTROL_MASK:
            return "GenericAll"
        if mask & _ADS_RIGHT_GENERIC_WRITE:
            return "GenericWrite"
        if mask & _ADS_RIGHT_DS_WRITE_PROP:
            return "GenericWrite"
        if mask & _ADS_RIGHT_WRITE_DACL:
            return "WriteDACL"
        if mask & _ADS_RIGHT_WRITE_OWNER:
            return "WriteOwner"
        if mask & _ADS_RIGHT_DS_CONTROL_ACCESS:
            return "AllExtendedRights"
        return None

    def _build_property_guid_map(self, attrs: dict[str, str]) -> dict[str, str]:
        result: dict[str, str] = {}
        for attr_name, relation in attrs.items():
            guid = self._resolve_property_guid(attr_name)
            if guid:
                result[guid] = relation
        return result

    def _resolve_property_guid(self, attr_name: str) -> str | None:
        if attr_name in self._guid_cache:
            return self._guid_cache[attr_name]
        if not self._connection:
            self._guid_cache[attr_name] = None
            return None
        try:
            schema_base = f"CN=Schema,{self._connection.config_dn}"
            self._connection.search(
                search_base=schema_base,
                search_filter=f"(lDAPDisplayName={attr_name})",
                attributes=["schemaIDGUID"],
                search_scope="SUBTREE",
            )
            entries = self._connection.entries
            raw_guid_list = (
                entries[0].entry_raw_attributes.get("schemaIDGUID") or []
                if entries
                else []
            )
            raw_guid = raw_guid_list[0] if raw_guid_list else None
            if not raw_guid:
                self._guid_cache[attr_name] = None
                return None
            guid_str = str(UUID(bytes_le=raw_guid)).lower()
            self._guid_cache[attr_name] = guid_str
            return guid_str
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[acl_parser] Failed to resolve GUID for {attr_name}: {exc}"
            )
            self._guid_cache[attr_name] = None
            return None

    def _ace_type(self, ace: Any) -> int | None:
        ace_type = getattr(ace, "AceType", None)
        if ace_type is None:
            return None
        value = getattr(ace_type, "value", None)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
        try:
            return int(ace_type)
        except (TypeError, ValueError):
            return None

    def _ace_flags(self, ace: Any) -> int:
        """Return ``AceHeader.AceFlags`` (header-level) as int, 0 on failure."""
        try:
            value = getattr(ace, "AceFlags", 0)
            inner = getattr(value, "value", None)
            if inner is not None:
                return int(inner)
            return int(value or 0)
        except Exception:
            return 0

    def _ace_object_flags(self, ace: Any) -> int:
        """Return ``ACCESS_ALLOWED_OBJECT_ACE.Flags`` (per-ACE-body bitmap).

        Distinct from ``AceFlags`` (the header field). ``Flags`` carries
        ``ACE_OBJECT_TYPE_PRESENT`` (0x01) and
        ``ACE_INHERITED_OBJECT_TYPE_PRESENT`` (0x02) and tells us whether
        ``ObjectType`` / ``InheritedObjectType`` are meaningful.
        """
        try:
            value = getattr(ace, "Flags", 0)
            inner = getattr(value, "value", None)
            if inner is not None:
                return int(inner)
            return int(value or 0)
        except Exception:
            return 0

    def _ace_mask(self, ace: Any) -> int | None:
        mask = getattr(ace, "Mask", None)
        if mask is None:
            return None
        if isinstance(mask, int):
            return mask
        nested = getattr(mask, "Mask", None)
        if isinstance(nested, int):
            return nested
        try:
            return int(mask)
        except (TypeError, ValueError):
            return None

    def _trustee_sid(self, ace: Any) -> str | None:
        try:
            return str(getattr(ace, "Sid", "") or "")
        except Exception:
            return None

    def _object_type_guid(self, ace: Any) -> str | None:
        try:
            raw = getattr(ace, "ObjectType", None)
        except Exception:
            return None
        if not raw:
            return None
        try:
            if isinstance(raw, bytes):
                return str(UUID(bytes_le=raw)).lower()
            return str(raw).lower()
        except Exception:
            return None
