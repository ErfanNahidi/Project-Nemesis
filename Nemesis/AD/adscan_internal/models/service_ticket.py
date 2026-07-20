"""ServiceTicket model — derived Kerberos service tickets persisted in workspace state.

Service tickets are tickets that authenticate access to one specific service
on one specific host (or set of hosts).  They are produced by attack flows
that move past the authenticator's TGT — RBCD/S4U2Proxy, constrained
delegation with protocol transition, silver tickets, S4U2Self impersonation —
and persisted so follow-up steps can consume them without re-running the
delegation chain.

These tickets MUST NOT be confused with TGTs.  A TGT can authenticate any
Kerberos request as the user it was issued for; a service ticket only opens
a single service principal.  Mixing the two in ``domains_data["kerberos_tickets"]``
caused real bugs in production where LDAP code took the existence of *some*
ccache as a signal that Kerberos auth was ready, then tried to bind without
the user's TGT in scope.

The ``kind`` field records *how* the ticket was produced so the consumer can
reason about its capabilities:

- ``rbcd``: produced by an RBCD chain (NewMachineAccount → SetSPN →
  WriteAccountRestrictions → S4U2Self → S4U2Proxy).  ``owner_principal`` is
  the attacker-controlled machine account; ``impersonated_user`` is the
  delegatee.  Only valid against ``spn``.
- ``constrained_delegation``: produced by S4U2Self+S4U2Proxy on an account
  that already had constrained-delegation rights (no MAQ creation).
- ``silver_ticket``: forged with the service account's secret material.
  ``owner_principal`` is the service account whose key signed the PAC.
- ``s4u2self_only``: only the S4U2Self step succeeded; the proxy step
  failed.  Useful for diagnostics, not for execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class ServiceTicketKind(str, Enum):
    """How the service ticket was produced."""

    RBCD = "rbcd"
    CONSTRAINED_DELEGATION = "constrained_delegation"
    SILVER_TICKET = "silver_ticket"
    S4U2SELF_ONLY = "s4u2self_only"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, value: Any) -> "ServiceTicketKind":
        """Best-effort conversion from a stored string."""
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value or "").strip().lower())
        except ValueError:
            return cls.UNKNOWN


@dataclass
class ServiceTicket:
    """One persisted derived service ticket.

    Attributes:
        ccache_path: Filesystem path to the ``.ccache`` file containing the ST.
            The file is the source of truth — fields below are metadata
            duplicated for fast lookup without re-parsing every entry.
        kind: How this ticket was produced.
        owner_principal: The principal whose TGT/key produced the ST.
            For RBCD this is the attacker machine account (e.g. ``ADSCANE66DD6$``).
            For silver tickets this is the service account.
        impersonated_user: The "for client" of the ST (e.g. ``administrator``).
            Equal to ``owner_principal`` for direct (non-S4U) STs.
        spn: The service principal name the ST grants access to (e.g.
            ``cifs/rodc01.garfield.htb``).
        target_host: The host portion of *spn* (e.g. ``rodc01.garfield.htb``)
            kept separate so callers can match by host without parsing.
        realm: Kerberos realm of the ST (uppercase, e.g. ``GARFIELD.HTB``).
        etype: Encryption type of the ticket session key when known
            (18 = AES256, 17 = AES128, 23 = RC4).  ``None`` when unknown.
        issued_at: Epoch seconds when the ST was issued.
        expires_at: Epoch seconds when the ST expires.
        source_step: Optional opaque identifier (attack step, edge id, ...)
            recording which workflow produced the ticket.  Useful for
            telemetry and for cleanup when the producing step is rerun.
        notes: Free-form metadata bag — kept narrow so it does not become a
            second source of truth.
    """

    ccache_path: str
    kind: ServiceTicketKind
    owner_principal: str
    impersonated_user: str
    spn: str
    target_host: str = ""
    realm: str = ""
    etype: Optional[int] = None
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None
    source_step: Optional[str] = None
    notes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to the workspace-persisted JSON shape."""
        return {
            "ccache_path": self.ccache_path,
            "kind": self.kind.value,
            "owner_principal": self.owner_principal,
            "impersonated_user": self.impersonated_user,
            "spn": self.spn,
            "target_host": self.target_host,
            "realm": self.realm,
            "etype": self.etype,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "source_step": self.source_step,
            "notes": dict(self.notes or {}),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceTicket":
        """Restore from workspace JSON (tolerant of missing fields)."""
        return cls(
            ccache_path=str(data.get("ccache_path") or "").strip(),
            kind=ServiceTicketKind.coerce(data.get("kind")),
            owner_principal=str(data.get("owner_principal") or "").strip(),
            impersonated_user=str(data.get("impersonated_user") or "").strip(),
            spn=str(data.get("spn") or "").strip(),
            target_host=str(data.get("target_host") or "").strip(),
            realm=str(data.get("realm") or "").strip(),
            etype=_coerce_optional_int(data.get("etype")),
            issued_at=_coerce_optional_int(data.get("issued_at")),
            expires_at=_coerce_optional_int(data.get("expires_at")),
            source_step=_optional_str(data.get("source_step")),
            notes=dict(data.get("notes") or {}),
        )

    def matches(
        self,
        *,
        spn: Optional[str] = None,
        impersonated_user: Optional[str] = None,
        target_host: Optional[str] = None,
        kind: Optional[ServiceTicketKind] = None,
    ) -> bool:
        """Predicate for filtered lookup over a ``service_tickets`` list.

        Each non-None argument adds a case-insensitive AND constraint.
        """
        if spn and self.spn.casefold() != spn.casefold():
            return False
        if (
            impersonated_user
            and self.impersonated_user.casefold() != impersonated_user.casefold()
        ):
            return False
        if target_host and self.target_host.casefold() != target_host.casefold():
            return False
        if kind is not None and self.kind is not kind:
            return False
        return True


def _coerce_optional_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
