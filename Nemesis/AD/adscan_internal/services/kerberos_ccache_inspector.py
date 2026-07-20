"""Pure-logic ccache inspector built on top of kerbad's CCACHE parser.

This module is the single source of truth for asking "what is inside this
ccache file?" — used both by storage validators (``credential_store_service``)
and by callers that need to decide whether a ccache contains a TGT for a
specific user before driving Kerberos auth.

Design goals:

- **No subprocess**.  All parsing happens in-process via ``kerbad.common.ccache``
  so the module is safe to call from async contexts and unit tests.
- **No side effects**.  The functions never set environment variables, never
  touch the global gssapi state, and never log to stdout.
- **Best-effort**.  When the ccache cannot be parsed (truncated, foreign
  format, missing) the helpers return a structured result with
  ``status = "unparseable"``; callers decide whether to treat that as fatal.

The contract intentionally separates *what is in the file* from *whether the
ccache is currently usable*.  Validity-against-clock-skew is delegated to
``KerberosTicketService.is_ticket_valid`` (klist -s).  Here we only answer
"does this ccache contain a TGT issued for principal X in realm Y?".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


class CCacheStatus(str, Enum):
    """Coarse classification of a ccache inspection result."""

    OK = "ok"
    MISSING = "missing"
    UNPARSEABLE = "unparseable"
    EMPTY = "empty"


class TicketKind(str, Enum):
    """Coarse classification of what a single Kerberos credential represents."""

    TGT = "tgt"  # server == krbtgt/<REALM>@<REALM>
    REFERRAL_TGT = "referral_tgt"  # server == krbtgt/<OTHER_REALM>@<REALM>
    SERVICE = "service"  # any other server SPN
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CredentialEntry:
    """Single credential inside a ccache file, normalised to plain strings."""

    client_name: str  # e.g. "j.arbuckle"  (no realm)
    client_realm: str  # e.g. "GARFIELD.HTB"
    server_spn: str  # e.g. "krbtgt/GARFIELD.HTB" or "cifs/rodc01.garfield.htb"
    server_realm: str  # e.g. "GARFIELD.HTB"
    starttime: Optional[int] = None  # epoch seconds, when known
    endtime: Optional[int] = None
    renew_till: Optional[int] = None
    kind: TicketKind = TicketKind.UNKNOWN

    def server_principal(self) -> str:
        """Canonical ``server@realm`` representation."""
        return f"{self.server_spn}@{self.server_realm}"

    def client_principal(self) -> str:
        """Canonical ``client@realm`` representation."""
        return f"{self.client_name}@{self.client_realm}"


@dataclass(frozen=True)
class CCacheInfo:
    """Full parsed view of a ccache file."""

    path: str
    status: CCacheStatus
    default_client_name: Optional[str] = None  # principal name without realm
    default_client_realm: Optional[str] = None
    credentials: List[CredentialEntry] = field(default_factory=list)
    error: Optional[str] = None  # populated when status != OK

    def has_tgt_for(self, username: str, realm: Optional[str] = None) -> bool:
        """Return True when the ccache contains a TGT whose client matches.

        Matching is case-insensitive on both the client name and the realm.
        When *realm* is None, only the client name is compared (any realm).
        """
        norm_user = (username or "").strip().casefold()
        norm_realm = (realm or "").strip().casefold() or None
        if not norm_user:
            return False
        for cred in self.credentials:
            if cred.kind is not TicketKind.TGT:
                continue
            if cred.client_name.casefold() != norm_user:
                continue
            if norm_realm and cred.client_realm.casefold() != norm_realm:
                continue
            return True
        return False

    def first_service_ticket(self) -> Optional[CredentialEntry]:
        """Return the first non-TGT credential, if any.

        Useful when persisting a ccache produced by S4U/RBCD where the
        operationally-meaningful entry is the service ticket, not the TGT
        bound to the owner principal.
        """
        for cred in self.credentials:
            if cred.kind is TicketKind.SERVICE:
                return cred
        return None


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a ``validate_tgt_for_user`` call."""

    ok: bool
    reason: Optional[str] = None  # populated when ok is False


def _principal_components(principal: object) -> List[str]:
    """Return the list of name components of a kerbad CCACHEPrincipal."""
    components = getattr(principal, "components", None) or []
    out: List[str] = []
    for comp in components:
        try:
            out.append(comp.to_string())
        except Exception:
            out.append(str(comp))
    return out


def _principal_realm(principal: object) -> str:
    """Return the realm of a kerbad CCACHEPrincipal as plain str."""
    realm = getattr(principal, "realm", None)
    if realm is None:
        return ""
    try:
        return realm.to_string()
    except Exception:
        return str(realm)


def _classify_server(components: List[str], server_realm: str) -> TicketKind:
    """Classify a credential by its server SPN components."""
    if not components:
        return TicketKind.UNKNOWN
    if components[0].casefold() != "krbtgt":
        return TicketKind.SERVICE
    # krbtgt/<X>@<server_realm> — TGT iff X == server_realm (intra-realm).
    target_realm = components[1] if len(components) > 1 else ""
    if target_realm and server_realm and target_realm.casefold() == server_realm.casefold():
        return TicketKind.TGT
    return TicketKind.REFERRAL_TGT


def inspect_ccache(path: str | Path) -> CCacheInfo:
    """Parse a ccache file and return a structured view of its contents.

    The function never raises on bad input — it returns a ``CCacheInfo``
    whose ``status`` field describes the failure mode.
    """
    str_path = str(path or "").strip()
    if not str_path:
        return CCacheInfo(path="", status=CCacheStatus.MISSING, error="empty path")

    p = Path(str_path)
    if not p.exists():
        return CCacheInfo(path=str_path, status=CCacheStatus.MISSING, error="file not found")

    try:
        from kerbad.common.ccache import CCACHE  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover - import-time failure
        return CCacheInfo(
            path=str_path,
            status=CCacheStatus.UNPARSEABLE,
            error=f"kerbad import failed: {type(exc).__name__}: {exc}",
        )

    try:
        ccache = CCACHE.from_file(str_path)
    except Exception as exc:
        return CCacheInfo(
            path=str_path,
            status=CCacheStatus.UNPARSEABLE,
            error=f"ccache parse failed: {type(exc).__name__}: {exc}",
        )

    raw_creds = list(getattr(ccache, "credentials", []) or [])
    if not raw_creds:
        return CCacheInfo(
            path=str_path,
            status=CCacheStatus.EMPTY,
            error="ccache contains no credentials",
        )

    entries: List[CredentialEntry] = []
    default_name: Optional[str] = None
    default_realm: Optional[str] = None

    for raw in raw_creds:
        try:
            client = getattr(raw, "client", None)
            server = getattr(raw, "server", None)
            client_components = _principal_components(client) if client else []
            server_components = _principal_components(server) if server else []
            client_realm = _principal_realm(client) if client else ""
            server_realm = _principal_realm(server) if server else ""

            # Multi-component clients (e.g. computer accounts with $) join with '/'.
            client_name = "/".join(client_components)
            server_spn = "/".join(server_components)

            kind = _classify_server(server_components, server_realm)

            times = getattr(raw, "time", None)
            entries.append(
                CredentialEntry(
                    client_name=client_name,
                    client_realm=client_realm,
                    server_spn=server_spn,
                    server_realm=server_realm,
                    starttime=_safe_epoch(getattr(times, "starttime", None)),
                    endtime=_safe_epoch(getattr(times, "endtime", None)),
                    renew_till=_safe_epoch(getattr(times, "renew_till", None)),
                    kind=kind,
                )
            )

            if default_name is None and client_name:
                default_name = client_name
                default_realm = client_realm
        except Exception:
            # Skip malformed entries — keep parsing the rest.
            continue

    if not entries:
        return CCacheInfo(
            path=str_path,
            status=CCacheStatus.EMPTY,
            error="ccache parsed but produced no usable credentials",
        )

    return CCacheInfo(
        path=str_path,
        status=CCacheStatus.OK,
        default_client_name=default_name,
        default_client_realm=default_realm,
        credentials=entries,
    )


def validate_tgt_for_user(
    path: str | Path,
    *,
    username: str,
    realm: Optional[str] = None,
) -> ValidationResult:
    """Confirm *path* is a ccache containing a TGT issued for *username*.

    A ccache passes validation when:

    1. It can be parsed by kerbad.
    2. It contains at least one credential whose *server* is
       ``krbtgt/<realm>@<realm>`` (intra-realm TGT).
    3. That credential's *client* name matches *username* (case-insensitive),
       and — when *realm* is provided — the realm matches too.

    The check is intentionally strict: an S4U2Self/S4U2Proxy ccache produced
    by an RBCD flow contains a TGT *for the proxy account*, not for the
    impersonated user.  Such a ccache must therefore NOT pass validation when
    the caller wants to register it under the impersonated user's slot.
    """
    info = inspect_ccache(path)
    if info.status is not CCacheStatus.OK:
        return ValidationResult(ok=False, reason=f"{info.status.value}: {info.error}")

    norm_user = (username or "").strip()
    if not norm_user:
        return ValidationResult(ok=False, reason="empty username")

    if info.has_tgt_for(norm_user, realm):
        return ValidationResult(ok=True)

    # Build a precise diagnostic.  When the ccache is from RBCD, the most
    # common failure mode is "TGT belongs to <owner>$, requested for
    # <impersonated>" — surface that instead of a generic mismatch.
    tgt_clients = sorted(
        {f"{c.client_name}@{c.client_realm}" for c in info.credentials if c.kind is TicketKind.TGT}
    )
    if not tgt_clients:
        return ValidationResult(
            ok=False,
            reason="ccache contains no TGT (only service tickets)",
        )

    return ValidationResult(
        ok=False,
        reason=(
            f"ccache TGT belongs to {', '.join(tgt_clients)}; "
            f"expected {norm_user}{('@' + realm) if realm else ''}"
        ),
    )


def _safe_epoch(value: object) -> Optional[int]:
    """Best-effort coercion of a kerbad time value to integer epoch seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    # kerbad sometimes wraps timestamps in a small object exposing .timestamp()
    ts = getattr(value, "timestamp", None)
    if callable(ts):
        try:
            return int(ts())
        except Exception:
            return None
    try:
        return int(value)
    except Exception:
        return None
