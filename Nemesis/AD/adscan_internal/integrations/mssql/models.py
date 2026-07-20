"""Typed contracts shared between the native MSSQL backend and presentation.

These dataclasses are the *single source of truth* for what an MSSQL native
operation returns. The backend builds them; the presentation layer renders
them; the exploitation services consume them. Anything that needs a new
field touches this file first — never an ad-hoc dict.

Design rules:

* All dataclasses are ``frozen=True`` and use ``slots=True``. They are pure
  values. No mutation, no surprise attributes.
* No Rich or Textual imports. This module must be safe to import from
  unit tests, the report writer, and the web app.
* Identity / privilege information is mapped to the ADscan canonical
  nomenclature (``CompromiseClass``, ``PathState``) via the
  :class:`PrivilegeSweep` ``compromise_signal`` property. The classifier
  itself lives elsewhere; this module only carries the inputs it needs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Sequence


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class XpCmdshellStatus(str, Enum):
    """Lifecycle state of ``xp_cmdshell`` on one server."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class IntegrityHint(str, Enum):
    """Best-effort classification of the OS-level identity reached.

    This is a *hint*, not a proven fact. The proof comes from a successful
    ``whoami /priv`` run — until then we infer from the SQL identity.
    """

    SYSTEM = "SYSTEM-equivalent"
    SERVICE = "service-account"
    INTERACTIVE = "interactive-user"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Core records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IdentityFingerprint:
    """Effective identity confirmed by the server after login.

    Captures both the *requested* login (``original_login``) and the
    *effective* login (``system_user``) so that ``EXECUTE AS`` chains are
    visible in the UX without a second query.
    """

    login_name: str
    system_user: str
    original_login: str
    server_name: str
    server_version: str
    product_version: str
    edition: str
    current_database: str

    @property
    def has_execute_as_chain(self) -> bool:
        """Whether the effective principal differs from the original login."""
        if not self.original_login or not self.system_user:
            return False
        return self.original_login.casefold() != self.system_user.casefold()

    @property
    def short_version(self) -> str:
        """Compact rendering of ``server_version`` for one-line headers."""
        first_line = (self.server_version or "").splitlines()[0:1]
        if first_line:
            return first_line[0].strip()
        return self.product_version or ""


@dataclass(frozen=True, slots=True)
class PrivilegeSweep:
    """One-shot privilege fingerprint of an MSSQL principal.

    Built by :meth:`ImpacketMSSQLBackend.sweep_privileges`. Carries every
    fact a caller might need so that the CLI, the report writer, and the
    exploitation service all see the same picture.
    """

    identity: IdentityFingerprint
    is_sysadmin: bool
    server_permissions: tuple[tuple[str, str, str], ...]
    impersonable_principals: tuple[str, ...]
    xp_cmdshell: XpCmdshellStatus
    show_advanced_options_enabled: bool
    owned_databases: tuple[str, ...]
    trustworthy_databases_owned_by_sysadmin: tuple[str, ...]
    linked_servers: tuple["LinkedServer", ...]
    duration_seconds: float

    @property
    def can_execute_os_commands(self) -> bool:
        """True if ``xp_cmdshell`` will run *right now*, without remediation.

        Returns False for sysadmin + xp_cmdshell DISABLED — that case is
        recoverable (the caller can enable xp_cmdshell first), but it is
        not a one-step path. Use :attr:`can_unlock_os_commands` for the
        broader "is OS execution reachable from this surface".
        """
        return self.is_sysadmin and self.xp_cmdshell == XpCmdshellStatus.ENABLED

    @property
    def can_unlock_os_commands(self) -> bool:
        """True if OS execution is reachable from the current login.

        Distinct from :attr:`can_execute_os_commands` because the latter
        is "ready now"; this one includes the "sysadmin can flip the
        config" path. UX uses both: the first to recommend
        ``pop shell``, the second to recommend ``enable shell``.
        """
        if self.can_execute_os_commands:
            return True
        return self.is_sysadmin and self.xp_cmdshell == XpCmdshellStatus.DISABLED

    @property
    def has_dbowner_privesc_candidate(self) -> bool:
        """Whether a ``db_owner`` → sysadmin escalation candidate exists."""
        return any(
            db in self.trustworthy_databases_owned_by_sysadmin
            for db in self.owned_databases
        )

    @property
    def has_impersonation_privesc(self) -> bool:
        """Whether at least one impersonable principal is reachable."""
        return bool(self.impersonable_principals)

    @property
    def integrity_hint(self) -> IntegrityHint:
        """Best-effort guess of the OS integrity unlocked by sysadmin."""
        if not self.is_sysadmin:
            return IntegrityHint.UNKNOWN
        login = self.identity.system_user.lower()
        if login.startswith("nt service\\") or "mssqlserver" in login:
            return IntegrityHint.SYSTEM
        if "$" in login:
            return IntegrityHint.SERVICE
        return IntegrityHint.INTERACTIVE


@dataclass(frozen=True, slots=True)
class LinkedServer:
    """One linked SQL server reachable from the current connection."""

    name: str
    product: str = ""
    provider: str = ""
    data_source: str = ""
    rpc_out_enabled: bool = False
    data_access_enabled: bool = False
    local_to_remote_logins: tuple[tuple[str, str], ...] = ()

    @property
    def is_actionable(self) -> bool:
        """Whether the link can run code (``rpc_out`` enabled)."""
        return bool(self.rpc_out_enabled)


@dataclass(frozen=True, slots=True)
class PivotHop:
    """One hop in a linked-server pivot chain.

    A chain is a list of hops where the first hop is the entry point
    (``hop_index == 0``) and each subsequent hop is reached via the
    ``incoming_link`` of the previous.
    """

    hop_index: int
    server_label: str
    effective_login: str
    is_sysadmin: bool
    xp_cmdshell: XpCmdshellStatus
    incoming_link: str | None = None

    @property
    def is_terminal_win(self) -> bool:
        """Whether this hop already proves OS execution capability."""
        return self.is_sysadmin and self.xp_cmdshell == XpCmdshellStatus.ENABLED


@dataclass(frozen=True, slots=True)
class PivotChain:
    """A discovered linked-server pivot chain.

    The chain is *theoretical* until each hop's identity is probed via
    ``identity_fingerprint_at_link``. The presentation layer reads
    :attr:`probed` to know which hops to render bold and which dim.
    """

    entry_server: str
    hops: tuple[PivotHop, ...]
    probed: bool
    discovery_seconds: float

    @property
    def length(self) -> int:
        return len(self.hops)

    @property
    def reaches_sysadmin(self) -> bool:
        return any(hop.is_sysadmin for hop in self.hops)

    @property
    def terminal_hop(self) -> PivotHop | None:
        return self.hops[-1] if self.hops else None


@dataclass(frozen=True, slots=True)
class ServerLogin:
    """One row of ``sys.server_principals`` joined with ``syslogins`` flags.

    Captured by :meth:`ImpacketMSSQLBackend.enumerate_logins`. The
    ``flags`` map is a typed projection of the canonical fixed-server
    roles a principal has been granted — ``sysadmin``, ``securityadmin``,
    ``dbcreator``, etc. ``None`` means the row had no ``syslogins``
    counterpart (typical for Windows groups before they are mapped).
    """

    name: str
    type_desc: str
    is_disabled: bool
    flags: dict[str, bool] = field(default_factory=dict)

    @property
    def is_sysadmin(self) -> bool:
        return bool(self.flags.get("sysadmin"))


@dataclass(frozen=True, slots=True)
class ImpersonationGrant:
    """One ``IMPERSONATE`` grant — server scope or database scope.

    Returned by :meth:`ImpacketMSSQLBackend.enumerate_impersonation_map`.
    The ``scope`` field is ``"LOGIN"`` for server-level grants and
    ``"USER"`` for database-level grants. ``database`` is empty for the
    server-level rows, populated for the per-database rows.
    """

    scope: str  # "LOGIN" | "USER"
    database: str
    permission_name: str  # IMPERSONATE | IMPERSONATE_ANY_LOGIN | …
    state_desc: str  # GRANT | DENY | GRANT_WITH_GRANT_OPTION
    grantee: str
    grantor: str


@dataclass(frozen=True, slots=True)
class CommandExecution:
    """Outcome of one ``xp_cmdshell`` invocation.

    Carries the full evidence needed to (a) print the premium "pop card"
    in the CLI, (b) auto-generate a report evidence block, and (c) emit a
    ``derived`` edge in the attack graph.
    """

    host: str
    command: str
    sql_executed: str
    success: bool
    stdout: str
    stderr: str
    duration_seconds: float
    via_linked_server: str | None = None
    integrity_hint: IntegrityHint = IntegrityHint.UNKNOWN
    error_message: str | None = None

    @property
    def stdout_lines(self) -> tuple[str, ...]:
        return tuple(line for line in (self.stdout or "").splitlines() if line)

    @property
    def is_terminal_win(self) -> bool:
        """Whether this execution should promote the path state."""
        return self.success and self.integrity_hint == IntegrityHint.SYSTEM


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def coalesce_permissions(
    rows: Sequence[Mapping[str, object]],
) -> tuple[tuple[str, str, str], ...]:
    """Normalize ``sys.fn_my_permissions`` rows to a tuple-of-tuples.

    Some drivers return entity_name as ``None`` for server-scope grants.
    We collapse those to empty strings so the presentation layer never has
    to ``or ""`` defensively.
    """
    result: list[tuple[str, str, str]] = []
    for row in rows:
        entity = str(row.get("entity_name") or "").strip()
        permission = str(row.get("permission_name") or "").strip()
        state = str(row.get("state_desc") or "").strip()
        if not permission:
            continue
        result.append((entity, permission, state))
    return tuple(result)


__all__ = [
    "XpCmdshellStatus",
    "IntegrityHint",
    "IdentityFingerprint",
    "PrivilegeSweep",
    "LinkedServer",
    "PivotHop",
    "PivotChain",
    "CommandExecution",
    "ServerLogin",
    "ImpersonationGrant",
    "coalesce_permissions",
]
