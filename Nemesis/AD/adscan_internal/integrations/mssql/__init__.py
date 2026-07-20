"""MSSQL integration — fully native impacket TDS backend.

The NetExec subprocess runner that this package shipped during the
migration window has been retired: there is now a single execution
surface — :class:`ImpacketMSSQLBackend` — and one premium presentation
layer for the CLI.

Typical usage::

    from adscan_internal.integrations.mssql import (
        ImpacketMSSQLBackend,
        print_mssql_sweep_card,
    )

    backend = ImpacketMSSQLBackend(host="sql01.corp.local")
    sweep = backend.sweep_privileges(
        domain="CORP", username="alice", secret="Password123!"
    )
    if sweep:
        print_mssql_sweep_card(sweep)
"""

from .helpers import is_hash_authentication
from .models import (
    CommandExecution,
    IdentityFingerprint,
    ImpersonationGrant,
    IntegrityHint,
    LinkedServer,
    PivotChain,
    PivotHop,
    PrivilegeSweep,
    ServerLogin,
    XpCmdshellStatus,
    coalesce_permissions,
)
from .native_backend import ImpacketMSSQLBackend, NativeMSSQLQueryResult
from .parsers import (
    WindowsPrivilege,
    check_seimpersonate_privilege,
    parse_whoami_priv_output,
    parse_xp_cmdshell_enable_failure_reason,
)
from .presentation import (
    print_mssql_command_card,
    print_mssql_pivot_chain,
    print_mssql_sweep_card,
    print_query_progress,
)

__all__ = [
    # Native backend + typed contracts
    "ImpacketMSSQLBackend",
    "NativeMSSQLQueryResult",
    "CommandExecution",
    "IdentityFingerprint",
    "ImpersonationGrant",
    "IntegrityHint",
    "LinkedServer",
    "PivotChain",
    "PivotHop",
    "PrivilegeSweep",
    "ServerLogin",
    "XpCmdshellStatus",
    "coalesce_permissions",
    # Premium presentation
    "print_mssql_sweep_card",
    "print_mssql_command_card",
    "print_mssql_pivot_chain",
    "print_query_progress",
    # Source-agnostic parsers
    "WindowsPrivilege",
    "parse_whoami_priv_output",
    "check_seimpersonate_privilege",
    "parse_xp_cmdshell_enable_failure_reason",
    # Helpers
    "is_hash_authentication",
]
