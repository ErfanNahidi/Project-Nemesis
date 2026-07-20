"""Native async remote-execution stack with method cascade.

Public API for ADscan flows that need to run a command on a remote
Windows host without forcing a single execution backend. Every backend
in this package is 100% native (aiosmb) — no NetExec subprocess.

Two cascades are exposed:

* :data:`STDOUT_CASCADE` — SMBEXEC → ATEXEC → WINRM. Use for callers
  that consume process output (the common case). WinRM is last-resort:
  it rides a distinct transport (PSRP / 5985) and reaches hosts where
  the SMB-based methods (445) are blocked or aggressively reset.
* :data:`DEFAULT_CASCADE` — SMBEXEC → ATEXEC → WMIEXEC → DCOMEXEC.
  Pass with ``require_stdout=False`` for fire-and-forget executions.

Quick start::

    from adscan_internal.services.remote_exec import (
        build_smb_config_from_credential,
        execute_with_fallback,
    )

    config = build_smb_config_from_credential(
        domain="htb.local",
        username="Administrator",
        secret="32693b11e6aa90eb43d32c72a07ceea6",
        secret_kind="nt_hash",
        target_host="forest.htb.local",
        target_ip="10.10.10.161",
    )
    result = await execute_with_fallback(config, 'cmd /c whoami')
"""

from __future__ import annotations

from adscan_internal.services.remote_exec.cascade import (
    DEFAULT_CASCADE,
    STDOUT_CASCADE,
    execute_with_fallback,
    raise_if_failed,
)
from adscan_internal.services.remote_exec.config_builder import (
    SecretKind,
    build_smb_config_from_credential,
)
from adscan_internal.services.remote_exec.models import (
    AllMethodsFailed,
    AuthError,
    ExecMethod,
    MethodFailure,
    RemoteExecError,
    RemoteExecResult,
)

__all__ = [
    "DEFAULT_CASCADE",
    "STDOUT_CASCADE",
    "ExecMethod",
    "MethodFailure",
    "RemoteExecResult",
    "RemoteExecError",
    "AuthError",
    "AllMethodsFailed",
    "execute_with_fallback",
    "raise_if_failed",
    "build_smb_config_from_credential",
    "SecretKind",
]
