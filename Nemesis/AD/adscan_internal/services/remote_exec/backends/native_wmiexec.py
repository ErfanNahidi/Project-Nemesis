"""wmiexec backend — native via aiosmb WMI Win32_Process.Create.

Wraps :meth:`aiosmb.commons.interfaces.machine.SMBMachine.wmi_cmd_exec`.
WMI does not capture stdout — the spawned process runs server-side
detached. The cascade auto-skips this backend when the caller requires
stdout (default for stdout-consuming flows).
"""

from __future__ import annotations

from adscan_internal.services.remote_exec.backends._native_runner import run_blind
from adscan_internal.services.remote_exec.models import ExecMethod, RemoteExecResult
from adscan_internal.services.smb_transport import SMBConfig


async def execute(config: SMBConfig, command: str, *, timeout: int) -> RemoteExecResult:
    """Run ``command`` via WMI Win32_Process.Create.

    Args:
        config: Authenticated SMB config.
        command: Command line to execute on the remote host.
        timeout: Per-call timeout in seconds.

    Returns:
        :class:`RemoteExecResult` with ``method=ExecMethod.WMIEXEC``,
        ``captures_stdout=False`` and ``process_id`` populated when the
        remote returns one.

    Raises:
        AuthError: Credentials were rejected.
    """

    async def _invoke(machine):
        return await machine.wmi_cmd_exec(command)

    return await run_blind(config, ExecMethod.WMIEXEC, _invoke, timeout=timeout)


__all__ = ["execute"]
