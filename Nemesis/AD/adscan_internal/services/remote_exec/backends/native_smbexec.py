"""smbexec backend (SCMR services) — native via aiosmb.

Wraps :meth:`aiosmb.commons.interfaces.machine.SMBMachine.service_cmd_exec`.
Streams stdout chunks back to the cascade as they arrive.
"""

from __future__ import annotations

from adscan_internal.services.remote_exec.backends._native_runner import run_streaming
from adscan_internal.services.remote_exec.models import ExecMethod, RemoteExecResult
from adscan_internal.services.smb_transport import SMBConfig


async def execute(config: SMBConfig, command: str, *, timeout: int) -> RemoteExecResult:
    """Run ``command`` via SCMR services (smbexec-style).

    Args:
        config: Authenticated SMB config.
        command: Command line to execute on the remote host.
        timeout: Per-call timeout in seconds.

    Returns:
        :class:`RemoteExecResult` with ``method=ExecMethod.SMBEXEC`` and
        ``captures_stdout=True``.

    Raises:
        AuthError: Credentials were rejected — caller must abort the cascade.
    """

    def _open(machine):
        return machine.service_cmd_exec(command, result_wait_timeout=timeout)

    return await run_streaming(config, ExecMethod.SMBEXEC, _open, timeout=timeout)


__all__ = ["execute"]
