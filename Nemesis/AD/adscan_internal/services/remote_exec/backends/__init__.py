"""Backend registry for the remote-exec cascade.

Adding a new method = add a row here. The cascade orchestrator is
agnostic to which backend implements which method. Every backend is a
coroutine ``(config, command, *, timeout) -> RemoteExecResult`` that
either returns a result (success or non-fatal failure) or raises
:class:`AuthError` to abort the cascade.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from adscan_internal.services.remote_exec.backends import (
    native_atexec,
    native_dcomexec,
    native_smbexec,
    native_winrm,
    native_wmiexec,
)
from adscan_internal.services.remote_exec.models import ExecMethod, RemoteExecResult

BackendCallable = Callable[..., Awaitable[RemoteExecResult]]

# Mapping consumed only by the cascade. Private to the package.
BACKEND_REGISTRY: dict[ExecMethod, BackendCallable] = {
    ExecMethod.SMBEXEC: native_smbexec.execute,
    ExecMethod.ATEXEC: native_atexec.execute,
    ExecMethod.WMIEXEC: native_wmiexec.execute,
    ExecMethod.DCOMEXEC: native_dcomexec.execute,
    ExecMethod.WINRM: native_winrm.execute,
}


__all__ = ["BACKEND_REGISTRY", "BackendCallable"]
