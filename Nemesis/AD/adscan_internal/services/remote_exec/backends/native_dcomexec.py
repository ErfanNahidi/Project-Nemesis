"""dcomexec backend — native via aiosmb DCOM siblings.

Tries the three DCOM activation paths in order:

1. ``MMC20.Application`` — most reliable on modern Windows.
2. ``ShellWindows`` — fallback when MMC20 is hardened.
3. ``ShellBrowserWindow`` — last resort.

The first sibling whose ``(success, err)`` returns ``success=True`` and
``err is None`` wins. None of these primitives capture stdout — the
spawned process runs detached, so the cascade auto-skips this backend
when the caller requires output.
"""

from __future__ import annotations

import time

from adscan_internal import telemetry
from adscan_internal.services.remote_exec.backends._common import (
    classify_native_exec_error,
)
from adscan_internal.services.remote_exec.models import (
    AuthError,
    ExecMethod,
    MethodFailure,
    RemoteExecResult,
)
from adscan_internal.services.smb_transport import (
    SMBAccessDeniedError,
    SMBAuthError,
    SMBConfig,
    SMBTransportError,
    smb_machine_with_fallback,
)

_SIBLINGS: tuple[str, ...] = (
    "mmc20_cmd_exec",
    "shellwindows_cmd_exec",
    "shellbrowserwindow_cmd_exec",
)


async def execute(config: SMBConfig, command: str, *, timeout: int) -> RemoteExecResult:
    """Run ``command`` via DCOM activation (MMC20 → ShellWindows → ShellBrowserWindow).

    Args:
        config: Authenticated SMB config.
        command: Command line to execute on the remote host.
        timeout: Per-call timeout in seconds (applied per sibling).

    Returns:
        :class:`RemoteExecResult` with ``method=ExecMethod.DCOMEXEC``
        and ``captures_stdout=False``.

    Raises:
        AuthError: Credentials were rejected on any sibling — abort cascade.
    """
    import asyncio

    started = time.monotonic()
    sibling_failures: list[MethodFailure] = []

    try:
        async with smb_machine_with_fallback(config) as machine:
            for primitive_name in _SIBLINGS:
                primitive = getattr(machine, primitive_name, None)
                if primitive is None:
                    sibling_failures.append(
                        MethodFailure(
                            method=ExecMethod.DCOMEXEC,
                            error_kind="not_supported",
                            message=f"{primitive_name} not exposed by aiosmb",
                        )
                    )
                    continue

                try:
                    success, err = await asyncio.wait_for(
                        primitive(command), timeout=timeout
                    )
                except asyncio.TimeoutError:
                    sibling_failures.append(
                        MethodFailure(
                            method=ExecMethod.DCOMEXEC,
                            error_kind="timeout",
                            message=f"{primitive_name} timed out after {timeout}s",
                        )
                    )
                    continue
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    kind, message = classify_native_exec_error(str(exc))
                    if kind == "auth":
                        raise AuthError(message) from exc
                    sibling_failures.append(
                        MethodFailure(
                            method=ExecMethod.DCOMEXEC,
                            error_kind=kind,  # type: ignore[arg-type]
                            message=f"{primitive_name}: {message}",
                        )
                    )
                    continue

                if err is not None:
                    kind, message = classify_native_exec_error(str(err))
                    if kind == "auth":
                        raise AuthError(message)
                    sibling_failures.append(
                        MethodFailure(
                            method=ExecMethod.DCOMEXEC,
                            error_kind=kind,  # type: ignore[arg-type]
                            message=f"{primitive_name}: {message}",
                        )
                    )
                    continue

                if success:
                    return RemoteExecResult(
                        success=True,
                        method=ExecMethod.DCOMEXEC,
                        stdout="",
                        captures_stdout=False,
                        elapsed_ms=int((time.monotonic() - started) * 1000),
                        errors=tuple(sibling_failures),
                    )

                sibling_failures.append(
                    MethodFailure(
                        method=ExecMethod.DCOMEXEC,
                        error_kind="other",
                        message=f"{primitive_name}: returned success=False with no error",
                    )
                )
    except SMBAuthError as exc:
        raise AuthError(str(exc)) from exc
    except SMBAccessDeniedError as exc:
        sibling_failures.append(
            MethodFailure(
                method=ExecMethod.DCOMEXEC,
                error_kind="access_denied",
                message=str(exc)[:240],
            )
        )
    except SMBTransportError as exc:
        sibling_failures.append(
            MethodFailure(
                method=ExecMethod.DCOMEXEC,
                error_kind="network",
                message=str(exc)[:240],
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        kind, message = classify_native_exec_error(str(exc))
        if kind == "auth":
            raise AuthError(message) from exc
        sibling_failures.append(
            MethodFailure(
                method=ExecMethod.DCOMEXEC,
                error_kind=kind,  # type: ignore[arg-type]
                message=message,
            )
        )

    return RemoteExecResult(
        success=False,
        method=ExecMethod.DCOMEXEC,
        captures_stdout=False,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        errors=tuple(sibling_failures),
    )


__all__ = ["execute"]
