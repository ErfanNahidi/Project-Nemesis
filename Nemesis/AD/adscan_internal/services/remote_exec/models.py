"""Data model for the ``remote_exec`` package.

This module defines the public types every backend and the cascade
orchestrator share. Keep it dependency-light: no aiosmb, no rich, no
shell imports — only stdlib types so the module is importable from
both async and sync call sites and from tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal


class ExecMethod(StrEnum):
    """Remote command-execution backends supported by the cascade.

    The string value is what is recorded in :class:`RemoteExecResult`
    and in telemetry, so do not rename casually — downstream dashboards
    rely on these labels.
    """

    SMBEXEC = "smbexec"  # SCMR / Windows services (smbexec-style, captures stdout)
    ATEXEC = "atexec"  # Task Scheduler (TSCH, captures stdout)
    WMIEXEC = "wmiexec"  # WMI Win32_Process.Create (no stdout)
    DCOMEXEC = "dcomexec"  # MMC20 / ShellWindows / ShellBrowserWindow (no stdout)
    WINRM = "winrm"  # PowerShell remoting over WSMAN 5985/5986 (captures stdout)


# Closed catalogue of error kinds — keeps caller diagnostic logic uniform.
ErrorKind = Literal[
    "auth",
    "access_denied",
    "not_supported",
    "timeout",
    "network",
    "other",
]


@dataclass(frozen=True, slots=True)
class MethodFailure:
    """One failed attempt inside a cascade.

    Attributes:
        method: The :class:`ExecMethod` that produced this failure.
        error_kind: Coarse-grained category used by the cascade to
            decide whether to retry the next method or abort.
        message: Sanitised, human-readable error message — safe to show
            in logs and panels.
    """

    method: ExecMethod
    error_kind: ErrorKind
    message: str


@dataclass(frozen=True, slots=True)
class RemoteExecResult:
    """Result of a remote-execution attempt (success or final failure).

    Attributes:
        success: True iff at least one backend ran the command without
            an unrecoverable error.
        method: Which backend produced the result. ``None`` only when
            no backend ever ran (e.g. empty cascade).
        stdout: Captured standard output. **Always empty** for backends
            with ``captures_stdout=False`` (WMI, DCOM) — those primitives
            spawn the process server-side without piping output back.
            Callers that need the output must use a side channel
            (write-to-file + SMB read-back).
        stderr: Captured standard error, when the backend exposes it.
        return_code: Process return code if the backend reports one.
            For DCOM the value is ``None`` (success/failure only).
        captures_stdout: True when this backend can return process
            stdout. The cascade auto-skips backends with ``False`` when
            ``require_stdout=True`` (the default for stdout-consuming
            callers).
        process_id: PID of the spawned process when the backend exposes
            it (WMI returns one; SMBEXEC/ATEXEC/DCOM do not).
        elapsed_ms: Total wall-clock cost across the whole cascade,
            including failed attempts.
        errors: Per-method failures that happened before this success
            (or, for failed results, the full list of attempts).
    """

    success: bool
    method: ExecMethod | None
    stdout: str = ""
    stderr: str = ""
    return_code: int | None = None
    captures_stdout: bool = True
    process_id: int | None = None
    elapsed_ms: int = 0
    errors: tuple[MethodFailure, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class RemoteExecError(Exception):
    """Base class for all ``remote_exec`` failures."""


class AuthError(RemoteExecError):
    """Raised when credentials are rejected.

    The cascade must abort on this error — trying more methods with
    the same wrong credentials wastes time and risks lockout.
    """


class AllMethodsFailed(RemoteExecError):
    """Every method in the cascade was attempted and none succeeded.

    The :attr:`failures` tuple preserves the per-method diagnostic so
    the caller can render a helpful error panel.
    """

    def __init__(self, failures: tuple[MethodFailure, ...]) -> None:
        self.failures: tuple[MethodFailure, ...] = failures
        summary = ", ".join(f"{f.method}={f.error_kind}" for f in failures)
        super().__init__(f"All remote-exec methods failed: {summary or 'no attempts'}")


__all__ = [
    "ExecMethod",
    "ErrorKind",
    "MethodFailure",
    "RemoteExecResult",
    "RemoteExecError",
    "AuthError",
    "AllMethodsFailed",
]
