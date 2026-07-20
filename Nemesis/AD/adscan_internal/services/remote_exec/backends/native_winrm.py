"""WinRM execution backend.

Wraps :class:`adscan_internal.services.winrm_psrp_service.WinRMPSRPService`.
Translates the PSRP execution result and exceptions into the cascade's
:class:`RemoteExecResult` / :class:`MethodFailure` contract. Does NOT
reimplement PowerShell remoting — that lives in
:mod:`adscan_internal.services.winrm_psrp_service`.

Note on stdout: PowerShell remoting captures stdout natively, unlike
WMI/DCOM which only return exit codes. WinRM is the cleanest stdout path
in the cascade (alongside SMBEXEC/ATEXEC).
"""

from __future__ import annotations

import asyncio
import time

from adscan_core.rich_output import print_info_debug
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
from adscan_internal.services.smb_transport import SMBConfig
from adscan_internal.services.winrm_psrp_service import (
    WinRMPSRPError,
    WinRMPSRPService,
    is_clock_skew_error,
)


_AUTH_MARKERS_LOWER = (
    "unauthorized",
    "status_logon_failure",
    "access is denied to the wsman service",
    "bad http response 401",
    "bad http response: 401",
    "credentials were rejected",
    "logon failure",
    "invalid credentials",
)


def _looks_like_auth_failure(message: str) -> bool:
    """Return True when *message* matches a WinRM credential-rejection pattern."""
    lowered = (message or "").lower()
    return any(marker in lowered for marker in _AUTH_MARKERS_LOWER)


def _wrap_command_for_psrp(command: str) -> str:
    """Wrap a shell command so PSRP captures stdout reliably.

    Heuristic:
      * If the command already looks like a PowerShell snippet
        (``powershell ...``, ``pwsh ...``, ``$...``), pass it through.
      * Otherwise wrap it as ``cmd /c <command>`` so PSRP returns the
        downstream stdout via PowerShell's pipeline.
    """
    text = (command or "").strip()
    if not text:
        return text
    head = text.split(None, 1)[0].lower()
    if head in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"} or text.startswith(
        "$"
    ):
        return text
    escaped = text.replace("'", "''")
    return f"& {{ cmd /c '{escaped}' }}"


def _resolve_secret(config: SMBConfig) -> str:
    """Pick the secret to hand to ``WinRMPSRPService`` from an SMBConfig.

    Order of preference matches the existing PSRP service contract:
      1. ccache path (Kerberos)
      2. password
      3. NT hash (the service normalises bare NT hashes for NTLM auth)
    """
    if config.ccache_path:
        return config.ccache_path
    if config.password:
        return config.password
    if config.nt_hash:
        return config.nt_hash
    return ""


async def execute(
    config: SMBConfig, command: str, *, timeout: int
) -> RemoteExecResult:
    """Run ``command`` on ``config.target_ip`` via PowerShell remoting (PSRP).

    Args:
        config: Authenticated SMB-style config; reused here as the
            credential carrier so the cascade can keep one config type.
        command: Command line to execute on the remote host.
        timeout: Per-call timeout in seconds.

    Returns:
        :class:`RemoteExecResult` with ``method=ExecMethod.WINRM`` and
        ``captures_stdout=True``.

    Raises:
        AuthError: Credentials were rejected — caller must abort cascade.
    """
    started = time.monotonic()

    target_host = (config.target_hostname or "").strip() or (
        config.target_ip or ""
    ).strip()
    domain = (config.domain or config.auth_domain or "").strip()
    username = (config.username or "").strip()
    secret = _resolve_secret(config)

    script = _wrap_command_for_psrp(command)
    print_info_debug(
        "[remote_exec.winrm] dispatching PSRP exec: "
        f"host={target_host} user={username} domain={domain} "
        f"timeout={timeout}s"
    )

    def _build_failure(kind: str, message: str) -> RemoteExecResult:
        return RemoteExecResult(
            success=False,
            method=ExecMethod.WINRM,
            stdout="",
            stderr=message,
            return_code=None,
            captures_stdout=True,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            errors=(
                MethodFailure(
                    method=ExecMethod.WINRM,
                    error_kind=kind,  # type: ignore[arg-type]
                    message=message,
                ),
            ),
        )

    try:
        svc = WinRMPSRPService(
            domain=domain,
            host=target_host,
            username=username,
            password=secret,
            auth_mode="auto",
            kerberos_spn_host=config.target_hostname or None,
            kdc_ip=config.kdc_ip or None,
            posture_snapshot=getattr(config, "posture_snapshot", None),
        )
        result = await asyncio.wait_for(
            svc.async_execute_powershell(
                script,
                operation_name="remote_exec.cascade.winrm",
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return _build_failure("timeout", f"WinRM PSRP timed out after {timeout}s")
    except WinRMPSRPError as exc:
        message = str(exc)
        if _looks_like_auth_failure(message):
            raise AuthError(message) from exc
        if is_clock_skew_error(exc):
            return _build_failure("other", "clock_skew")
        kind, sanitised = classify_native_exec_error(message)
        if kind == "auth":
            raise AuthError(sanitised) from exc
        return _build_failure(kind, sanitised)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        message = str(exc)
        if _looks_like_auth_failure(message):
            raise AuthError(message) from exc
        kind, sanitised = classify_native_exec_error(message)
        if kind == "auth":
            raise AuthError(sanitised) from exc
        return _build_failure(kind, sanitised)

    elapsed_ms = int((time.monotonic() - started) * 1000)
    return RemoteExecResult(
        success=not result.had_errors,
        method=ExecMethod.WINRM,
        stdout=result.stdout or "",
        stderr=result.stderr or "",
        return_code=None,
        captures_stdout=True,
        process_id=None,
        elapsed_ms=elapsed_ms,
        errors=(),
    )


__all__ = ["execute"]
