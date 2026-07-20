"""Microsoft Defender scanner via MSSQL xp_cmdshell on a remote Windows host.

Two scan modes controlled by ``DefenderTarget.scan_mode``:

MPCMDRUN (default in previous code, kept for compatibility)
    Upload to an exclusion-listed directory, run
    ``MpCmdRun -Scan -ScanType 3``, parse "found no threats" / "threat".
    Fast but misses ML/cloud-reputation detection because MpCmdRun static
    scan does not trigger the cloud lookup pipeline.

RTP  (recommended for evasion research)
    Upload to a normal temp path (no exclusion), wait for Defender's
    real-time protection to scan the file, then query Get-MpThreat for
    detections in the last 60s.  If the upload itself is blocked the
    verdict is UPLOAD_BLOCKED.  This is the same detection path that
    fires in production — it catches ML/cloud detections that the
    MpCmdRun static scan misses.

Lifecycle is identical for both modes:
    setup() → scan*() → teardown()

The orchestrator (toggle_ablation, truncation_bisect) drives the
lifecycle; user code only calls scan().

Why xp_cmdshell / MSSQL:
    The lab credential (jon.snow) is a SQL sysadmin on castelblack.
    Adding WinRM or SMB-based backends is a one-file change that
    implements the same DefenderScanner protocol — the registry
    handles dispatch.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from avlab.core.models import ScanResult, ScanVerdict
from avlab.core.workspace import Workspace
from avlab.scanners.base import ScanRequest

from adscan_internal.integrations.mssql import ImpacketMSSQLBackend


_MPCMDRUN = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
_RTP_WAIT_S = 3   # seconds to let RTP finish scanning after upload


class ScanMode(str, Enum):
    MPCMDRUN = "mpcmdrun"
    RTP = "rtp"


@dataclass(frozen=True, slots=True)
class DefenderTarget:
    """Connection info for the Windows host running Defender."""

    host: str
    domain: str
    username: str
    password: str
    port: int = 1433
    remote_dir: str = r"C:\avlab"
    scan_mode: ScanMode = ScanMode.RTP
    rtp_temp_dir: str = r"C:\Windows\Temp"
    """Where RTP-mode artefacts are dropped. Must NOT be in the exclusion list."""
    rtp_wait_seconds: int = _RTP_WAIT_S
    """How long to wait after upload for RTP to finish scanning."""

    # SMB upload transport (optional).
    # When set, artefacts are uploaded via SMB C$ share as smb_username
    # instead of MSSQL base64 upload. Required when Defender's WdFilter
    # intercepts the PowerShell base64-decode write used by MSSQL upload.
    smb_username: str = ""
    smb_password: str = ""


class DefenderScanner:
    """Scanner protocol — Defender on a remote Windows host via xp_cmdshell.

    Construct with :class:`DefenderTarget` + :class:`Workspace`, then call
    ``setup → scan* → teardown``.  Scan mode (MPCMDRUN vs RTP) is set on
    the target — no code changes needed to switch.
    """

    name = "defender"

    def __init__(self, target: DefenderTarget, workspace: Workspace) -> None:
        self.target = target
        self.workspace = workspace
        self._backend = ImpacketMSSQLBackend(host=target.host, port=target.port)

    # ------------------------------------------------------------------
    # Lifecycle — MPCMDRUN mode needs an exclusion dir; RTP mode does not
    # ------------------------------------------------------------------

    def setup(self) -> None:
        t = self.target
        if t.scan_mode == ScanMode.MPCMDRUN:
            self._exec(
                rf"cmd /c if not exist {t.remote_dir} mkdir {t.remote_dir}",
                timeout=15,
                log_label="__setup__",
            )
            self._exec(
                f'powershell -NoP -C "Add-MpPreference -ExclusionPath '
                f"'{t.remote_dir}' -ErrorAction SilentlyContinue\"",
                timeout=30,
                log_label="__setup__",
            )
        else:
            # RTP: no exclusion — we WANT Defender to scan the file on arrival.
            # Just ensure the temp dir exists (it always does on Windows but
            # be defensive).
            self._exec(
                rf"cmd /c if not exist {t.rtp_temp_dir} mkdir {t.rtp_temp_dir}",
                timeout=15,
                log_label="__setup__",
            )

    def teardown(self) -> None:
        t = self.target
        if t.scan_mode == ScanMode.MPCMDRUN:
            self._exec(
                f'powershell -NoP -C "Remove-MpPreference -ExclusionPath '
                f"'{t.remote_dir}' -ErrorAction SilentlyContinue\"",
                timeout=30,
                log_label="__teardown__",
            )
            self._exec(
                rf'cmd /c rmdir /S /Q "{t.remote_dir}"',
                timeout=30,
                log_label="__teardown__",
            )
        # RTP mode: no exclusion to remove; temp files are cleaned per-scan

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def scan(self, request: ScanRequest) -> ScanResult:
        if self.target.scan_mode == ScanMode.RTP:
            return self._scan_rtp(request)
        return self._scan_mpcmdrun(request)

    def _scan_rtp(self, request: ScanRequest) -> ScanResult:
        """Upload to a non-excluded path, let RTP scan it, query Get-MpThreat."""
        t = self.target
        artefact = Path(request.artefact_path)
        token = secrets.token_hex(6)
        remote_path = rf"{t.rtp_temp_dir}\avlab_{token}.exe"

        started = time.monotonic()

        upload = self._upload(artefact, remote_path, request)
        if not upload.success:
            return ScanResult(
                variant_name=request.variant_name,
                scanner_name=self.name,
                verdict=ScanVerdict.UPLOAD_BLOCKED,
                duration_seconds=time.monotonic() - started,
                raw_output=getattr(upload, "message", "") or "",
                error_message="upload blocked by RTP",
            )

        # Give RTP time to scan the newly-written file.
        time.sleep(t.rtp_wait_seconds)

        # Check if file was quarantined BEFORE we delete it: if Defender
        # removed it already, that's a DETECTED signal even if Get-MpThreat
        # hasn't recorded the name yet (race window).
        still_exists = self._file_exists(remote_path, request.variant_name)

        # Query recent threats — anything detected in the last 60s counts.
        threats = self._get_recent_threats(
            request.variant_name, window_seconds=60
        )

        # Best-effort delete (may already be quarantined/gone).
        self._exec(
            rf'cmd /c del /f /q "{remote_path}" 2>nul',
            timeout=15,
            log_label=request.variant_name,
        )

        # Verdict: quarantined by RTP (GONE without our delete) OR threat listed.
        quarantined = still_exists is False   # file missing before our delete
        if threats or quarantined:
            verdict = ScanVerdict.DETECTED
        else:
            verdict = ScanVerdict.CLEAN

        return ScanResult(
            variant_name=request.variant_name,
            scanner_name=self.name,
            verdict=verdict,
            duration_seconds=time.monotonic() - started,
            threat_names=threats,
            raw_output="",
        )

    def _scan_mpcmdrun(self, request: ScanRequest) -> ScanResult:
        """Upload to excluded dir, run MpCmdRun -ScanType 3, parse output."""
        t = self.target
        artefact = Path(request.artefact_path)
        remote_path = rf"{t.remote_dir}\{_safe_remote_name(artefact.name)}"

        started = time.monotonic()

        upload = self._upload(artefact, remote_path, request)
        if not upload.success:
            return ScanResult(
                variant_name=request.variant_name,
                scanner_name=self.name,
                verdict=ScanVerdict.UPLOAD_BLOCKED,
                duration_seconds=time.monotonic() - started,
                raw_output=getattr(upload, "message", "") or "",
                error_message="upload blocked",
            )

        # cmd.exe quoting: wrap with cmd /c "..." so the inner quoted path
        # survives xp_cmdshell's cmd /c invocation without stripping.
        scan_cmd = (
            f'cmd /c "\\"{_MPCMDRUN}\\" -Scan -ScanType 3 -File \\"{remote_path}\\" '
            '-DisableRemediation -Trace -Level 0x10"'
        )
        result = self._exec(
            scan_cmd, timeout=request.timeout_seconds,
            log_label=request.variant_name,
        )
        out = result.stdout or ""
        lower = out.lower()

        self._exec(
            rf'cmd /c del /f /q "{remote_path}" 2>nul',
            timeout=15,
            log_label=request.variant_name,
        )

        verdict, error = _classify_mpcmdrun_output(lower, result.success)
        threats: tuple[str, ...] = ()
        if verdict == ScanVerdict.DETECTED:
            threats = self._collect_threat_names(request.variant_name)

        return ScanResult(
            variant_name=request.variant_name,
            scanner_name=self.name,
            verdict=verdict,
            duration_seconds=time.monotonic() - started,
            threat_names=threats,
            raw_output=_truncate(out),
            error_message=error,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _upload(self, artefact: Path, remote_path: str, request: ScanRequest):
        t = self.target
        if t.smb_username:
            return self._upload_smb(artefact, remote_path, request)
        up = self._backend.upload_file(
            domain=t.domain,
            username=t.username,
            secret=t.password,
            local_path=str(artefact),
            remote_path=remote_path,
            timeout=max(60, request.timeout_seconds * 2),
        )
        self._log(
            request.variant_name,
            f"$ upload(mssql) {artefact.name} → {remote_path}\n"
            f"  success={up.success}\n",
        )
        return up

    def _upload_smb(self, artefact: Path, remote_path: str, request: ScanRequest):
        """Upload via SMB C$ share using the adscan_internal RemoteWindowsExecution layer.

        Delegates to :meth:`RemoteWindowsExecution.upload_file` with
        ``preferred_transport="smb"``.  This reuses the tested aiosmb path
        (including correct event-loop handling) that the rest of ADscan uses,
        and avoids reimplementing asyncio.run() in the scanner.
        """
        from adscan_internal.services.exploitation.remote_windows_execution import (
            RemoteWindowsAuth,
            RemoteWindowsExecution,
        )

        t = self.target
        auth = RemoteWindowsAuth(
            domain=t.domain,
            host=t.host,
            username=t.smb_username,
            secret=t.smb_password,
        )
        svc = RemoteWindowsExecution()
        result = svc.upload_file(
            auth,
            local_path=str(artefact),
            remote_path=remote_path,
            preferred_transport="smb",
            timeout=120,
        )

        self._log(
            request.variant_name,
            f"$ upload(smb) {artefact.name} → {remote_path}\n"
            f"  transport={result.transport} success={result.success}"
            f" err={result.error_message}\n",
        )
        return result

    def _get_recent_threats(
        self, variant_name: str, *, window_seconds: int
    ) -> tuple[str, ...]:
        """Return threat names detected in the last ``window_seconds`` seconds."""
        cmd = (
            f'powershell -NoP -C "'
            f"$cutoff = (Get-Date).AddSeconds(-{window_seconds}); "
            f"Get-MpThreat | Where-Object {{$_.InitialDetectionTime -gt $cutoff}} | "
            f"Sort-Object InitialDetectionTime -Descending | "
            f'Select-Object -ExpandProperty ThreatName"'
        )
        r = self._exec(cmd, timeout=30, log_label=variant_name)
        seen: list[str] = []
        for line in (r.stdout or "").splitlines():
            name = line.strip()
            if name and name not in seen and name != "NULL":
                seen.append(name)
        return tuple(seen)

    def _collect_threat_names(self, variant_name: str) -> tuple[str, ...]:
        """Most recent 5 threat names — for MPCMDRUN mode post-detection."""
        cmd = (
            'powershell -NoP -C "Get-MpThreat | Sort-Object -Property '
            'InitialDetectionTime -Descending | Select-Object -First 5 '
            '-ExpandProperty ThreatName"'
        )
        r = self._exec(cmd, timeout=30, log_label=variant_name)
        seen: list[str] = []
        for line in (r.stdout or "").splitlines():
            name = line.strip()
            if name and name not in seen and name != "NULL":
                seen.append(name)
        return tuple(seen)

    def _file_exists(self, remote_path: str, variant_name: str) -> bool | None:
        """Return True/False/None (None = command error)."""
        r = self._exec(
            f'cmd /c if exist "{remote_path}" (echo EXISTS) else (echo GONE)',
            timeout=10,
            log_label=variant_name,
        )
        out = (r.stdout or "").strip().upper()
        if "EXISTS" in out:
            return True
        if "GONE" in out:
            return False
        return None

    def _exec(self, command: str, *, timeout: int, log_label: str):
        t = self.target
        r = self._backend.execute_command(
            domain=t.domain,
            username=t.username,
            secret=t.password,
            command=command,
            host=t.host,
            timeout=timeout,
        )
        self._log(
            log_label,
            f"$ {command}\n"
            f"  success={r.success}\n"
            f"--- stdout ---\n{r.stdout or ''}\n",
        )
        return r

    def _log(self, variant_name: str, text: str) -> None:
        self.workspace.append_scanner_log(variant_name, self.name, text)


# ---------------------------------------------------------------------------
# Output classification for MpCmdRun mode
# ---------------------------------------------------------------------------


def _classify_mpcmdrun_output(
    lower_output: str, success: bool | None
) -> tuple[ScanVerdict, str | None]:
    if "found no threats" in lower_output:
        return ScanVerdict.CLEAN, None
    if "threat" in lower_output or "threats found" in lower_output:
        return ScanVerdict.DETECTED, None
    # xp_cmdshell success=False → MpCmdRun exited non-zero → detection
    if success is False:
        return ScanVerdict.DETECTED, None
    if success is True:
        return ScanVerdict.CLEAN, None
    return ScanVerdict.INCONCLUSIVE, "could not parse MpCmdRun output"


def _safe_remote_name(name: str) -> str:
    return name.replace("/", "_").replace("\\", "_")


def _truncate(text: str, limit: int = 2048) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 32] + f"\n…[truncated {len(text) - limit} chars]"


__all__ = ["DefenderScanner", "DefenderTarget", "ScanMode"]
