"""Method catalog for the remote-exec cascade.

Each entry pairs an :class:`ExecMethod` with a static metadata block —
opsec score, stdout capability, and a coarse detection signature. The
selector reads this catalog to rank methods at runtime; new backends are
added by appending to :data:`REMOTE_EXEC_METHODS`.
"""

from __future__ import annotations

from dataclasses import dataclass

from adscan_internal.services.remote_exec.models import ExecMethod


@dataclass(frozen=True)
class RemoteExecMethodMeta:
    """Static metadata for one remote-execution backend.

    Attributes:
        method: The :class:`ExecMethod` this entry describes.
        captures_stdout: True when the backend returns process output.
        opsec_score: 1=loud, 5=stealthy. Roughly inverse to detection
            mirror coverage in real-world EDR rules.
        detection_signature: Coarse class of the IOC the backend leaves
            behind. Used by the selector to apply uniform penalties.
        description: Human-readable summary for panels and logs.
    """

    method: ExecMethod
    captures_stdout: bool
    opsec_score: int
    detection_signature: str
    description: str


REMOTE_EXEC_METHODS: tuple[RemoteExecMethodMeta, ...] = (
    RemoteExecMethodMeta(
        method=ExecMethod.SMBEXEC,
        captures_stdout=True,
        opsec_score=2,
        detection_signature="service_create",
        description="SCMR service install — fires Event 7045, top-tier IOC.",
    ),
    RemoteExecMethodMeta(
        method=ExecMethod.ATEXEC,
        captures_stdout=True,
        opsec_score=3,
        detection_signature="scheduled_task",
        description="Scheduled task via TSCH — Event 4698, less mirrored than 7045.",
    ),
    RemoteExecMethodMeta(
        method=ExecMethod.WMIEXEC,
        captures_stdout=False,
        opsec_score=2,
        detection_signature="wmi_process",
        description="WMI Win32_Process.Create — WmiPrvSE→cmd is widely flagged.",
    ),
    RemoteExecMethodMeta(
        method=ExecMethod.DCOMEXEC,
        captures_stdout=False,
        opsec_score=3,
        detection_signature="dcom_mmc20",
        description="DCOM MMC20 / ShellWindows — mmc.exe parent is less covered.",
    ),
    RemoteExecMethodMeta(
        method=ExecMethod.WINRM,
        captures_stdout=True,
        opsec_score=4,
        detection_signature="winrm_psrp",
        description="PowerShell remoting over WinRM (5985/5986). Reaches hosts with SMB hardened.",
    ),
)

METHOD_META_BY_EXEC: dict[ExecMethod, RemoteExecMethodMeta] = {
    m.method: m for m in REMOTE_EXEC_METHODS
}


__all__ = [
    "RemoteExecMethodMeta",
    "REMOTE_EXEC_METHODS",
    "METHOD_META_BY_EXEC",
]
