"""Source-agnostic parsers for MSSQL command output.

What lives here:

* :func:`parse_whoami_priv_output` — parses ``whoami /priv`` output, no
  matter how it was executed (native ``xp_cmdshell``, future WinRM,
  whatever). The format is a Windows OS contract.
* :func:`check_seimpersonate_privilege` — boolean wrapper on top.
* :func:`parse_xp_cmdshell_enable_failure_reason` — distils a SQL
  RECONFIGURE error into a one-line user-facing reason. Used to
  classify why a sysadmin attempt to flip ``xp_cmdshell`` failed.
* :class:`WindowsPrivilege` — typed record returned by the parser.

Anything that parsed NetExec stdout markers (``Pwn3d!``, ``[+]
Executed command via linked server``, etc.) was retired alongside the
NetExec subprocess backend.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


_PRIVILEGE_LINE = re.compile(
    r"^(Se\w+Privilege)\s+(.*?)\s+(Enabled|Disabled|Enabled by Default)\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class WindowsPrivilege:
    """One Windows token privilege parsed out of ``whoami /priv``."""

    name: str
    description: str
    state: str  # "Enabled", "Disabled", or "Enabled by Default"


def parse_whoami_priv_output(output: str) -> list[WindowsPrivilege]:
    """Parse ``whoami /priv`` text into structured privilege entries.

    The shape of ``whoami /priv`` is a Windows OS contract — independent
    of how the command was executed. Lines that do not match the
    privilege grammar are silently skipped.
    """
    if not output:
        return []

    privileges: list[WindowsPrivilege] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _PRIVILEGE_LINE.match(line)
        if match:
            privileges.append(
                WindowsPrivilege(
                    name=match.group(1),
                    description=match.group(2).strip(),
                    state=match.group(3),
                )
            )
    return privileges


def check_seimpersonate_privilege(output: str) -> bool:
    """Return whether ``SeImpersonatePrivilege`` is present and enabled."""
    if not output:
        return False

    for priv in parse_whoami_priv_output(output):
        if priv.name.lower() == "seimpersonateprivilege":
            return "Enabled" in priv.state

    # Fallback for localized or non-canonical output.
    return "SeImpersonatePrivilege" in output and (
        "Enabled" in output or "Habilitado" in output  # Spanish Windows
    )


def parse_xp_cmdshell_enable_failure_reason(output: str) -> str | None:
    """Distil a one-line user-facing reason from an ``xp_cmdshell`` enable error.

    The output may come from native impacket TDS (``ERROR(...): Line 1:
    You do not have permission ...``) or any future transport — only the
    SQL-side error text is inspected.
    """
    if not output:
        return None

    normalized = output.lower()
    if (
        "do not have permission" in normalized
        or "permission to run the reconfigure statement" in normalized
        or ("failed to enable xp_cmdshell" in normalized and "reconfigure" in normalized)
    ):
        return "insufficient SQL privileges to run RECONFIGURE and enable xp_cmdshell"

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if "Failed to enable xp_cmdshell:" in line:
            return line.split("Failed to enable xp_cmdshell:", 1)[1].strip() or None

    if "xp_cmdshell is disabled" in normalized:
        return "xp_cmdshell is currently disabled and could not be enabled"

    return None


__all__ = [
    "WindowsPrivilege",
    "parse_whoami_priv_output",
    "check_seimpersonate_privilege",
    "parse_xp_cmdshell_enable_failure_reason",
]
