"""Static catalogs for the CTF flag collector.

Pure data, no logic. Adding a new alternative path or a new excluded
walk directory should never require touching the orchestrator or the
strategy implementations — extend the tuples here and the rest of the
collector picks the change up automatically.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Strategy 2 — Alternative known paths (host-global, owner-independent).
# ---------------------------------------------------------------------------

ALTERNATIVE_FLAG_PATHS: tuple[str, ...] = (
    # Root of C: — common in beginner THM and crafted boxes.
    r"\C$\flag.txt",
    r"\C$\root.txt",
    r"\C$\user.txt",
    r"\C$\system.txt",
    r"\C$\proof.txt",
    # Public desktop — multi-user CTF setups.
    r"\C$\Users\Public\Desktop\flag.txt",
    r"\C$\Users\Public\Desktop\root.txt",
    r"\C$\Users\Public\Desktop\user.txt",
    r"\C$\Users\Public\flag.txt",
    # Web roots — IIS / XAMPP / Apache CTFs.
    r"\C$\inetpub\wwwroot\flag.txt",
    r"\C$\inetpub\wwwroot\user.txt",
    r"\C$\xampp\htdocs\flag.txt",
    # ProgramData.
    r"\C$\ProgramData\flag.txt",
    r"\C$\ProgramData\root.txt",
)


# Per-owner alternative path templates. ``{user}`` is filled at runtime.
PER_OWNER_ALTERNATIVE_TEMPLATES: tuple[str, ...] = (
    r"\C$\Users\{user}\Documents\flag.txt",
    r"\C$\Users\{user}\Documents\proof.txt",
    r"\C$\Users\{user}\Documents\user.txt",
    r"\C$\Users\{user}\Documents\root.txt",
    r"\C$\Users\{user}\flag.txt",
)


def build_alternative_candidates(
    users: tuple[str, ...] | list[str],
    *,
    max_total: int = 30,
) -> list[tuple[str, str, str | None]]:
    """Build ``(path, kind, owner)`` triples for the alternative strategy.

    Args:
        users: Candidate owner names for per-owner templates.
        max_total: Hard cap on total alternative paths (keeps latency bounded).

    Returns:
        List of ``(share_path, kind, owner_or_None)``. ``kind`` is inferred
        from the filename so the panel can display it accurately.
    """
    out: list[tuple[str, str, str | None]] = []

    for path in ALTERNATIVE_FLAG_PATHS:
        kind = _kind_from_basename(path)
        out.append((path, kind, None))

    for user in users:
        for template in PER_OWNER_ALTERNATIVE_TEMPLATES:
            path = template.format(user=user)
            kind = _kind_from_basename(path)
            out.append((path, kind, user))

    if len(out) > max_total:
        out = out[:max_total]
    return out


# ---------------------------------------------------------------------------
# Strategy 3 — Bounded SMB walk configuration.
# ---------------------------------------------------------------------------

WALK_DEPTH: int = 4
WALK_MAX_ENTRIES: int = 2000
WALK_MAX_FILE_SIZE: int = 1024
WALK_TIMEOUT_SECONDS: float = 18.0

# Roots launched in parallel — each gets its own ``list_r`` invocation.
#
# NOTE: the unbounded whole-drive ``\C$\\`` root was deliberately REMOVED.
# A full recursive walk of C: is the single most expensive operation in the
# collector and reliably exceeded the 25s hard cap on slow/unstable DCs — it
# was cancelled before reaching custom top-level directories (e.g.
# ``C:\share\transfer\user.txt``) and emitted no diagnostic. The dedicated
# roots below cover the common deep paths (user profiles, IIS, XAMPP); custom
# top-level directories are now covered cheaply by the shallow top-level
# discovery strategy (see ``TOP_LEVEL_*`` below), which lists ``\C$\`` once
# and runs a bounded shallow walk only on non-system, non-covered directories.
WALK_ROOTS: tuple[str, ...] = (
    r"\C$\Users\\",
    r"\C$\inetpub\\",
    r"\C$\xampp\\",
)

# Directory names skipped by the walk (case-insensitive match on basename).
# Each of these is enormous on a typical Windows host; they never carry
# CTF flags.
WALK_EXCLUDE_DIRS: tuple[str, ...] = (
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "$Recycle.Bin",
    "$WinREAgent",
    "$SysReset",
    "Recovery",
    "PerfLogs",
    "Microsoft",          # under ProgramData — huge, no flags
    "Package Cache",      # under ProgramData
    "WindowsApps",
    "SystemApps",
    "Microsoft.NET",
    "assembly",
)


# ---------------------------------------------------------------------------
# Strategy 3b — Shallow top-level ``C:\`` discovery configuration.
#
# Replaces the removed unbounded ``\C$\\`` walk. It lists the top level of
# ``\C$\`` once (one cheap directory enumeration), drops system directories
# and directories already covered by the dedicated roots, then runs a SHALLOW
# bounded walk on each remaining CUSTOM top-level directory (``share``,
# ``backup``, ``temp``, ``data``, …). Pure SMB byte-read, no command-exec —
# it works even when the exec cascade (smbexec/atexec/WinRM) is denied.
# ---------------------------------------------------------------------------

# Depth of the per-custom-dir shallow walk. ``C:\share\transfer\user.txt`` is
# reachable at depth 2 (share → transfer → user.txt). A small headroom (3)
# catches one more nesting level without inviting unbounded recursion.
TOP_LEVEL_WALK_DEPTH: int = 3

# Entry cap for each per-custom-dir shallow walk (much tighter than the deep
# roots — a custom flag directory is small by definition).
TOP_LEVEL_WALK_MAX_ENTRIES: int = 400

# Hard cap on how many custom top-level directories we shallow-walk. Bounds
# breadth so a host with dozens of top-level dirs can't eat the whole budget.
TOP_LEVEL_MAX_DIRS: int = 12

# Per-custom-dir shallow-walk timeout. Keeps any single slow directory from
# starving the others; the overall strategy still lives under the 25s cap.
TOP_LEVEL_PER_DIR_TIMEOUT_SECONDS: float = 4.0

# Timeout for the single top-level ``\C$\`` directory listing.
TOP_LEVEL_LIST_TIMEOUT_SECONDS: float = 5.0

# Top-level directory basenames (case-insensitive) already covered by a
# dedicated ``WALK_ROOTS`` entry — skip them in the top-level discovery to
# avoid duplicate work.
WALK_COVERED_TOP_LEVEL_DIRS: frozenset[str] = frozenset(
    {"users", "inetpub", "xampp"}
)

# Top-level directory basenames (case-insensitive) that are pure Windows
# system noise and never carry CTF flags — skipped on top of
# ``WALK_EXCLUDE_DIRS`` (which is matched everywhere, not just top-level).
# These are common ``C:\`` entries that ``WALK_EXCLUDE_DIRS`` may not name.
TOP_LEVEL_SYSTEM_DIRS: frozenset[str] = frozenset(
    {
        "windows",
        "program files",
        "program files (x86)",
        "programdata",
        "$recycle.bin",
        "$winreagent",
        "$sysreset",
        "recovery",
        "perflogs",
        "system volume information",
        "documents and settings",  # junction → Users on modern Windows
        "msocache",
        "config.msi",
        "intel",
        "amd",
        "nvidia",
        "drivers",
        "windows.old",
        "boot",
        "efi",
    }
)


def is_custom_top_level_dir(name: str) -> bool:
    """Return True if ``name`` is a CUSTOM top-level ``C:\\`` directory.

    A custom directory is one that is neither pure Windows system noise nor
    already covered by a dedicated walk root — i.e. exactly the kind of
    operator/box-author-created directory (``share``, ``backup``, ``data``)
    that may carry a flag in a non-standard path.

    Args:
        name: Top-level directory basename (no path).
    """
    if not name:
        return False
    lname = name.lower()
    if lname in WALK_COVERED_TOP_LEVEL_DIRS:
        return False
    if lname in TOP_LEVEL_SYSTEM_DIRS:
        return False
    if lname in {d.lower() for d in WALK_EXCLUDE_DIRS}:
        return False
    return True


# Filename extensions considered for flag candidates.
WALK_FLAG_EXTENSIONS: tuple[str, ...] = (".txt", ".flag")

# Exact filenames that are always plausible flag candidates.
WALK_FLAG_EXACT_NAMES: frozenset[str] = frozenset(
    {"user.txt", "root.txt", "system.txt", "flag.txt", "proof.txt"}
)

# Filename noise — names that match the extension filter but are
# extremely unlikely to carry a flag and are common on Windows.
WALK_NAME_NOISE: frozenset[str] = frozenset(
    {
        "readme.txt",
        "license.txt",
        "eula.txt",
        "changelog.txt",
        "install.txt",
        "history.txt",
        "version.txt",
        "manifest.txt",
        "desktop.ini",
        "thumbs.db",
    }
)

# Wildcard pattern: ``*flag*.txt`` (case-insensitive).
_FLAG_WILDCARD_RE = re.compile(r"flag", re.IGNORECASE)


def is_flag_candidate_name(name: str, *, size: int) -> bool:
    """Return True if the filename pattern + size look like a flag.

    Args:
        name: Basename only (no path).
        size: File size in bytes.
    """
    if not name:
        return False
    if size < 0 or size > WALK_MAX_FILE_SIZE:
        return False
    lname = name.lower()
    if lname in WALK_NAME_NOISE:
        return False
    if lname in WALK_FLAG_EXACT_NAMES:
        return True
    # extension gate
    if not any(lname.endswith(ext) for ext in WALK_FLAG_EXTENSIONS):
        return False
    if _FLAG_WILDCARD_RE.search(lname):
        return True
    return False


def _kind_from_basename(path: str) -> str:
    """Infer the flag kind from the file basename.

    Returns one of ``user``, ``root``, ``system``, ``flag``, ``proof``,
    ``unknown``.
    """
    base = path.rsplit("\\", 1)[-1].lower()
    if base.startswith("user"):
        return "user"
    if base.startswith("root"):
        return "root"
    if base.startswith("system"):
        return "system"
    if base.startswith("proof"):
        return "proof"
    if "flag" in base:
        return "flag"
    return "unknown"


__all__ = [
    "ALTERNATIVE_FLAG_PATHS",
    "PER_OWNER_ALTERNATIVE_TEMPLATES",
    "WALK_DEPTH",
    "WALK_MAX_ENTRIES",
    "WALK_MAX_FILE_SIZE",
    "WALK_TIMEOUT_SECONDS",
    "WALK_ROOTS",
    "WALK_EXCLUDE_DIRS",
    "WALK_FLAG_EXTENSIONS",
    "WALK_FLAG_EXACT_NAMES",
    "WALK_NAME_NOISE",
    "TOP_LEVEL_WALK_DEPTH",
    "TOP_LEVEL_WALK_MAX_ENTRIES",
    "TOP_LEVEL_MAX_DIRS",
    "TOP_LEVEL_PER_DIR_TIMEOUT_SECONDS",
    "TOP_LEVEL_LIST_TIMEOUT_SECONDS",
    "WALK_COVERED_TOP_LEVEL_DIRS",
    "TOP_LEVEL_SYSTEM_DIRS",
    "is_custom_top_level_dir",
    "build_alternative_candidates",
    "is_flag_candidate_name",
]
