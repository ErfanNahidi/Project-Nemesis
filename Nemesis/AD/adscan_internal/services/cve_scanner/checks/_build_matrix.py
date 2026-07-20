"""Shared OS-build classification helpers for CVE checks.

AD's ``operatingSystemVersion`` only exposes the *base* build (e.g.
``10.0 (17763)``) — not the cumulative-update revision. CVE checks that
gate on patch state therefore rely on coarse base-build matrices kept
here so the logic stays DRY and is independently unit-testable.
"""

from __future__ import annotations


def parse_base_build(os_version_raw: str | None) -> int | None:
    """Parse the integer base build out of an LDAP ``operatingSystemVersion``.

    Args:
        os_version_raw: The raw LDAP value (e.g. ``"10.0 (18362)"``) or
            ``None`` when the attribute was not exposed.

    Returns:
        The integer base build (``18362``), or ``None`` when the input
        is missing or unparseable.
    """
    if not os_version_raw:
        return None
    raw = str(os_version_raw).strip()
    _, _, build_part = raw.partition("(")
    build_str = build_part.rstrip(")").strip().split(".", 1)[0]
    try:
        return int(build_str)
    except ValueError:
        return None


# CVE-2020-0796 (SMBGhost) was introduced in Windows 10 1903 (build
# 18362) and 1909 (build 18363). It was patched in March 2020 in those
# same families. AD only exposes the base build — so a host advertising
# ``10.0 (18362)`` or ``10.0 (18363)`` MAY be vulnerable depending on the
# applied cumulative update; the SMB negotiate response gives the
# definitive signal via ``SMB2_COMPRESSION_CAPABILITIES``.
SMBGHOST_VULNERABLE_BASE_BUILDS: frozenset[int] = frozenset({18362, 18363})


def smbghost_build_signal(os_version_raw: str | None) -> tuple[bool, str]:
    """Return (build_in_window, why) for the SMBGhost build matrix.

    A build *in the SMBGhost window* (1903 / 1909) corroborates the
    SMB-side compression-capability signal. Other builds make the host
    not-applicable for SMBGhost regardless of compression caps.
    """
    build = parse_base_build(os_version_raw)
    if build is None:
        return (
            False,
            "operatingSystemVersion missing or unparseable — cannot corroborate build window",
        )
    if build in SMBGHOST_VULNERABLE_BASE_BUILDS:
        return True, f"OS base build {build} is in the SMBGhost window (1903/1909)"
    return False, f"OS base build {build} is outside the SMBGhost window (1903/1909)"


__all__ = [
    "SMBGHOST_VULNERABLE_BASE_BUILDS",
    "parse_base_build",
    "smbghost_build_signal",
]
