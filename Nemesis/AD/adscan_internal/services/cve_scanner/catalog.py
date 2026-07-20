"""Frozen registry of CVE definitions known to the native scanner.

Slice 1 only ships the five coercion-technique entries that are actually
wired up. Adding a new check is a two-step change: drop the
:class:`CVEDefinition` row here and add the check class.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from adscan_internal.services.cve_scanner.checks.base import CVECheck
from adscan_internal.services.cve_scanner.checks.coercion import CoercionCVECheck
from adscan_internal.services.cve_scanner.checks.badsuccessor import BadSuccessorCheck
from adscan_internal.services.cve_scanner.checks.drop_the_mic import DropTheMICCheck
from adscan_internal.services.cve_scanner.checks.ms17_010 import MS17_010Check
from adscan_internal.services.cve_scanner.checks.ntlm_reflection import (
    NTLMReflectionCheck,
)
from adscan_internal.services.cve_scanner.checks.printerbug import (
    PrinterBugSurfaceCheck,
)
from adscan_internal.services.cve_scanner.checks.smbghost import SMBGhostCheck
from adscan_internal.services.cve_scanner.checks.webdav import WebDAVCheck
from adscan_internal.services.cve_scanner.checks.nopac import NoPacCheck
from adscan_internal.services.cve_scanner.checks.printnightmare import (
    PrintNightmareCheck,
)
from adscan_internal.services.cve_scanner.checks.zerologon import ZerologonCheck
from adscan_internal.services.cve_scanner.result import Severity
from adscan_internal.services.edge_kind import EdgeKind


class TargetScope(str, Enum):
    """Where a CVE check applies."""

    DCS_ONLY = "dcs_only"
    ALL_HOSTS = "all_hosts"
    DOMAIN_LDAP = "domain_ldap"


@dataclass(frozen=True)
class CVEDefinition:
    """Catalog entry for one CVE the native scanner knows how to check."""

    id: str
    aka: str
    cvss_v3: float
    cvss_vector: str
    severity: Severity
    target_scope: TargetScope
    requires_auth: bool
    affects_protocol: str
    references: tuple[str, ...]
    mitre_attack: tuple[str, ...]
    check_class: type[CVECheck]
    graph_edge_relation: str | None
    graph_edge_kind: EdgeKind | None
    promotes_to_domain_breaker: bool
    technique: str | None = None


_PETITPOTAM_REFS = (
    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942",
    "https://github.com/topotam/PetitPotam",
)
_PRINTERBUG_REFS = ("https://github.com/leechristensen/SpoolSample",)
_SHADOWCOERCE_REFS = ("https://github.com/ShutdownRepo/ShadowCoerce",)
_MSEVEN_REFS = ("https://github.com/Wh04m1001/MS-EVEN",)
_DFSCOERCE_REFS = ("https://github.com/Wh04m1001/DFSCoerce",)


CVE_CATALOG: tuple[CVEDefinition, ...] = (
    CVEDefinition(
        id="ADSCAN-COERCION-PETITPOTAM",
        aka="PetitPotam",
        cvss_v3=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-EFSR",
        references=_PETITPOTAM_REFS,
        mitre_attack=("T1187",),
        check_class=CoercionCVECheck,
        graph_edge_relation="CoercePetitPotam",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        technique="PetitPotam",
    ),
    CVEDefinition(
        id="ADSCAN-COERCION-PRINTERBUG",
        aka="PrinterBug",
        cvss_v3=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-RPRN",
        references=_PRINTERBUG_REFS,
        mitre_attack=("T1187",),
        check_class=CoercionCVECheck,
        graph_edge_relation="CoercePrinterBug",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        technique="PrinterBug",
    ),
    CVEDefinition(
        id="ADSCAN-COERCION-DFSCOERCE",
        aka="DFSCoerce",
        cvss_v3=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-DFSNM",
        references=_DFSCOERCE_REFS,
        mitre_attack=("T1187",),
        check_class=CoercionCVECheck,
        graph_edge_relation="CoerceDFSCoerce",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        technique="DFSCoerce",
    ),
    CVEDefinition(
        id="ADSCAN-COERCION-SHADOWCOERCE",
        aka="ShadowCoerce",
        cvss_v3=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        severity=Severity.MEDIUM,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-FSRVP",
        references=_SHADOWCOERCE_REFS,
        mitre_attack=("T1187",),
        check_class=CoercionCVECheck,
        graph_edge_relation="CoerceShadowCoerce",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        technique="ShadowCoerce",
    ),
    CVEDefinition(
        id="ADSCAN-COERCION-MSEVENCOERCE",
        aka="MSEvenCoerce",
        cvss_v3=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        severity=Severity.MEDIUM,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-EVEN",
        references=_MSEVEN_REFS,
        mitre_attack=("T1187",),
        check_class=CoercionCVECheck,
        graph_edge_relation="CoerceMSEvenCoerce",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
        technique="MSEvenCoerce",
    ),
    # ----- Slice 2: Pack DC ------------------------------------------------
    CVEDefinition(
        id="CVE-2020-1472",
        aka="Zerologon",
        cvss_v3=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity=Severity.CRITICAL,
        target_scope=TargetScope.DCS_ONLY,
        requires_auth=False,
        affects_protocol="MS-NRPC",
        references=(
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472",
            "https://www.secura.com/uploads/whitepapers/Zerologon.pdf",
        ),
        mitre_attack=("T1068", "T1210"),
        check_class=ZerologonCheck,
        graph_edge_relation="Zerologon",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=True,
    ),
    CVEDefinition(
        id="CVE-2021-42278",
        aka="NoPac",
        cvss_v3=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity=Severity.HIGH,
        target_scope=TargetScope.DCS_ONLY,
        requires_auth=True,
        affects_protocol="MS-NRPC/Kerberos",
        references=(
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287",
            "https://github.com/cube0x0/noPac",
        ),
        mitre_attack=("T1068",),
        check_class=NoPacCheck,
        graph_edge_relation="NoPac",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=True,
    ),
    CVEDefinition(
        id="CVE-2021-34527",
        aka="PrintNightmare",
        cvss_v3=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-RPRN",
        references=(
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
            "https://github.com/calebstewart/CVE-2021-34527",
        ),
        mitre_attack=("T1068",),
        check_class=PrintNightmareCheck,
        graph_edge_relation="PrintNightmare",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=True,
    ),
    CVEDefinition(
        id="ADSCAN-BADSUCCESSOR-2025",
        aka="BadSuccessor",
        cvss_v3=9.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        severity=Severity.CRITICAL,
        target_scope=TargetScope.DCS_ONLY,
        requires_auth=True,
        affects_protocol="LDAP",
        references=(
            "https://www.akamai.com/blog/security-research/abusing-dmsa-for-priv-esc-in-active-directory",
        ),
        mitre_attack=("T1078.002", "T1098.001"),
        check_class=BadSuccessorCheck,
        graph_edge_relation="BadSuccessor",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=True,
    ),
    # ----- Slice 3: host-level CVEs and NTLM enablers --------------------
    CVEDefinition(
        id="CVE-2017-0144",
        aka="MS17-010",
        cvss_v3=8.1,
        cvss_vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=False,
        affects_protocol="SMBv1",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
        ),
        mitre_attack=("T1210",),
        check_class=MS17_010Check,
        graph_edge_relation="MS17-010",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
    ),
    CVEDefinition(
        id="CVE-2020-0796",
        aka="SMBGhost",
        cvss_v3=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=Severity.CRITICAL,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=False,
        affects_protocol="SMB 3.1.1",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796",
        ),
        mitre_attack=("T1210",),
        check_class=SMBGhostCheck,
        graph_edge_relation="SMBGhost",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
    ),
    CVEDefinition(
        id="ADSCAN-PRINTERBUG-SURFACE",
        aka="PrinterBugSurface",
        cvss_v3=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        severity=Severity.HIGH,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="MS-RPRN",
        references=(
            "https://github.com/leechristensen/SpoolSample",
            "https://posts.specterops.io/the-ghost-of-printer-past-87cd3a4f8ae3",
        ),
        mitre_attack=("T1187",),
        check_class=PrinterBugSurfaceCheck,
        graph_edge_relation="PrinterBugSurface",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
    ),
    CVEDefinition(
        id="ADSCAN-WEBDAV-ENABLED",
        aka="WebDAVEnabled",
        cvss_v3=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        severity=Severity.MEDIUM,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="SMB / WebClient",
        references=(
            "https://www.thehacker.recipes/ad/movement/ntlm/relay#webdav",
            "https://github.com/Wh04m1001/WebDAVPocs",
        ),
        mitre_attack=("T1187",),
        check_class=WebDAVCheck,
        graph_edge_relation="WebDAVEnabled",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
    ),
    CVEDefinition(
        id="CVE-2019-1166",
        aka="DropTheMIC",
        cvss_v3=6.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        severity=Severity.MEDIUM,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="NTLM",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1166",
            "https://www.preempt.com/blog/drop-the-mic/",
        ),
        mitre_attack=("T1557.001",),
        check_class=DropTheMICCheck,
        graph_edge_relation="DropTheMIC",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
    ),
    CVEDefinition(
        id="CVE-2019-1040",
        aka="NTLMReflection",
        cvss_v3=5.9,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        severity=Severity.MEDIUM,
        target_scope=TargetScope.ALL_HOSTS,
        requires_auth=True,
        affects_protocol="NTLM",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1040",
            "https://www.preempt.com/blog/active-directory-vulnerability-disclosure/",
        ),
        mitre_attack=("T1557.001",),
        check_class=NTLMReflectionCheck,
        graph_edge_relation="NTLMReflection",
        graph_edge_kind=EdgeKind.DERIVED,
        promotes_to_domain_breaker=False,
    ),
)


def scope_applies_to_target(scope: TargetScope, *, is_dc: bool) -> bool:
    """Return whether a catalog ``scope`` runs against a target.

    This is the **single source of truth** for the scope→target gate.
    ``runner._applies`` delegates here so the live scheduler and any
    pre-scan display (e.g. the confirmation panel) can never disagree
    about which checks will actually execute.

    Semantics:

    - ``ALL_HOSTS`` runs against every target (DC or member host).
    - ``DCS_ONLY`` / ``DOMAIN_LDAP`` run only against domain controllers.

    Args:
        scope: The catalog entry's :class:`TargetScope`.
        is_dc: Whether the target is a domain controller.

    Returns:
        ``True`` when a check with ``scope`` would run against the target.
    """

    if scope is TargetScope.ALL_HOSTS:
        return True
    if scope in (TargetScope.DCS_ONLY, TargetScope.DOMAIN_LDAP):
        return is_dc
    return False


def cves_for_target(*, is_dc: bool) -> tuple[CVEDefinition, ...]:
    """Return the catalog entries that will run against a target type.

    Data-driven counterpart to the scheduler: pass ``is_dc=True`` for the
    "Domain Controllers only" scope (DC-scoped checks PLUS the all-hosts
    checks like coercion that also run against a DC), or ``is_dc=False``
    for a non-DC member host (all-hosts checks only). The result is the
    exact set the scan would execute, so any operator-facing list derived
    from it can never drift from reality.

    Args:
        is_dc: Whether the targeted host(s) are domain controllers.

    Returns:
        The applicable :class:`CVEDefinition` entries, in catalog order.
    """

    return tuple(
        cve
        for cve in CVE_CATALOG
        if scope_applies_to_target(cve.target_scope, is_dc=is_dc)
    )


def cve_akas_for_target(*, is_dc: bool) -> tuple[str, ...]:
    """Return the de-duplicated display labels (``aka``) for a target type.

    Convenience wrapper over :func:`cves_for_target` for building the
    operator-facing CVE list in the confirmation panel. Order follows the
    catalog; duplicates (none today, but cheap insurance) are dropped.

    Args:
        is_dc: Whether the targeted host(s) are domain controllers.

    Returns:
        The ordered, de-duplicated ``aka`` labels for the applicable checks.
    """

    seen: set[str] = set()
    out: list[str] = []
    for cve in cves_for_target(is_dc=is_dc):
        if cve.aka not in seen:
            seen.add(cve.aka)
            out.append(cve.aka)
    return tuple(out)


def _normalize_selector(value: str) -> str:
    """Lower-case and strip non-alphanumeric chars for fuzzy matching.

    Lets ``"printerbug-surface"``, ``"PrinterBugSurface"``, ``"printerbug surface"``
    all resolve to the same catalog entry.
    """

    return "".join(ch for ch in value.lower() if ch.isalnum())


_SHORT_ALIASES: dict[str, str] = {
    # Operator-friendly short selectors → canonical aka.
    "webdav": "WebDAVEnabled",
    "printerbug": "PrinterBugSurface",
    "printerbugsurface": "PrinterBugSurface",
    "dropthemic": "DropTheMIC",
    "ntlmreflection": "NTLMReflection",
    "ms17010": "MS17-010",
}


def _index() -> dict[str, CVEDefinition]:
    """Build a case-insensitive, punctuation-insensitive id/aka index."""

    idx: dict[str, CVEDefinition] = {}
    for cve in CVE_CATALOG:
        idx[cve.id.lower()] = cve
        idx[cve.aka.lower()] = cve
        idx[_normalize_selector(cve.id)] = cve
        idx[_normalize_selector(cve.aka)] = cve
    by_aka = {cve.aka: cve for cve in CVE_CATALOG}
    for short, aka in _SHORT_ALIASES.items():
        if aka in by_aka:
            idx[short] = by_aka[aka]
    return idx


def resolve_cves(selectors: tuple[str, ...]) -> tuple[CVEDefinition, ...]:
    """Resolve CLI selectors (id or aka) to catalog entries.

    An empty ``selectors`` resolves to the full catalog. Unknown
    selectors raise ``KeyError`` listing the valid options.
    """

    if not selectors:
        return CVE_CATALOG
    idx = _index()
    out: list[CVEDefinition] = []
    seen: set[str] = set()
    for sel in selectors:
        key = sel.lower()
        if key not in idx:
            key = _normalize_selector(sel)
        if key not in idx:
            valid = sorted({cve.id for cve in CVE_CATALOG})
            raise KeyError(f"Unknown CVE selector {sel!r}. Known: {valid}")
        cve = idx[key]
        if cve.id not in seen:
            out.append(cve)
            seen.add(cve.id)
    return tuple(out)


__all__ = [
    "CVE_CATALOG",
    "CVEDefinition",
    "TargetScope",
    "cve_akas_for_target",
    "cves_for_target",
    "resolve_cves",
    "scope_applies_to_target",
]
