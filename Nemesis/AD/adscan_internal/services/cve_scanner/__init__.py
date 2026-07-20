"""Native async CVE scanner.

This package replaces ADscan's legacy netexec-based CVE checks with a
fully native async pipeline. Slice 1 ships the catalog, runner, result
types, premium Rich Live dashboard, workspace persistence and the
coercion-technique adapter (PetitPotam, PrinterBug, ShadowCoerce,
MSEvenCoerce, DFSCoerce).

See ``docs/superpowers/specs/2026-05-02-native-cve-scanner-design.md``
for the full architecture and the per-slice scope.
"""

from adscan_internal.services.cve_scanner.catalog import (
    CVE_CATALOG,
    CVEDefinition,
    TargetScope,
    resolve_cves,
)
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEScanReport,
    CVEStatus,
    Evidence,
    Severity,
)
from adscan_internal.services.cve_scanner.runner import (
    CVEScanRunner,
    ScanContext,
    ScanTarget,
)

__all__ = [
    "CVE_CATALOG",
    "CVEDefinition",
    "CVEResult",
    "CVEScanReport",
    "CVEScanRunner",
    "CVEStatus",
    "Evidence",
    "ScanContext",
    "ScanTarget",
    "Severity",
    "TargetScope",
    "resolve_cves",
]
