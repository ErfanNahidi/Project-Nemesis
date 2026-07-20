"""Protocol for native CVE checks."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover - type-checking only
    from adscan_internal.services.cve_scanner.result import CVEResult
    from adscan_internal.services.cve_scanner.runner import ScanContext, ScanTarget


@runtime_checkable
class CVECheck(Protocol):
    """One CVE check, single-purpose, independently testable.

    Implementations are async, never spawn subprocesses, and return one or
    more :class:`CVEResult` rows describing what was tested on the host.
    Returning a list lets one check (e.g. coercion) report per-technique
    findings while keeping a single dispatch unit at the runner layer.
    """

    cve_id: str

    async def run(
        self,
        target: ScanTarget,
        creds: Any | None,
        ctx: ScanContext,
    ) -> list[CVEResult]:
        """Run the check and return the resulting findings."""
        ...


__all__ = ["CVECheck"]
