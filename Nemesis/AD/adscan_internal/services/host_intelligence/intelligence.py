"""Per-host catch / outcome intelligence.

Thin re-export of the historical
:class:`adscan_internal.workspaces.edr_intelligence.EdrIntelligence` so that
new callers depend on ``services.host_intelligence`` rather than the legacy
``workspaces`` location. The persistent format is unchanged so existing
workspace data files keep working.
"""

from __future__ import annotations

from adscan_internal.workspaces.edr_intelligence import (
    CatchEvent,
    EdrIntelligence,
)

__all__ = ["EdrIntelligence", "CatchEvent"]
