"""Generic host intelligence — AV/EDR fingerprinting + catch history.

Public API consumed by remote-exec, dump orchestrators, and any future
post-ex code that needs to know what's protecting a host before acting.

This package never imports from
:mod:`adscan_internal.services.exploitation` — it is a foundation, not a
consumer. LSASS-specific PPL extensions live in the exploitation package
on top of these primitives.
"""

from __future__ import annotations

from adscan_internal.services.host_intelligence.cache import HostIntelligenceCache
from adscan_internal.services.host_intelligence.defender_config_probe import (
    DefenderConfig,
    DefenderConfigProbe,
)
from adscan_internal.services.host_intelligence.fingerprint_service import (
    HostFingerprintService,
)
from adscan_internal.services.host_intelligence.intelligence import (
    CatchEvent,
    EdrIntelligence,
)
from adscan_internal.services.host_intelligence.models import (
    DetectedProduct,
    HostFingerprint,
)
from adscan_internal.services.host_intelligence.product_catalog import (
    PRODUCT_CATALOG,
    ProductSignature,
)

__all__ = [
    "DefenderConfig",
    "DefenderConfigProbe",
    "DetectedProduct",
    "HostFingerprint",
    "HostFingerprintService",
    "HostIntelligenceCache",
    "EdrIntelligence",
    "CatchEvent",
    "PRODUCT_CATALOG",
    "ProductSignature",
]
