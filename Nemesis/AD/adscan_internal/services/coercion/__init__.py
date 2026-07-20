"""Native async coercion primitives for ADscan."""

from adscan_internal.services.coercion.core import (
    CoercionEngine,
    CoercionListener,
    CoercionMethod,
    CoercionMethodResult,
    CoercionRunConfig,
    CoercionRunResult,
    CoercionTarget,
    RpcEndpoint,
    RpcProtocolAdapter,
)
from adscan_internal.services.coercion.registry import default_coercion_methods
from adscan_internal.services.coercion.runner import (
    NativeCoercionRunConfig,
    run_native_coercion,
)

__all__ = [
    "CoercionEngine",
    "CoercionListener",
    "CoercionMethod",
    "CoercionMethodResult",
    "CoercionRunConfig",
    "CoercionRunResult",
    "CoercionTarget",
    "NativeCoercionRunConfig",
    "RpcEndpoint",
    "RpcProtocolAdapter",
    "default_coercion_methods",
    "run_native_coercion",
]
