"""Compatibility helpers for optional reporting/PRO integrations."""

from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from types import ModuleType
from typing import TypeVar

T = TypeVar("T")


def is_optional_pro_import_error(
    exc: Exception,
    *,
    allowed_missing_modules: tuple[str, ...] = (),
) -> bool:
    """Return whether ``exc`` is an expected optional ``/pro`` import failure."""
    if not isinstance(exc, ModuleNotFoundError):
        return False

    missing_module = str(getattr(exc, "name", "") or "").strip()
    if missing_module in allowed_missing_modules:
        return True
    if missing_module == "adscan_internal.pro" or missing_module.startswith(
        "adscan_internal.pro."
    ):
        return True

    error_message = str(exc)
    return any(module_name in error_message for module_name in allowed_missing_modules) or (
        "adscan_internal.pro." in error_message
    )


def handle_optional_pro_import_exception(
    exc: Exception,
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[pro]",
    allowed_missing_modules: tuple[str, ...] = (),
) -> bool:
    """Log and suppress expected optional ``/pro`` import failures in LITE builds."""
    if not is_optional_pro_import_error(
        exc,
        allowed_missing_modules=allowed_missing_modules,
    ):
        return False

    debug_printer(
        f"{prefix} {action} unavailable in this build; "
        f"skipping legacy sync ({type(exc).__name__})."
    )
    return True


def import_optional_pro_module(
    module_name: str,
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[pro]",
) -> ModuleType | None:
    """Import an optional ``/pro`` module, returning ``None`` in LITE builds."""
    try:
        return import_module(module_name)
    except ImportError as exc:
        if handle_optional_pro_import_exception(
            exc,
            action=action,
            debug_printer=debug_printer,
            prefix=prefix,
            allowed_missing_modules=(module_name,),
        ):
            return None
        raise


def load_optional_pro_attr(
    module_name: str,
    attr_name: str,
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[pro]",
) -> T | None:
    """Load an attribute from an optional ``/pro`` module."""
    module = import_optional_pro_module(
        module_name,
        action=action,
        debug_printer=debug_printer,
        prefix=prefix,
    )
    if module is None:
        return None
    return getattr(module, attr_name, None)


def is_optional_report_service_import_error(exc: Exception) -> bool:
    """Return whether ``exc`` is the expected report-service import failure."""
    return is_optional_pro_import_error(
        exc,
        allowed_missing_modules=(
            "adscan_internal.services.report_service",
            "adscan_internal.pro.services",
            "adscan_internal.pro.services.report_service",
        ),
    )


def handle_optional_report_service_exception(
    exc: Exception,
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[report]",
) -> bool:
    """Log and suppress expected report-service import failures in LITE builds."""
    return handle_optional_pro_import_exception(
        exc,
        action=action,
        debug_printer=debug_printer,
        prefix=prefix,
        allowed_missing_modules=(
            "adscan_internal.services.report_service",
            "adscan_internal.pro.services",
            "adscan_internal.pro.services.report_service",
        ),
    )


def import_optional_report_service_module(
    module_name: str = "adscan_internal.services.report_service",
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[report]",
) -> ModuleType | None:
    """Import an optional report-service module, returning ``None`` in LITE builds."""
    try:
        return import_module(module_name)
    except ImportError as exc:
        if handle_optional_report_service_exception(
            exc,
            action=action,
            debug_printer=debug_printer,
            prefix=prefix,
        ):
            return None
        raise


# Write primitives that were relocated to ``adscan_core`` so they survive the
# LITE image strip (the PRO report service and its shim are removed from LITE).
# When the stripped module is absent, these attrs are resolved from the core
# module instead — that is what makes the LITE technical_report.json populate.
_CORE_REPORT_ATTRS: frozenset[str] = frozenset(
    {
        "record_technical_finding",
        "record_technical_event",
        "record_control_evidence",
        "record_exposure_score",
        "initialize_technical_report",
        "TECHNICAL_REPORT_FILENAME",
        "TECHNICAL_REPORT_SCHEMA_VERSION",
    }
)


def load_optional_report_service_attr(
    attr_name: str,
    *,
    action: str,
    debug_printer: Callable[[str], None],
    prefix: str = "[report]",
    module_name: str = "adscan_internal.services.report_service",
) -> T | None:
    """Load an attribute from an optional report-service module.

    Recorders relocated to ``adscan_core.reporting.technical_report`` are
    resolved from the core module when the PRO report service is stripped from
    the LITE image, so the writer no longer no-ops in LITE.
    """
    module = import_optional_report_service_module(
        module_name,
        action=action,
        debug_printer=debug_printer,
        prefix=prefix,
    )
    if module is not None:
        attr = getattr(module, attr_name, None)
        if attr is not None:
            return attr
    if attr_name in _CORE_REPORT_ATTRS:
        core_module = import_module("adscan_core.reporting.technical_report")
        return getattr(core_module, attr_name, None)
    return None
