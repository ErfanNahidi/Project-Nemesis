"""Shared helpers for ``remote_exec`` backends."""

from __future__ import annotations

from typing import Tuple

from adscan_internal.services.remote_exec.models import ErrorKind

_AUTH_MARKERS = (
    "logon failure",
    "wrong password",
    "STATUS_LOGON_FAILURE",
    "STATUS_WRONG_PASSWORD",
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_LOCKED_OUT",
    "STATUS_PASSWORD_EXPIRED",
    "KRB_AP_ERR",
    "KDC_ERR",
    "pre-authentication",
)

_DENIED_MARKERS = (
    "STATUS_ACCESS_DENIED",
    "access denied",
    "STATUS_SHARING_VIOLATION",
)

_NOT_SUPPORTED_MARKERS = (
    "STATUS_NOT_SUPPORTED",
    "RPC_S_PROCNUM_OUT_OF_RANGE",
    "WERR_NOT_SUPPORTED",
    "ERROR_NOT_SUPPORTED",
)

_TIMEOUT_MARKERS = ("timeout", "timed out", "SCHED_S_TASK_HAS_NOT_RUN")

_NETWORK_MARKERS = (
    "connection refused",
    "connection reset",
    "unreachable",
    "broken pipe",
    "EOF",
    "no route to host",
)


def classify_native_exec_error(message: str) -> Tuple[ErrorKind, str]:
    """Map a free-text error message to an ``ErrorKind``.

    Args:
        message: The raw error text from a backend.

    Returns:
        A ``(kind, sanitised_message)`` tuple. The message is the
        original text trimmed to a reasonable display length.
    """
    text = (message or "").strip()
    if not text:
        return "other", "unknown error"

    lower = text.lower()
    upper = text.upper()

    if any(m.lower() in lower for m in _AUTH_MARKERS) or any(
        m in upper for m in ("KRB_AP_ERR", "KDC_ERR")
    ):
        return "auth", text[:240]
    if any(m in upper for m in _DENIED_MARKERS) or "access denied" in lower:
        return "access_denied", text[:240]
    if any(m in upper for m in _NOT_SUPPORTED_MARKERS):
        return "not_supported", text[:240]
    if any(m in lower for m in _TIMEOUT_MARKERS):
        return "timeout", text[:240]
    if any(m in lower for m in _NETWORK_MARKERS):
        return "network", text[:240]
    return "other", text[:240]


__all__ = ["classify_native_exec_error"]
