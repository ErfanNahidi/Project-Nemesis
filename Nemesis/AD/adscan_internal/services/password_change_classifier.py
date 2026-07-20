"""Gate-2 reactive password-change rejection classifier.

When a password set/reset is rejected by the Domain Controller, the raw error
text differs by backend (SAMR ``NTSTATUS`` vs LDAP ``unicodePwd`` result codes)
and by operation (an admin RESET bypasses min-age/history, whereas a self-CHANGE
is subject to both). This module turns that raw error into a structured verdict
the retry loop can act on without re-deriving the policy.

The classification is **pure** — it only inspects the error string, the backend
name, and the operation kind. No network, no AD state. That makes it fully
unit-testable (L1).

References:
  * MS-SAMR NTSTATUS codes (aiosmb renders them as
    ``SAMR SessionError: code: 0x... - <NAME>``, NTStatus name WITHOUT the
    ``STATUS_`` prefix).
  * MS-ADTS / Win32 password-restriction sub-codes returned in the LDAP
    diagnostic message on ``unwillingToPerform`` (data ``0x0000052D`` =
    ``ERROR_PASSWORD_RESTRICTIONS``).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RejectionClass(Enum):
    """Category of a password-change rejection."""

    COMPLEXITY_OR_LENGTH = "complexity_or_length"
    """Policy rejected the value's strength — retry with a BETTER password helps."""

    HISTORY_OR_MIN_AGE = "history_or_min_age"
    """Reused/too-recent password — retry with a DIFFERENT password helps
    (self-CHANGE only; an admin RESET bypasses these checks)."""

    ACCESS_DENIED = "access_denied"
    """The caller lacks the right to change the password — retry does NOT help."""

    ACCOUNT_LOCKED = "account_locked"
    """The target account is locked out — retry does NOT help."""

    UNKNOWN = "unknown"
    """Unrecognized rejection — surface the raw error, offer a single manual retry."""


#: Valid backends the classifier understands.
BACKEND_SAMR = "samr"
BACKEND_LDAP_UNICODEPWD = "ldap_unicodepwd"

#: Valid operations the classifier understands.
OPERATION_ADMIN_RESET = "admin_reset"
OPERATION_SELF_CHANGE = "self_change"


@dataclass(frozen=True)
class PasswordChangeRejection:
    """Structured verdict for a password-change rejection.

    Attributes:
        category: The :class:`RejectionClass` the rejection maps to.
        retry_helps: Whether re-attempting (with a better/different password)
            can plausibly succeed. ``False`` for access-denied / locked-out and
            for ``UNKNOWN`` rejections where an automated retry is not promised.
        human_message: Operator-facing English message explaining the rejection
            and what (if anything) a retry would do. Never contains the raw DC
            error verbatim (the caller surfaces that separately under SECRET
            mode); this is the clean summary line.
    """

    category: RejectionClass
    retry_helps: bool
    human_message: str


# ── NTSTATUS markers (SAMR backend) ──────────────────────────────────────────
# aiosmb renders the NTStatus name WITHOUT the ``STATUS_`` prefix and includes
# the hex code, e.g. ``SAMR SessionError: code: 0xc000006c - PASSWORD_RESTRICTION``.
# We match on the hex code (most robust) AND tolerate both the bare name and the
# spec's ``STATUS_``-prefixed name so the table reads cleanly against the spec.

_SAMR_COMPLEXITY_CODES = ("0xc000006c",)  # STATUS_PASSWORD_RESTRICTION
_SAMR_COMPLEXITY_NAMES = (
    "PASSWORD_RESTRICTION",
    "PASSWORD_TOO_SHORT",
)
_SAMR_HISTORY_CODES = ("0xc000025b", "0xc000025c")  # PWD_TOO_RECENT / PWD_HISTORY_CONFLICT
_SAMR_HISTORY_NAMES = (
    "PWD_TOO_RECENT",
    "PWD_HISTORY_CONFLICT",
)
_SAMR_ACCESS_DENIED_CODES = ("0xc0000022",)  # STATUS_ACCESS_DENIED
_SAMR_ACCESS_DENIED_NAMES = ("ACCESS_DENIED",)
_SAMR_LOCKED_CODES = ("0xc0000234",)  # STATUS_ACCOUNT_LOCKED_OUT
_SAMR_LOCKED_NAMES = ("ACCOUNT_LOCKED_OUT",)


# ── LDAP unicodePwd markers ──────────────────────────────────────────────────
# A complexity/length reject on the LDAP unicodePwd replace surfaces as
# ``unwillingToPerform`` / ``WILL_NOT_PERFORM`` (result code 0x35) with the
# Win32 sub-code 0x0000052D (ERROR_PASSWORD_RESTRICTIONS) embedded in the
# diagnostic message. ``insufficientAccessRights`` (0x32) is the access-denied
# signal.

_LDAP_UNWILLING_MARKERS = ("unwillingtoperform", "will_not_perform")
_LDAP_PASSWORD_RESTRICTION_SUBCODES = ("0x52d", "0x0000052d", "52d", "0000052d")
_LDAP_ACCESS_DENIED_MARKERS = (
    "insufficientaccessrights",
    "0x32",
    "insufficient access",
)


def _contains_any(haystack: str, needles: tuple[str, ...]) -> bool:
    """Return ``True`` if any needle is a substring of ``haystack``."""
    return any(needle in haystack for needle in needles)


def _classify_samr(lowered: str) -> RejectionClass:
    """Classify a SAMR ``NTSTATUS`` rejection from its lowered error string."""
    if _contains_any(lowered, _SAMR_ACCESS_DENIED_CODES) or _contains_any(
        lowered, tuple(name.lower() for name in _SAMR_ACCESS_DENIED_NAMES)
    ):
        return RejectionClass.ACCESS_DENIED
    if _contains_any(lowered, _SAMR_LOCKED_CODES) or _contains_any(
        lowered, tuple(name.lower() for name in _SAMR_LOCKED_NAMES)
    ):
        return RejectionClass.ACCOUNT_LOCKED
    if _contains_any(lowered, _SAMR_COMPLEXITY_CODES) or _contains_any(
        lowered, tuple(name.lower() for name in _SAMR_COMPLEXITY_NAMES)
    ):
        return RejectionClass.COMPLEXITY_OR_LENGTH
    if _contains_any(lowered, _SAMR_HISTORY_CODES) or _contains_any(
        lowered, tuple(name.lower() for name in _SAMR_HISTORY_NAMES)
    ):
        return RejectionClass.HISTORY_OR_MIN_AGE
    return RejectionClass.UNKNOWN


def _classify_ldap(lowered: str) -> RejectionClass:
    """Classify an LDAP ``unicodePwd`` rejection from its lowered error string."""
    if _contains_any(lowered, _LDAP_ACCESS_DENIED_MARKERS):
        return RejectionClass.ACCESS_DENIED
    if _contains_any(lowered, _LDAP_UNWILLING_MARKERS):
        # unwillingToPerform with the password-restriction sub-code is a
        # complexity/length reject; without it the reason is opaque.
        if _contains_any(lowered, _LDAP_PASSWORD_RESTRICTION_SUBCODES):
            return RejectionClass.COMPLEXITY_OR_LENGTH
        return RejectionClass.UNKNOWN
    return RejectionClass.UNKNOWN


_HUMAN_MESSAGES: dict[RejectionClass, str] = {
    RejectionClass.COMPLEXITY_OR_LENGTH: (
        "The Domain Controller rejected the new password because it does not "
        "meet the domain/PSO complexity or length policy. Retrying with a "
        "freshly generated policy-compliant password can succeed."
    ),
    RejectionClass.HISTORY_OR_MIN_AGE: (
        "The Domain Controller rejected the new password because it was used "
        "too recently or matches the password history. Retrying with a "
        "different password can succeed."
    ),
    RejectionClass.ACCESS_DENIED: (
        "The Domain Controller refused the password change: the calling "
        "principal does not have the right to reset this account's password. "
        "Retrying will not help."
    ),
    RejectionClass.ACCOUNT_LOCKED: (
        "The target account is locked out, so the password change was refused. "
        "Retrying will not help until the lockout clears."
    ),
    RejectionClass.UNKNOWN: (
        "The Domain Controller rejected the password change for an "
        "unrecognized reason. Review the raw error and retry manually if "
        "appropriate."
    ),
}


def classify_password_change_rejection(
    error_text: str,
    *,
    backend: str,
    operation: str,
) -> PasswordChangeRejection:
    """Classify a password-change rejection into a retry-actionable verdict.

    Args:
        error_text: The raw DC rejection string (NTSTATUS render for SAMR, LDAP
            result string for ``unicodePwd``). ``None``/empty is treated as
            UNKNOWN.
        backend: The backend that produced the rejection. One of
            :data:`BACKEND_SAMR` / :data:`BACKEND_LDAP_UNICODEPWD`. Any other
            value falls back to a backend-agnostic substring scan.
        operation: The change kind. One of :data:`OPERATION_ADMIN_RESET` /
            :data:`OPERATION_SELF_CHANGE`. Drives operation-awareness:
            an admin RESET bypasses min-age/history, so a HISTORY_OR_MIN_AGE
            signal there is reclassified UNKNOWN (a retry with a different
            password is NOT promised to help — the real cause is something
            else the DC mislabeled or that we can't act on).

    Returns:
        A :class:`PasswordChangeRejection` with the category, whether a retry
        is worth offering, and a clean operator-facing message.
    """
    lowered = (error_text or "").lower()

    if backend == BACKEND_SAMR:
        category = _classify_samr(lowered)
    elif backend == BACKEND_LDAP_UNICODEPWD:
        category = _classify_ldap(lowered)
    else:
        # Backend-agnostic: try both tables, prefer a definitive hit.
        category = _classify_samr(lowered)
        if category is RejectionClass.UNKNOWN:
            category = _classify_ldap(lowered)

    # Operation-awareness: admin RESET bypasses min-age + history. A
    # history/min-age-looking code there cannot be the real cause, so we do not
    # promise a "retry with a different password" — reclassify to UNKNOWN.
    if (
        category is RejectionClass.HISTORY_OR_MIN_AGE
        and operation == OPERATION_ADMIN_RESET
    ):
        return PasswordChangeRejection(
            category=RejectionClass.UNKNOWN,
            retry_helps=False,
            human_message=(
                "The Domain Controller returned a history/min-age rejection on "
                "an administrative reset, which normally bypasses those checks. "
                "The real cause is unclear; review the raw error before "
                "retrying manually."
            ),
        )

    retry_helps = category in (
        RejectionClass.COMPLEXITY_OR_LENGTH,
        RejectionClass.HISTORY_OR_MIN_AGE,
    )

    return PasswordChangeRejection(
        category=category,
        retry_helps=retry_helps,
        human_message=_HUMAN_MESSAGES[category],
    )
