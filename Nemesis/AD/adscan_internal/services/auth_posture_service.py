"""Persistent authentication posture helpers for domain runtime state.

DEPRECATED public surface: this module is now a thin compatibility shim.
New code MUST consume :mod:`adscan_internal.services.domain_posture` directly,
which is the canonical, unified source of truth for every domain-level
environment constraint (NTLM, RC4, AES-only, LDAPS availability, LDAP/SMB
signing, channel binding, etc.).

This shim preserves the public signatures of the legacy API
(``get_ntlm_status``, ``record_ntlm_disabled_signal``,
``record_ntlm_enabled_signal``, ``get_rc4_status``, ``record_rc4_disabled_signal``
and the legacy update dataclasses) and the legacy on-disk layout under
``domains_data[domain]["auth_posture"]["ntlm" | "kerberos"]``. Each mutation
also forwards a typed ``PostureSignal`` to ``domain_posture.update_posture``
so the new ``constraints`` block stays in sync. Existing call sites continue
to work unchanged; callers will be migrated module-by-module in later PRs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    PostureSignal,
    SignalConfidence,
    TriState,
    update_posture,
)


AuthPostureStatus = str
_VALID_NTLM_STATUSES = {"unknown", "likely_enabled", "likely_disabled"}
_VALID_RC4_STATUSES = {"unknown", "likely_disabled"}


@dataclass(frozen=True)
class AuthPostureUpdate:
    """Result of persisting one auth-posture signal."""

    domain: str
    protocol: str | None
    status_before: AuthPostureStatus
    status_after: AuthPostureStatus
    domain_status_before: AuthPostureStatus
    domain_status_after: AuthPostureStatus
    changed: bool
    should_notify_user: bool


@dataclass(frozen=True)
class RC4PostureUpdate:
    """Result of persisting one RC4 posture signal."""

    domain: str
    status_before: str
    status_after: str
    changed: bool
    should_notify_user: bool


def get_ntlm_status(
    domains_data: Mapping[str, Any] | None,
    *,
    domain: str | None,
    protocol: str | None = None,
) -> AuthPostureStatus:
    """Return the persisted NTLM posture for a domain/protocol.

    Resolution order:
    1. protocol-specific status
    2. domain-wide status
    3. ``"unknown"``
    """
    domain_entry = _get_domain_entry(domains_data, domain)
    if not isinstance(domain_entry, dict):
        return "unknown"

    posture = domain_entry.get("auth_posture")
    if not isinstance(posture, dict):
        return "unknown"

    ntlm = posture.get("ntlm")
    if not isinstance(ntlm, dict):
        return "unknown"

    protocol_key = str(protocol or "").strip().lower()
    if protocol_key:
        protocol_status = (
            ntlm.get("protocols", {}) if isinstance(ntlm.get("protocols"), dict) else {}
        )
        value = str(protocol_status.get(protocol_key) or "").strip().lower()
        if value in _VALID_NTLM_STATUSES and value != "unknown":
            return value

    value = str(ntlm.get("domain_status") or "").strip().lower()
    if value in _VALID_NTLM_STATUSES:
        return value
    return "unknown"


def record_ntlm_disabled_signal(
    domains_data: dict[str, Any] | None,
    *,
    domain: str | None,
    protocol: str | None,
    source: str,
    signal: str,
    message: str | None = None,
) -> AuthPostureUpdate | None:
    """Persist evidence that NTLM looks disabled/unsupported."""
    return _record_ntlm_evidence(
        domains_data,
        domain=domain,
        protocol=protocol,
        new_status="likely_disabled",
        source=source,
        signal=signal,
        message=message,
    )


def record_ntlm_enabled_signal(
    domains_data: dict[str, Any] | None,
    *,
    domain: str | None,
    protocol: str | None,
    source: str,
    signal: str = "ntlm_success",
    message: str | None = None,
) -> AuthPostureUpdate | None:
    """Persist evidence that NTLM succeeded for a domain/protocol."""
    return _record_ntlm_evidence(
        domains_data,
        domain=domain,
        protocol=protocol,
        new_status="likely_enabled",
        source=source,
        signal=signal,
        message=message,
    )


def get_rc4_status(
    domains_data: Mapping[str, Any] | None,
    *,
    domain: str | None,
) -> str:
    """Return the persisted RC4 posture for a domain.

    Returns ``"likely_disabled"`` if RC4 has been observed to fail with
    ``KDC_ERR_ETYPE_NOSUPP``, otherwise ``"unknown"``.
    """
    domain_entry = _get_domain_entry(domains_data, domain)
    if not isinstance(domain_entry, dict):
        return "unknown"
    posture = domain_entry.get("auth_posture")
    if not isinstance(posture, dict):
        return "unknown"
    kerberos = posture.get("kerberos")
    if not isinstance(kerberos, dict):
        return "unknown"
    value = str(kerberos.get("rc4_status") or "").strip().lower()
    return value if value in _VALID_RC4_STATUSES else "unknown"


def record_rc4_disabled_signal(
    domains_data: dict[str, Any] | None,
    *,
    domain: str | None,
    source: str,
    signal: str = "KDC_ERR_ETYPE_NOSUPP",
    message: str | None = None,
) -> RC4PostureUpdate | None:
    """Persist evidence that the KDC rejected RC4 (AES-only domain)."""
    if not isinstance(domains_data, dict):
        return None
    domain_key = str(domain or "").strip()
    if not domain_key:
        return None

    domain_entry = domains_data.setdefault(domain_key, {})
    if not isinstance(domain_entry, dict):
        return None
    posture = domain_entry.setdefault("auth_posture", {})
    if not isinstance(posture, dict):
        return None
    kerberos = posture.setdefault("kerberos", {})
    if not isinstance(kerberos, dict):
        return None

    status_before = str(kerberos.get("rc4_status") or "unknown").strip().lower()
    if status_before not in _VALID_RC4_STATUSES:
        status_before = "unknown"

    kerberos["rc4_status"] = "likely_disabled"
    kerberos["updated_at"] = _utc_now_iso()

    evidence = kerberos.setdefault("evidence", [])
    if isinstance(evidence, list):
        evidence.append(
            {
                "source": str(source or "").strip() or "unknown",
                "signal": str(signal or "").strip() or "KDC_ERR_ETYPE_NOSUPP",
                "message": str(message or "").strip() or None,
                "status": "likely_disabled",
                "timestamp": _utc_now_iso(),
            }
        )
        if len(evidence) > 20:
            del evidence[:-20]

    user_notice_emitted = bool(kerberos.get("user_notice_emitted_rc4_disabled"))
    should_notify_user = status_before != "likely_disabled" and not user_notice_emitted
    if should_notify_user:
        kerberos["user_notice_emitted_rc4_disabled"] = True

    # Forward to the unified posture model (silent — legacy block above is the
    # source of truth for the legacy update dataclass result).
    update_posture(
        domains_data,
        signal=PostureSignal(
            domain=domain_key,
            category=ConstraintCategory.KERBEROS_RC4,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            source=str(source or "").strip() or "unknown",
            signal_code=str(signal or "").strip() or "KDC_ERR_ETYPE_NOSUPP",
            message=(str(message).strip() if message else None) or None,
            protocol="kerberos",
            observed_at=datetime.now(timezone.utc),
        ),
    )

    return RC4PostureUpdate(
        domain=domain_key,
        status_before=status_before,
        status_after="likely_disabled",
        changed=(status_before != "likely_disabled"),
        should_notify_user=should_notify_user,
    )


def _record_ntlm_evidence(
    domains_data: dict[str, Any] | None,
    *,
    domain: str | None,
    protocol: str | None,
    new_status: AuthPostureStatus,
    source: str,
    signal: str,
    message: str | None,
) -> AuthPostureUpdate | None:
    """Upsert one auth posture evidence entry into ``domains_data``."""
    if not isinstance(domains_data, dict):
        return None
    domain_key = str(domain or "").strip()
    if not domain_key:
        return None

    domain_entry = domains_data.setdefault(domain_key, {})
    if not isinstance(domain_entry, dict):
        return None

    posture = domain_entry.setdefault("auth_posture", {})
    if not isinstance(posture, dict):
        return None

    ntlm = posture.setdefault("ntlm", {})
    if not isinstance(ntlm, dict):
        return None

    protocol_key = str(protocol or "").strip().lower()
    protocol_status_before = get_ntlm_status(
        domains_data, domain=domain_key, protocol=protocol_key or None
    )
    domain_status_before = str(ntlm.get("domain_status") or "unknown").strip().lower()
    if domain_status_before not in _VALID_NTLM_STATUSES:
        domain_status_before = "unknown"

    if protocol_key:
        protocols = ntlm.setdefault("protocols", {})
        if isinstance(protocols, dict):
            protocols[protocol_key] = new_status

    ntlm["domain_status"] = _merge_ntlm_status(domain_status_before, new_status)
    ntlm["updated_at"] = _utc_now_iso()
    domain_status_after = str(ntlm.get("domain_status") or "unknown").strip().lower()
    if domain_status_after not in _VALID_NTLM_STATUSES:
        domain_status_after = "unknown"

    evidence = ntlm.setdefault("evidence", [])
    if isinstance(evidence, list):
        evidence.append(
            {
                "source": str(source or "").strip() or "unknown",
                "protocol": protocol_key or None,
                "signal": str(signal or "").strip() or "unknown",
                "message": str(message or "").strip() or None,
                "status": new_status,
                "timestamp": _utc_now_iso(),
            }
        )
        if len(evidence) > 20:
            del evidence[:-20]

    user_notice_emitted = bool(ntlm.get("user_notice_emitted_disabled"))
    should_notify_user = (
        new_status == "likely_disabled"
        and domain_status_before != "likely_disabled"
        and domain_status_after == "likely_disabled"
        and not user_notice_emitted
    )
    if should_notify_user:
        ntlm["user_notice_emitted_disabled"] = True

    status_after = get_ntlm_status(
        domains_data, domain=domain_key, protocol=protocol_key or None
    )

    # Forward to the unified posture model. Use HIGH confidence on disabled
    # transitions (matches today's "we trust this enough to notify the user")
    # and MEDIUM on enabled successes.
    tri_state = (
        TriState.DISABLED if new_status == "likely_disabled" else TriState.ENABLED
    )
    confidence = (
        SignalConfidence.HIGH
        if new_status == "likely_disabled"
        else SignalConfidence.MEDIUM
    )
    update_posture(
        domains_data,
        signal=PostureSignal(
            domain=domain_key,
            category=ConstraintCategory.NTLM_AUTHENTICATION,
            state=tri_state,
            confidence=confidence,
            source=str(source or "").strip() or "unknown",
            signal_code=str(signal or "").strip() or "unknown",
            message=(str(message).strip() if message else None) or None,
            protocol=protocol_key or None,
            observed_at=datetime.now(timezone.utc),
        ),
    )

    return AuthPostureUpdate(
        domain=domain_key,
        protocol=protocol_key or None,
        status_before=protocol_status_before,
        status_after=status_after,
        domain_status_before=domain_status_before,
        domain_status_after=domain_status_after,
        changed=(protocol_status_before != status_after)
        or (domain_status_before != domain_status_after),
        should_notify_user=should_notify_user,
    )


def _merge_ntlm_status(
    current_status: AuthPostureStatus,
    new_status: AuthPostureStatus,
) -> AuthPostureStatus:
    """Merge one new NTLM signal into the domain-wide status."""
    if current_status == new_status:
        return current_status
    if current_status == "unknown":
        return new_status
    return current_status


def _get_domain_entry(
    domains_data: Mapping[str, Any] | None,
    domain: str | None,
) -> Mapping[str, Any] | None:
    """Resolve one domain entry from a case-insensitive ``domains_data`` mapping."""
    if not isinstance(domains_data, Mapping):
        return None
    domain_key = str(domain or "").strip()
    if not domain_key:
        return None
    if domain_key in domains_data:
        entry = domains_data.get(domain_key)
        return entry if isinstance(entry, Mapping) else None

    normalized = domain_key.casefold()
    for key, value in domains_data.items():
        if str(key).strip().casefold() == normalized and isinstance(value, Mapping):
            return value
    return None


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()
