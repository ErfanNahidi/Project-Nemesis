"""Authentication context helpers for persisted pivot workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping


PIVOT_AUTH_SCHEMA_VERSION = 1


def _normalize_username(value: object) -> str:
    """Return a stable username key for case-insensitive workspace lookups."""
    return str(value or "").strip().casefold()


def _looks_like_ccache(value: object) -> bool:
    """Return True when one secret looks like a Kerberos ccache path."""
    return str(value or "").strip().lower().endswith(".ccache")


def _path_exists_or_unchecked(path: str) -> bool:
    """Return whether a persisted path can reasonably be reused."""
    value = str(path or "").strip()
    if not value:
        return False
    if value.startswith("FILE:"):
        value = value[5:]
    try:
        return Path(value).expanduser().exists()
    except OSError:
        return True


def _lookup_mapping_casefold(mapping: object, key: str) -> str | None:
    """Return one mapping value using case-insensitive string key matching."""
    if not isinstance(mapping, Mapping):
        return None
    normalized_key = _normalize_username(key)
    for candidate_key, value in mapping.items():
        if _normalize_username(candidate_key) != normalized_key:
            continue
        text = str(value or "").strip()
        return text or None
    return None


def _domain_data(shell: Any, domain: str) -> Mapping[str, Any]:
    """Return one domain data mapping from a shell-like object."""
    domains_data = getattr(shell, "domains_data", {})
    if not isinstance(domains_data, Mapping):
        return {}
    value = domains_data.get(domain, {})
    return value if isinstance(value, Mapping) else {}


def build_persisted_pivot_auth_context(
    *,
    source_service: str,
    username: str,
    secret: str,
    kerberos_spn_host: str | None = None,
) -> dict[str, Any]:
    """Build sanitized auth metadata for one persisted pivot record."""
    credential_kind = "kerberos_ccache" if _looks_like_ccache(secret) else "workspace_credential"
    normalized_spn_host = str(kerberos_spn_host or "").strip()
    context: dict[str, Any] = {
        "schema_version": PIVOT_AUTH_SCHEMA_VERSION,
        "source_service": str(source_service or "").strip().lower() or "winrm",
        "username": str(username or "").strip(),
        "credential_kind": credential_kind,
    }
    if credential_kind == "kerberos_ccache":
        context["ccache_path"] = str(secret or "").strip()
    if normalized_spn_host:
        context["kerberos_spn_host"] = normalized_spn_host
    return context


def resolve_pivot_auth_secret(
    shell: Any,
    *,
    domain: str,
    username: str,
    source_service: str,
    record: Mapping[str, Any] | None = None,
    fallback_secret: str | None = None,
) -> str | None:
    """Return the best reusable secret for a persisted pivot workflow.

    Kerberos ccaches are preferred for WinRM pivots when the original tunnel
    was established that way. Cleartext workspace credentials remain the
    fallback for older records and non-Kerberos pivots.
    """
    auth_context = record.get("pivot_auth") if isinstance(record, Mapping) else None
    if isinstance(auth_context, Mapping):
        credential_kind = str(auth_context.get("credential_kind") or "").strip().lower()
        ccache_path = str(auth_context.get("ccache_path") or "").strip()
        if credential_kind == "kerberos_ccache" and ccache_path and _path_exists_or_unchecked(ccache_path):
            return ccache_path

    if fallback_secret and _looks_like_ccache(fallback_secret):
        return str(fallback_secret).strip()

    data = _domain_data(shell, domain)
    kerberos_ticket = _lookup_mapping_casefold(data.get("kerberos_tickets", {}), username)
    if (
        str(source_service or "").strip().lower() == "winrm"
        and kerberos_ticket
        and _path_exists_or_unchecked(kerberos_ticket)
    ):
        return kerberos_ticket

    if fallback_secret and str(fallback_secret).strip():
        return str(fallback_secret).strip()

    credential = _lookup_mapping_casefold(data.get("credentials", {}), username)
    if not credential:
        return None
    if getattr(shell, "is_hash", lambda _: False)(credential):
        return None
    return credential
