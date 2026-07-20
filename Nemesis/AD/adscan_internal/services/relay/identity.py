"""Helpers for extracting identity metadata from relay contexts."""

from __future__ import annotations

from typing import Any


def _get_ntlm_handler(gssapi: Any) -> Any:
    """Return the inner NTLM handler from a GSSAPI/SPNEGO relay context."""
    ntlm = None
    if hasattr(gssapi, "get_ntlm"):
        ntlm = gssapi.get_ntlm()
    if ntlm is None and hasattr(gssapi, "authentication_contexts"):
        ntlm = gssapi.authentication_contexts.get(
            "NTLMSSP - Microsoft NTLM Security Support Provider"
        )
    return ntlm


def extract_ntlm_hash_from_relay(
    gssapi: Any,
) -> tuple[str | None, str | None, str | None, str | None]:
    """Extract a hashcat-format NTLM hash from a completed relay context.

    Returns ``(fullhash, ntlm_version, username, domain)`` where
    ``ntlm_version`` is ``"NTLMv1"`` or ``"NTLMv2"``, or ``None`` if the
    authentication material is not yet complete or cannot be parsed.
    """
    ntlm = _get_ntlm_handler(gssapi)
    if ntlm is None:
        return None, None, None, None

    negotiate = getattr(ntlm, "ntlmNegotiate", None) or getattr(
        ntlm, "ntlmNegotiate_server", None
    )
    challenge = getattr(ntlm, "ntlmChallenge", None) or getattr(
        ntlm, "ntlmChallenge_server", None
    )
    authenticate = getattr(ntlm, "ntlmAuthenticate", None) or getattr(
        ntlm, "ntlmAuthenticate_server", None
    )

    if negotiate is None or challenge is None or authenticate is None:
        return None, None, None, None

    try:
        from badauth.protocols.ntlm.creds_calc import NTLMCredentials  # noqa: PLC0415

        creds_list = NTLMCredentials.construct(negotiate, challenge, authenticate)
    except Exception:  # noqa: BLE001
        return None, None, None, None

    if not creds_list:
        return None, None, None, None

    cred = creds_list[0]
    ctype = str(getattr(cred, "ctype", "") or "").lower()
    if "v2" in ctype:
        version = "NTLMv2"
    elif "v1" in ctype or "ntlm" in ctype:
        version = "NTLMv1"
    else:
        return None, None, None, None

    fullhash = getattr(cred, "fullhash", None)
    username = getattr(cred, "username", None)
    domain = getattr(cred, "domain", None)
    return fullhash, version, username, domain


def extract_ntlm_identity(gssapi: Any) -> tuple[str | None, str | None]:
    """Return ``(domain, username)`` from a relayed NTLM context when available."""

    ntlm = _get_ntlm_handler(gssapi)
    if ntlm is None:
        return None, None
    authenticate = getattr(ntlm, "ntlmAuthenticate", None)
    if authenticate is None:
        authenticate = getattr(ntlm, "ntlmAuthenticate_server", None)
    if authenticate is None:
        return None, None

    domain = _string_attr(authenticate, "DomainName")
    username = _string_attr(authenticate, "UserName")
    return domain, username


def format_principal(domain: str | None, username: str | None) -> str | None:
    """Format a Windows principal from optional domain/user parts."""

    if not username:
        return None
    if domain:
        return f"{domain}\\{username}"
    return username


def _string_attr(obj: Any, name: str) -> str | None:
    value = getattr(obj, name, None)
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-16-le", errors="ignore").strip("\x00") or None
    text = str(value).strip()
    return text or None
