"""Shared helpers for the native MSSQL integration."""

from __future__ import annotations

from adscan_internal.services.credential_routing import looks_like_ntlm_hash


def is_hash_authentication(password: str) -> bool:
    """Return whether ``password`` is a 32-hex-character NTLM hash.

    Used by the native backend to decide whether to call
    ``impacket.tds.MSSQL.login`` with ``hashes=`` instead of a plaintext
    password. Delegates to the central
    :func:`adscan_internal.services.credential_routing.looks_like_ntlm_hash`
    so the format definition stays single-sourced across the codebase.
    """
    return looks_like_ntlm_hash(password)


__all__ = ["is_hash_authentication"]
