"""Provenance metadata carrier for credential additions.

This module provides the structured payload that callers attach to
``add_credential`` / ``add_credentials_batch`` so the credential store
ends up with consistent secret-interpretation hints and Kerberos-key
material regardless of which writer added the secret.

Phase-2 scope reduction
-----------------------

Privilege role classification (DA / EA / RID 500 / LAV) and account-
enabled state are now resolved at *read time* from the canonical
attack-graph + identity-risk store by
:func:`adscan_internal.services.credentials.privilege_role.pick_credential_for_local_admin`.
Writers no longer need to push those hints into ``credentials_meta`` —
the graph is the single source of truth. Consequently the carrier only
exposes the *non-derivable* fields:

* ``secret_kind`` — how to interpret the secret string (password vs
  NT hash vs AES key vs ccache); cannot be inferred reliably from the
  string alone.
* ``aes256_key`` / ``aes128_key`` / ``kerberos_keys`` — additional key
  material captured during DCSync that unlocks pass-the-key, Golden
  Ticket and Silver Ticket workflows. Not part of the primary
  ``{user: secret}`` map, so we surface it via metadata.

All four fields are optional — passing ``CredentialMetadata()`` is a
valid no-op. The dataclass is frozen so callers build it once and hand
it off; mutation is forbidden.
"""

from __future__ import annotations

from dataclasses import dataclass

from adscan_internal.services.credentials.privilege_role import CredentialKind


@dataclass(frozen=True)
class CredentialMetadata:
    """Provenance metadata for a single credential.

    Attributes:
        secret_kind: How to interpret the stored secret string. Persisted
            via ``set_credential_secret_kind``.
        aes256_key: Optional AES-256 Kerberos key.
        aes128_key: Optional AES-128 Kerberos key.
        kerberos_keys: Full ``((etype, key), ...)`` tuple as exposed by
            the DCSync raw-secret object.
    """

    secret_kind: CredentialKind | None = None
    aes256_key: str | None = None
    aes128_key: str | None = None
    kerberos_keys: tuple[tuple[str, str], ...] = ()


__all__ = ["CredentialMetadata"]
