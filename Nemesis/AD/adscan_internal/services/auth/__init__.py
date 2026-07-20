"""Centralized authentication primitives.

This subpackage owns the lifecycle of credential material that may need to be
re-authenticated mid-engagement (e.g. after a privilege-granting AddMember,
after the executor's own password has been reset, or after a shadow-credential
write that effectively replaces the secret).

Public API:

- :class:`CredentialContext` — a snapshot of credential material for one
  ``(principal_sid, target_realm)`` pair, plus the epoch the registry had at
  the time the bound TGT was minted.  Callers pass it to LDAP / Kerberos
  transports so binds automatically refresh when the cached PAC is stale.
- :class:`CredentialRegistry` — process-global tracker of "stale" events.
  Mutators (membership writers, password resetters, key-credential writers)
  bump epochs **and** wall-clock timestamps; consumers (transports) compare
  ccache mtime against the timestamp before binding.
- :func:`auth_aware_modify` — transport-level auto-retry wrapper that
  recovers from ``insufficientAccessRights`` via force-refresh and
  (operator-permitting, capability-permitting) NTLM fallback.
- :class:`NtlmCapabilityCache` — tri-state per-DC cache of NTLM bind support,
  consulted by ``auth_aware_modify`` before attempting the NTLM layer.

Both registry and contexts are intentionally lightweight: no I/O at
construction, no implicit process state beyond the singletons.
"""

from adscan_internal.services.auth.auth_retry import (
    auth_aware_modify,
    is_access_denied_error,
)
from adscan_internal.services.auth.credential_context import (
    CredentialContext,
    CredentialRegistry,
    get_credential_registry,
)
from adscan_internal.services.auth.ntlm_capability import (
    NtlmCapability,
    NtlmCapabilityCache,
    get_ntlm_capability_cache,
)

__all__ = [
    "CredentialContext",
    "CredentialRegistry",
    "NtlmCapability",
    "NtlmCapabilityCache",
    "auth_aware_modify",
    "get_credential_registry",
    "get_ntlm_capability_cache",
    "is_access_denied_error",
]
