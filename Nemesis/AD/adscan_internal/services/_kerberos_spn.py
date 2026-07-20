"""Shared helper to normalize Kerberos target hostnames.

Kerberos service tickets bind to the SPN exactly as requested. Asking for a
service ticket on a short hostname (``ldap/dc01``) yields a ticket the DC
rejects with ``SEC_E_LOGON_DENIED`` / ``KRB_AP_ERR_MODIFIED`` because its real
SPN registration is the FQDN (``ldap/dc01.<realm>``).

This bug is invisible to the client: the bind response is a clean
``invalidCredentials``, with no nested Kerberos error. Without this helper,
every transport-config consumer (LDAP, SMB, future ones) would have to
remember to promote short hostnames at every call site — which is exactly the
class of mistake that introduced the bug in the first place.

Centralised here, applied in each config's ``__post_init__``, so the fix
travels with the dataclass instead of with each caller.
"""

from __future__ import annotations

import ipaddress


class KerberosSpnUnresolvedError(ValueError):
    """Raised when a Kerberos SPN host cannot be built (IP with no FQDN).

    Subclasses :class:`ValueError` so existing ``except ValueError`` call sites
    keep catching it, but the distinct type lets transports recognise *this*
    specific failure (an IP was passed where an FQDN is required) and degrade to
    NTLM — instead of treating it as an unrecoverable crash. See
    ``smb_machine_with_fallback``: the SMB Kerberos branch catches this and
    retries with NTLM when posture allows the fallback.
    """


def is_ip_address(value: str | None) -> bool:
    """Return ``True`` when *value* is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def normalize_kerberos_target_hostname(
    host: str | None, domain: str | None
) -> str | None:
    """Return ``host`` promoted to FQDN when it is a short hostname.

    Rules:
        - ``host`` empty/None → ``None``.
        - ``host`` already contains a dot → returned as-is (assumed FQDN, even
          if the suffix differs from ``domain`` — cross-forest cases where the
          DNS suffix ≠ Kerberos realm).
        - ``host`` is a short label and ``domain`` is set → ``"<host>.<domain>"``.
        - ``host`` is a short label but ``domain`` is empty → returned as-is
          (cannot promote safely; better to surface the original error than to
          fabricate a wrong FQDN).

    Trailing dots on either input are stripped before comparison. The output
    never has a trailing dot.
    """
    h = (host or "").strip().rstrip(".")
    d = (domain or "").strip().rstrip(".")
    if not h:
        return None
    if "." in h or not d:
        return h
    return f"{h}.{d}"


def require_kerberos_target_hostname(
    host: str | None,
    *,
    protocol: str,
) -> str:
    """Return a valid Kerberos SPN hostname or raise a deterministic error.

    Transport builders call this at the final URL/SPN construction boundary.
    That makes the invariant central: native Kerberos transports may connect to
    an IP address, but they must never request ``ldap/<ip>`` or ``cifs/<ip>``.
    """
    value = str(host or "").strip().rstrip(".")
    if not value:
        raise KerberosSpnUnresolvedError(
            f"{protocol} Kerberos requires a DC FQDN for the service SPN; "
            "pass kerberos_target_hostname/target_hostname from domain_data "
            "instead of falling back to the DC IP."
        )
    if is_ip_address(value):
        raise KerberosSpnUnresolvedError(
            f"{protocol} Kerberos cannot use IP address {value!r} as the "
            "service SPN host; pass the DC FQDN from domain_data."
        )
    return value
