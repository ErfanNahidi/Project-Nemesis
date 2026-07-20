"""aiosmb-backed RPC adapter for native coercion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core.rich_output import print_info_debug

from adscan_internal.services.coercion.core import (
    CoercionTarget,
    RpcEndpoint,
    RpcProtocolAdapter,
    RpcSession,
)

# Friendly names for the impacket/aiosmb RPC_C_AUTHN_LEVEL_* integer values,
# so the per-attempt coercion debug log shows e.g. ``authlevel=NONE`` instead of
# a bare ``1``. Makes the PKT_PRIVACY-vs-NONE behaviour visible at --debug
# without having to infer it from the code.
_AUTHN_LEVEL_NAMES: dict[int, str] = {
    1: "NONE",
    2: "CONNECT",
    3: "CALL",
    4: "PKT",
    5: "PKT_INTEGRITY",
    6: "PKT_PRIVACY",
}


@dataclass
class AiosmbRpcAdapter(RpcProtocolAdapter):
    """RPC adapter that uses ADscan's async SMB/DCERPC stack."""

    connection_factory: Any

    async def iter_endpoints(
        self,
        *,
        target: CoercionTarget,
        protocol: str,
    ) -> list[RpcEndpoint]:
        protocol_class = _protocol_class(protocol)
        endpoints = []
        for endpoint in protocol_class.endpoints():
            endpoints.append(
                RpcEndpoint(
                    transport=endpoint.etype,
                    protocol=protocol.upper(),
                    uuid=endpoint.uuid,
                    version=endpoint.version,
                    pipe=endpoint.pipename,
                )
            )
        return endpoints

    async def connect(
        self,
        *,
        target: CoercionTarget,
        endpoint: RpcEndpoint,
    ) -> RpcSession:
        protocol_class = _protocol_class(endpoint.protocol)
        native_endpoint = _find_native_endpoint(protocol_class, endpoint)
        # Use aiosmb's registered RPC auth level for the endpoint
        # (RPC_C_AUTHN_LEVEL_PKT_PRIVACY for the EFSR/RPRN/EVEN/DFSNM/FSRVP
        # named-pipe interfaces). Do NOT downgrade to NONE: hardened member
        # servers (Server 2019+) reject an unsealed EFSR coercion call with
        # ACCESS_DENIED, while PKT_PRIVACY triggers on member servers (soft AND
        # hardened) and DCs alike. See _coercion_auth_level_note() for the full
        # empirical rationale.
        _level = getattr(native_endpoint, "authlevel", None)
        print_info_debug(
            "coercion rpc-bind "
            f"transport={getattr(native_endpoint, 'etype', '?')} "
            f"pipe={getattr(native_endpoint, 'pipename', None) or '-'} "
            f"authlevel={_AUTHN_LEVEL_NAMES.get(_level, _level)}"
        )
        connection = self.connection_factory.create_connection_newtarget(target.host)
        rpc, err = await protocol_class.from_smbconnection(
            connection, endpoint=native_endpoint
        )
        _log_smb_session_state(connection, bind_ok=err is None)
        if err is not None:
            raise err
        return rpc


def _log_smb_session_state(connection: Any, *, bind_ok: bool) -> None:
    """Best-effort: surface the SMB session identity for coercion debugging.

    The decisive member-vs-DC question is whether the SMB session authenticated
    as the supplied domain user or silently fell back to GUEST/anonymous — a
    guest session opens fine but is ACCESS_DENIED on the EFSR/RPRN/etc. pipes,
    which looks identical to a real auth failure in the per-attempt log. aiosmb
    exposes ``connection.gssapi.is_guest()`` and ``connection.login_ok`` /
    ``connection.signing_required``. Never raises — diagnostics must not break
    the coercion flow.
    """
    try:
        login_ok = getattr(connection, "login_ok", None)
        signing_required = getattr(connection, "signing_required", None)
        gssapi = getattr(connection, "gssapi", None)
        is_guest: object = "?"
        if gssapi is not None and hasattr(gssapi, "is_guest"):
            try:
                is_guest = gssapi.is_guest()
            except Exception:  # noqa: BLE001
                is_guest = "?"
        print_info_debug(
            "coercion smb-session "
            f"login_ok={login_ok} guest={is_guest} "
            f"signing_required={signing_required} bind_ok={bind_ok}"
        )
    except Exception:  # noqa: BLE001
        pass


def _coercion_auth_level_note() -> None:
    """Why coercion binds use RPC_C_AUTHN_LEVEL_PKT_PRIVACY (the aiosmb default).

    ADscan does NOT override the RPC auth level for coercion: it uses the level
    aiosmb registers on each interface endpoint — ``RPC_C_AUTHN_LEVEL_PKT_PRIVACY``
    for the EFSR/RPRN/EVEN/DFSNM/FSRVP named-pipe interfaces.

    This is the empirically correct choice across the whole target spectrum,
    validated live against GOAD + an HTB member behind a Ligolo pivot:

    - **Hardened member servers (Server 2019+)** REJECT an unsealed EFSR coercion
      call with ``ACCESS_DENIED`` — e.g. ``EfsRpcAddUsersToFile`` over ``\\lsarpc``
      returns ``rpc_s_access_denied`` at ``RPC_C_AUTHN_LEVEL_NONE`` but
      ``ERROR_BAD_NETPATH`` (a successful trigger) at ``PKT_PRIVACY``.
    - **Soft member servers and DCs** trigger at BOTH ``NONE`` and ``PKT_PRIVACY``.

    So ``PKT_PRIVACY`` strictly dominates ``NONE``: it works everywhere ``NONE``
    works, plus on hardened members where ``NONE`` fails. An earlier revision
    downgraded named-pipe coercion binds to ``NONE`` for supposed Coercer parity;
    that was a double mistake — it was rationalised from a misdiagnosed
    key-derivation regression (see the aiosmb ``connection.py`` fix) AND it
    actively broke coercion on patched member servers. Coercer itself triggers
    such hosts via its PKT_PRIVACY-sealed transport, not the unsealed SMB path.

    This is documentation only; the bind level flows straight from the endpoint
    catalog. ``tests/unit/services/coercion/test_aiosmb_adapter.py`` locks it.
    """


def _protocol_class(protocol: str) -> Any:
    protocol_upper = protocol.upper()
    if protocol_upper == "EFSR":
        from aiosmb.dcerpc.v5.interfaces.efsrmgr import EFSRRPC  # pylint: disable=import-error,no-name-in-module

        return EFSRRPC
    if protocol_upper == "RPRN":
        from aiosmb.dcerpc.v5.interfaces.rprnmgr import RPRNRPC

        return RPRNRPC
    if protocol_upper == "FSRVP":
        from aiosmb.dcerpc.v5.interfaces.fsrvpmgr import FSRVPRPC  # pylint: disable=import-error,no-name-in-module

        return FSRVPRPC
    if protocol_upper == "EVEN":
        from aiosmb.dcerpc.v5.interfaces.evenmgr import EVENRPC  # pylint: disable=import-error,no-name-in-module

        return EVENRPC
    if protocol_upper == "DFSNM":
        from aiosmb.dcerpc.v5.interfaces.dfsnmmgr import DFSNMRPC  # pylint: disable=import-error,no-name-in-module

        return DFSNMRPC
    raise ValueError(f"Unsupported coercion protocol: {protocol}")


def _find_native_endpoint(protocol_class: Any, endpoint: RpcEndpoint) -> Any:
    for candidate in protocol_class.endpoints():
        if (
            candidate.etype == endpoint.transport
            and candidate.uuid.lower() == endpoint.uuid.lower()
            and candidate.version == endpoint.version
            and candidate.pipename == endpoint.pipe
        ):
            return candidate
    raise ValueError(f"Endpoint is not valid for {endpoint.protocol}: {endpoint.label}")
