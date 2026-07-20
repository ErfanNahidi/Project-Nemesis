"""ADCS CA HTTP web enrollment probe (ESC8).

Detects whether the CA host exposes an exploitable ``/certsrv/`` web
enrollment endpoint. A raw TCP port check is NOT sufficient: ports 80/443 are
routinely open for unrelated IIS/ADFS sites, which produced ESC8 false
positives (e.g. an IIS host with no ``/certsrv/`` at all). The true-positive
signature of an ESC8-vulnerable certsrv endpoint is an HTTP ``401`` response
to ``GET /certsrv/certfnsh.asp`` carrying a ``WWW-Authenticate`` header that
offers ``NTLM`` or ``Negotiate`` — that is the surface an NTLM relay actually
lands on.

We deliberately avoid pulling in an HTTP client dependency (no aiohttp /
httpx). asysocks ships an HTTP ``ClientSession``, but it is a full session
abstraction (cookie jar, auth manager, connection factory, redirect handling,
proxy plumbing) — disproportionate for a stateless reachability probe that
only needs to read the status line and the ``WWW-Authenticate`` header. The
relay client (``relay/adcs_esc8.py``) already drives this exact endpoint with
``asyncio.open_connection`` + a permissive ``ssl`` context, so we mirror that
pattern here for a minimal hand-written HTTP/1.1 ``GET``: same transport, same
TLS posture (CA web certs are routinely self-signed → verification disabled),
no extra dependency.

False-negative biased: any failure, non-401 status, or absent NTLM/Negotiate
offer -> the scheme is treated as NOT web-enrollment-enabled.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass

from adscan_core.rich_output import print_info_debug, print_info_verbose
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive

# Single source of truth for the certsrv enrollment endpoint path. Shared by
# the probe (detection) and conceptually mirrored by the relay client.
CERTSRV_ENROLL_PATH = "/certsrv/certfnsh.asp"

_HTTP_USER_AGENT = "Mozilla/5.0 (compatible; ADscan ADCS Web Enrollment Probe)"
# Header-read ceiling: certsrv 401 responses are tiny; cap so a misbehaving
# endpoint that never sends the header terminator cannot stall the probe.
_MAX_HEADER_BYTES = 64 * 1024


@dataclass
class WebEnrollmentProbeResult:
    """Outcome of probing a CA host for an exploitable certsrv endpoint.

    ``web_enrollment_enabled`` is the overall ESC8 verdict (HTTP-aware): True
    only when at least one scheme answered ``GET /certsrv/certfnsh.asp`` with a
    401 offering NTLM/Negotiate. The per-scheme ``*_ntlm`` flags and
    ``answering_scheme`` let the relay pick the right transport (HTTPS-first
    when both qualify).
    """

    target_host: str
    web_enrollment_enabled: bool
    https_enabled: bool
    http_enabled: bool
    https_ntlm: bool = False
    http_ntlm: bool = False
    answering_scheme: str | None = None
    error_message: str | None = None


@dataclass
class _SchemeProbeResult:
    """Per-scheme HTTP probe outcome."""

    tcp_open: bool
    status: int | None
    ntlm_offered: bool


class ADCSWebEnrollmentProbe:
    """Detect an exploitable HTTP(S) ``/certsrv/`` endpoint on a CA host."""

    async def probe(
        self, *, host: str, timeout: float = 5.0
    ) -> WebEnrollmentProbeResult:
        if not host:
            return WebEnrollmentProbeResult(
                target_host="",
                web_enrollment_enabled=False,
                https_enabled=False,
                http_enabled=False,
                error_message="missing host",
            )

        # Probe HTTPS first so HTTPS-first scheme selection in the relay reflects
        # the operator-preferred transport when both qualify.
        https = await self._probe_scheme(host, "https", 443, timeout)
        http = await self._probe_scheme(host, "http", 80, timeout)

        masked = mark_sensitive(host, "host")
        for scheme, res in (("https", https), ("http", http)):
            if not res.tcp_open:
                print_info_debug(
                    f"[adcs-web-probe] {scheme} port closed: host={masked}"
                )
                continue
            print_info_verbose(
                f"[adcs-web-probe] {scheme} {CERTSRV_ENROLL_PATH}: host={masked} "
                f"status={res.status} ntlm_or_negotiate={res.ntlm_offered}"
            )

        # ESC8 verdict: a scheme qualifies only on 401 + NTLM/Negotiate offer.
        answering_scheme: str | None = None
        if https.ntlm_offered:
            answering_scheme = "https"
        elif http.ntlm_offered:
            answering_scheme = "http"

        enabled = answering_scheme is not None
        print_info_debug(
            f"[adcs-web-probe] ESC8 verdict for host={masked}: "
            f"enabled={enabled} answering_scheme={answering_scheme} "
            f"(https_ntlm={https.ntlm_offered} http_ntlm={http.ntlm_offered})"
        )

        return WebEnrollmentProbeResult(
            target_host=host,
            web_enrollment_enabled=enabled,
            https_enabled=https.tcp_open,
            http_enabled=http.tcp_open,
            https_ntlm=https.ntlm_offered,
            http_ntlm=http.ntlm_offered,
            answering_scheme=answering_scheme,
        )

    async def _probe_scheme(
        self, host: str, scheme: str, port: int, timeout: float
    ) -> _SchemeProbeResult:
        """TCP pre-check, then an HTTP GET of the certsrv endpoint.

        Returns ``ntlm_offered=True`` only on the true-positive ESC8 signature
        (HTTP 401 with a ``WWW-Authenticate`` header offering NTLM/Negotiate).
        Any failure / non-401 / no-NTLM keeps the false-negative bias.
        """
        if not await self._tcp_open(host, port, timeout):
            return _SchemeProbeResult(tcp_open=False, status=None, ntlm_offered=False)

        try:
            status, www_authenticate = await self._http_get_certsrv(
                host, scheme, port, timeout
            )
        except (
            asyncio.TimeoutError,
            asyncio.LimitOverrunError,
            asyncio.IncompleteReadError,
            ConnectionResetError,
            ConnectionRefusedError,
            OSError,
            ssl.SSLError,
            socket.gaierror,
        ):
            # Reachable on TCP but the HTTP/TLS exchange failed — not a
            # confirmed certsrv endpoint. False-negative bias: not enabled.
            return _SchemeProbeResult(tcp_open=True, status=None, ntlm_offered=False)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return _SchemeProbeResult(tcp_open=True, status=None, ntlm_offered=False)

        ntlm_offered = status == 401 and _offers_ntlm_or_negotiate(www_authenticate)
        return _SchemeProbeResult(
            tcp_open=True, status=status, ntlm_offered=ntlm_offered
        )

    async def _http_get_certsrv(
        self, host: str, scheme: str, port: int, timeout: float
    ) -> tuple[int | None, str]:
        """Issue ``GET /certsrv/certfnsh.asp`` and return (status, WWW-Authenticate).

        Hand-written HTTP/1.1; no redirect following. TLS verification is
        disabled for the https scheme because CA web certificates are commonly
        self-signed — we only inspect the status line and headers, never trust
        the channel for data.
        """
        ssl_context = None
        server_hostname = None
        if scheme == "https":
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            server_hostname = host

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ssl_context,
                server_hostname=server_hostname,
                limit=_MAX_HEADER_BYTES,
            ),
            timeout=timeout,
        )
        try:
            request = (
                f"GET {CERTSRV_ENROLL_PATH} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {_HTTP_USER_AGENT}\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=timeout)

            header_bytes = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=timeout
            )
        finally:
            try:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            except Exception:  # noqa: BLE001
                pass

        return parse_status_and_www_authenticate(header_bytes)

    @staticmethod
    async def _tcp_open(host: str, port: int, timeout: float) -> bool:
        try:
            fut = asyncio.open_connection(host, port)
            _reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            try:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            except Exception:  # noqa: BLE001
                pass
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, socket.gaierror):
            return False
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return False


def parse_status_and_www_authenticate(header_bytes: bytes) -> tuple[int | None, str]:
    """Parse an HTTP/1.1 response head into (status_code, joined WWW-Authenticate).

    Pure function so the FP-prevention contract is unit-testable without a
    socket. Folds repeated ``WWW-Authenticate`` headers (servers emit one per
    scheme: ``Negotiate`` then ``NTLM``) into a single comma-joined string.
    Returns ``(None, "")`` when the status line is unparseable.
    """
    text = header_bytes.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None, ""

    status: int | None = None
    parts = lines[0].split(" ", 2)
    if len(parts) >= 2 and parts[0].upper().startswith("HTTP/"):
        try:
            status = int(parts[1])
        except ValueError:
            status = None

    www_authenticate_values: list[str] = []
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() == "www-authenticate":
            stripped = value.strip()
            if stripped:
                www_authenticate_values.append(stripped)

    return status, ", ".join(www_authenticate_values)


def _offers_ntlm_or_negotiate(www_authenticate: str) -> bool:
    """True when the WWW-Authenticate header offers NTLM or Negotiate."""
    lowered = www_authenticate.lower()
    return "ntlm" in lowered or "negotiate" in lowered
