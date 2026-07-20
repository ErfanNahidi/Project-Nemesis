"""Lightweight async TCP connectivity probe for pre-flight attack step validation.

Distinguishes three network states before committing to a full auth attempt:

  open     — TCP handshake completed: host up, port listening, service reachable.
  closed   — TCP RST received: host up, port explicitly refused (service down/disabled).
  filtered — Timeout or ICMP unreachable: host offline, firewall dropping, or no route.

Intentionally has zero dependency on the skelsec native stack — this is a raw
asyncio probe, not an AD protocol. asysocks is correct for protocol traffic that
needs to traverse proxies; a 3-second TCP check before auth does not.

Never raises. All exceptions are mapped to a ProbeStatus.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Literal


ProbeStatus = Literal["open", "closed", "filtered"]

# Per-service canonical port list (primary first).
SERVICE_PROBE_PORTS: dict[str, list[int]] = {
    "smb":   [445],
    "rdp":   [3389],
    "winrm": [5985, 5986],
    "mssql": [1433],
    "dcom":  [135],
    "ldap":  [389],
    "ldaps": [636],
    "kerberos": [88],
    "dns":   [53],
}

# BloodHound action → service key (for the blocked-gate advisory).
ACTION_TO_SERVICE: dict[str, str] = {
    "adminto":    "smb",
    "sqlaccess":  "mssql",
    "sqladmin":   "mssql",
    "canrdp":     "rdp",
    "canpsremote": "winrm",
    "executedcom": "dcom",
}


@dataclass(frozen=True)
class TCPProbeResult:
    host: str
    port: int
    status: ProbeStatus
    elapsed_ms: float


async def tcp_probe(
    host: str,
    port: int,
    *,
    timeout: float = 3.0,
) -> TCPProbeResult:
    """Probe a single TCP port. Never raises."""
    t0 = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        elapsed = (time.monotonic() - t0) * 1000
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return TCPProbeResult(host=host, port=port, status="open", elapsed_ms=elapsed)
    except ConnectionRefusedError:
        elapsed = (time.monotonic() - t0) * 1000
        return TCPProbeResult(host=host, port=port, status="closed", elapsed_ms=elapsed)
    except (asyncio.TimeoutError, OSError, Exception):  # noqa: BLE001
        elapsed = (time.monotonic() - t0) * 1000
        return TCPProbeResult(host=host, port=port, status="filtered", elapsed_ms=elapsed)


async def tcp_probe_multi(
    host: str,
    ports: list[int],
    *,
    timeout: float = 3.0,
) -> TCPProbeResult:
    """Probe multiple ports — returns first open result, otherwise the last result.

    Sequential: short-circuits as soon as one port is open. Use this when probing
    fallback ports of the same service (e.g. WinRM 5985 → 5986).
    """
    result = TCPProbeResult(host=host, port=ports[0] if ports else 0, status="filtered", elapsed_ms=0)
    for port in ports:
        result = await tcp_probe(host, port, timeout=timeout)
        if result.status == "open":
            return result
    return result


async def tcp_probe_batch(
    host: str,
    ports: list[int],
    *,
    timeout: float = 3.0,
) -> dict[int, TCPProbeResult]:
    """Probe many ports concurrently against ONE host. Returns one result per port.

    Use this when probing distinct services in parallel (e.g. checking 53/389/445
    on a DC at once instead of three sequential 2s waits).
    """
    if not ports:
        return {}
    results = await asyncio.gather(
        *(tcp_probe(host, port, timeout=timeout) for port in ports)
    )
    return {r.port: r for r in results}


async def tcp_probe_hosts(
    hosts: list[str],
    port: int,
    *,
    timeout: float = 3.0,
    max_concurrency: int = 50,
) -> dict[str, TCPProbeResult]:
    """Probe ONE port across MANY hosts with bounded concurrency.

    The bounded semaphore is mandatory at scale: 1000 simultaneous open sockets
    would exhaust file-descriptor limits (default 1024) and saturate kernel TCP
    buffers. ``max_concurrency=50`` is ~2× the auth concurrency of 20 because
    the per-socket cost is ~50× lower (no NTLM/Kerberos handshake, no protocol
    negotiation), so the optimal probe parallelism is higher.

    Returns a mapping ``host -> TCPProbeResult`` preserving order via dict
    insertion semantics (Python 3.7+).
    """
    if not hosts:
        return {}
    sem = asyncio.Semaphore(max_concurrency)

    async def _bounded(h: str) -> TCPProbeResult:
        async with sem:
            return await tcp_probe(h, port, timeout=timeout)

    results = await asyncio.gather(*(_bounded(h) for h in hosts))
    return {r.host: r for r in results}


def action_to_service_ports(action: str) -> list[int]:
    """Map a BloodHound action name to its probe ports. Returns [] if unknown."""
    service = ACTION_TO_SERVICE.get(action.lower().strip())
    if not service:
        return []
    return SERVICE_PROBE_PORTS.get(service, [])
