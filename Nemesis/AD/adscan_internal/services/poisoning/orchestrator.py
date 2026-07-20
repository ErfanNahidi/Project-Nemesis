"""Coordinator that runs LLMNR + mDNS + NBT-NS poisoners as one suite.

Mirrors the lifecycle of the rest of the relay layer
(``SMBNtlmCaptureSource``, ``HTTPKrbListener``): async ``start() / stop()``
with a single configuration object.  Failure of any one poisoner aborts the
whole suite to avoid running with partial coverage that would be confusing
to debug.

Typical use::

    config = PoisonerConfig(interface_name="eth0", our_ipv4="10.0.0.1")
    observations: asyncio.Queue[PoisonObservation] = asyncio.Queue()
    suite = PoisoningSuite(config, observations.put)
    await suite.start()
    try:
        # Hashes from poisoned victims will land in your separate
        # SMBNtlmCaptureSource queue.  The observations queue here is for
        # *which name was poisoned for which victim*, useful for telemetry.
        ...
    finally:
        await suite.stop()
"""

from __future__ import annotations

import asyncio
import contextlib

from adscan_internal.rich_output import print_info_debug
from adscan_internal.services.poisoning.poisoner import (
    LLMNRPoisoner,
    MDNSPoisoner,
    NBTNSPoisoner,
    PoisonCallback,
    PoisonerConfig,
)


class PoisoningSuite:
    """Run LLMNR + mDNS + NBT-NS poisoners with a shared lifecycle."""

    def __init__(
        self,
        config: PoisonerConfig,
        observation_callback: PoisonCallback = None,
        *,
        enable_llmnr: bool = True,
        enable_mdns: bool = True,
        enable_nbtns: bool = True,
    ) -> None:
        self._config = config
        self._observation_callback = observation_callback
        self._poisoners: list[LLMNRPoisoner | MDNSPoisoner | NBTNSPoisoner] = []
        if enable_llmnr:
            self._poisoners.append(LLMNRPoisoner(config, observation_callback))
        if enable_mdns:
            self._poisoners.append(MDNSPoisoner(config, observation_callback))
        if enable_nbtns:
            self._poisoners.append(NBTNSPoisoner(config, observation_callback))

    async def start(self) -> None:
        """Start every enabled poisoner; tear down on first failure."""

        started: list[LLMNRPoisoner | MDNSPoisoner | NBTNSPoisoner] = []
        try:
            for poisoner in self._poisoners:
                await poisoner.start()
                started.append(poisoner)
        except Exception:
            for poisoner in started:
                with contextlib.suppress(Exception):
                    await poisoner.stop()
            raise
        print_info_debug(
            "[poisoning-suite] started "
            f"({', '.join(p.protocol for p in self._poisoners)})"
        )

    async def stop(self) -> None:
        """Stop all poisoners (best-effort, never raises)."""

        await asyncio.gather(
            *(self._stop_one(p) for p in self._poisoners), return_exceptions=True
        )
        print_info_debug("[poisoning-suite] stopped")

    @staticmethod
    async def _stop_one(poisoner: LLMNRPoisoner | MDNSPoisoner | NBTNSPoisoner) -> None:
        with contextlib.suppress(Exception):
            await poisoner.stop()


__all__ = ["PoisoningSuite"]
