"""Native LLMNR / mDNS / NBT-NS poisoners (Responder replacement)."""

from adscan_internal.services.poisoning.orchestrator import PoisoningSuite
from adscan_internal.services.poisoning.poisoner import (
    LLMNRPoisoner,
    MDNSPoisoner,
    NBTNSPoisoner,
    PoisonObservation,
    PoisonerConfig,
)

__all__ = [
    "LLMNRPoisoner",
    "MDNSPoisoner",
    "NBTNSPoisoner",
    "PoisonObservation",
    "PoisonerConfig",
    "PoisoningSuite",
]
