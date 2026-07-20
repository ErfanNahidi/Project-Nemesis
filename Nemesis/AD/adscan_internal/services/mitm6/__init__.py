"""Native MITM6 — DHCPv6 + RA poisoning + DNS hijacking (mitm6 replacement).

License-clean reimplementation that powers our async stack and integrates
with the existing relay layer.  Use ``MITM6Suite`` as the single
entry point for composed lifecycle management.
"""

from adscan_internal.services.mitm6.core import (
    DHCPv6Observation,
    DNSObservation,
    MITM6Callback,
    MITM6Config,
)
from adscan_internal.services.mitm6.dhcpv6_poisoner import (
    DHCPv6Poisoner,
    send_router_advertisement_loop,
)
from adscan_internal.services.mitm6.dns_hijacker import (
    DNSHijacker,
    build_dns_response,
    parse_dns_query,
)
from adscan_internal.services.mitm6.orchestrator import MITM6Suite

__all__ = [
    "DHCPv6Observation",
    "DHCPv6Poisoner",
    "DNSHijacker",
    "DNSObservation",
    "MITM6Callback",
    "MITM6Config",
    "MITM6Suite",
    "build_dns_response",
    "parse_dns_query",
    "send_router_advertisement_loop",
]
