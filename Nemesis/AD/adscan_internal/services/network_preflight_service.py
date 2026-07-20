"""Network preflight primitives shared by start and DNS flows.

This module is the **sync entry point** for route + TCP reachability checks.
The TCP probe semantics are owned by ``network_probe_service`` (async); this
module is a thin sync facade plus the route-assessment helpers that depend on
the host's ``run_command`` shell.

Single source of truth for TCP probing: ``network_probe_service.tcp_probe``.
Use it directly from async code; use this module from sync CLI flows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
import ipaddress
import re
import shlex

from adscan_internal import telemetry
from adscan_internal.services.async_bridge import run_async_sync
from adscan_internal.services.network_probe_service import (
    tcp_probe,
    tcp_probe_batch,
)


class NetworkPreflightHost(Protocol):
    """Protocol for host objects that can execute shell commands."""

    def run_command(self, command: str, **kwargs: Any):  # noqa: ANN401
        """Execute a command and return a CompletedProcess-like object."""


@dataclass(frozen=True)
class RouteAssessment:
    """Result of evaluating route presence for one target IP."""

    ok: bool
    reason: str
    route_interface: str | None = None
    source_ip: str | None = None
    raw_line: str | None = None


@dataclass(frozen=True)
class TargetReachabilityAssessment:
    """Result of evaluating route + TCP port reachability for one target IP.

    ``closed_ports`` and ``filtered_ports`` are kept distinct on purpose:
    a TCP RST (``closed``) is a definitive "nothing is listening here"
    answer, while a timeout/ICMP-unreachable (``filtered``) is inconclusive
    ("my probe budget expired"). Consumers that must not infer a negative
    verdict from a transient timeout (observe-vs-infer doctrine) rely on
    this distinction. ``closed_ports`` therefore contains ONLY explicitly
    refused ports; filtered/timeout ports live in ``filtered_ports``.
    """

    target_ip: str
    route: RouteAssessment
    open_ports: tuple[int, ...]
    closed_ports: tuple[int, ...]
    filtered_ports: tuple[int, ...] = ()

    def is_port_open(self, port: int) -> bool:
        """Return whether a specific TCP port is reachable."""
        return port in self.open_ports

    def is_port_filtered(self, port: int) -> bool:
        """Return whether a port was inconclusive (timeout/filtered, not RST)."""
        return port in self.filtered_ports


def get_interface_ipv4_addresses(interface: str) -> list[str]:
    """Return IPv4 addresses configured on an interface."""
    if not interface:
        return []
    try:
        import netifaces

        addresses = netifaces.ifaddresses(interface)
        inet_addresses = addresses.get(netifaces.AF_INET) or []
        values: list[str] = []
        for entry in inet_addresses:
            candidate = str(entry.get("addr", "")).strip()
            if not candidate:
                continue
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            values.append(candidate)
        return values
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return []


def assess_route_to_target(
    host: NetworkPreflightHost,
    *,
    target_ip: str,
    expected_interface: str | None = None,
) -> RouteAssessment:
    """Assess whether the host has a usable route to a target IP."""
    route_cmd = f"ip -4 route get {shlex.quote(target_ip)}"
    result = host.run_command(route_cmd, timeout=20, ignore_errors=True)
    if result is None:
        return RouteAssessment(
            ok=False,
            reason="route_command_failed",
        )

    output = "\n".join(
        line
        for line in ((result.stdout or "") + "\n" + (result.stderr or "")).splitlines()
        if line.strip()
    )
    first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    lowered = first_line.lower()
    if (
        result.returncode != 0
        or "unreachable" in lowered
        or "prohibit" in lowered
        or "blackhole" in lowered
    ):
        return RouteAssessment(
            ok=False,
            reason="no_route",
            raw_line=first_line or None,
        )

    route_interface = None
    source_ip = None
    dev_match = re.search(r"\bdev\s+(\S+)", first_line)
    if dev_match:
        route_interface = dev_match.group(1)
    src_match = re.search(r"\bsrc\s+(\S+)", first_line)
    if src_match:
        source_ip = src_match.group(1)

    if expected_interface and route_interface and route_interface != expected_interface:
        return RouteAssessment(
            ok=True,
            reason="route_interface_mismatch",
            route_interface=route_interface,
            source_ip=source_ip,
            raw_line=first_line or None,
        )

    return RouteAssessment(
        ok=True,
        reason="route_ok",
        route_interface=route_interface,
        source_ip=source_ip,
        raw_line=first_line or None,
    )


def is_tcp_port_open(host: str, port: int, *, timeout_seconds: float = 2.0) -> bool:
    """Return True when a TCP port is reachable.

    Sync wrapper over the canonical async ``tcp_probe``. From async code, call
    ``tcp_probe`` directly to avoid the thread-pool detour built into
    ``run_async_sync``.
    """
    result = run_async_sync(tcp_probe(host, port, timeout=timeout_seconds))
    return result.status == "open"


def assess_target_reachability(
    host: NetworkPreflightHost,
    *,
    target_ip: str,
    expected_interface: str | None = None,
    tcp_ports: tuple[int, ...] = (53,),
    timeout_seconds: float = 2.0,
) -> TargetReachabilityAssessment:
    """Assess route and TCP port reachability for a target IP.

    Port probes run concurrently — checking N ports costs ~one timeout window,
    not N. Probing 53/389/445 on a slow target now completes in ~timeout
    seconds instead of ~3*timeout.
    """
    route = assess_route_to_target(
        host, target_ip=target_ip, expected_interface=expected_interface
    )
    if not tcp_ports:
        return TargetReachabilityAssessment(
            target_ip=target_ip,
            route=route,
            open_ports=(),
            closed_ports=(),
            filtered_ports=(),
        )
    batch = run_async_sync(
        tcp_probe_batch(target_ip, list(tcp_ports), timeout=timeout_seconds)
    )
    open_ports = tuple(sorted(p for p, r in batch.items() if r.status == "open"))
    closed_ports = tuple(sorted(p for p, r in batch.items() if r.status == "closed"))
    filtered_ports = tuple(
        sorted(p for p, r in batch.items() if r.status not in ("open", "closed"))
    )
    return TargetReachabilityAssessment(
        target_ip=target_ip,
        route=route,
        open_ports=open_ports,
        closed_ports=closed_ports,
        filtered_ports=filtered_ports,
    )
