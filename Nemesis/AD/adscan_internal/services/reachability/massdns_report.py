"""Single source of truth for the massdns hostname resolution report.

This module owns the pure report-building, persistence, and loading logic for
the massdns hostname-to-IP resolution report. It is intentionally
dependency-light (stdlib ``os``/``json`` only) so that both layers that produce
or consume the report can share it without a CLI-layer dependency:

- Phase 2 — the collector DNS resolver (``collector/dns_resolver``) runs massdns
  in memory during attack-graph collection.
- Phase 3 — ``cli/nmap`` persists ``massdns_resolution_report.json`` for later
  review and consumption.

The JSON payload shape produced here is a consumed contract (see
``adscan_internal/services/kerberos_hostname_inventory.py`` and the report
display verb). Do not change the payload structure without updating every
consumer.

This module must NOT import from ``adscan_internal.cli`` (services-layer rule)
and must remain free of any print/logging side effects.
"""

from __future__ import annotations

import json
import os


def _flatten_massdns_unique_ips(
    hostnames: list[str],
    host_to_ips: dict[str, list[str]],
) -> list[str]:
    """Return unique IPs preserving hostname/input order from a massdns mapping."""
    normalized_host_to_ips = {
        str(hostname or "").strip().rstrip(".").lower(): list(ips)
        for hostname, ips in host_to_ips.items()
        if str(hostname or "").strip()
    }
    unique_ips: list[str] = []
    seen_ips: set[str] = set()
    for hostname in hostnames:
        normalized_hostname = str(hostname or "").strip().rstrip(".").lower()
        for ip_value in normalized_host_to_ips.get(normalized_hostname, []):
            if ip_value in seen_ips:
                continue
            seen_ips.add(ip_value)
            unique_ips.append(ip_value)
    return unique_ips


def _build_massdns_resolution_report(
    hostnames: list[str],
    host_to_ips: dict[str, list[str]],
    *,
    domain: str | None = None,
    input_file: str | None = None,
    resolvers: list[str] | None = None,
    ip_file: str | None = None,
    raw_output_file: str | None = None,
) -> dict[str, object]:
    """Build a structured massdns hostname resolution report."""
    resolved: list[dict[str, object]] = []
    unresolved: list[str] = []

    for original_host in hostnames:
        normalized_host = str(original_host or "").strip().rstrip(".").lower()
        ips = list(host_to_ips.get(normalized_host, []))
        if ips:
            resolved.append({"hostname": original_host, "ips": ips})
            continue
        unresolved.append(original_host)

    unique_ips = _flatten_massdns_unique_ips(
        [str(item["hostname"]) for item in resolved],
        {str(item["hostname"]): list(item["ips"]) for item in resolved},
    )
    multi_ip_hostnames = [
        str(item["hostname"]) for item in resolved if len(list(item["ips"])) > 1
    ]
    payload: dict[str, object] = {
        "summary": {
            "total_hostnames": len(hostnames),
            "resolved_hostnames": len(resolved),
            "unresolved_hostnames": len(unresolved),
            "unique_ip_count": len(unique_ips),
            "multi_ip_hostnames": multi_ip_hostnames,
        },
        "resolved": resolved,
        "unresolved": unresolved,
    }
    context: dict[str, object] = {}
    if domain:
        context["domain"] = domain
    if input_file:
        context["input_file"] = input_file
    if resolvers:
        context["resolver_sources"] = list(dict.fromkeys(resolvers))
    if ip_file:
        context["resolved_ip_file"] = ip_file
    if raw_output_file:
        context["raw_massdns_output_file"] = raw_output_file
    if context:
        payload["context"] = context
    return payload


def _write_massdns_resolution_report(
    report_path: str,
    *,
    hostnames: list[str],
    host_to_ips: dict[str, list[str]],
    domain: str | None = None,
    input_file: str | None = None,
    resolvers: list[str] | None = None,
    ip_file: str | None = None,
    raw_output_file: str | None = None,
) -> bool:
    """Persist a structured massdns resolution report for later review."""
    try:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        payload = _build_massdns_resolution_report(
            hostnames,
            host_to_ips,
            domain=domain,
            input_file=input_file,
            resolvers=resolvers,
            ip_file=ip_file,
            raw_output_file=raw_output_file,
        )
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=False)
            handle.write("\n")
    except OSError:
        return False
    return True


def _load_massdns_resolution_report(report_path: str) -> dict[str, object] | None:
    """Load a persisted massdns resolution report from disk."""
    if not report_path or not os.path.exists(report_path):
        return None
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None
