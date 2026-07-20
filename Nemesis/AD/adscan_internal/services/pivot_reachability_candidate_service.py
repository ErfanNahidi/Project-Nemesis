"""Shared pivot reachability candidate selection.

The current-vantage reachability report answers two distinct questions:
whether a host responds at all, and whether useful lateral-movement services
are exposed from the operator's current route. Pivot workflows need both
signals, independent of the execution surface used to pivot.
"""

from __future__ import annotations

from typing import Any

PIVOT_RELEVANT_CURRENT_VANTAGE_PORTS = {88, 389, 445, 1433, 3389, 5985, 5986}


def _extract_ports_scanned(payload: dict[str, Any]) -> list[int]:
    """Return TCP ports scanned in the current-vantage reachability report."""
    context = payload.get("context", {})
    if not isinstance(context, dict):
        return []
    return [
        int(port) for port in context.get("ports_scanned", []) if str(port).isdigit()
    ]


def _collect_trusted_domain_pivot_candidates(
    *,
    source_domain: str,
    domain_connectivity: dict[str, Any],
    domains_data: dict[str, Any],
    ports_scanned: list[int],
) -> list[dict[str, Any]]:
    """Collect trusted-domain PDCs that were not reachable from the current vantage."""
    candidates: list[dict[str, Any]] = []
    for trusted_domain, payload in domain_connectivity.items():
        if not isinstance(payload, dict):
            continue
        summary = payload.get("summary")
        if not isinstance(summary, dict):
            continue
        if (
            str(summary.get("source_domain") or "").strip().lower()
            != source_domain.lower()
        ):
            continue
        if bool(summary.get("reachable")):
            continue
        trusted_state = (
            domains_data.get(trusted_domain, {})
            if isinstance(domains_data, dict)
            else {}
        )
        if isinstance(trusted_state, dict) and bool(
            trusted_state.get("phase1_complete")
        ):
            continue
        pdc_ip = str(summary.get("pdc_ip") or "").strip()
        if not pdc_ip:
            continue
        candidates.append(
            {
                "ip": pdc_ip,
                "status": str(summary.get("status") or "").strip()
                or "no_response_from_current_vantage",
                "classification": "trusted_domain_pdc_unreachable",
                "hostname_candidates": [trusted_domain],
                "ports": list(ports_scanned),
                "origin": "trusted_domain_connectivity",
                "target_domain": trusted_domain,
            }
        )
    return candidates


def collect_pivot_reachability_candidates(
    *,
    source_domain: str,
    payload: dict[str, Any],
    domain_connectivity: dict[str, Any] | None = None,
    domains_data: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int], list[int]]:
    """Collect host-level, service-level, and trusted-domain pivot candidates."""
    ip_entries = payload.get("ips", []) if isinstance(payload.get("ips"), list) else []
    ports_scanned = _extract_ports_scanned(payload)

    candidates: list[dict[str, Any]] = []
    host_hidden_count = 0
    service_hidden_count = 0
    for entry in ip_entries:
        if not isinstance(entry, dict):
            continue
        ip_text = str(entry.get("ip") or "").strip()
        if not ip_text:
            continue
        status = str(entry.get("status") or "").strip()
        open_ports = {
            int(port) for port in entry.get("open_ports", []) if str(port).isdigit()
        }
        candidate_origin = "current_vantage"
        if status == "no_response_from_current_vantage":
            host_hidden_count += 1
        elif not open_ports.intersection(PIVOT_RELEVANT_CURRENT_VANTAGE_PORTS):
            service_hidden_count += 1
            candidate_origin = "current_vantage_service_gap"
        else:
            continue
        candidate = dict(entry)
        candidate["ports"] = list(ports_scanned)
        candidate["origin"] = candidate_origin
        candidate["target_domain"] = None
        candidates.append(candidate)

    trusted_domain_candidates = _collect_trusted_domain_pivot_candidates(
        source_domain=source_domain,
        domain_connectivity=domain_connectivity or {},
        domains_data=domains_data or {},
        ports_scanned=ports_scanned,
    )
    existing_ips = {str(entry.get("ip") or "").strip() for entry in candidates}
    for candidate in trusted_domain_candidates:
        if str(candidate.get("ip") or "").strip() in existing_ips:
            continue
        candidates.append(candidate)

    counts = {
        "host_hidden_count": host_hidden_count,
        "service_hidden_count": service_hidden_count,
        "trusted_domain_count": len(trusted_domain_candidates),
        "total_count": len(candidates),
    }
    return candidates, counts, ports_scanned
