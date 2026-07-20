"""Centralized target-access requirements for attack-step execution.

This module answers one narrow question: before executing an attack step
against a computer target, does ADscan need the host to expose a specific
service from the current vantage, or is the step directory-only?

It intentionally separates:

* directory-only object-control writes (LDAP / Kerberos against a DC)
* host-bound execution that requires a concrete target service

This keeps attack-path readiness aligned with how each step actually executes
instead of treating every computer target as a generic "reachable host".
"""

from __future__ import annotations

from dataclasses import dataclass

from adscan_internal.services.attack_step_catalog import normalize_execution_relation
from adscan_internal.services.network_probe_service import (
    ACTION_TO_SERVICE,
    SERVICE_PROBE_PORTS,
)


@dataclass(frozen=True, slots=True)
class AttackStepTargetAccessProfile:
    """Execution-time target access requirement for one attack step."""

    relation: str
    target_kind: str
    legacy_requirement: str
    access_mode: str
    required_service: str | None = None
    required_ports: tuple[int, ...] = ()
    block_on_unreachable: bool = False
    rationale: str = ""


_COMPUTER_OBJECT_CONTROL_RELATIONS = frozenset(
    {
        "genericall",
        "genericwrite",
        "owns",
        "writeaccountrestrictions",
    }
)

_EXPLICIT_RELATION_TO_SERVICE: dict[str, str] = {
    "hassession": "smb",
    "mssql_impersonate_login": "mssql",
    "mssql_linked_server_lateral": "mssql",
    "mssql_ntlmv2_theft": "mssql",
    "mssql_seimpersonate_escalation": "mssql",
    "mssql_token_theft_escalation": "mssql",
    "mssql_trustworthy_db_escalation": "mssql",
}


def resolve_attack_step_target_access_profile(
    relation: str,
    *,
    target_kind: str = "",
) -> AttackStepTargetAccessProfile:
    """Return the target-access profile for one attack step.

    The returned profile is the single source of truth for whether attack-path
    readiness should block on host/service reachability, and which ports must
    be present in the current-vantage report for that judgment.
    """
    relation_norm = normalize_execution_relation(relation)
    target_kind_norm = str(target_kind or "").strip().lower()

    if (
        target_kind_norm == "computer"
        and relation_norm in _COMPUTER_OBJECT_CONTROL_RELATIONS
    ):
        return AttackStepTargetAccessProfile(
            relation=relation_norm,
            target_kind=target_kind_norm,
            legacy_requirement="computer_reachable",
            access_mode="service_specific",
            required_service="smb",
            required_ports=tuple(SERVICE_PROBE_PORTS.get("smb", ())),
            block_on_unreachable=True,
            rationale=(
                "Computer-object control steps (RBCD, Shadow Credentials) always "
                "consume the directory write against the target host via SMB. "
                "The target must be reachable before execution can proceed."
            ),
        )

    service = _EXPLICIT_RELATION_TO_SERVICE.get(relation_norm) or ACTION_TO_SERVICE.get(
        relation_norm
    )
    if service:
        return AttackStepTargetAccessProfile(
            relation=relation_norm,
            target_kind=target_kind_norm,
            legacy_requirement="computer_reachable",
            access_mode="service_specific",
            required_service=service,
            required_ports=tuple(SERVICE_PROBE_PORTS.get(service, ())),
            block_on_unreachable=True,
            rationale=(
                "This step is host-bound and requires the target service to be "
                "reachable from the current vantage before execution can proceed."
            ),
        )

    return AttackStepTargetAccessProfile(
        relation=relation_norm,
        target_kind=target_kind_norm,
        legacy_requirement="none",
        access_mode="none",
        rationale="This step does not require a host-service reachability gate.",
    )
