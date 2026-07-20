"""Canonical lifecycle state for an ADscan attack path.

Declared in Phase 1 so the data model supports the lifecycle from the
start. State transitions (theoretical -> foothold_obtained -> ... ->
domain_compromised) are implemented in Phase 6 of the attack-graph
refactor — see ``adscan-obsidian/business/12_nomenclature_standard.md``
(§ Fase 1, subsection PathState).

Newly materialised paths default to :attr:`PathState.THEORETICAL`. The
runtime promotion to higher states happens only when ADscan executes a
post-exploitation technique and records the outcome (success, failure)
against the path.
"""

from __future__ import annotations

from enum import Enum


class PathState(str, Enum):
    """Canonical lifecycle state of an attack path."""

    THEORETICAL = "theoretical"
    FOOTHOLD_OBTAINED = "foothold_obtained"
    POST_EX_IN_PROGRESS = "post_ex_in_progress"
    POST_EX_FAILED = "post_ex_failed"
    DOMAIN_COMPROMISED = "domain_compromised"

    @property
    def is_proven(self) -> bool:
        """Return True when the state implies executed evidence (not just LDAP)."""
        return self in {
            PathState.FOOTHOLD_OBTAINED,
            PathState.POST_EX_IN_PROGRESS,
            PathState.POST_EX_FAILED,
            PathState.DOMAIN_COMPROMISED,
        }
