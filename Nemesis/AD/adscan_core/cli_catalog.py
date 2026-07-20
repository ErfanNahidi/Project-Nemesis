"""Single source of truth for CLI subcommand tier classification.

Used by both the host-side launcher (``adscan_launcher/cli.py``) and the
container-side dispatcher (``adscan.py``) to:

- Render the ``adscan --help`` listing with ``[PRO]`` / ``[LITE]`` badges
  grouped under a "Client Deliverables" category.
- Gate PRO-only commands with the exit-42 protocol (LITE container exits
  42 + JSON; launcher renders the canonical PRO upsell panel).

Keep this module dependency-light — it is imported by both the launcher
(host) and the runtime (container). No heavy imports.
"""

from __future__ import annotations

from typing import Literal

Tier = Literal["LITE", "PRO"]

# Commands that require PRO. Matches the dispatch gate in ``adscan.py``
# and the post-exit-42 upsell in ``adscan_launcher/cli.py``.
#
# After the surface-unification kill, the only PRO command is ``deliver``.
# The four PDFs that used to be standalone commands are now reachable via
# ``adscan deliver --only playbook|checklist|coverage-matrix|executive``.
PRO_ONLY_COMMANDS: frozenset[str] = frozenset({
    "deliver",
})

# Commands that ship in LITE (operator-facing desk references and the
# free entry points). Used purely for help-listing classification.
LITE_DELIVERABLE_COMMANDS: frozenset[str] = frozenset({
    "cheatsheet",
    "mitre-navigator",
})

# All commands that belong to the "Client Deliverables" help category, in
# the order they should be displayed. This tuple's only job is a stable
# display order; the LITE-vs-PRO grouping in the launcher help is derived
# from ``tier_for_command`` at render time, not from this ordering.
DELIVERABLE_COMMAND_ORDER: tuple[str, ...] = (
    "deliver",
    "cheatsheet",
    "mitre-navigator",
)


def tier_for_command(command: str) -> Tier:
    """Return the tier badge for ``command``.

    Defaults to ``"LITE"`` for any command not explicitly listed as PRO.
    """
    return "PRO" if command in PRO_ONLY_COMMANDS else "LITE"


def is_pro_only(command: str) -> bool:
    """Return ``True`` when ``command`` is gated to the PRO tier."""
    return command in PRO_ONLY_COMMANDS


__all__ = (
    "Tier",
    "PRO_ONLY_COMMANDS",
    "LITE_DELIVERABLE_COMMANDS",
    "DELIVERABLE_COMMAND_ORDER",
    "tier_for_command",
    "is_pro_only",
)
