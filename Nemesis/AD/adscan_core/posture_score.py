"""Canonical AD posture score.

This module is the **single source of truth** for the 0-100 posture score
ADscan surfaces in the executive PDF, the web dashboard, the scan-diff
endpoint, and the CLI demo recap. Before this module existed the score
was computed in three different places with three different formulas;
rolling them up here means a fix in one place fixes the whole product.

Design constraints:
    - Pure, deterministic, no I/O. Safe to import in ``adscan_core``
      (host + container, dependency-light layer).
    - Stdlib only — no numpy, no pydantic, no rich.
    - The output number is the headline KPI of the executive money-shot:
      it must be defensible to a CISO. The components dict makes the
      breakdown auditable.

Algorithm (state it like a CISO would explain it):

    score = 100 - min(100, weighted_findings + paths_penalty + tier0_penalty)

where:

    weighted_findings = (25*critical + 10*high + 4*medium + 1*low) / 200 * 70
                        capped at 70.
        # Saturates at 200 weighted points, mapped to a 0..70 budget.
        # 1 critical alone burns 8.75 of the 70-point budget.

    paths_penalty     = min(20, paths_to_da * 6)
        # 0 paths = 0, 1 = 6, 2 = 12, 3+ saturates at 20.

    tier0_penalty     = min(10, tier0_exposed * 2)
        # 0 = 0, 1 = 2, ..., 5+ saturates at 10.

Bands:
    >= 80 : "Healthy"      — green
    60-79 : "Acceptable"   — cyan / blue
    40-59 : "Elevated"     — amber
    < 40  : "Critical"     — red

Critical floor (overrides the band math):
    If there is >= 1 reachable path to Domain Admin (``paths_to_da >= 1``) OR
    >= 1 exposed Tier-0 asset (``tier0_exposed >= 1``) — regardless of whether
    those paths were exploited, attempted, or only theoretical — the score is
    capped into the Critical band (at ``CRITICAL_BAND_TOP``) and the label
    becomes "Critical". A reachable path to Domain Admin IS the risk; the
    finding-load budget must never paint over it with an "Acceptable" headline.

Why this is better than the prior weighted-only formulas
(``RISK_SATURATION = 200``, weights 25/12/5/1, no path/tier-0 terms):

    1. The prior formulas could give a clean-looking 80+ score to an
       environment with three paths to Domain Admin if the underlying
       findings happened to be tagged high/medium instead of critical.
       That's editorially indefensible — paths-to-DA *is* the risk.
    2. Splitting the penalty into three named components makes the score
       debuggable at a glance ("you lost 18 points from paths, 6 from
       tier-0 exposure, 25 from finding load").
    3. The weights are still dominant (70-point budget vs 20+10), so
       environments without path data still land in the right band.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# --- Tunable constants -------------------------------------------------------
# These are exported so callers can inspect / show them in tooltips.

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 25,
    "high": 10,
    "medium": 4,
    "low": 1,
    "info": 0,
}

# Weighted-finding load that fully saturates the finding-load budget.
RISK_SATURATION: int = 200

# Penalty budget split. Total = 100. weighted_findings owns the majority
# because most environments have no path data on their first scan.
WEIGHTED_FINDINGS_BUDGET: float = 70.0
PATHS_PENALTY_PER_PATH: int = 6
PATHS_PENALTY_CAP: int = 20
TIER0_PENALTY_PER_ASSET: int = 2
TIER0_PENALTY_CAP: int = 10

# Band thresholds (inclusive lower bound for the band).
BAND_HEALTHY: int = 80
BAND_ACCEPTABLE: int = 60
BAND_ELEVATED: int = 40

# Highest numeric score still inside the Critical band. ``BAND_ELEVATED`` is
# the inclusive lower bound of Elevated, so Critical tops out one below it.
# Used by the path-to-Domain-Admin floor so the number and the label agree
# (never "63/100 Acceptable" sitting next to N paths to Domain Admin).
CRITICAL_BAND_TOP: int = BAND_ELEVATED - 1


@dataclass(frozen=True)
class PostureInputs:
    """Inputs to :func:`compute_posture_score`.

    Keep this struct flat and primitive — every field is a count. The
    caller is responsible for translating its domain model
    (Finding ORM rows, attack-path JSON, etc.) into these counts.
    """

    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    paths_to_da: int = 0
    tier0_exposed: int = 0


@dataclass(frozen=True)
class PostureScore:
    """Result of :func:`compute_posture_score`.

    Attributes:
        score: 0-100 integer. 100 = pristine, 0 = saturated risk.
        label: One of ``"Healthy" | "Acceptable" | "Elevated" | "Critical"``.
        components: Per-component penalty breakdown (floats, pre-rounding).
            Keys: ``weighted_findings``, ``paths_penalty``, ``tier0_penalty``,
            ``total_penalty``.
    """

    score: int
    label: str
    components: dict[str, float] = field(default_factory=dict)


def _band_label(score: int) -> str:
    """Map a 0-100 score to its band label."""
    if score >= BAND_HEALTHY:
        return "Healthy"
    if score >= BAND_ACCEPTABLE:
        return "Acceptable"
    if score >= BAND_ELEVATED:
        return "Elevated"
    return "Critical"


def compute_posture_score(inputs: PostureInputs) -> PostureScore:
    """Compute the canonical 0-100 posture score from finding+path counts.

    Args:
        inputs: :class:`PostureInputs` with severity counts and path /
            tier-0 exposure counts.

    Returns:
        A :class:`PostureScore` with the integer score, band label, and a
        debug ``components`` dict listing each penalty's contribution.

    The function is total: every input combination produces a valid
    output in ``[0, 100]``. Negative input counts are clamped to 0.
    """
    crit = max(0, inputs.critical_findings)
    high = max(0, inputs.high_findings)
    med = max(0, inputs.medium_findings)
    low = max(0, inputs.low_findings)
    paths = max(0, inputs.paths_to_da)
    tier0 = max(0, inputs.tier0_exposed)

    weighted_raw = (
        SEVERITY_WEIGHTS["critical"] * crit
        + SEVERITY_WEIGHTS["high"] * high
        + SEVERITY_WEIGHTS["medium"] * med
        + SEVERITY_WEIGHTS["low"] * low
    )
    # Scale to 0..WEIGHTED_FINDINGS_BUDGET, saturating at RISK_SATURATION.
    weighted_findings_penalty = min(
        WEIGHTED_FINDINGS_BUDGET,
        weighted_raw / RISK_SATURATION * WEIGHTED_FINDINGS_BUDGET,
    )

    paths_penalty = float(min(PATHS_PENALTY_CAP, paths * PATHS_PENALTY_PER_PATH))
    tier0_penalty = float(min(TIER0_PENALTY_CAP, tier0 * TIER0_PENALTY_PER_ASSET))

    total_penalty = min(100.0, weighted_findings_penalty + paths_penalty + tier0_penalty)
    score = int(round(100.0 - total_penalty))
    score = max(0, min(100, score))

    # --- Critical floor: any reachable path to Domain Admin / Tier-0 -------
    # A single reachable path to Domain Admin (or any exposed Tier-0 asset)
    # IS the risk — it doesn't matter whether it was EXPLOITED, ATTEMPTED, or
    # merely THEORETICAL (derived from config). The weighted-finding budget
    # (70 pts) dominates the path/tier-0 penalties (20+10), so a "weak"
    # finding profile could otherwise leave the score in the Acceptable band
    # (e.g. 63/100) while the same report shows 16 paths to Domain Admin —
    # self-contradictory. When such exposure exists we FLOOR the posture into
    # the Critical band: cap the numeric score at the top of the Critical band
    # so the headline number and the band label always agree. The component
    # breakdown is preserved (auditable) and a ``critical_floor_applied`` flag
    # records that the floor fired.
    critical_floor_applied = paths > 0 or tier0 > 0
    if critical_floor_applied and score > CRITICAL_BAND_TOP:
        score = CRITICAL_BAND_TOP

    return PostureScore(
        score=score,
        label=_band_label(score),
        components={
            "weighted_findings": round(weighted_findings_penalty, 2),
            "paths_penalty": round(paths_penalty, 2),
            "tier0_penalty": round(tier0_penalty, 2),
            "total_penalty": round(total_penalty, 2),
            "critical_floor_applied": float(critical_floor_applied),
        },
    )


__all__ = (
    "BAND_ACCEPTABLE",
    "BAND_ELEVATED",
    "BAND_HEALTHY",
    "CRITICAL_BAND_TOP",
    "PATHS_PENALTY_CAP",
    "PATHS_PENALTY_PER_PATH",
    "PostureInputs",
    "PostureScore",
    "RISK_SATURATION",
    "SEVERITY_WEIGHTS",
    "TIER0_PENALTY_CAP",
    "TIER0_PENALTY_PER_ASSET",
    "WEIGHTED_FINDINGS_BUDGET",
    "compute_posture_score",
)
