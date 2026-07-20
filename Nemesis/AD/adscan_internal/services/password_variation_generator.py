"""Pure password variation generator for lockout-free spraying.

No I/O, no network. Callable in L1 unit tests with any base string.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordVariation:
    """One generated password candidate.

    Attributes:
        password: The candidate string.
        tier: 1, 2, or 3 (higher = lower expected hit-rate, more noise).
        rule: Stable identifier for the transformation (e.g. "base",
              "suffix_year_current", "leet_a_to_at"). Used in manifests
              and telemetry; never shown to the operator.
        priority: Stable rank within the tier (lower number = tried first).
    """

    password: str
    tier: int
    rule: str
    priority: int


def generate_variations(
    base: str,
    *,
    max_tier: int,
    current_year: int,
    year_sweep_back: int = 12,
) -> list[PasswordVariation]:
    """Return deduplicated variations of ``base`` up to ``max_tier``.

    Output is in stable (tier, priority) order.  The same input always
    produces the same output.  Caller is responsible for policy-compliance
    filtering and budget truncation.

    Args:
        base: The seed password (e.g. "adscan", "Adscan2026").
        max_tier: Maximum tier to include (1, 2, or 3).
        current_year: Integer year used for year-based mutations.
        year_sweep_back: How many years back Tier 2 sweeps.

    Returns:
        Deduplicated list of PasswordVariation in (tier, priority) order.
    """
    seen: set[str] = set()
    out: list[PasswordVariation] = []

    def _add(password: str, tier: int, rule: str) -> None:
        if password not in seen:
            seen.add(password)
            out.append(PasswordVariation(password=password, tier=tier, rule=rule, priority=len(out)))

    cap = base[0].upper() + base[1:].lower() if base else base

    yr = str(current_year)
    yr_prev = str(current_year - 1)
    yr_short = yr[2:]  # e.g. "26"

    if max_tier >= 1:
        _add(base,                        1, "base")
        _add(cap,                         1, "capitalize")
        _add(base + yr,                   1, "suffix_year_current")
        _add(base + yr_prev,              1, "suffix_year_prev")
        _add(base + yr_short,             1, "suffix_year_compressed")
        _add(base + "!",                  1, "suffix_bang")
        _add(base + "@",                  1, "suffix_at")
        _add(base + "#",                  1, "suffix_hash")
        _add(base + "1",                  1, "suffix_one")
        _add(base + "123",                1, "suffix_123")
        _add(base + yr + "!",             1, "suffix_year_bang")
        _add(base + yr + "@",             1, "suffix_year_at")
        _add(cap  + yr + "!",             1, "cap_year_bang")
        _add(cap  + yr + "@",             1, "cap_year_at")
        _add(cap  + yr,                   1, "cap_year")

    if max_tier >= 2:
        for y in range(current_year - year_sweep_back, current_year + 1):
            ys = str(y)
            ys_short = ys[2:]
            _add(base + ys,               2, f"sweep_year_{y}")
            _add(cap  + ys + "!",         2, f"sweep_cap_year_bang_{y}")
            _add(base + ys_short,         2, f"sweep_year_compressed_{y}")

    if max_tier >= 3:
        # Year-based Tier 3 patterns sweep the same dynamic range as Tier 2.
        # Same transformation types as before — just applied across the
        # operator's full pwdLastSet history instead of only current_year /
        # current_year - 1.  Dedup with Tier 2 is automatic via ``seen``.
        upper = base.upper()
        for y in range(current_year - year_sweep_back, current_year + 1):
            ys = str(y)
            for sep in ("-", "_", ".", "@"):
                _add(base + sep + ys,         3, f"sep_{sep}_year_{y}")
                _add(cap  + sep + ys,         3, f"sep_cap_{sep}_year_{y}")
                _add(cap  + sep + ys + "!",   3, f"sep_cap_{sep}_year_bang_{y}")
            _add(upper + ys + "!",            3, f"upper_year_bang_{y}")
            _add(base + ys + "!",             3, f"lower_year_bang_{y}")

        # Non-year Tier 3 transformations (no sweep — they don't depend on a
        # year token at all).
        _add(upper,                       3, "upper")

        leet_map = {"a": "@", "s": "$", "o": "0", "i": "1"}
        for char, sub in leet_map.items():
            leeted = base.replace(char, sub, 1)
            if leeted != base:
                _add(leeted,              3, f"leet_{char}_to_{sub}")

        for sym in ("$", "*", "&", "?", "1!", "12!", "01"):
            _add(base + sym,              3, f"extra_sym_{sym}")

    return out
