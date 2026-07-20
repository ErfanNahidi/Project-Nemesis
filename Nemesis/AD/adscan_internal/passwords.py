"""Centralized password generation and validation helpers.

This module is the single source of truth for every password ADscan
generates and for validating an operator-supplied password against a
resolved policy. The policy-driven entry points
(:func:`generate_compliant_password`, :func:`validate_against_policy`)
consume a :class:`~adscan_internal.services.domain_posture.ResultantPasswordPolicy`
produced by
:func:`adscan_internal.services.posture_probe.resolve_resultant_password_policy`.
"""

from __future__ import annotations

import secrets
import string
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from adscan_internal.services.domain_posture import ResultantPasswordPolicy

# Keep symbols deliberately conservative. These passwords are often embedded in
# shell-built commands, batch files, PowerShell one-liners, or third-party
# tooling, so we avoid characters that commonly trigger escaping or expansion in
# cmd.exe, PowerShell, POSIX shells, or argument parsers.
CLI_SAFE_PASSWORD_SYMBOLS = "#$*+-=_"
CLI_SAFE_PASSWORD_ALNUM = string.ascii_lowercase + string.ascii_uppercase + string.digits

# Floors applied on top of whatever the resolved policy demands.
_USER_LENGTH_FLOOR = 14
_MACHINE_LENGTH_FLOOR = 18
# Hard cap when a policy declares no maximum but we still want a sane bound.
_DEFAULT_MAX_LENGTH = 64


def generate_strong_password(length: int = 12) -> str:
    """Generate a random password with AD and CLI-safe complexity guarantees.

    The generated password intentionally avoids characters and edge-cases that
    frequently break shell-built command strings or argument parsers in third-
    party tools:
    - first character is always alphanumeric
    - no whitespace
    - no quotes/backslashes
    - no leading hyphen
    - no shell/meta characters such as ^, &, %, |, <, >, !, (, ), ;, :, @
    """
    if length < 12:
        length = 12

    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = CLI_SAFE_PASSWORD_SYMBOLS
    pool = CLI_SAFE_PASSWORD_ALNUM + symbols

    first_char = secrets.choice(CLI_SAFE_PASSWORD_ALNUM)
    chars = [first_char]

    if first_char not in lowers:
        chars.append(secrets.choice(lowers))
    if first_char not in uppers:
        chars.append(secrets.choice(uppers))
    if first_char not in digits:
        chars.append(secrets.choice(digits))
    chars.append(secrets.choice(symbols))
    chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))

    shuffled: list[str] = []
    tail = chars[1:]
    while tail:
        shuffled.append(tail.pop(secrets.randbelow(len(tail))))
    return first_char + "".join(shuffled)


def is_password_complex(value: str) -> bool:
    """Return True when a password meets the minimum AD complexity target.

    Thin legacy wrapper kept for existing callers. Equivalent to validating
    against the strong safe default policy (>=12 chars, complexity required).
    New code should resolve the live policy and call
    :func:`validate_against_policy`.
    """
    ok, _unmet = validate_against_policy(value, _default_strong_policy())
    return ok


# --------------------------------------------------------------------------- #
# AD complexity character classes
# --------------------------------------------------------------------------- #


def _char_classes(value: str) -> set[str]:
    """Return the set of AD complexity classes present in ``value``.

    AD complexity counts 3 of these 5 classes: lowercase, uppercase, digit,
    non-alphanumeric (symbol), and "other unicode" (alphabetic but neither
    lower nor upper in the ASCII sense, e.g. category Lo/Lt).
    """
    classes: set[str] = set()
    for ch in value:
        if ch.islower():
            classes.add("lower")
        elif ch.isupper():
            classes.add("upper")
        elif ch.isdigit():
            classes.add("digit")
        elif not ch.isalnum():
            classes.add("symbol")
        else:
            # Alphabetic but not cased in the ASCII sense (unicode letter).
            classes.add("unicode")
    return classes


def _default_strong_policy() -> "ResultantPasswordPolicy":
    """Strong safe default policy used by legacy wrappers and as a fallback."""
    from datetime import datetime, timezone

    from adscan_internal.services.domain_posture import ResultantPasswordPolicy

    return ResultantPasswordPolicy(
        min_length=12,
        require_complexity=True,
        required_classes=3,
        source="default_assumed",
        detected_at=datetime.now(timezone.utc),
    )


# --------------------------------------------------------------------------- #
# Policy-driven generation and validation
# --------------------------------------------------------------------------- #


def generate_compliant_password(
    policy: "ResultantPasswordPolicy", *, machine: bool = False
) -> str:
    """Generate a CLI-safe password that satisfies ``policy``.

    Extends :func:`generate_strong_password`'s CLI-safe charset approach:

    * first character is alphanumeric, no shell metacharacters;
    * length is ``max(policy.min_length, floor)`` where ``floor`` is 14 for
      user passwords and 18 for machine accounts, clamped to ``policy.max_length``
      (or a sane :data:`_DEFAULT_MAX_LENGTH` when the policy declares none);
    * when complexity is required (or ``machine=True``), guarantees at least
      ``policy.required_classes`` distinct character classes;
    * avoids trivial patterns (no 3-char sequential or repeated runs).

    Args:
        policy: Resolved policy to satisfy.
        machine: When True, applies the machine-account length floor (18) and
            always enforces complexity silently — used for AddComputer / RBCD /
            ESC machine generation where there is no interactive prompt.

    Returns:
        A generated password guaranteed to pass
        :func:`validate_against_policy` for ``policy``.
    """
    floor = _MACHINE_LENGTH_FLOOR if machine else _USER_LENGTH_FLOOR
    target_len = max(int(getattr(policy, "min_length", 0) or 0), floor)

    max_len = getattr(policy, "max_length", None)
    upper_bound = int(max_len) if max_len else _DEFAULT_MAX_LENGTH
    # Never let the floor exceed the policy max; respect the max if it is below
    # our floor (a quirky restrictive policy).
    if target_len > upper_bound:
        target_len = upper_bound
    # Need enough room to seed the required classes.
    target_len = max(target_len, 4)

    require_complexity = bool(getattr(policy, "require_complexity", False)) or machine
    required_classes = int(getattr(policy, "required_classes", 0) or 0)
    if require_complexity and required_classes < 1:
        required_classes = 3

    # Retry loop: secrets-random draws can (rarely) produce a trivial run or
    # miss a class on tiny lengths. Re-roll until the result validates.
    for _ in range(64):
        candidate = _draw_candidate(
            length=target_len,
            require_complexity=require_complexity,
            required_classes=required_classes,
        )
        ok, _unmet = validate_against_policy(candidate, policy, machine=machine)
        if ok and not _has_trivial_run(candidate):
            return candidate

    # Deterministic fallback that always satisfies the canonical classes.
    return _draw_candidate(
        length=target_len,
        require_complexity=True,
        required_classes=max(required_classes, 4),
    )


def _draw_candidate(*, length: int, require_complexity: bool, required_classes: int) -> str:
    """Draw a single CLI-safe candidate honouring the requested class count."""
    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = CLI_SAFE_PASSWORD_SYMBOLS
    pool = CLI_SAFE_PASSWORD_ALNUM + symbols

    first_char = secrets.choice(CLI_SAFE_PASSWORD_ALNUM)
    chars = [first_char]

    if require_complexity:
        # The four CLI-safe character classes, in priority order. "unicode" is
        # deliberately never seeded (would break CLI-safety); AD's 3-of-5 rule
        # is satisfied with lower/upper/digit/symbol.
        class_generators = [
            lambda: secrets.choice(lowers),
            lambda: secrets.choice(uppers),
            lambda: secrets.choice(digits),
            lambda: secrets.choice(symbols),
        ]
        wanted = min(max(required_classes, 1), len(class_generators))
        present = _char_classes(first_char) - {"unicode"}
        for gen in class_generators:
            if len(present) >= wanted:
                break
            seed = gen()
            seed_class = (_char_classes(seed) - {"unicode"})
            if not seed_class <= present:
                chars.append(seed)
                present |= seed_class

    chars.extend(secrets.choice(pool) for _ in range(max(0, length - len(chars))))
    # Trim if seeds + first char already exceeded a short target length.
    chars = chars[:length]

    tail = chars[1:]
    shuffled: list[str] = []
    while tail:
        shuffled.append(tail.pop(secrets.randbelow(len(tail))))
    return chars[0] + "".join(shuffled)


def _has_trivial_run(value: str) -> bool:
    """Return True when ``value`` contains an obvious 3+ char run.

    Catches repeated runs (``aaa``) and sequential walks (``abc`` / ``789``)
    that make a password trivially guessable even when it passes AD's own
    class/length check.
    """
    for i in range(len(value) - 2):
        a, b, c = value[i], value[i + 1], value[i + 2]
        if a == b == c:
            return True
        if a.isalnum() and b.isalnum() and c.isalnum():
            if ord(b) - ord(a) == 1 and ord(c) - ord(b) == 1:
                return True
            if ord(a) - ord(b) == 1 and ord(b) - ord(c) == 1:
                return True
    return False


def validate_against_policy(
    value: str, policy: "ResultantPasswordPolicy", *, machine: bool = False
) -> tuple[bool, list[str]]:
    """Validate ``value`` against ``policy``; return ``(ok, unmet_requirements)``.

    Used by Gate-1 (Phase 2) when an operator overrides the generated default,
    and to seed Gate-2 messaging. The returned list contains human-readable,
    English, non-sensitive requirement strings (never the password itself).

    Args:
        value: Candidate password.
        policy: Resolved policy to validate against.
        machine: When True, complexity is treated as required regardless of the
            policy flag (machine generation always enforces it).

    Returns:
        ``(True, [])`` when compliant; otherwise ``(False, [reasons...])``.
    """
    password = str(value or "")
    unmet: list[str] = []

    min_length = int(getattr(policy, "min_length", 0) or 0)
    if min_length and len(password) < min_length:
        unmet.append(f"Must be at least {min_length} characters long")

    max_length = getattr(policy, "max_length", None)
    if max_length and len(password) > int(max_length):
        unmet.append(f"Must be at most {int(max_length)} characters long")

    require_complexity = bool(getattr(policy, "require_complexity", False)) or machine
    if require_complexity:
        required_classes = int(getattr(policy, "required_classes", 0) or 0) or 3
        present = _char_classes(password)
        if len(present) < required_classes:
            unmet.append(
                f"Must contain at least {required_classes} of: lowercase, "
                f"uppercase, digit, symbol, other-unicode"
            )

    return (not unmet, unmet)
