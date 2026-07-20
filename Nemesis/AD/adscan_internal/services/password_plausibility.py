"""Password plausibility validator — the narrow waist of cred filtering.

This module is the **single source of truth** for "does this string look
like a password worth attempting against a domain controller?" Every
credential source in ADscan (CredSweeper findings, LSASS dump parsing,
hash-crack output, ASRoast results, future scanners) routes through
:func:`is_plausible_password` before the value reaches the spraying
gate or the auditor-facing reports.

Why a separate module:

* CredSweeper's built-in ML (BiLSTM, English-trained) does not score
  candidates extracted by our custom multilingual rules (ES/CA/EUS/DE/
  FR/PT/IT), so those rules ship with ``use_ml: false`` and produce raw
  regex output with no ML guard.
* The 2026-05-21 HTB Puppy run exposed the cost: a JSON fragment from
  ``DeviceSearchCache/SettingsCache.txt`` was reported as a credential
  at 60% confidence and sprayed against the domain, producing 6 useless
  AS-REQ events and one ``AttributeError`` downstream.
* Adding heuristics directly to every scanner is duplicated work and
  drifts across sources. Centralising them here means future sources
  inherit the same filter for free.

Design principles (do not negotiate these):

1. **Conservative bias** — when uncertain, return ``True`` (plausible).
   Recall is more valuable than precision because the spraying gate
   downstream is a free secondary validator: a wrongly-accepted FP just
   costs one AS-REQ, while a wrongly-rejected TP loses a credential the
   operator may never recover.

2. **Determinism over ML** — no model weights, no network calls, no
   non-determinism. The full pipeline runs in microseconds, offline,
   in any container. ML/LLM tiers are roadmap items, not requirements.

3. **Layered checks** — each rejection layer answers "is this PROVABLY
   not a password?" with high confidence. Layers do NOT compose into
   "scores" — a single hard match rejects, anything else passes.

4. **Reason transparency** — every rejection carries a one-line reason
   the renderer surfaces as a badge so the operator sees what was
   filtered and can manually re-include if their judgement disagrees.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional


# ─────────────────────────────────────────────────────────────────────
# Compiled patterns — kept module-level so the cost is paid once.
# ─────────────────────────────────────────────────────────────────────


# A canonical RFC 4122 UUID/GUID, optionally wrapped in braces. Real
# passwords never look like this. The character class matches both
# lower-case (Linux) and upper-case (Windows registry) representations.
_GUID_PATTERN = re.compile(
    r"^\{?[0-9A-Fa-f]{8}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{12}\}?$"
)

# Pure hexadecimal strings at the exact lengths of well-known hashes
# (MD5/NT=32, SHA-1=40, SHA-256=64, SHA-512=128). When a candidate has
# both the length AND the charset, the probability it is a password
# rather than a leaked hash is essentially zero.
_HASH_LENGTHS: frozenset[int] = frozenset({32, 40, 64, 128})
_PURE_HEX_PATTERN = re.compile(r"^[0-9A-Fa-f]+$")

# Base64-encoded blob with explicit padding (``=`` or ``==`` at the
# tail). Real passwords do not end in ``=``; appearance of trailing
# padding plus a length ≥ 24 is a strong serialised-data signal.
_BASE64_PADDED_PATTERN = re.compile(r"^[A-Za-z0-9+/]+={1,2}$")

# Structural delimiters that no AD password can legitimately contain.
# These are JSON/XML/array syntax. ``unicodePwd`` storage simply does
# not accept them through standard channels, and operators picking
# their own passwords avoid them because they break shell quoting and
# config-file embedding. Any candidate that contains even one of these
# is almost certainly an upstream tokenisation artefact (a regex that
# walked past a string boundary into surrounding markup).
_STRUCTURAL_DELIMITERS: frozenset[str] = frozenset('"\'{}[]<>')

# Acceptable password length envelope. The lower bound matches the
# practical minimum a domain policy would tolerate (4 chars). The upper
# bound is generous to cover passphrases without admitting paragraphs
# of leaked text.
_LENGTH_MIN: int = 4
_LENGTH_MAX: int = 128


# ─────────────────────────────────────────────────────────────────────
# Public surface
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PlausibilityVerdict:
    """Outcome of :func:`is_plausible_password`.

    Attributes:
        plausible: ``True`` when nothing in the string proves it cannot
            be a password. Conservative — uncertainty resolves to ``True``.
        reason: One-line operator-facing explanation when ``plausible``
            is ``False``. Empty string when ``plausible`` is ``True``.
            Always safe to render directly in a Rich panel or badge.
        category: Short machine-readable tag for the rejection class
            (``"structural"``, ``"guid"``, ``"hash"``, ``"base64"``,
            ``"length"``, ``"nonprintable"``, or ``""``). Useful for
            telemetry aggregation and for the renderer's icon mapping.
    """

    plausible: bool
    reason: str
    category: str


_OK_VERDICT = PlausibilityVerdict(plausible=True, reason="", category="")


# ─────────────────────────────────────────────────────────────────────
# Tier 3+ plug-in surface — architectural hook only, no implementation
# ─────────────────────────────────────────────────────────────────────
#
# The deterministic Tier 1+2 pipeline cannot judge semantic plausibility
# (e.g. distinguishing a Spanish verb captured by a narrative rule from
# a real Spanish-language password). That class of FP requires an ML or
# LLM judge — the BERT INT8 / Ollama tiers documented in BACKLOG.md.
#
# To keep the door open without pulling in any ML dependency today, this
# module exposes a single optional hook that downstream code can register
# at startup. When unset (the default), the deterministic verdict is
# returned unchanged — every test and runtime path behaves exactly as
# before. When set, the hook is consulted only AFTER Tier 1+2 has
# already cleared the candidate, so cheap deterministic rejections are
# never charged the model-inference cost.
#
# Future Tier 3 implementations (vendored DeepPass2 BERT, our own
# rockyou-trained classifier, a sidecar microservice) attach here. No
# refactoring of call sites is required for those integrations to ship.

AdvancedPlausibilityHook = Callable[
    [str, Optional[str]],
    Optional[PlausibilityVerdict],
]
"""Signature contract for a Tier 3+ plausibility judge.

A hook receives the candidate value and an optional context line (the
surrounding prose / line of text from which the value was extracted).
It returns either:

* ``None`` — abstain. The deterministic Tier 1+2 verdict stands.
* A :class:`PlausibilityVerdict` — override. The returned verdict is
  the final answer; the hook is therefore both authorised and
  responsible for the ``reason`` / ``category`` strings.

Hooks must be safe to call inline from any thread, must not raise
under normal operation, and should target sub-second latency per
candidate so credential rendering remains snappy.
"""


_ADVANCED_HOOK: Optional[AdvancedPlausibilityHook] = None


def register_advanced_plausibility_hook(
    hook: Optional[AdvancedPlausibilityHook],
) -> None:
    """Install (or clear) the Tier 3+ plug-in hook.

    The hook fires only after every deterministic Tier 1+2 layer has
    accepted the candidate, so an inexpensive heuristic rejection is
    never charged the cost of model inference.

    Args:
        hook: A callable matching :data:`AdvancedPlausibilityHook`, or
            ``None`` to clear any previously-installed hook and return
            the validator to pure deterministic behaviour.

    Notes:
        Idempotent — calling with the same hook twice is a no-op for
        callers. Replacing a hook is allowed; the next invocation of
        :func:`is_plausible_password` picks up the new one.
    """
    global _ADVANCED_HOOK
    _ADVANCED_HOOK = hook


def is_plausible_password(
    value: Optional[str],
    *,
    context: Optional[str] = None,
) -> PlausibilityVerdict:
    """Return whether ``value`` could plausibly be an AD user password.

    The function rejects only strings that are PROVABLY not passwords —
    JSON/XML delimiters, GUIDs, hashes, Base64-padded blobs, and
    length outliers. Anything else passes, including:

    * Dictionary words (``password``, ``admin`` — these are real bad
      passwords seen in the wild).
    * Low-entropy strings (``Aa1!`` — short but valid).
    * Single tokens without uppercase or digit (``letmeinpls`` —
      simple but legitimate).

    A registered Tier 3+ hook (see
    :func:`register_advanced_plausibility_hook`) may further refine the
    verdict, but only for candidates that have already passed every
    deterministic layer.

    Args:
        value: The candidate string to validate. ``None``, empty, or
            whitespace-only inputs return an implausible verdict.
        context: Optional surrounding line of text from which the
            candidate was extracted. Ignored by the deterministic
            layers; forwarded to any registered Tier 3+ hook so an
            ML / LLM judge can use it for semantic scoring.

    Returns:
        :class:`PlausibilityVerdict` with ``plausible``, a one-line
        ``reason`` (when implausible), and a machine-readable
        ``category`` for telemetry / badge selection.

    Notes:
        The deterministic path is pure and side-effect-free. When a
        Tier 3+ hook is registered, the function inherits whatever
        side-effects the hook itself may introduce; the validator
        protects against hook exceptions by swallowing them and
        falling back to the deterministic verdict.
    """
    if value is None:
        return PlausibilityVerdict(False, "empty value", "length")
    candidate = str(value)
    if not candidate:
        return PlausibilityVerdict(False, "empty value", "length")

    # ── Layer 1: length envelope ─────────────────────────────────────
    length = len(candidate)
    if length < _LENGTH_MIN:
        return PlausibilityVerdict(
            False,
            f"too short ({length} < {_LENGTH_MIN} chars)",
            "length",
        )
    if length > _LENGTH_MAX:
        return PlausibilityVerdict(
            False,
            f"too long ({length} > {_LENGTH_MAX} chars)",
            "length",
        )

    # ── Layer 2: printable ASCII (rejects binary/control noise) ──────
    # Non-printable chars almost always indicate the regex extracted a
    # chunk of binary data — DPAPI blobs, registry hive bytes, etc.
    if not candidate.isprintable():
        return PlausibilityVerdict(
            False,
            "contains non-printable characters",
            "nonprintable",
        )

    # ── Layer 3: GUID pattern (Windows registry / settings cache) ────
    # Checked BEFORE structural delimiters so that brace-wrapped GUIDs
    # (``{907F...}``) surface as ``guid`` rather than as a generic
    # ``{``-delimiter hit. The regex is anchored to the full string, so
    # it cannot shadow legitimate JSON fragments.
    if _GUID_PATTERN.match(candidate):
        return PlausibilityVerdict(
            False,
            "looks like a GUID/UUID",
            "guid",
        )

    # ── Layer 4: structural delimiters (the most common FP class) ────
    # JSON/XML/array syntax means we walked into surrounding markup.
    # Listed individually so the badge can name the exact offender.
    structural_hit = next(
        (c for c in candidate if c in _STRUCTURAL_DELIMITERS),
        None,
    )
    if structural_hit is not None:
        return PlausibilityVerdict(
            False,
            f"contains structural delimiter {structural_hit!r} "
            "(JSON/XML fragment, not a password)",
            "structural",
        )

    # ── Layer 5: known-length pure-hex strings (MD5/SHA/NT hash) ─────
    # We only reject at the EXACT well-known hash lengths to avoid
    # killing legit passwords that happen to be all-hex but at an
    # unusual length (e.g. an 11-char hex token is much more likely a
    # short password than a truncated hash).
    if length in _HASH_LENGTHS and _PURE_HEX_PATTERN.match(candidate):
        bits = length * 4
        return PlausibilityVerdict(
            False,
            f"looks like a {bits}-bit hash (pure hex, "
            f"length={length})",
            "hash",
        )

    # ── Layer 6: Base64-padded blob (serialised data) ────────────────
    # The padding requirement protects us from rejecting normal mixed
    # passwords that happen to use Base64-friendly characters: only
    # candidates that LOOK like deliberate Base64 (proper alphabet +
    # explicit ``=`` padding) get caught here.
    if length >= 24 and _BASE64_PADDED_PATTERN.match(candidate):
        return PlausibilityVerdict(
            False,
            "looks like Base64-encoded data (padded, length≥24)",
            "base64",
        )

    # ── Tier 3+ plug-in hook (BERT / LLM / custom ML, optional) ──────
    # Only reached when every deterministic layer accepts the
    # candidate. Hook errors are absorbed: a broken Tier 3+ judge
    # must never crash the credential pipeline, and the deterministic
    # verdict is always a safe conservative fallback because the
    # spraying gate downstream is a free secondary validator.
    hook = _ADVANCED_HOOK
    if hook is not None:
        advanced: Optional[PlausibilityVerdict] = None
        try:
            advanced = hook(candidate, context)
        except Exception:  # noqa: BLE001 — hooks must never crash callers
            advanced = None
        if advanced is not None:
            return advanced

    return _OK_VERDICT


# ─────────────────────────────────────────────────────────────────────
# Category metadata for renderers / telemetry
# ─────────────────────────────────────────────────────────────────────


CATEGORY_DISPLAY: dict[str, str] = {
    "structural": "JSON/XML fragment",
    "guid": "GUID",
    "hash": "Hash",
    "base64": "Base64 blob",
    "length": "Bad length",
    "nonprintable": "Binary",
    "": "",
}
"""Short human labels for each rejection category, suitable for badges.

Keys match :class:`PlausibilityVerdict.category`. Renderers should map
through this table so a single update to a category name propagates
everywhere without grepping for string literals scattered across the UI.
"""


__all__ = (
    "AdvancedPlausibilityHook",
    "CATEGORY_DISPLAY",
    "PlausibilityVerdict",
    "is_plausible_password",
    "register_advanced_plausibility_hook",
)
