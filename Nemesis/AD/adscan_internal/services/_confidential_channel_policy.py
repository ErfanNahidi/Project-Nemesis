"""Single confidential-channel policy for write/read operations on AD secrets.

A small, **pure-logic** module that answers two questions for any operation
that touches a CONFIDENTIAL Active Directory attribute (a password / managed
secret that AD only accepts or returns over a sealed channel):

1. ``requires_confidential_channel(op)`` — does this operation need a sealed
   (encrypted) channel at all? Today every member of :class:`ConfidentialOp`
   does; the function exists so future non-confidential variants can opt out
   without touching call sites.

2. ``prefer_ldap_over_samr(posture)`` — when both an LDAP confidential ladder
   (LDAPS / StartTLS / SASL sign+seal) and a SAMR-over-RPC confidential
   fallback (``RPC_C_AUTHN_LEVEL_PKT_PRIVACY`` on 445) are available, which
   one should the operation try FIRST?

**Why this module exists.** Before it, ``acl.py`` and ``delegation_native.py``
each decided LDAP-vs-SAMR by inspecting ONLY
``ConstraintCategory.LDAPS_AVAILABLE``. That dropped to SAMR prematurely
whenever LDAPS (636) was filtered, even though StartTLS (389) or SASL sign+seal
(389) would have provided a perfectly good confidential LDAP rung. The SAMR
fallback trigger must be "no confidential LDAP rung is plausible", not "LDAPS
is down". This module is the single place that computes that, reading the FULL
confidentiality picture (LDAPS + StartTLS) — the same posture-derived view the
LDAP auth planner consumes for intra-LDAP rung selection.

**Posture discipline (observe-vs-infer).** ``prefer_ldap_over_samr`` only
prefers SAMR-first when the posture HIGH-confidently observed that BOTH LDAPS
and StartTLS are unavailable. UNKNOWN / LOW / absent posture → LDAP-first: the
confidentiality ladder plus ``require_confidential=True`` will raise
:class:`ConfidentialChannelUnavailableError` if no sealed rung can be
established, and the caller falls through to SAMR safely. We never strand a
confidential LDAP rung on an inferred-by-absence (timeout / loop-saturation)
signal.

This module is pure logic — no I/O, no logging, no rich output.
"""

from __future__ import annotations

import enum
from typing import Any

from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    SignalConfidence,
    TriState,
)


class ConfidentialOp(enum.Enum):
    """An operation that touches a CONFIDENTIAL AD attribute.

    Every member needs a sealed channel today. The enum decouples the policy
    decisions below from individual call sites so a future operation that does
    NOT require confidentiality can be added without re-checking every caller.
    """

    FORCE_CHANGE_PASSWORD = "force_change_password"
    SELF_CHANGE_PASSWORD = "self_change_password"
    ADD_COMPUTER = "add_computer"
    READ_GMSA = "read_gmsa"


def requires_confidential_channel(op: ConfidentialOp) -> bool:
    """Return whether ``op`` requires a confidential (sealed) channel.

    Args:
        op: The :class:`ConfidentialOp` being performed.

    Returns:
        ``True`` for every operation today. Centralised here so a future
        non-confidential variant can opt out without editing call sites.
    """
    # All current operations write or read a confidential attribute
    # (``unicodePwd`` / password change / ``msDS-ManagedPassword``), each of
    # which AD only accepts or returns over a sealed channel.
    return op in {
        ConfidentialOp.FORCE_CHANGE_PASSWORD,
        ConfidentialOp.SELF_CHANGE_PASSWORD,
        ConfidentialOp.ADD_COMPUTER,
        ConfidentialOp.READ_GMSA,
    }


def _is_high_confidence(state: TriState, confidence: SignalConfidence) -> bool:
    """Return True when a constraint carries actionable high-confidence evidence.

    Mirrors ``auth_plan._has_high_confidence`` exactly: a verdict is only
    actionable when the DC gave us a definitive HIGH-confidence answer and the
    state is not UNKNOWN. Inferred-by-absence states (UNKNOWN / LOW) never gate
    a decision.
    """
    return confidence is SignalConfidence.HIGH and state is not TriState.UNKNOWN


def prefer_ldap_over_samr(posture_snapshot: Any | None) -> bool:
    """Return whether confidential ops should try the LDAP ladder before SAMR.

    LDAP-first iff ANY confidential LDAP rung is plausible. SAMR-first ONLY when
    the posture HIGH-confidently observed that NO confidential LDAP rung is
    plausible — i.e. both LDAPS (636) and StartTLS (389) are
    ``DISABLED`` at ``HIGH`` confidence. In that case the only remaining LDAP
    confidentiality option is SASL sign+seal, which can fail when the bind
    cannot negotiate GSS; the confidential SAMR fallback is the more reliable
    first choice.

    Decision table:

    +------------------------------+-----------------------------+---------------+
    | LDAPS_AVAILABLE              | LDAP_STARTTLS_AVAILABLE     | Result        |
    +==============================+=============================+===============+
    | ENABLED (HIGH)              | any                         | LDAP-first    |
    +------------------------------+-----------------------------+---------------+
    | any                          | ENABLED (HIGH)             | LDAP-first    |
    +------------------------------+-----------------------------+---------------+
    | DISABLED (HIGH)             | DISABLED (HIGH)            | SAMR-first    |
    +------------------------------+-----------------------------+---------------+
    | DISABLED (HIGH)             | UNKNOWN / LOW / absent      | LDAP-first    |
    +------------------------------+-----------------------------+---------------+
    | UNKNOWN / LOW / absent       | any                         | LDAP-first    |
    +------------------------------+-----------------------------+---------------+
    | posture is None              | —                           | LDAP-first    |
    +------------------------------+-----------------------------+---------------+

    The UNKNOWN/incomplete rows resolve to LDAP-first by design: the
    confidentiality ladder plus ``require_confidential=True`` raises
    :class:`ConfidentialChannelUnavailableError` when it truly cannot seal, and
    the caller then falls through to SAMR — so a transient/incomplete posture
    never strands SAMR's confidential last resort.

    Args:
        posture_snapshot: A :class:`DomainPosture` snapshot or ``None``. Only
            the LDAPS and StartTLS availability categories are consulted.

    Returns:
        ``True`` to try the LDAP confidential ladder first, ``False`` to try
        the confidential SAMR backend first.
    """
    if posture_snapshot is None:
        return True

    ldaps = posture_snapshot.get(ConstraintCategory.LDAPS_AVAILABLE)
    starttls = posture_snapshot.get(ConstraintCategory.LDAP_STARTTLS_AVAILABLE)

    ldaps_enabled_high = (
        _is_high_confidence(ldaps.effective_state, ldaps.confidence)
        and ldaps.effective_state is TriState.ENABLED
    )
    starttls_enabled_high = (
        _is_high_confidence(starttls.effective_state, starttls.confidence)
        and starttls.effective_state is TriState.ENABLED
    )

    # A confidential LDAP rung is known-available — try LDAP first.
    if ldaps_enabled_high or starttls_enabled_high:
        return True

    ldaps_disabled_high = (
        _is_high_confidence(ldaps.effective_state, ldaps.confidence)
        and ldaps.effective_state is TriState.DISABLED
    )
    starttls_disabled_high = (
        _is_high_confidence(starttls.effective_state, starttls.confidence)
        and starttls.effective_state is TriState.DISABLED
    )

    # Both transport-layer confidential rungs HIGH-confidently unavailable —
    # SAMR (PKT_PRIVACY over RPC) is the more reliable confidential first try.
    if ldaps_disabled_high and starttls_disabled_high:
        return False

    # Anything else (UNKNOWN / LOW / partial observation) — LDAP-first; the
    # ladder + require_confidential safely raise and trigger SAMR if needed.
    return True
