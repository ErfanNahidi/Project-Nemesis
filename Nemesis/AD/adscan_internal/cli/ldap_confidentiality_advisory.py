"""Operator advisory: an LDAP read proceeded over a CLEARTEXT channel.

Structural note (read before extending this module)
----------------------------------------------------
This panel is **operator-only**. It describes ADscan's own operational
situation during a single run — "ADscan could not establish a confidential
channel for THIS operation, so the directory read travelled in cleartext".
It is NOT a statement about the client's DC hardening posture.

Because it is operational and ephemeral, this module **must never** call
``record_technical_finding`` (or any report-emitting helper). Doing so would
leak our situational outcome into the client's PDF report, conflating two
distinct questions:

  * "Is the client exposed?" (a DC-posture finding) — answered elsewhere by
    the ``ldap_security_posture`` finding (see
    ``adscan_internal/pro/services/posture_findings_emitter.py``). THAT goes
    to the report.
  * "Was MY traffic exposed during THIS run?" (this advisory) — operational,
    CLI-only, NEVER in the report.

If you ever feel tempted to import ``record_technical_finding`` here, the
design is being violated: the cleartext outcome is surfaced ONLY via this
ephemeral CLI panel, never cached and never reported.

Modeled on ``render_confidential_channel_panel`` (gMSA's sealed-channel
panel) but kept GENERIC — it is not gMSA-specific and lives outside
``integrations/gmsa.py`` so any LDAP-read boundary can reuse it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from adscan_internal.services.ldap_transport_service import ConfidentialityMechanism


__all__ = ["render_cleartext_ldap_advisory", "should_advise_cleartext_once"]


# Transient, process-local dedup so the advisory surfaces at most ONCE per
# ``(domain, operation)`` during a run. Kept as a module-level set rather than
# in ``domains_data`` deliberately: this is situational CLI state, not domain
# posture — persisting it would both spam-suppress across runs incorrectly and
# violate the JSON-serializable invariant on the workspace cache.
_ADVISED_CLEARTEXT: set[tuple[str, str]] = set()


def should_advise_cleartext_once(domain: str, operation: str) -> bool:
    """Return True the FIRST time a ``(domain, operation)`` cleartext is seen.

    Idempotent guard so the advisory panel is rendered at most once per
    ``(domain, operation)`` per process. Subsequent calls for the same pair
    return False, avoiding terminal spam when a single enumeration boundary
    opens several connections.

    Args:
        domain: Target domain the cleartext read touched.
        operation: Short, stable operation label (e.g. ``"ldap_enumeration"``).

    Returns:
        True when this is the first time the pair is observed this run.
    """
    key = ((domain or "").lower(), (operation or "").strip())
    if key in _ADVISED_CLEARTEXT:
        return False
    _ADVISED_CLEARTEXT.add(key)
    return True


def render_cleartext_ldap_advisory(
    dc_ip: str,
    mechanism: "ConfidentialityMechanism",
    reason: str,
) -> None:
    """Render the operator advisory for an LDAP read that ran over cleartext.

    This is the C.b counterpart to the gMSA sealed-channel panel: an
    operational notice that ADscan could not negotiate any confidential
    channel for this read, so the directory traffic travelled in the clear.
    It frames the situation as an environment limitation (no DC certificate,
    no reachable LDAPS, an unauthenticated/SIMPLE bind that cannot seal), NOT
    an ADscan bug, and tells the operator exactly how to unblock a confidential
    channel.

    This function is operator-only and must NEVER record a technical finding
    (see the module docstring). It always prints; it never gates on
    interactivity.

    Args:
        dc_ip: The domain controller the read was performed against (masked).
        mechanism: The :class:`ConfidentialityMechanism` the read used — by the
            time this is called it is expected to be ``CLEARTEXT``; the value is
            rendered for operator context.
        reason: Short operator-facing reason string (e.g. the operation that
            ran in cleartext), surfaced verbatim in the panel body.
    """
    from rich.console import Group
    from rich.text import Text

    from adscan_core.output._log import BRAND_COLORS
    from adscan_internal import print_panel
    from adscan_internal.rich_output import mark_sensitive

    accent = BRAND_COLORS["info"]
    masked_dc = mark_sensitive(dc_ip, "ip")
    mech_label = getattr(mechanism, "value", str(mechanism))
    clean_reason = (reason or "").strip()

    def _heading(label: str) -> Text:
        return Text(label, style=f"bold {accent}")

    def _body(text: str) -> Text:
        return Text(text, style="white")

    sections: list[Text] = []

    sections.append(_heading("What happened"))
    happened = (
        f"An LDAP read against {masked_dc} proceeded over a CLEARTEXT channel "
        f"(no confidentiality, mechanism={mech_label})."
    )
    if clean_reason:
        happened += f" Operation: {clean_reason}."
    sections.append(_body(happened))
    sections.append(Text(""))

    sections.append(_heading("Why (this is the environment, not an ADscan bug)"))
    sections.append(
        _body(
            "ADscan could not establish any confidential channel to this DC for "
            "this read. This is an environment limitation — typically no reachable "
            "LDAPS, no usable DC certificate for StartTLS, and a bind that cannot "
            "negotiate GSS-API sealing (anonymous and SIMPLE binds cannot seal). It "
            "is not an ADscan failure."
        )
    )
    sections.append(Text(""))

    sections.append(_heading("What ADscan tried"))
    for step in (
        "LDAPS (TLS on 636) — unavailable (port filtered or no DC certificate).",
        "StartTLS (TLS on 389, RFC 2830) — unavailable (no usable DC certificate).",
        "GSS-API SASL sign and seal on 389 — unavailable (anonymous/SIMPLE bind, "
        "or the server could not negotiate sealing).",
    ):
        line = Text("  • ", style=accent)
        line.append(step, style="white")
        sections.append(line)
    sections.append(Text(""))

    sections.append(_heading("How to unblock a confidential channel"))
    for step in (
        "Make LDAPS (TCP 636) reachable to the DC, with a valid DC certificate.",
        "If 636 is filtered, deploy a DC certificate so StartTLS on 389 can wrap "
        "the channel in TLS.",
        "Provide a Kerberos or NTLM credential so the 389 bind can negotiate "
        "GSS-API sign and seal — anonymous and SIMPLE binds cannot seal the channel.",
    ):
        line = Text("  • ", style=accent)
        line.append(step, style="white")
        sections.append(line)

    print_panel(
        Group(*sections),
        title="🔓 LDAP Read · Cleartext Channel (Operator Notice)",
        border_style=BRAND_COLORS["warning"],
        expand=False,
    )
