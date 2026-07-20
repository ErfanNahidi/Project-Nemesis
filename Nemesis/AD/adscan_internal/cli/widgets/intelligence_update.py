"""Intelligence Update CLI panel.

Pure renderer for :class:`IntelligenceFinding` instances produced by
:func:`adscan_internal.services.domain_posture.update_posture`. The widget
is intentionally a pure function: it does not consult posture state and
does not deduplicate. Callers must rely on ``update_posture`` returning
``None`` for repeated signals (the canonical source of de-dup).

The exact copy and palette here are locked by upstream design — keep them
in sync with the PR5 spec when editing.
"""

from __future__ import annotations

from rich import box
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text

from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.domain_posture import (
    AdaptationOutcome,
    ConstraintCategory,
    IntelligenceFinding,
    TriState,
)


# --------------------------------------------------------------------------- #
# Locked copy
# --------------------------------------------------------------------------- #


_CONSTRAINT_DISPLAY_MAP: dict[tuple[ConstraintCategory, TriState], str] = {
    (ConstraintCategory.NTLM_AUTHENTICATION, TriState.DISABLED): (
        "NTLM authentication disabled"
    ),
    (ConstraintCategory.NTLM_AUTHENTICATION, TriState.ENABLED): (
        "NTLM authentication enabled"
    ),
    (ConstraintCategory.KERBEROS_RC4, TriState.DISABLED): (
        "RC4 Kerberos encryption disabled"
    ),
    (ConstraintCategory.KERBEROS_AES_ONLY, TriState.ENABLED): (
        "AES-only Kerberos enforced"
    ),
    (ConstraintCategory.KERBEROS_ETYPE_PROBE, TriState.ENABLED): (
        "Non-default Kerberos salt — etype probe required"
    ),
    (ConstraintCategory.KERBEROS_ETYPE_PROBE, TriState.DISABLED): (
        "Standard Kerberos salt"
    ),
    (ConstraintCategory.LDAPS_AVAILABLE, TriState.ENABLED): "LDAPS available",
    (ConstraintCategory.LDAPS_AVAILABLE, TriState.DISABLED): "LDAPS unavailable",
    (ConstraintCategory.LDAP_SIGNING, TriState.REQUIRED): "LDAP signing required",
    (ConstraintCategory.LDAP_CHANNEL_BINDING, TriState.REQUIRED): (
        "LDAP channel binding required"
    ),
    (ConstraintCategory.LDAP_CHANNEL_BINDING, TriState.DISABLED): (
        "LDAP channel binding not enforced"
    ),
    (ConstraintCategory.SMB_SIGNING, TriState.REQUIRED): "SMB signing required",
}


_FRAMING_SENTENCE_BY_OUTCOME: dict[AdaptationOutcome, str] = {
    AdaptationOutcome.ADAPTED: (
        "This is good defensive posture — your client has hardened "
        "their domain against legacy authentication."
    ),
    AdaptationOutcome.DEGRADED: (
        "This control limits ADscan's coverage. Findings remain valid; "
        "some attack paths cannot be tested without additional credentials."
    ),
    AdaptationOutcome.BLOCKED: (
        "This control prevents ADscan from continuing on this surface. "
        "Provide additional credentials or skip this surface to proceed."
    ),
}


_OUTCOME_BORDER_STYLE: dict[AdaptationOutcome, str] = {
    AdaptationOutcome.ADAPTED: "green",
    AdaptationOutcome.DEGRADED: "yellow",
    AdaptationOutcome.BLOCKED: "yellow",
}


# --------------------------------------------------------------------------- #
# Public renderer
# --------------------------------------------------------------------------- #


def render_intelligence_update(finding: IntelligenceFinding) -> Panel:
    """Build the 'Intelligence Update' panel for one posture discovery.

    Pure renderer: receives a finding produced by
    :func:`adscan_internal.services.domain_posture.update_posture` and returns
    a Rich :class:`~rich.panel.Panel` ready to print. Does not consult posture
    state, does not deduplicate — callers must rely on ``update_posture``
    returning ``None`` for repeated signals (the source of truth for de-dup).

    Args:
        finding: Posture discovery to render.

    Returns:
        A Rich :class:`~rich.panel.Panel` with the locked Intelligence Update
        layout, ready to pass to ``console.print``.
    """
    outcome = finding.suggested_outcome
    border_style = _OUTCOME_BORDER_STYLE.get(outcome, "yellow")
    action_style = (
        "bold green" if outcome is AdaptationOutcome.ADAPTED else "bold yellow"
    )

    masked_domain = mark_sensitive(finding.domain, "domain")

    # Headline.
    headline = Text()
    headline.append("Detected security hardening on ")
    headline.append(masked_domain, style="bold")

    # Field rows.
    constraint_label = _CONSTRAINT_DISPLAY_MAP.get(
        (finding.category, finding.state),
        f"{finding.category.value} ({finding.state.value})",
    )

    evidence_text = finding.evidence_message or finding.evidence_signal_code or "—"

    source_text = Text()
    source_text.append(finding.evidence_source or "unknown")
    source_text.append(" · ", style="dim")
    source_text.append(masked_domain)

    action_value = Text()
    if outcome is AdaptationOutcome.ADAPTED:
        action_value.append("⚡ ", style=action_style)
    action_value.append(finding.suggested_action or "", style=action_style)

    fields = _build_fields_block(
        constraint_label=constraint_label,
        evidence_text=evidence_text,
        source_renderable=source_text,
        action_renderable=action_value,
    )

    # Framing sentence.
    framing_sentence = Text(
        _FRAMING_SENTENCE_BY_OUTCOME.get(
            outcome,
            _FRAMING_SENTENCE_BY_OUTCOME[AdaptationOutcome.ADAPTED],
        ),
        style="italic dim",
    )

    # Footer rows.
    footer_lines: list[RenderableType] = []
    learned_line = Text()
    learned_line.append("📌 Learned   ", style="dim cyan")
    if finding.persisted:
        learned_line.append("posture saved · no further retries this scan")
    else:
        learned_line.append("posture not persisted (no workspace map)", style="yellow")
    footer_lines.append(learned_line)

    report_line = Text()
    report_line.append("📊 Report    ", style="dim cyan")
    report_line.append('will appear in "Detected Defensive Posture"')
    footer_lines.append(report_line)

    body = Group(
        headline,
        Text(),
        fields,
        Text(),
        framing_sentence,
        Text(),
        *footer_lines,
    )

    return Panel(
        Padding(body, (1, 2)),
        title="[bold cyan]🧠  ADscan Intelligence Update[/bold cyan]",
        border_style=border_style,
        box=box.ROUNDED,
        expand=False,
    )


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def _build_fields_block(
    *,
    constraint_label: str,
    evidence_text: str,
    source_renderable: RenderableType,
    action_renderable: RenderableType,
) -> RenderableType:
    """Render the four-row field block (Constraint / Evidence / Source / Action)."""
    from rich.table import Table

    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", no_wrap=True)
    table.add_column(no_wrap=False)

    table.add_row("Constraint", Text(constraint_label))
    table.add_row("Evidence", Text(evidence_text))
    table.add_row("Source", source_renderable)
    table.add_row("Action", action_renderable)
    return table
