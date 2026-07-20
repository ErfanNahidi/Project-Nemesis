"""Pre-flight Rich UX panel and confirmation for ESC exploitation flows."""
from __future__ import annotations
from typing import TYPE_CHECKING
from rich.box import ROUNDED
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from adscan_internal.rich_output import mark_sensitive

if TYPE_CHECKING:
    from adscan_internal.services.adcs.esc_types import EscConfig, EscStep

_AMBER = "#FF9500"
_STEEL = "#4A9EBA"
_CRIMSON = "#DC2626"
_MUTED = "grey50"

_ESC_TITLES = {
    2:  "ESC2 — Any Purpose EKU (Enrollment Agent chain)",
    4:  "ESC4 — Write Access on Certificate Template",
    6:  "ESC6 — CA-level SubjectAltName Flag (EDITF_ATTRIBUTESUBJECTALTNAME2)",
    7:  "ESC7 — ManageCA → Enable SubCA → Issue Certificate",
    9:  "ESC9 — No-Security-Extension via UPN Manipulation",
    14: "ESC14 — AltSecurityIdentities Write",
    15: "ESC15 — Application Policy Injection (Enrollment Agent)",
}


def build_esc_steps(config: "EscConfig") -> list["EscStep"]:
    from adscan_internal.services.adcs.esc_types import EscStep
    n = config.esc
    if n == 6:
        return [
            EscStep("Request certificate", f"Enroll in {config.template} with UPN SAN = {config.target_upn}"),
            EscStep("PKINIT authenticate", "Exchange PFX for NT hash via UnPAC-the-hash"),
        ]
    if n == 2:
        return [
            EscStep("Request agent cert", f"Enroll in {config.template} as enrollment agent"),
            EscStep("Request on-behalf-of cert", f"Use agent cert to enroll on behalf of {config.target_upn}"),
            EscStep("PKINIT authenticate", "Exchange PFX for NT hash via UnPAC-the-hash"),
        ]
    if n == 15:
        return [
            EscStep("Request cert with appPolicy OID", f"Enroll in {config.template} with enrollment-agent application policy"),
            EscStep("Request on-behalf-of cert", f"Use cert to enroll on behalf of {config.target_upn}"),
            EscStep("PKINIT authenticate", "Exchange PFX for NT hash via UnPAC-the-hash"),
        ]
    if n == 4:
        return [
            EscStep("Snapshot template", f"Save current attributes of {config.template}"),
            EscStep("Mutate template flags", f"Enable ENROLLEE_SUPPLIES_SUBJECT on {config.template}", destructive=True, rollback_label="Restore template"),
            EscStep("Request certificate", f"Enroll with UPN SAN = {config.target_upn}"),
            EscStep("Restore template", f"Revert {config.template} to original state", rollback_label="Rollback"),
            EscStep("PKINIT authenticate", "Exchange PFX for NT hash via UnPAC-the-hash"),
        ]
    if n == 7:
        return [
            EscStep("Enable SubCA template", "Add SubCA to certificateTemplates on EnterpriseCA", destructive=True, rollback_label="Disable SubCA"),
            EscStep("Request SubCA cert", f"Enroll in SubCA with UPN = {config.target_upn}"),
            EscStep("Issue pending request", "Approve pending request via ManageCA right"),
            EscStep("Retrieve certificate", "Download issued certificate"),
            EscStep("Disable SubCA template", "Remove SubCA from certificateTemplates (rollback)", rollback_label="Rollback"),
            EscStep("PKINIT authenticate", "Exchange PFX for NT hash via UnPAC-the-hash"),
        ]
    if n == 9:
        return [
            EscStep("Add shadow credentials", f"Write msDS-KeyCredentialLink on {config.target_account}", destructive=True, rollback_label="Remove shadow credentials"),
            EscStep("Get target NT hash", f"PKINIT as {config.target_account} via shadow creds"),
            EscStep("Change UPN", f"Set {config.target_account} UPN → {config.target_upn}", destructive=True, rollback_label="Restore UPN"),
            EscStep("Request certificate", f"Enroll as {config.target_account} in {config.template}"),
            EscStep("Restore UPN", f"Revert {config.target_account} UPN to original", rollback_label="Rollback"),
            EscStep("Remove shadow credentials", f"Clear msDS-KeyCredentialLink on {config.target_account}", rollback_label="Rollback"),
            EscStep("PKINIT authenticate", f"Authenticate as {config.target_upn} via UnPAC-the-hash"),
        ]
    if n == 14:
        return [
            EscStep("Create machine account", "Add computer account via MachineAccountQuota", destructive=True, rollback_label="Delete computer account"),
            EscStep("Request Machine certificate", "Enroll computer account in Machine template"),
            EscStep("Compute X509IssuerSerial", "Extract issuer+serial from cert DER"),
            EscStep("Write altSecurityIdentities", f"Set X509 binding on {config.target_account}", destructive=True, rollback_label="Clear altSecurityIdentities"),
            EscStep("PKINIT authenticate", f"Authenticate as {config.target_account}"),
        ]
    return []


def print_esc_preflight(config: "EscConfig", steps: list["EscStep"]) -> bool:
    from adscan_core.rich_output import _get_console, confirm_ask
    console = _get_console()

    has_destructive = any(s.destructive for s in steps)
    border = _CRIMSON if has_destructive else _AMBER
    title_text = _ESC_TITLES.get(config.esc, f"ESC{config.esc}")

    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=_MUTED, justify="right", min_width=16)
    grid.add_column()

    if config.target_upn:
        grid.add_row("Impersonating", Text(mark_sensitive(config.target_upn, "user"), style=f"bold {_STEEL}"))
    grid.add_row("Executing as", Text(mark_sensitive(config.username, "user"), style="bold"))
    if config.template:
        grid.add_row("Template", Text(config.template, style=f"bold {_AMBER}"))
    if config.target_account:
        grid.add_row("Modifying", Text(mark_sensitive(config.target_account, "user"), style=f"bold {_AMBER}"))
    grid.add_row("CA", Text(f"{config.ca_name} @ {config.ca_host}", style=_MUTED))

    step_table = Table.grid(padding=(0, 1))
    step_table.add_column(style=_MUTED, width=3)
    step_table.add_column(min_width=30)
    step_table.add_column(width=22)

    for i, step in enumerate(steps, 1):
        if step.destructive:
            badge = Text("⚠ DESTRUCTIVE", style=f"bold {_AMBER}")
        elif step.rollback_label and not step.destructive:
            badge = Text("↩ rollback", style=_STEEL)
        else:
            badge = Text("read-only", style=_MUTED)
        step_table.add_row(f"{i}", step.label, badge)

    from rich.console import Group
    body = Group(grid, Text(""), Text("  Steps", style=f"bold {_MUTED}"), step_table, Text(""))
    if has_destructive:
        body = Group(body, Text(
            "  All destructive changes are registered to the environment ledger and "
            "restored automatically on failure.",
            style=_MUTED,
        ))

    title = Text.assemble(
        Text.from_markup(f"[bold {_CRIMSON}]⚡[/] "),
        (title_text, "bold"),
    )
    console.print(Panel(body, title=title, border_style=border, box=ROUNDED, padding=(0, 1)))
    return confirm_ask("  Proceed?", default=True)
