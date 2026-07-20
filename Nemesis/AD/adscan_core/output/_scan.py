"""Scan status, results summary, and domain/credential table helpers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from rich.box import ROUNDED
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import adscan_core.output._state as _state_mod
from adscan_core.output._log import (
    BRAND_COLORS,
    _handle_spacing,
    print_success,
)
from adscan_core.output._state import (
    _get_console,
    _get_telemetry_console,
    _mark_operation_details,
    mark_sensitive,
)
from adscan_core.output._tables import create_styled_table
from adscan_core.theme import ADSCAN_PRIMARY


__all__ = [
    "print_scan_status",
    "print_results_summary",
    "print_domain_info",
    "create_domains_table",
    "create_credentials_table",
    "print_workflow_summary",
    "print_delegations_summary",
]


def print_scan_status(
    service: str,
    status: str,
    details: Optional[str] = None,
) -> None:
    """Print scan status with professional styling.

    Args:
        service: Service name (e.g., "SMB", "LDAP")
        status: Status (e.g., "starting", "running", "completed", "failed")
        details: Optional additional details

    Example:
        >>> print_scan_status("SMB", "completed", "15 hosts discovered")
    """
    console = _get_console()
    _get_telemetry_console()
    from rich.text import Text

    # Status styling
    status_styles = {
        "starting": ("⚡", "bold yellow"),
        "running": ("⏳", f"bold {ADSCAN_PRIMARY}"),
        "completed": ("✓", "bold green"),
        "failed": ("✗", "bold red"),
        "pending": ("○", "dim"),
    }

    icon, style = status_styles.get(status.lower(), ("•", "white"))

    text = Text()
    text.append(f"{icon} ", style=style)
    text.append(f"{service} ", style=f"bold {ADSCAN_PRIMARY}")
    text.append(status.title(), style=style)

    if details:
        text.append(" - ", style="dim")
        text.append(details, style="white")

    spacing_before = _handle_spacing("info", False, "auto")
    if spacing_before:
        console.print()

    console.print(text)


def print_results_summary(
    title: str,
    results: Dict[str, Any],
    show_panel: bool = True,
) -> None:
    """Print a professional summary of operation results.

    Args:
        title: Summary title
        results: Dictionary of result key-value pairs
        show_panel: Whether to wrap in a panel (default: True)

    Example:
        >>> print_results_summary(
        ...     "Scan Results",
        ...     {"Domains Found": 3, "Hosts Discovered": 15, "Credentials": 5}
        ... )
    """
    console = _get_console()
    _get_telemetry_console()
    from rich.text import Text
    from rich.panel import Panel
    from rich.table import Table

    # Create results table
    results_table = Table.grid(padding=(0, 2))
    results_table.add_column(style=f"bold {ADSCAN_PRIMARY}", justify="right")
    results_table.add_column(style="white", justify="left")

    for key, value in results.items():
        # Style based on value
        if isinstance(value, (int, float)):
            if value > 0:
                value_style = "bold green"
            else:
                value_style = "dim"
            value_str = str(value)
        elif isinstance(value, bool):
            value_style = "bold green" if value else "bold red"
            value_str = "Yes" if value else "No"
        else:
            value_style = "white"
            value_str = str(value)

        results_table.add_row(f"{key}:", Text(value_str, style=value_style))

    if show_panel:
        panel = Panel(
            results_table,
            title=f"[bold]{title}[/bold]",
            border_style=ADSCAN_PRIMARY,
            padding=(1, 2),
        )
        spacing_before = _handle_spacing("success", True, "auto")
        if spacing_before:
            console.print()

        console.print(panel)
    else:
        spacing_before = _handle_spacing("info", False, "auto")
        if spacing_before:
            console.print()

        console.print(results_table)


def print_domain_info(
    domain: str,
    pdc: Optional[str] = None,
    credentials: Optional[Dict[str, str]] = None,
    additional_info: Optional[Dict[str, Any]] = None,
) -> None:
    """Print professional domain information panel.

    Args:
        domain: Domain name
        pdc: Primary domain controller (optional)
        credentials: Dictionary with username/password or hash (optional)
        additional_info: Additional key-value information (optional)

    Example:
        >>> print_domain_info(
        ...     "example.local",
        ...     pdc="dc01.example.local",
        ...     credentials={"username": "admin", "type": "password"}
        ... )
    """
    console = _get_console()
    _get_telemetry_console()
    from rich.text import Text
    from rich.panel import Panel
    from rich.table import Table

    # Create info table
    info_table = Table.grid(padding=(0, 2))
    info_table.add_column(style="dim", justify="right")
    info_table.add_column(style="white")

    # Domain - mark as sensitive
    info_table.add_row(
        "Domain:",
        Text(mark_sensitive(domain, "domain"), style=f"bold {ADSCAN_PRIMARY}"),
    )

    # PDC - mark as sensitive (could be IP or hostname)
    if pdc:
        # Check if PDC is IP or hostname
        import re

        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        if re.search(ip_pattern, pdc):
            marked_pdc = mark_sensitive(pdc, "ip")
        elif "." in pdc:
            # FQDN
            marked_pdc = mark_sensitive(pdc, "domain")
        else:
            # Hostname
            marked_pdc = mark_sensitive(pdc, "hostname")
        info_table.add_row("PDC:", marked_pdc)

    # Credentials
    if credentials:
        if "username" in credentials:
            marked_username = mark_sensitive(credentials["username"], "user")
            info_table.add_row("Username:", marked_username)
        if "type" in credentials:
            cred_type = credentials["type"]
            icon = "🔐" if cred_type == "password" else "🔑"
            info_table.add_row("Auth Type:", f"{icon} {cred_type.title()}")

    # Additional info - mark using intelligent detection
    if additional_info:
        marked_info = _mark_operation_details(additional_info)
        for key, value in marked_info.items():
            info_table.add_row(f"{key}:", str(value))

    panel = Panel(
        info_table,
        title="[bold]🎯 New Domain Discovered[/bold]",
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
    )

    spacing_before = _handle_spacing("info", True, "auto")
    if spacing_before:
        console.print()

    console.print(panel)


def create_domains_table(
    domains_data: Dict[str, Dict[str, Any]],
    title: str = "Discovered Domains",
) -> Table:
    """Create a professional table displaying domains and their information.

    Args:
        domains_data: Dictionary mapping domain names to their data
        title: Table title

    Returns:
        Rich Table object

    Example:
        >>> domains_data = {
        ...     "example.local": {"pdc": "10.0.0.1", "reachable": True},
        ...     "test.local": {"pdc": "10.0.0.2", "reachable": False}
        ... }
        >>> table = create_domains_table(domains_data)
        >>> console.print(table)
    """
    table = create_styled_table(title=title)
    table.add_column("Domain", style=f"bold {ADSCAN_PRIMARY}", no_wrap=True)
    table.add_column("PDC", style="cyan")
    table.add_column("Reachable", justify="center")

    for domain, data in domains_data.items():
        pdc = data.get("pdc", "N/A")

        # Mark sensitive data
        marked_domain = mark_sensitive(domain, "domain")

        # Mark PDC (could be IP or hostname)
        if pdc != "N/A":
            import re

            ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            if re.search(ip_pattern, pdc):
                marked_pdc = mark_sensitive(pdc, "ip")
            elif "." in pdc:
                # FQDN
                marked_pdc = mark_sensitive(pdc, "domain")
            else:
                # Hostname
                marked_pdc = mark_sensitive(pdc, "hostname")
        else:
            marked_pdc = pdc

        reachable = data.get("reachable")
        if reachable is True:
            reachable_display = "[green]✓ Reachable[/green]"
        elif reachable is False:
            reachable_display = "[yellow]✗ Unreachable[/yellow]"
        else:
            reachable_display = "[dim]? Unknown[/dim]"

        table.add_row(marked_domain, marked_pdc, reachable_display)

    return table


def create_credentials_table(
    credentials: Dict[str, str],
    title: str = "Compromised Credentials",
    show_preview: bool = True,
) -> Table:
    """Create a professional table displaying credentials.

    Args:
        credentials: Dictionary mapping usernames to passwords/hashes
        title: Table title
        show_preview: Whether to show credential preview (default: True)

    Returns:
        Rich Table object

    Example:
        >>> creds = {"admin": "Password123!", "user": "aad3b435b51404eeaad3b435b51404ee"}
        >>> table = create_credentials_table(creds)
        >>> console.print(table)
    """
    table = create_styled_table(title=title)
    table.add_column("Username", style=f"bold {ADSCAN_PRIMARY}")
    table.add_column("Type", justify="center")
    table.add_column("Preview", style="dim" if show_preview else "")

    for username, credential in credentials.items():
        # Mark username as sensitive
        marked_username = mark_sensitive(username, "user")

        # Determine if hash or password
        is_hash = len(credential) == 32 and all(
            c in "0123456789abcdefABCDEF" for c in credential
        )

        if is_hash:
            cred_type = "[yellow]🔑 Hash[/yellow]"
            if show_preview:
                # Mark the preview parts separately and reconstruct
                preview_start = mark_sensitive(credential[:8], "password")
                preview_end = mark_sensitive(credential[-4:], "password")
                preview = f"{preview_start}...{preview_end}"
            else:
                preview = "••••••••"
        else:
            cred_type = "[green]🔐 Password[/green]"
            if show_preview:
                # Mark the visible part
                visible_part = credential[:3]
                marked_visible = mark_sensitive(visible_part, "password")
                preview = f"{marked_visible}{'*' * min(len(credential) - 3, 8)}"
            else:
                preview = "••••••••"

        table.add_row(marked_username, cred_type, preview)

    return table


def print_workflow_summary(
    workflow_name: str,
    results: Dict[str, Any],
    show_panel: bool = True,
    icon: str = "📊",
) -> None:
    """Print a professional summary of a completed workflow with statistics.

    This function displays a comprehensive summary at the end of a scan workflow,
    showing what was executed, results obtained, and overall status.

    Args:
        workflow_name: Name of the workflow (e.g., "Unauthenticated Scan")
        results: Dictionary of workflow results with keys like:
            - "status": Overall status (Success, Partial, Failed)
            - "steps_completed": Number of steps completed
            - "steps_total": Total number of steps
            - "duration": Duration in seconds (optional)
            - Any other key-value pairs for statistics
        show_panel: Whether to wrap in a panel (default: True)
        icon: Icon to display (default: 📊)

    Examples:
        print_workflow_summary(
            "Unauthenticated Scan",
            {
                "status": "Success",
                "steps_completed": 5,
                "steps_total": 5,
                "duration": 120.5,
                "hosts_found": 15,
                "shares_discovered": 8,
                "users_enumerated": 150,
            }
        )
    """
    console = _get_console()
    _get_telemetry_console()

    # Build header
    header_text = Text()
    header_text.append(f"{icon} ", style="bold")
    header_text.append(workflow_name, style=f"bold {ADSCAN_PRIMARY}")
    header_text.append(" - Summary", style="bold white")

    # Determine overall status styling
    status = results.get("status", "Unknown")
    if status.lower() in ["success", "completed"]:
        status_color = "green"
        status_icon = "✓"
    elif status.lower() in ["partial", "warning"]:
        status_color = "yellow"
        status_icon = "⚠"
    elif status.lower() in ["failed", "error"]:
        status_color = "red"
        status_icon = "✗"
    else:
        status_color = "white"
        status_icon = "○"

    # Create results table
    results_table = Table.grid(padding=(0, 2))
    results_table.add_column(style=f"bold {ADSCAN_PRIMARY}", justify="right")
    results_table.add_column(style="white", justify="left")

    # Add overall status first
    status_text = Text()
    status_text.append(f"{status_icon} ", style=f"bold {status_color}")
    status_text.append(status, style=f"bold {status_color}")
    results_table.add_row("Status:", status_text)

    # Add step completion if provided
    steps_completed = results.get("steps_completed")
    steps_total = results.get("steps_total")
    if steps_completed is not None and steps_total is not None:
        completion_pct = (steps_completed / steps_total * 100) if steps_total > 0 else 0
        completion_text = Text()
        completion_text.append(f"{steps_completed}/{steps_total}", style="white")
        completion_text.append(f" ({completion_pct:.0f}%)", style="dim")
        results_table.add_row("Steps Completed:", completion_text)

    # Add duration if provided
    duration = results.get("duration")
    if duration is not None:
        if duration < 60:
            duration_str = f"{duration:.1f} seconds"
        elif duration < 3600:
            duration_str = f"{duration / 60:.1f} minutes"
        else:
            duration_str = f"{duration / 3600:.1f} hours"
        results_table.add_row("Duration:", duration_str)

    # Add all other results (excluding metadata keys)
    metadata_keys = {"status", "steps_completed", "steps_total", "duration"}
    for key, value in results.items():
        if key not in metadata_keys:
            # Format key (capitalize first letter, replace underscores)
            formatted_key = key.replace("_", " ").title()

            # Style value based on type and content
            if isinstance(value, bool):
                value_style = "bold green" if value else "bold red"
                value_str = "Yes" if value else "No"
            elif isinstance(value, (int, float)):
                if value > 0:
                    value_style = "bold green"
                else:
                    value_style = "dim"
                value_str = str(value)
            else:
                value_style = "white"
                value_str = str(value)

            results_table.add_row(
                f"{formatted_key}:", Text(value_str, style=value_style)
            )

    # Create content
    content = Group(header_text, Text(""), results_table)

    if show_panel:
        # Determine panel border color based on status
        border_color = status_color if status_color != "white" else ADSCAN_PRIMARY

        panel = Panel(
            content,
            border_style=border_color,
            padding=(1, 2),
            box=ROUNDED,
        )

        spacing_before = _handle_spacing("success", True, "auto")
        if spacing_before:
            console.print()

        console.print(panel)
    else:
        spacing_before = _handle_spacing("info", False, "auto")
        if spacing_before:
            console.print()

        console.print(content)


def print_delegations_summary(
    domain: str,
    delegations_data: List[Dict[str, str]],
    show_empty: bool = True,
) -> None:
    """Display a professional summary of Kerberos delegations grouped by type.

    Args:
        domain: Domain name
        delegations_data: List of delegation dictionaries with keys:
            - account: Account name
            - account_type: Account type (User/Computer)
            - delegation_type: Type of delegation
            - delegation_to: Target of delegation (if applicable)
        show_empty: Whether to show a message when no delegations found

    Example:
        >>> delegations = [
        ...     {
        ...         "account": "WIN-DC$",
        ...         "account_type": "Computer",
        ...         "delegation_type": "Unconstrained",
        ...         "delegation_to": "N/A"
        ...     }
        ... ]
        >>> print_delegations_summary("example.local", delegations)
    """
    from rich.table import Table
    from rich.text import Text

    if not delegations_data:
        if show_empty:
            print_success(f"No Kerberos delegations found in domain {domain}")
        return

    # Group delegations by type
    delegation_groups = {
        "unconstrained": [],
        "constrained": [],
        "constrained_protocol_transition": [],
        "resource_based_constrained": [],
        "unknown": [],
    }

    for delegation in delegations_data:
        delegation_type_lower = delegation.get("delegation_type", "").lower()
        if (
            "unconstrained" in delegation_type_lower
            and "resource-based" not in delegation_type_lower
        ):
            delegation_groups["unconstrained"].append(delegation)
        elif (
            "resource-based" in delegation_type_lower
            or "resource based" in delegation_type_lower
        ):
            delegation_groups["resource_based_constrained"].append(delegation)
        elif (
            "protocol transition" in delegation_type_lower
            and "w/o" not in delegation_type_lower
        ):
            delegation_groups["constrained_protocol_transition"].append(delegation)
        elif "constrained" in delegation_type_lower:
            delegation_groups["constrained"].append(delegation)
        else:
            delegation_groups["unknown"].append(delegation)

    # Count total and by type
    total = len(delegations_data)

    # Create summary header
    summary_text = Text()
    summary_text.append("Kerberos Delegations Found: ", style="bold white")
    summary_text.append(str(total), style=f"bold {BRAND_COLORS['success']}")

    _state_mod._console.print()
    _state_mod._console.print(
        Panel(
            summary_text,
            title=f"🔗 Domain: {domain}",
            border_style=BRAND_COLORS["info"],
            padding=(0, 2),
        )
    )

    # Display each delegation type with its own table
    delegation_type_info = {
        "unconstrained": {
            "title": "⚠️  Unconstrained Delegation",
            "description": "High risk - Account can impersonate any user to any service",
            "color": "red",
        },
        "constrained": {
            "title": "🔒 Constrained Delegation",
            "description": "Limited risk - Account can impersonate users to specific services",
            "color": "yellow",
        },
        "constrained_protocol_transition": {
            "title": "🔐 Constrained with Protocol Transition",
            "description": "Moderate risk - Can switch protocols during delegation",
            "color": "yellow",
        },
        "resource_based_constrained": {
            "title": "🎯 Resource-Based Constrained Delegation (RBCD)",
            "description": "Service-controlled - Configured on target resource",
            "color": "cyan",
        },
        "unknown": {
            "title": "❓ Unknown Delegation Type",
            "description": "Could not classify delegation type",
            "color": "dim white",
        },
    }

    for delegation_type, delegations in delegation_groups.items():
        if not delegations:
            continue

        info = delegation_type_info[delegation_type]

        # Create table for this delegation type
        table = Table(
            title=f"{info['title']} ({len(delegations)})",
            title_style=f"bold {info['color']}",
            border_style=info["color"],
            show_header=True,
            header_style=f"bold {info['color']}",
            padding=(0, 1),
        )

        table.add_column("Account", style="cyan", no_wrap=False)
        table.add_column("Type", style="white", justify="center")
        table.add_column("Delegation To", style="yellow", no_wrap=False)

        for delegation in delegations:
            account = delegation.get("account", "N/A")
            account_type = delegation.get("account_type", "N/A")
            delegation_to = delegation.get("delegation_to", "N/A")

            # Add icon based on account type
            if account_type.lower() == "computer":
                account_icon = "💻 "
            elif account_type.lower() == "user":
                account_icon = "👤 "
            else:
                account_icon = "📋 "

            # Mark sensitive data
            marked_account = (
                mark_sensitive(account, "user") if account != "N/A" else account
            )

            if delegation_to != "N/A" and delegation_to.lower() not in [
                "any service",
                "any",
                "-",
            ]:
                marked_delegation_to = mark_sensitive(delegation_to, "service")
            else:
                marked_delegation_to = (
                    delegation_to
                    if delegation_to != "N/A"
                    else "[dim]Any service[/dim]"
                )

            table.add_row(
                f"{account_icon}{marked_account}", account_type, marked_delegation_to
            )

        _state_mod._console.print()
        _state_mod._console.print(table)
        _state_mod._console.print(f"[dim]{info['description']}[/dim]")

    _state_mod._console.print()
