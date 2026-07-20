"""Context panel: posture score, attack paths, and discovered credentials.

Right-rail companion to the live console. Renders the canonical posture
score (cyan headline), attack-path KPIs and credential roster, all sourced
from the workspace state on disk via :mod:`adscan_internal.tui.data`.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Log, Static

from adscan_internal.tui.data import empty_posture, load_workspace_summary
from adscan_internal.tui.widgets.posture_badge import PostureBadge


class ContextPanel(Widget):
    """Right panel showing posture, attack paths and credentials."""

    def __init__(self, shell: Any, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._shell = shell

    def compose(self) -> ComposeResult:
        yield PostureBadge(empty_posture(), id="posture-badge")
        yield _AttackPathsSection(shell=self._shell, id="attack-paths-section")
        yield _CredentialsSection(shell=self._shell, id="credentials-section")

    def on_mount(self) -> None:
        self.refresh_context()

    def refresh_context(self) -> None:
        """Refresh posture, attack paths and credentials from shell state."""
        self._refresh_posture()
        try:
            self.query_one(_AttackPathsSection).refresh_content()
            self.query_one(_CredentialsSection).refresh_content()
        except Exception:  # noqa: BLE001
            pass

    # ── Posture ──────────────────────────────────────────────────────────────

    def _refresh_posture(self) -> None:
        """Reload posture from the current workspace's technical report."""
        try:
            badge = self.query_one("#posture-badge", PostureBadge)
        except Exception:  # noqa: BLE001
            return

        ws_path = self._current_workspace_path()
        if ws_path is None or not ws_path.exists():
            badge.set_posture(empty_posture())
            return
        summary = load_workspace_summary(ws_path)
        badge.set_posture(summary.posture or empty_posture())

    def _current_workspace_path(self):
        """Resolve the on-disk path of the shell's current workspace."""
        try:
            from adscan_core.paths import get_workspaces_dir

            workspace_name = getattr(self._shell, "current_workspace", None)
            if not workspace_name:
                return None
            return get_workspaces_dir() / str(workspace_name)
        except Exception:  # noqa: BLE001
            return None


class _AttackPathsSection(Widget):
    """Attack paths sub-panel."""

    def __init__(self, shell: Any, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._shell = shell

    def compose(self) -> ComposeResult:
        yield Static("  ATTACK PATHS", id="attack-paths-title")
        yield Log(id="attack-paths-list", highlight=True)

    def on_mount(self) -> None:
        self.refresh_content()

    def refresh_content(self) -> None:
        """Reload attack paths from shell state."""
        log = self.query_one("#attack-paths-list", Log)
        log.clear()
        # Attack-path caching for the TUI is not yet wired up to the native
        # graph service; the panel reads from in-memory state once that lands.
        log.write_line("[dim]No attack paths yet[/dim]")


class _CredentialsSection(Widget):
    """Discovered credentials sub-panel."""

    def __init__(self, shell: Any, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._shell = shell

    def compose(self) -> ComposeResult:
        yield Static("  CREDENTIALS", id="credentials-title")
        yield Log(id="credentials-list", highlight=True)

    def on_mount(self) -> None:
        self.refresh_content()

    def refresh_content(self) -> None:
        """Reload discovered credentials from shell state."""
        log = self.query_one("#credentials-list", Log)
        log.clear()

        creds: list = []
        try:
            cred_svc = getattr(self._shell, "_credential_service", None)
            if cred_svc and hasattr(cred_svc, "get_valid_credentials"):
                creds = cred_svc.get_valid_credentials() or []
        except Exception:  # noqa: BLE001
            pass

        if not creds:
            log.write_line("[dim]No credentials yet[/dim]")
            return

        for cred in creds[:30]:
            if isinstance(cred, dict):
                user = cred.get("username", "?")
                secret = cred.get("password") or cred.get("hash") or "?"
                if len(str(secret)) > 16:
                    secret = str(secret)[:14] + "…"
                log.write_line(f"● {user} : {secret}")
            else:
                log.write_line(f"● {cred}")
