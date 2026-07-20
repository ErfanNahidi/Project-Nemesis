"""SMB enumeration mixin.

Thin orchestration layer over the native async SMB stack. The legacy
NetExec subprocess paths (``nxc smb --shares`` / ``--sessions``) were
deleted in favour of :mod:`adscan_internal.services.enumeration.smb_shares_native`,
which uses ``aiosmb`` + ``smb_machine_with_fallback`` directly. The mixin
preserves its existing signatures so external callers do not break, but
each method now delegates to the native service.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from adscan_internal.core import (
    AuthMode,
    requires_auth,
)
from adscan_internal.models import SMBShare
from adscan_internal.services.enumeration.smb_shares_native import (
    NativeShareEntry,
    NativeSharesResult,
    enumerate_sessions_native_sync,
    enumerate_shares_native_sync,
)
from adscan_internal.services.smb_transport import SMBConfig


logger = logging.getLogger(__name__)


def _native_share_to_model(host: str, entry: NativeShareEntry) -> SMBShare:
    """Adapt a :class:`NativeShareEntry` to the public ``SMBShare`` model.

    Preserves the metadata bag with the structured fields the native path
    can supply (type, remark, probe error) so consumers that already parse
    ``metadata`` keep working without modification.
    """
    metadata: Dict[str, Any] = {"source": "native_aiosmb", "type": entry.type}
    if entry.remark:
        metadata["remark"] = entry.remark
    if entry.probe_error:
        metadata["probe_error"] = entry.probe_error
    return SMBShare(
        host=host,
        share_name=entry.name,
        permissions=list(entry.permissions),
        accessible=entry.accessible,
        metadata=metadata,
    )


@dataclass
class SMBSession:
    """Represents an active SMB session.

    Attributes:
        hostname: Host where session is active
        username: Username of session
        ip_address: IP address of host
        is_admin: Whether session has admin privileges
        connection_time: When session was established (optional)
    """

    hostname: str
    username: str
    ip_address: str
    is_admin: bool = False
    connection_time: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hostname": self.hostname,
            "username": self.username,
            "ip_address": self.ip_address,
            "is_admin": self.is_admin,
            "connection_time": self.connection_time,
        }


class SMBEnumerationMixin:
    """SMB enumeration operations.

    This mixin provides SMB-specific enumeration methods that adapt
    their behavior based on the authentication mode.

    Note: This is a mixin, not a standalone service. It requires a parent
    EnumerationService to provide event_bus, logger, and license_mode.
    """

    def __init__(self, parent_service):
        """Initialize SMB enumeration mixin.

        Args:
            parent_service: Parent EnumerationService instance
        """
        self.parent = parent_service
        self.logger = parent_service.logger

    def enumerate_shares(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        netexec_path: str = "",  # noqa: ARG002 — kept for signature stability
        username: Optional[str] = None,
        password: Optional[str] = None,
        scan_id: Optional[str] = None,
        timeout: int = 60,
    ) -> List[SMBShare]:
        """Enumerate SMB shares on target via the native async stack.

        Adapts behavior based on authentication mode:

        * ``UNAUTHENTICATED`` — null session (no credentials).
        * ``AUTHENTICATED`` — Kerberos-first with NTLM fallback through
          ``smb_machine_with_fallback`` (posture-aware; obeys NTLM-disabled).
        * ``USER_LIST`` — not applicable; returns empty list with a warning.

        ``netexec_path`` is accepted for backward-compatibility only — the
        legacy NetExec subprocess path was deleted; permissions are now read
        directly from the SMB ``maximal_access`` field per share.
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="smb_share_enumeration",
            progress=0.0,
            message=f"Starting SMB share enumeration on {pdc}",
        )

        if auth_mode == AuthMode.AUTHENTICATED and not (username and password):
            raise ValueError(
                "Username and password required for authenticated SMB enumeration"
            )
        if auth_mode not in (AuthMode.UNAUTHENTICATED, AuthMode.AUTHENTICATED):
            self.logger.warning(
                f"SMB share enumeration not supported with auth_mode={auth_mode.value}"
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="smb_share_enumeration",
                progress=1.0,
                message="SMB share enumeration skipped (mode not supported)",
            )
            return []

        config = self._build_smb_config(
            pdc=pdc,
            domain=domain,
            username=username if auth_mode == AuthMode.AUTHENTICATED else None,
            password=password if auth_mode == AuthMode.AUTHENTICATED else None,
            timeout=timeout,
        )

        result: NativeSharesResult = enumerate_shares_native_sync(
            config=config, timeout=timeout, probe_access=True
        )

        if result.status not in {"ok", "partial"}:
            self.logger.warning(
                f"SMB share enumeration on {pdc} returned status={result.status}: "
                f"{result.error or 'unknown error'}"
            )

        shares = [_native_share_to_model(pdc, entry) for entry in result.shares]

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="smb_share_enumeration",
            progress=1.0,
            message=f"SMB share enumeration completed: {len(shares)} share(s) found",
        )
        return shares

    @staticmethod
    def _build_smb_config(
        *,
        pdc: str,
        domain: Optional[str],
        username: Optional[str],
        password: Optional[str],
        timeout: int,
    ) -> SMBConfig:
        """Translate mixin args to ``SMBConfig`` for the native transport.

        ``password`` may be a plaintext password or a 32-hex NT hash; the
        same heuristic the legacy nxc path used (``len==32`` and all hex)
        is preserved so call-site behaviour is identical.
        """
        nt_hash: Optional[str] = None
        plain_password: Optional[str] = None
        if password:
            if len(password) == 32 and all(c in "0123456789abcdef" for c in password.lower()):
                nt_hash = password
            else:
                plain_password = password
        return SMBConfig(
            target_ip=pdc,
            target_hostname=pdc,
            domain=domain,
            username=username or None,
            password=plain_password,
            nt_hash=nt_hash,
            timeout=max(timeout, 5),
        )

    @requires_auth(AuthMode.AUTHENTICATED)
    def enumerate_sessions(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        username: str,
        password: str,
        netexec_path: str = "",  # noqa: ARG002 — kept for signature stability
        scan_id: Optional[str] = None,
        timeout: int = 60,
    ) -> List[SMBSession]:
        """Enumerate active SMB sessions on domain controller.

        This operation requires authenticated access.

        Args:
            domain: Domain name
            pdc: PDC hostname/IP
            auth_mode: Authentication mode (must be AUTHENTICATED)
            username: Username
            password: Password or hash
            netexec_path: Path to NetExec
            scan_id: Optional scan ID
            timeout: Timeout in seconds

        Returns:
            List of active SMB sessions

        Raises:
            AuthenticationError: If auth_mode is not AUTHENTICATED
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="smb_session_enumeration",
            progress=0.0,
            message=f"Enumerating SMB sessions on {pdc}",
        )

        config = self._build_smb_config(
            pdc=pdc,
            domain=domain,
            username=username,
            password=password,
            timeout=timeout,
        )

        result = enumerate_sessions_native_sync(config=config, timeout=timeout)

        if result.status not in {"ok", "partial"}:
            self.logger.warning(
                f"SMB session enumeration on {pdc} returned status={result.status}: "
                f"{result.error or 'unknown error'}"
            )

        sessions = [
            SMBSession(
                hostname=pdc,
                username=entry.username,
                ip_address=entry.source_ip,
                is_admin=False,
            )
            for entry in result.sessions
        ]

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="smb_session_enumeration",
            progress=1.0,
            message=f"Session enumeration completed: {len(sessions)} session(s) found",
        )
        return sessions
