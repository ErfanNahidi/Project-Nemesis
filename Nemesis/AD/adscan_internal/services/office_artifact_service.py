"""Deterministic encrypted Office artifact cracking.

Detects CDFV2-encrypted Office documents (xlsx, xlsm, docx, pptx, …),
extracts a John-compatible hash with office2john, and attempts to crack it
with the configured wordlist.  Content extraction from the decrypted file
is explicitly deferred to a future release.

Detection heuristic
-------------------
Modern OpenXML formats (.xlsx/.docx/…) are ZIP containers.  When an Office
application protects a file with a password it re-wraps the document inside
a CDFV2 (Compound Document File Version 2) container.  The result is *not* a
valid ZIP file.  Attempting ``zipfile.ZipFile(bytes)`` therefore raises
``BadZipFile`` on any encrypted Office document, which is the detection gate.

Legacy binary formats (.xls/.doc) are already OLE/CDFV2, so the same check
applies: if the bytes are valid ZIP → plain, otherwise → potentially encrypted.
"""

from __future__ import annotations

import io
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path

from adscan_internal import print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.john_artifact_cracking_service import (
    JohnArtifactCrackingService,
)


_OFFICE_ENCRYPTED_EXTENSIONS: frozenset[str] = frozenset({
    ".xlsx", ".xlsm", ".xls",
    ".docx", ".doc",
    ".pptx", ".ppt",
})


@dataclass(frozen=True)
class OfficeArtifactCrackResult:
    """Outcome of one encrypted Office file cracking attempt.

    Content extraction is not performed here — the caller receives the cracked
    password and the original encrypted path.  The decryption + content dump
    step will be added in a future release alongside msoffcrypto-tool
    integration.
    """

    source_path: str
    hash_file: str | None
    cracked_password: str | None
    cracked: bool
    error_message: str | None = None


class OfficeArtifactService(BaseService):
    """Crack password-protected Office files and surface the recovered secret.

    Mirrors :class:`adscan_internal.services.keepass_artifact_service.KeePassArtifactService`
    in structure.  Uses ``office2john`` (JtR bundled tool) to extract a
    hashcat/John-compatible hash, then runs John with the engagement wordlist.
    """

    def __init__(
        self,
        *,
        john_service: JohnArtifactCrackingService | None = None,
    ) -> None:
        super().__init__()
        self._john_service = john_service or JohnArtifactCrackingService()

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_encrypted_bytes(file_bytes: bytes) -> bool:
        """Return True when ``file_bytes`` represent an encrypted Office document.

        Encrypted OpenXML files are CDFV2 containers, not ZIP archives.
        ``zipfile.ZipFile`` raises ``BadZipFile`` on them — that is our signal.
        An empty or unreadable file returns False so no false-positives are
        emitted for corrupt downloads.
        """
        if not file_bytes:
            return False
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)):
                return False
        except zipfile.BadZipFile:
            return True
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def is_encrypted_path(file_path: str) -> bool:
        """Return True when the file at ``file_path`` is an encrypted Office doc."""
        try:
            with open(file_path, "rb") as fh:
                header = fh.read(4096)
            return OfficeArtifactService.is_encrypted_bytes(header)
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def is_office_extension(path: str) -> bool:
        """Return True when the path has a tracked Office extension."""
        return Path(path).suffix.lower() in _OFFICE_ENCRYPTED_EXTENSIONS

    # ------------------------------------------------------------------
    # Cracking
    # ------------------------------------------------------------------

    def crack(
        self,
        *,
        domain: str,
        source_path: str,
        wordlist_path: str,
        office2john_path: str,
        python_executable: str | None = None,
        report_dir: str | None = None,
    ) -> OfficeArtifactCrackResult:
        """Extract hash from an encrypted Office file then attempt to crack it.

        Args:
            domain: Target domain label (used for workspace path construction).
            source_path: Absolute path to the encrypted Office file.
            wordlist_path: Absolute path to the John wordlist.
            office2john_path: Path to the office2john.py converter script.
            python_executable: Python interpreter to invoke the script with.
                Defaults to the venv Python when not provided.
            report_dir: Directory in which to persist the hash file and report.

        Returns:
            :class:`OfficeArtifactCrackResult` — always returned, never raises.
        """
        normalized = str(source_path or "").strip()
        if not normalized or not os.path.isfile(normalized):
            return OfficeArtifactCrackResult(
                source_path=normalized,
                hash_file=None,
                cracked_password=None,
                cracked=False,
                error_message="Office artifact path does not exist.",
            )

        stem = Path(normalized).stem
        artifact_root = (
            str(report_dir or "").strip()
            or os.path.join(
                os.path.dirname(normalized),
                f"domains/{domain}/smb/office_artifacts",
            )
        )
        hash_file = os.path.join(artifact_root, f"{stem}.office.hash")

        # Step 1 — extract hash with office2john
        extracted = self._john_service.extract_hash_with_script(
            script_path=office2john_path,
            input_paths=[normalized],
            hash_file=hash_file,
            python_executable=python_executable,
        )
        if not extracted or not os.path.isfile(hash_file):
            return OfficeArtifactCrackResult(
                source_path=normalized,
                hash_file=None,
                cracked_password=None,
                cracked=False,
                error_message="office2john failed to produce a usable hash.",
            )

        # Step 2 — crack with John
        crack_result = self._john_service.crack_hash_file(
            hash_file=hash_file,
            wordlist_path=wordlist_path,
        )
        cracked = crack_result.cracked_secret is not None
        print_info_debug(
            "[office_artifact] Crack attempt complete: "
            f"source={mark_sensitive(stem, 'path')} "
            f"cracked={cracked}"
        )
        return OfficeArtifactCrackResult(
            source_path=normalized,
            hash_file=hash_file,
            cracked_password=crack_result.cracked_secret,
            cracked=cracked,
            error_message=None if cracked else "Password not found in wordlist.",
        )


OFFICE_ENCRYPTED_EXTENSIONS = _OFFICE_ENCRYPTED_EXTENSIONS

__all__ = [
    "OfficeArtifactCrackResult",
    "OfficeArtifactService",
    "OFFICE_ENCRYPTED_EXTENSIONS",
]
