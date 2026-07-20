"""Scanner protocol — every detection backend implements this.

The framework only knows about :class:`Scanner` and :class:`ScanRequest`.
Anything else (Defender, AMSI, CrowdStrike, S1) lives in its own module
and registers itself through :mod:`avlab.scanners.registry`.

This split is the point that makes the framework outlast individual
EDRs: a future scanner is "drop a new file under scanners/, register
it, done" — no caller code changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from avlab.core.models import ScanResult


@dataclass(frozen=True, slots=True)
class ScanRequest:
    """Input to :meth:`Scanner.scan`.

    Carries the file plus the *names* the result will reference.
    Scanners are otherwise stateless — same input → same output —
    which is what lets us replay runs from the JSON record alone.
    """

    variant_name: str
    artefact_path: Path
    timeout_seconds: int = 60


@runtime_checkable
class Scanner(Protocol):
    """Detection backend contract.

    Implementations live in :mod:`avlab.scanners.<name>` and must:

    * Provide a unique :attr:`name` (matches the registry key).
    * Implement :meth:`setup` once before the first scan.
    * Implement :meth:`scan` for one artefact.
    * Implement :meth:`teardown` to leave the target as it was found.

    The lifecycle (setup → many scans → teardown) is driven by the
    :mod:`avlab.methods` orchestrators, never by user code directly.
    """

    name: str

    def setup(self) -> None: ...
    def scan(self, request: ScanRequest) -> ScanResult: ...
    def teardown(self) -> None: ...


__all__ = ["Scanner", "ScanRequest"]
