"""Typed contracts shared across the AV/EDR validation lab.

Three axes the framework rotates around:

* **Variant**  — one specific build of a payload/loader. Identified by a
  set of toggles (which OPSEC layers are on/off) and a content hash.
* **Scanner** — a detection backend (Defender via MpCmdRun, AMSI via
  PowerShell, CrowdStrike via API, etc). Implemented in
  :mod:`avlab.scanners` against the :class:`Scanner` protocol.
* **Method**  — an analysis strategy. Today we ship two:
  :mod:`avlab.methods.truncation_bisect` for static byte-pattern
  signatures and :mod:`avlab.methods.toggle_ablation` for ML/behavioural
  detection where the bisect collapses.

These three combine into a :class:`MatrixRun`: "scan every variant
in catalog X with scanner Y using method Z, capture every result".
The output is a deterministic ``matrix.json`` + ``matrix.md`` that
both humans and CI can consume.

The point of locking these contracts down is *years* of accumulating
data: every run must remain interpretable when read 18 months later.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ScanVerdict(str, Enum):
    """What the scanner said about one artefact."""

    CLEAN = "clean"
    DETECTED = "detected"
    INCONCLUSIVE = "inconclusive"  # scanner errored or timed out
    UPLOAD_BLOCKED = "upload_blocked"  # detection during transfer (RTP-style)


class DetectionKind(str, Enum):
    """Best-effort classification of *how* a detection fired."""

    BYTE_SIGNATURE = "byte_signature"  # bisect found a concrete range
    AGGREGATE_ML = "aggregate_ml"  # bisect inconclusive — full-binary features
    CLOUD_REPUTATION = "cloud_reputation"  # MAPS / cloud lookup
    BEHAVIOURAL = "behavioural"  # caught during runtime, not on disk
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Toggle specs — every OPSEC layer the variant compiler can flip on/off
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToggleSpec:
    """Declarative description of one variant's OPSEC layer set.

    Each field is a layer the loader knows how to omit. ``True`` means
    the layer is present, ``False`` means it is omitted at compile time
    via a ``-DADSCAN_NO_<LAYER>=1`` define.

    Adding a new layer:
        1. Add a field here with a default of ``True`` (preserves
           backward-compat: existing variant catalogs keep working).
        2. Wire the corresponding ``#ifndef ADSCAN_NO_<LAYER>`` in the
           relevant ``loader_src/*.c`` file.
        3. Update :func:`compile_flags` below to emit the right define.
    """

    # Shellcode wrapping
    donut_wrap: bool = True
    """Use Donut to PE→shellcode. False → custom encoder (future)."""

    # Encryption layer over shellcode
    xor_encrypt: bool = True
    """16-byte per-build XOR key. False → plain shellcode (debug)."""

    # Direct syscalls vs Win32 wrappers
    sw4_syscalls: bool = True
    """SysWhispers4 RecycledGate stubs. False → ntdll Win32 wrappers."""

    # Userland evasion layers
    ntdll_unhook: bool = True
    """Remap clean ntdll .text from \\KnownDlls before any syscall."""
    etw_patch: bool = True
    """Patch EtwEventWrite to no-op."""
    amsi_patch: bool = True
    """Patch AmsiScanBuffer to E_INVALIDARG."""
    anti_debug: bool = True
    """6-check anti-debug suite (RDTSC, IsDebuggerPresent, etc.)."""

    # Static analysis evasion
    api_hashing: bool = False
    """API resolution by CRC32/FNV-1a hash. Default False (not yet implemented)."""
    polymorphic_codegen: bool = False
    """Junk instructions + function reordering. Default False (future)."""
    strip_metadata: bool = False
    """Strip RC manifest, debug info, .pdata, build timestamps."""
    minimal_imports: bool = False
    """Reduce IAT to bare minimum (VirtualAlloc, CreateThread)."""

    # Anti-emulation
    antiemu: bool = True
    """Derive XOR key from process count + PID so MpEngine emulator decrypts garbage.
    Emulator: ~5-15 fake processes, PID < 16 → wrong key.
    Real system (incl. HyperV): 50-200+ processes, PID > 100 → correct key.
    Disable (-DADSCAN_NO_ANTIEMU=1) for debug / controlled test runs."""

    # Execution model
    module_stomping: bool = False
    """Stomp legit DLL .text instead of allocate-write-execute. Future."""

    @property
    def slug(self) -> str:
        """Short stable identifier — used in build dir names and reports.

        Reads off field defaults: only flipped fields appear in the slug,
        keeping output paths short and human-readable.
        """
        defaults = ToggleSpec()
        deltas: list[str] = []
        for fname in self.__dataclass_fields__:
            cur = getattr(self, fname)
            base = getattr(defaults, fname)
            if cur != base:
                # E.g. "etw_patch" with default True flipped → "no_etw_patch"
                # "api_hashing" with default False flipped → "api_hashing"
                deltas.append(("no_" + fname) if base is True else fname)
        return "baseline" if not deltas else "_".join(sorted(deltas))

    def compile_flags(self) -> tuple[str, ...]:
        """Translate this spec into mingw -D flags for the build."""
        flags: list[str] = []
        if not self.donut_wrap:
            flags.append("-DADSCAN_NO_DONUT=1")
        if not self.xor_encrypt:
            flags.append("-DADSCAN_NO_XOR=1")
        if not self.sw4_syscalls:
            flags.append("-DADSCAN_NO_SW4=1")
        if not self.ntdll_unhook:
            flags.append("-DADSCAN_NO_UNHOOK=1")
        if not self.etw_patch:
            flags.append("-DADSCAN_NO_ETW=1")
        if not self.amsi_patch:
            flags.append("-DADSCAN_NO_AMSI=1")
        if not self.anti_debug:
            flags.append("-DADSCAN_NO_ANTIDEBUG=1")
        if not self.antiemu:
            flags.append("-DADSCAN_NO_ANTIEMU=1")
        if self.api_hashing:
            flags.append("-DADSCAN_API_HASH=1")
        if self.polymorphic_codegen:
            flags.append("-DADSCAN_POLY=1")
        if self.strip_metadata:
            flags.append("-DADSCAN_STRIP_META=1")
        if self.minimal_imports:
            flags.append("-DADSCAN_MIN_IMPORTS=1")
        if self.module_stomping:
            flags.append("-DADSCAN_MODSTOMP=1")
        return tuple(flags)


# ---------------------------------------------------------------------------
# Variant — one compiled artefact ready to scan
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Variant:
    """One compiled artefact + the toggles that produced it."""

    name: str
    """Catalog-level identifier, e.g. ``"adscan_loader.v1_no_donut"``."""

    artefact_path: Path
    """Local path to the compiled binary."""

    toggles: ToggleSpec
    """Which OPSEC layers were active when this was built."""

    payload_name: str
    """Name of the wrapped payload (e.g. ``"godpotato-net4"``)."""

    artefact_hash: str
    """SHA-256 of the file contents (full hex)."""

    artefact_size: int
    """Size in bytes."""

    build_seconds: float
    """How long the build took. Useful for trending."""

    notes: str = ""

    @classmethod
    def from_path(
        cls,
        *,
        name: str,
        artefact_path: Path,
        toggles: ToggleSpec,
        payload_name: str,
        build_seconds: float,
        notes: str = "",
    ) -> "Variant":
        """Build a variant record by hashing the file on disk."""
        data = artefact_path.read_bytes()
        return cls(
            name=name,
            artefact_path=artefact_path,
            toggles=toggles,
            payload_name=payload_name,
            artefact_hash=hashlib.sha256(data).hexdigest(),
            artefact_size=len(data),
            build_seconds=build_seconds,
            notes=notes,
        )


# ---------------------------------------------------------------------------
# Scan results — what a scanner reports for one variant
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScanResult:
    """One scan of one variant by one scanner."""

    variant_name: str
    scanner_name: str
    verdict: ScanVerdict
    duration_seconds: float
    threat_names: tuple[str, ...] = ()
    """Detected names if any (Defender ThreatName, S1 IOA, etc.)."""
    raw_output: str = ""
    """Trimmed scanner log lines for the audit record (max ~2KB)."""
    error_message: str | None = None

    @property
    def detected(self) -> bool:
        return self.verdict == ScanVerdict.DETECTED

    @property
    def is_clean(self) -> bool:
        return self.verdict == ScanVerdict.CLEAN


# ---------------------------------------------------------------------------
# Method-level outputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BisectFinding:
    """Output of a truncation bisect."""

    variant_name: str
    scanner_name: str
    inconclusive: bool
    """True when the bisect collapsed (typical for ML/aggregate detection)."""
    end_offset: int | None = None
    """If conclusive: the smallest prefix length that still detects."""
    iterations: int = 0
    elapsed_seconds: float = 0.0
    hex_window: str = ""
    """ASCII-formatted hex dump of bytes around the boundary, for the report."""
    notes: str = ""

    @property
    def detection_kind(self) -> DetectionKind:
        if self.inconclusive:
            return DetectionKind.AGGREGATE_ML
        return DetectionKind.BYTE_SIGNATURE


@dataclass(frozen=True, slots=True)
class ToggleAblation:
    """Output of a toggle-ablation study.

    Carries one row per variant tested.  Downstream the report writer
    cross-tabulates this against the toggle matrix to identify which
    layer changes flip detection.
    """

    matrix_run_id: str
    catalog_name: str
    scanner_name: str
    rows: tuple[ScanResult, ...]
    elapsed_seconds: float

    @property
    def passing(self) -> tuple[ScanResult, ...]:
        return tuple(r for r in self.rows if r.is_clean)

    @property
    def failing(self) -> tuple[ScanResult, ...]:
        return tuple(r for r in self.rows if r.detected)


# ---------------------------------------------------------------------------
# Top-level matrix run — what gets persisted to runs/<timestamp>/
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MatrixRun:
    """A complete validation run.

    Persisted as ``runs/<timestamp>/matrix.json`` + ``matrix.md``.
    Future runs against the same catalog can be diffed against this to
    detect signature drift over months/years.
    """

    run_id: str
    """ISO-style timestamp, used as run dir name."""
    started_at: datetime
    finished_at: datetime
    catalog_name: str
    scanner_name: str
    method: str
    """``"truncation_bisect"`` | ``"toggle_ablation"`` | etc."""
    variants: tuple[Variant, ...]
    results: tuple[ScanResult, ...]
    bisect_findings: tuple[BisectFinding, ...] = ()
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def now(cls, *, prefix: str = "") -> str:
        """Return a stable run id derived from the current UTC time."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"{prefix}{ts}" if prefix else ts


__all__ = [
    "ScanVerdict",
    "DetectionKind",
    "ToggleSpec",
    "Variant",
    "ScanResult",
    "BisectFinding",
    "ToggleAblation",
    "MatrixRun",
]
