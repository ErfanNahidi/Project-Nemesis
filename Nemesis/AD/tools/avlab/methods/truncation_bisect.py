"""Truncation-bisect method — find the smallest detected prefix.

Classic ThreatCheck / GoCheck approach, refactored onto the framework's
:class:`Scanner` protocol so it works against any backend (Defender today,
CrowdStrike / S1 / AMSI tomorrow) without code changes.

Algorithm
---------

Given a detected file ``F`` of length ``L``, find the smallest ``N``
such that ``F[0:N]`` is still detected.  ``N`` marks the *end* of the
offending byte region — the static signature lives somewhere in
``F[0:N]``.  Convergence is ``O(log L)``.

What this CANNOT do
-------------------

Locate ML- or cloud-based detections that fire on aggregate features of
the whole binary.  In that case every prefix from the smallest size up
keeps detecting and the method exits **inconclusive** — which is itself
a strong signal: switch to :mod:`avlab.methods.toggle_ablation`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from avlab.core.models import (
    BisectFinding,
    ScanResult,
    ScanVerdict,
    Variant,
)
from avlab.core.workspace import Workspace
from avlab.scanners.base import ScanRequest, Scanner

_HEX_WINDOW_BYTES = 256


@dataclass(frozen=True, slots=True)
class BisectOutcome:
    """Bundle of what one bisect run produced."""

    finding: BisectFinding
    sanity_result: ScanResult
    """Full-file scan that confirmed the variant is detected."""


def run_truncation_bisect(
    *,
    scanner: Scanner,
    variant: Variant,
    workspace: Workspace,
    scan_timeout_s: int = 60,
    max_iterations: int = 32,
) -> BisectOutcome:
    """Bisect ``variant.artefact_path`` against ``scanner``.

    Caller is responsible for ``scanner.setup()`` / ``scanner.teardown()``
    (typically a method orchestrator covers many variants under one
    setup/teardown to keep AV-exclusion churn low).
    """
    data = Path(variant.artefact_path).read_bytes()
    n = len(data)

    started = time.monotonic()

    sanity = _scan_bytes(
        scanner=scanner,
        workspace=workspace,
        variant_name=variant.name,
        label="full",
        data=data,
        timeout_s=scan_timeout_s,
    )
    if sanity.verdict != ScanVerdict.DETECTED:
        # Nothing to bisect — record an inconclusive finding with the reason.
        return BisectOutcome(
            finding=BisectFinding(
                variant_name=variant.name,
                scanner_name=scanner.name,
                inconclusive=True,
                iterations=0,
                elapsed_seconds=time.monotonic() - started,
                notes=(
                    f"Full-file scan returned {sanity.verdict.value!r}; "
                    "nothing to bisect."
                ),
            ),
            sanity_result=sanity,
        )

    last_good = 0
    last_bad = n
    test_size = n // 2
    iteration = 0
    inconclusive = False
    inconclusive_note = ""

    while iteration < max_iterations:
        iteration += 1
        if test_size <= 0 or test_size > n:
            inconclusive = True
            inconclusive_note = f"test_size out of bounds: {test_size}"
            break

        prefix = data[:test_size]
        result = _scan_bytes(
            scanner=scanner,
            workspace=workspace,
            variant_name=variant.name,
            label=f"prefix_{test_size:08x}",
            data=prefix,
            timeout_s=scan_timeout_s,
        )
        if result.verdict == ScanVerdict.DETECTED or result.verdict == ScanVerdict.UPLOAD_BLOCKED:
            last_bad = test_size
        elif result.verdict == ScanVerdict.CLEAN:
            last_good = test_size
        else:
            inconclusive = True
            inconclusive_note = f"scanner returned {result.verdict.value!r} at size {test_size}"
            break

        gap = last_bad - last_good
        if gap <= 1:
            break

        # Aggregate-features heuristic: if we never found a clean prefix
        # and we're already very small, every prefix detects → ML/cloud.
        if last_good == 0 and test_size < max(64, n // 32):
            inconclusive = True
            inconclusive_note = (
                f"every prefix down to {test_size} bytes still detected — "
                "classic ML / cloud-reputation signal"
            )
            break

        test_size = (last_good + last_bad) // 2

    elapsed = time.monotonic() - started

    if inconclusive:
        return BisectOutcome(
            finding=BisectFinding(
                variant_name=variant.name,
                scanner_name=scanner.name,
                inconclusive=True,
                iterations=iteration,
                elapsed_seconds=elapsed,
                notes=inconclusive_note,
            ),
            sanity_result=sanity,
        )

    end_offset = last_bad
    return BisectOutcome(
        finding=BisectFinding(
            variant_name=variant.name,
            scanner_name=scanner.name,
            inconclusive=False,
            end_offset=end_offset,
            iterations=iteration,
            elapsed_seconds=elapsed,
            hex_window=_format_hex_window(data, end_offset),
        ),
        sanity_result=sanity,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _scan_bytes(
    *,
    scanner: Scanner,
    workspace: Workspace,
    variant_name: str,
    label: str,
    data: bytes,
    timeout_s: int,
) -> ScanResult:
    """Stash a byte slice in the variant directory and scan it.

    Each prefix gets its own file so the scanner_logs trail and the
    workspace artefact directory together reproduce the bisect step by
    step.  This is the property that makes a finished run replayable.
    """
    variant_dir = workspace.variant_dir_for(variant_name)
    artefact = variant_dir / f"{label}.bin"
    artefact.write_bytes(data)

    request = ScanRequest(
        variant_name=variant_name,
        artefact_path=artefact,
        timeout_seconds=timeout_s,
    )
    return scanner.scan(request)


def _format_hex_window(data: bytes, end_offset: int) -> str:
    start = max(0, end_offset - _HEX_WINDOW_BYTES)
    chunk = data[start:end_offset]
    lines: list[str] = [
        f"hex window [0x{start:x}, 0x{end_offset:x}) — {len(chunk)} bytes",
    ]
    for i in range(0, len(chunk), 16):
        row = chunk[i : i + 16]
        hex_str = " ".join(f"{x:02x}" for x in row)
        ascii_str = "".join(chr(x) if 32 <= x < 127 else "." for x in row)
        lines.append(f"{start + i:08x}  {hex_str:<48}  {ascii_str}")
    return "\n".join(lines)


__all__ = ["run_truncation_bisect", "BisectOutcome"]
