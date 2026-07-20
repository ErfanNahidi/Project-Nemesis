"""Toggle-ablation method — find the layer combination that bypasses.

When a static-byte bisect comes back inconclusive (every prefix still
detects), the detection is not on a contiguous byte signature — it is
on aggregate features of the whole binary (ML, cloud reputation,
behavioural).  Bisecting bytes is hopeless against that.

The right move is to change the *features*: rebuild the loader with one
or more OPSEC layers omitted, scan each variant, and look at which
combinations of toggles flip the verdict.  That tells the operator
which layer (or combination) is feeding the model the smell test
without locking onto a specific sequence.

This module is the orchestrator for that study:

* It takes a pre-built catalog of :class:`Variant` artefacts (built by
  the loader builder against a ``ToggleSpec`` matrix — declared in YAML
  under ``avlab/catalogs/``).
* It scans each variant once with the chosen scanner.
* It emits a :class:`ToggleAblation` row set + the canonical
  :class:`MatrixRun` so reporting is unified with bisect runs.

The orchestrator deliberately does **not** rebuild loaders — keeping
build vs scan separate makes the runs cacheable, parallelisable, and
re-scannable months later against new signature definitions.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Iterable

from avlab.core.models import (
    MatrixRun,
    ScanResult,
    ScanVerdict,
    ToggleAblation,
    Variant,
)
from avlab.core.workspace import Workspace
from avlab.scanners.base import ScanRequest, Scanner


def run_toggle_ablation(
    *,
    scanner: Scanner,
    variants: Iterable[Variant],
    workspace: Workspace,
    catalog_name: str,
    run_id: str,
    scan_timeout_s: int = 60,
    notes: str = "",
) -> MatrixRun:
    """Scan every variant in the catalog and bundle the results.

    The scanner's ``setup`` / ``teardown`` are driven here so the AV
    exclusion is added once per run, not once per variant.  Even if a
    single scan errors, ``teardown`` still runs.
    """
    started_at = datetime.now(timezone.utc)
    variants_tuple = tuple(variants)
    if not variants_tuple:
        raise ValueError("toggle ablation needs at least one variant")

    results: list[ScanResult] = []
    scanner.setup()
    try:
        for variant in variants_tuple:
            stashed = workspace.stash_artefact(
                variant.name, variant.artefact_path
            )
            request = ScanRequest(
                variant_name=variant.name,
                artefact_path=stashed,
                timeout_seconds=scan_timeout_s,
            )
            t0 = time.monotonic()
            try:
                result = scanner.scan(request)
            except Exception as exc:  # noqa: BLE001 — record and keep going
                result = ScanResult(
                    variant_name=variant.name,
                    scanner_name=scanner.name,
                    verdict=ScanVerdict.INCONCLUSIVE,
                    duration_seconds=time.monotonic() - t0,
                    error_message=f"scanner raised: {exc!r}",
                )
            results.append(result)
    finally:
        scanner.teardown()

    finished_at = datetime.now(timezone.utc)
    return MatrixRun(
        run_id=run_id,
        started_at=started_at,
        finished_at=finished_at,
        catalog_name=catalog_name,
        scanner_name=scanner.name,
        method="toggle_ablation",
        variants=variants_tuple,
        results=tuple(results),
        notes=notes,
    )


def build_ablation_summary(run: MatrixRun) -> ToggleAblation:
    """Convenience projection — the typed row bundle for downstream diffs."""
    elapsed = (run.finished_at - run.started_at).total_seconds()
    return ToggleAblation(
        matrix_run_id=run.run_id,
        catalog_name=run.catalog_name,
        scanner_name=run.scanner_name,
        rows=run.results,
        elapsed_seconds=elapsed,
    )


__all__ = ["run_toggle_ablation", "build_ablation_summary"]
