"""Matrix run report generators (JSON + Markdown).

Two outputs from one :class:`MatrixRun`:

* ``matrix.json`` — canonical, machine-readable, append-only history.
  Versioned schema (``schema_version``) so future readers can adapt.
* ``matrix.md``   — human-readable digest with a verdict line, the
  pass/fail table per variant, the toggle differential, and the
  hex window when bisect found a concrete byte signature.

The Markdown template is intentionally narrow (≤ 100 cols where
practical) so it renders cleanly in GitHub PR diffs.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Iterable

from .models import (
    BisectFinding,
    MatrixRun,
    ScanResult,
    ScanVerdict,
    Variant,
)
from .workspace import Workspace

SCHEMA_VERSION = "1"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def write_matrix_report(workspace: Workspace, run: MatrixRun) -> None:
    """Persist the JSON record + render the Markdown digest."""
    workspace.write_matrix_json(_to_json_payload(run))
    workspace.write_matrix_md(_render_markdown(run))


# ---------------------------------------------------------------------------
# JSON projection — independent of dataclass shape so the schema is stable
# ---------------------------------------------------------------------------


def _to_json_payload(run: MatrixRun) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run.run_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "catalog_name": run.catalog_name,
        "scanner_name": run.scanner_name,
        "method": run.method,
        "notes": run.notes,
        "extra": run.extra,
        "variants": [
            {
                "name": v.name,
                "payload_name": v.payload_name,
                "artefact_path": str(v.artefact_path),
                "artefact_hash": v.artefact_hash,
                "artefact_size": v.artefact_size,
                "build_seconds": v.build_seconds,
                "toggles": asdict(v.toggles),
                "toggle_slug": v.toggles.slug,
                "notes": v.notes,
            }
            for v in run.variants
        ],
        "results": [asdict(r) for r in run.results],
        "bisect_findings": [asdict(f) for f in run.bisect_findings],
        "summary": _summary_block(run.results),
    }


def _summary_block(results: Iterable[ScanResult]) -> dict:
    by_verdict: dict[str, int] = {}
    for r in results:
        by_verdict[r.verdict.value] = by_verdict.get(r.verdict.value, 0) + 1
    total = sum(by_verdict.values())
    clean = by_verdict.get(ScanVerdict.CLEAN.value, 0)
    return {
        "total": total,
        "clean": clean,
        "detected": by_verdict.get(ScanVerdict.DETECTED.value, 0),
        "inconclusive": by_verdict.get(ScanVerdict.INCONCLUSIVE.value, 0),
        "upload_blocked": by_verdict.get(ScanVerdict.UPLOAD_BLOCKED.value, 0),
        "pass_rate": (clean / total) if total else 0.0,
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _render_markdown(run: MatrixRun) -> str:
    summary = _summary_block(run.results)
    pass_pct = f"{summary['pass_rate'] * 100:.0f}%"

    lines: list[str] = []
    lines.append(f"# AV/EDR Matrix Run — `{run.run_id}`")
    lines.append("")
    lines.append(f"- Catalog: `{run.catalog_name}`")
    lines.append(f"- Scanner: `{run.scanner_name}`")
    lines.append(f"- Method:  `{run.method}`")
    lines.append(f"- Started: {run.started_at.isoformat()}")
    lines.append(f"- Finished: {run.finished_at.isoformat()}")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append(
        f"**{summary['clean']}/{summary['total']} variants clean ({pass_pct})** · "
        f"detected={summary['detected']} · "
        f"inconclusive={summary['inconclusive']} · "
        f"upload_blocked={summary['upload_blocked']}"
    )
    lines.append("")
    lines.append("## Per-variant results")
    lines.append("")
    lines.append("| Variant | Toggle slug | Hash (12) | Size | Verdict | Threats | ms |")
    lines.append("|---|---|---|---:|---|---|---:|")

    by_name = {v.name: v for v in run.variants}
    for r in run.results:
        v = by_name.get(r.variant_name)
        slug = v.toggles.slug if v else "—"
        hsh = v.artefact_hash[:12] if v else "—"
        size = f"{v.artefact_size}" if v else "—"
        threats = ", ".join(r.threat_names) if r.threat_names else "—"
        ms = int(r.duration_seconds * 1000)
        verdict_cell = _verdict_cell(r.verdict)
        lines.append(
            f"| `{r.variant_name}` | `{slug}` | `{hsh}` | {size} | "
            f"{verdict_cell} | {threats} | {ms} |"
        )

    if run.bisect_findings:
        lines.append("")
        lines.append("## Bisect findings")
        lines.append("")
        for f in run.bisect_findings:
            lines.append(_render_bisect(f))
            lines.append("")

    if run.notes:
        lines.append("")
        lines.append("## Notes")
        lines.append("")
        lines.append(run.notes)

    return "\n".join(lines).rstrip() + "\n"


def _verdict_cell(verdict: ScanVerdict) -> str:
    if verdict == ScanVerdict.CLEAN:
        return "✅ clean"
    if verdict == ScanVerdict.DETECTED:
        return "❌ detected"
    if verdict == ScanVerdict.UPLOAD_BLOCKED:
        return "🚫 upload-blocked"
    return "⚠️ inconclusive"


def _render_bisect(finding: BisectFinding) -> str:
    lines = [
        f"### `{finding.variant_name}` × `{finding.scanner_name}`",
        "",
        f"- iterations: {finding.iterations}",
        f"- elapsed:    {finding.elapsed_seconds:.1f}s",
        f"- detection:  `{finding.detection_kind.value}`",
    ]
    if finding.inconclusive:
        lines.append("- result:     **inconclusive** — every prefix kept detecting.")
        lines.append("")
        lines.append(
            "  This is the canonical signal that detection is on aggregate "
            "binary features (ML, cloud reputation, behavioural). "
            "Switch to a toggle-ablation method."
        )
    else:
        lines.append(f"- end offset: `0x{finding.end_offset:x}` ({finding.end_offset})")
        if finding.hex_window:
            lines.append("")
            lines.append("```")
            lines.append(finding.hex_window.rstrip())
            lines.append("```")
    if finding.notes:
        lines.append("")
        lines.append(finding.notes)
    return "\n".join(lines)


__all__ = ["write_matrix_report", "SCHEMA_VERSION"]
