"""Per-run workspace handling.

Every avlab run gets a deterministic directory:

    tools/avlab/runs/<run_id>/
    ├── matrix.json
    ├── matrix.md
    ├── variants/
    │   └── <variant_name>/
    │       └── <artefact_name>.exe
    └── scanner_logs/
        └── <variant_name>__<scanner>.log

Runs are append-only.  Nothing in this module ever overwrites a finished
run; that's the contract that makes month-over-month signature drift
analysis sound.

Read-only consumers (CI dashboards, drift detectors, reports) should
treat ``runs/`` as immutable history.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


_AVLAB_ROOT = Path(__file__).resolve().parents[1]
_RUNS_ROOT = _AVLAB_ROOT / "runs"


def _json_default(obj: Any) -> Any:
    """JSON encoder for the few non-primitive types used in records."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    raise TypeError(f"unhandled type for JSON: {type(obj).__name__}")


class Workspace:
    """File-layout helper for one validation run.

    Construct a workspace with :meth:`create_for` (new run) or
    :meth:`open_existing` (replay/inspection).
    """

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.variants_dir = run_dir / "variants"
        self.logs_dir = run_dir / "scanner_logs"
        self.matrix_json = run_dir / "matrix.json"
        self.matrix_md = run_dir / "matrix.md"

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def create_for(cls, run_id: str) -> "Workspace":
        """Create the directory tree for a new run."""
        run_dir = _RUNS_ROOT / run_id
        if run_dir.exists():
            raise FileExistsError(f"run_id {run_id!r} already exists")
        run_dir.mkdir(parents=True)
        ws = cls(run_dir)
        ws.variants_dir.mkdir()
        ws.logs_dir.mkdir()
        return ws

    @classmethod
    def open_existing(cls, run_id: str) -> "Workspace":
        """Open a prior run for read-only access (replay, reporting)."""
        run_dir = _RUNS_ROOT / run_id
        if not run_dir.is_dir():
            raise FileNotFoundError(run_dir)
        return cls(run_dir)

    @classmethod
    def runs_root(cls) -> Path:
        return _RUNS_ROOT

    # ------------------------------------------------------------------
    # Variant artefact management
    # ------------------------------------------------------------------

    def variant_dir_for(self, variant_name: str) -> Path:
        d = self.variants_dir / _safe_slug(variant_name)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def stash_artefact(self, variant_name: str, source: Path) -> Path:
        """Copy an artefact into the run dir and return the new path."""
        dst = self.variant_dir_for(variant_name) / source.name
        dst.write_bytes(source.read_bytes())
        return dst

    # ------------------------------------------------------------------
    # Scanner logs
    # ------------------------------------------------------------------

    def scanner_log_for(self, variant_name: str, scanner_name: str) -> Path:
        return self.logs_dir / f"{_safe_slug(variant_name)}__{_safe_slug(scanner_name)}.log"

    def append_scanner_log(self, variant_name: str, scanner_name: str, text: str) -> None:
        path = self.scanner_log_for(variant_name, scanner_name)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")

    # ------------------------------------------------------------------
    # Matrix output
    # ------------------------------------------------------------------

    def write_matrix_json(self, payload: Any) -> None:
        text = json.dumps(payload, indent=2, default=_json_default, sort_keys=True)
        self.matrix_json.write_text(text + "\n", encoding="utf-8")

    def write_matrix_md(self, body: str) -> None:
        self.matrix_md.write_text(body, encoding="utf-8")


def _safe_slug(name: str) -> str:
    """Normalise a name for filesystem use without losing readability."""
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)


__all__ = ["Workspace"]
