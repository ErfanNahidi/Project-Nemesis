"""Analysis methods — strategies for turning scans into findings."""

from avlab.methods.toggle_ablation import (
    build_ablation_summary,
    run_toggle_ablation,
)
from avlab.methods.truncation_bisect import BisectOutcome, run_truncation_bisect

__all__ = [
    "BisectOutcome",
    "build_ablation_summary",
    "run_toggle_ablation",
    "run_truncation_bisect",
]
