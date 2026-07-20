"""Core types + persistence for the AV/EDR validation lab."""

from .models import (
    BisectFinding,
    DetectionKind,
    MatrixRun,
    ScanResult,
    ScanVerdict,
    ToggleAblation,
    ToggleSpec,
    Variant,
)
from .reporting import write_matrix_report
from .workspace import Workspace

__all__ = [
    "BisectFinding",
    "DetectionKind",
    "MatrixRun",
    "ScanResult",
    "ScanVerdict",
    "ToggleAblation",
    "ToggleSpec",
    "Variant",
    "Workspace",
    "write_matrix_report",
]
