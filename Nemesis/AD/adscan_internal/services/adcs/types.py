"""Shared ADCS data types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ADCSVulnerability:
    """Represents an ADCS vulnerability finding."""

    esc_number: str
    source: str  # "ca" or "template"
    template: Optional[str] = None
