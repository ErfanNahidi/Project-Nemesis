"""Detection backends for the AV/EDR validation lab."""

from avlab.scanners.base import ScanRequest, Scanner
from avlab.scanners.registry import create, known_scanners, register

__all__ = ["Scanner", "ScanRequest", "create", "register", "known_scanners"]
