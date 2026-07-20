"""Backward-compatibility shim — re-exports from smb_byte_reader_service (aiosmb).

All production code should import from
``adscan_internal.services.smb_byte_reader_service`` directly.
This file exists only so that legacy import paths in tests and callers
that still reference the old module name keep working.
"""

from adscan_internal.services.smb_byte_reader_service import (  # noqa: F401
    SMBByteReadResult,
    SMBByteReaderService,
    SMBByteReaderService as ImpacketSMBByteReaderService,
)

__all__ = [
    "SMBByteReadResult",
    "SMBByteReaderService",
    "ImpacketSMBByteReaderService",
]
