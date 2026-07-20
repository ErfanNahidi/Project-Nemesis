"""Extension helpers for PAC buffer types not present in kerbad.protocol.external.pac.

MS-PAC types 17 (PAC_ATTRIBUTES_INFO) and 18 (PAC_REQUESTOR_INFO) were added in
Windows Server 2012+ PAC hardening.  They are not in kerbad's pac.py (which mirrors
an older impacket baseline), so we implement them here as simple byte-pack helpers
rather than full NDRSTRUCT subclasses.

Import these constants and helpers wherever PAC forging needs modern buffer support.
"""

from __future__ import annotations

import struct

# PAC buffer type constants missing from kerbad.protocol.external.pac
PAC_ATTRIBUTES_INFO = 17
PAC_REQUESTOR_INFO = 18


def make_pac_attributes_info_bytes() -> bytes:
    """Build a PAC_ATTRIBUTES_INFO buffer (type 17).

    Structure: FlagsLength (ULONG, 4 bytes) + Flags (ULONG, 4 bytes).
    FlagsLength = 2 means "2 bits defined".
    Flags bit 0 = PAC_WAS_REQUESTED.
    """
    return struct.pack("<II", 2, 1)


def make_pac_requestor_info_bytes(sid_str: str) -> bytes:
    """Build a PAC_REQUESTOR_INFO buffer (type 18) for the given domain SID.

    The buffer is a raw Windows SID (binary, no NDR conformant count):
        Revision       1 byte
        SubAuthCount   1 byte
        Authority      6 bytes (big-endian, high byte = authority)
        SubAuth[0..n]  4 bytes each (little-endian)

    Args:
        sid_str: Canonical SID string, e.g. ``S-1-5-21-111-222-333-500``.
    """
    parts = sid_str.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    sub_auths = [int(x) for x in parts[3:]]
    count = len(sub_auths)
    data = struct.pack("BB", revision, count)
    data += b"\x00\x00\x00\x00\x00" + struct.pack("B", authority)
    data += struct.pack(f"<{count}I", *sub_auths)
    return data


__all__ = [
    "PAC_ATTRIBUTES_INFO",
    "PAC_REQUESTOR_INFO",
    "make_pac_attributes_info_bytes",
    "make_pac_requestor_info_bytes",
]
