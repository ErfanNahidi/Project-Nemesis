"""Timeroasting configuration and result dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TimeroastConfig:
    """Parameters for one native timeroasting run.

    dc_ip:       DC to query (NTP server, UDP/123).
    rids:        Sequence of RIDs to probe. Derived from candidate machine accounts.
    rate:        NTP packets per second (default 180 — matches netexec timeroast default).
    timeout:     Seconds to wait for lagging responses after the last RID is sent.
    old_password: Request hash using the previous password (key flag 2^31).
    """
    dc_ip: str
    rids: tuple[int, ...]
    rate: int = 180
    timeout: float = 24.0
    old_password: bool = False


@dataclass(frozen=True)
class TimeroastHashResult:
    """A single captured Timeroast hash for one RID."""
    rid: int
    hash_hex: str   # HMAC-MD5 digest (16 bytes → 32 hex chars)
    salt_hex: str   # First 48 bytes of NTP response (used as "salt")

    @property
    def hashcat_line(self) -> str:
        """Format: RID:$sntp-ms$<hash>$<salt>  (hashcat mode 31300, --username)."""
        return f"{self.rid}:$sntp-ms${self.hash_hex}${self.salt_hex}"


@dataclass
class TimeroastRunResult:
    """Aggregate result of a timeroasting run."""
    hashes: list[TimeroastHashResult] = field(default_factory=list)
    rids_attempted: int = 0
    rids_responded: int = 0
    error: str | None = None

    @property
    def success(self) -> bool:
        return bool(self.hashes) and self.error is None

    @property
    def captured_count(self) -> int:
        return len(self.hashes)
