"""Asciinema v2 .cast file player for ``adscan demo``.

Preferred path: delegates to the ``asciinema play`` CLI (installed in the
Docker image) for maximum terminal fidelity — correct dimensions, raw TTY
mode, and upstream timing handling.

Fallback path: pure-stdlib player (json + sys + time) used when the
``asciinema`` binary is not available (e.g. dev machine without Docker).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence


def _asciinema_bin() -> str | None:
    """Return the path to the ``asciinema`` binary, or None if absent."""
    return shutil.which("asciinema")


def _play_native(cast_path: Path, *, fast_factor: float = 1.0) -> None:
    """Replay via ``asciinema play`` — best quality, handles terminal dims."""
    speed = round(1.0 / fast_factor, 2) if fast_factor > 0 else 1.0
    subprocess.run(
        ["asciinema", "play", "--speed", str(speed), str(cast_path)],
        check=False,  # don't raise on Ctrl+C / non-zero exit
    )


def _play_fallback(
    cast_path: Path,
    *,
    fast_factor: float = 1.0,
    idle_time_limit: float = 3.0,
) -> None:
    """Pure-stdlib fallback player — no asciinema binary required."""
    lines = cast_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return

    try:
        header = json.loads(lines[0])
        if header.get("version") != 2:
            raise ValueError(
                f"Unsupported asciinema version: {header.get('version')!r}. "
                "Only v2 is supported."
            )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"Invalid .cast header in {cast_path}: {exc}") from exc

    # Warn if terminal is narrower than the recording.
    rec_width: int = int(header.get("width", 80))
    term_cols, _ = shutil.get_terminal_size(fallback=(80, 24))
    if term_cols < rec_width - 10:
        sys.stdout.write(
            f"\033[33m  ⚠  Terminal is {term_cols} cols wide; "
            f"recording was {rec_width} cols. "
            "Resize for best experience.\033[0m\n\n"
        )
        sys.stdout.flush()

    prev_t: float = 0.0
    try:
        for raw_line in lines[1:]:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            if not (isinstance(event, list) and len(event) >= 3):
                continue

            t: float = float(event[0])
            event_type: str = str(event[1])
            data: str = str(event[2])

            if event_type != "o":
                prev_t = t
                continue

            delta = t - prev_t
            prev_t = t

            if fast_factor > 0 and delta > 0:
                sleep_duration = min(delta, idle_time_limit) * fast_factor
                if sleep_duration > 0:
                    time.sleep(sleep_duration)

            sys.stdout.write(data)
            sys.stdout.flush()

    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()


def play_cast(
    cast_path: Path,
    *,
    fast_factor: float = 1.0,
    idle_time_limit: float = 3.0,
) -> None:
    """Replay an asciinema v2 .cast file.

    Uses the ``asciinema play`` CLI when available (preferred — handles
    terminal dimensions and raw TTY correctly). Falls back to the stdlib
    player otherwise.

    Args:
        cast_path: Path to the .cast file.
        fast_factor: Timing compression. 1.0 = real-time, 0.18 = fast.
        idle_time_limit: Cap on inter-event pauses (fallback player only).
    """
    if _asciinema_bin():
        _play_native(cast_path, fast_factor=fast_factor)
    else:
        _play_fallback(cast_path, fast_factor=fast_factor, idle_time_limit=idle_time_limit)


__all__: Sequence[str] = ("play_cast",)
