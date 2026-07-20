"""Persistent disk queue for telemetry session uploads.

This module is the crash-recovery + size-overflow safety net for the
session telemetry pipeline. When ``_send_session_to_vercel`` cannot
deliver a session — because the network is down, the proxy times out,
the host is killed mid-flight, or the payload exceeds the server's
hard body limit — the payload is written to a local queue under
``~/.adscan/telemetry-queue/`` and retried on the next CLI invocation.

The queue is intentionally minimal:

* One file per pending session, atomic rename on write, gzip-compressed
  JSON body so a long session sits in a few KB on disk.
* Filename is sortable by enqueue time so the drain is FIFO.
* TTL cleanup deletes anything older than ``MAX_AGE_DAYS`` — sessions
  that were never deliverable shouldn't grow the queue unbounded.
* A drain budget caps how many sessions are flushed per invocation so
  a backlog doesn't dominate a fresh CLI launch.
* All disk I/O is best-effort: any OSError is swallowed and surfaces
  only as a debug log. The queue must never break the foreground CLI.

The drain itself runs on a daemon background thread so the next CLI
startup is not blocked by a stale upload. Telemetry is best-effort by
design — if the user kills the next CLI before the drain finishes,
the remaining files are picked up by the invocation after that.
"""

from __future__ import annotations

import gzip
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

# Capacity ceilings — chosen so the on-disk queue stays small enough to
# audit by hand if it ever grows, and so a long-running backlog from a
# disconnected machine cannot DoS the next CLI start.
MAX_AGE_DAYS: int = 7
MAX_QUEUE_FILES: int = 50
MAX_DRAIN_PER_RUN: int = 10

# File-name convention: <epoch_ms>-<short_trace>.json.gz. Sortable, easy
# to debug, low collision risk for parallel CLI invocations on the same
# user account (extremely rare for ADscan).
_FILENAME_SUFFIX: str = ".json.gz"


def _resolve_queue_dir() -> Path:
    """Return the queue directory path, respecting ``ADSCAN_HOME``."""
    base = os.getenv("ADSCAN_HOME") or str(Path.home() / ".adscan")
    return Path(base) / "telemetry-queue"


def _safe_trace_slug(trace_id: Optional[str]) -> str:
    """Return a filesystem-safe short slug for ``trace_id``.

    Trace IDs come from upstream as hex strings (``uuid4().hex``) but we
    defensively clip and strip non-hex characters so a stray value cannot
    smuggle path separators or shell metacharacters into the filename.
    """
    if not trace_id:
        return "unknown"
    safe = "".join(ch for ch in str(trace_id) if ch.isalnum())
    return safe[:12] if safe else "unknown"


def enqueue_session(payload: dict[str, Any]) -> Optional[Path]:
    """Persist ``payload`` to the disk queue for later retry.

    Atomic write: encode → gzip → write to ``<name>.tmp`` → rename to
    ``<name>``. If the rename fails the temp file is best-effort deleted
    so a partial write cannot be mistaken for a complete session.
    Returns the final file path on success, ``None`` on any error.

    The payload is the same dict that ``_send_session_to_vercel`` would
    have POSTed; replaying it later is a single ``requests.post`` with
    the original body.
    """
    queue_dir = _resolve_queue_dir()
    try:
        queue_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None

    epoch_ms = int(time.time() * 1000)
    slug = _safe_trace_slug(
        payload.get("session_trace_id") or payload.get("trace_id") or payload.get("session_id")
    )
    final_name = f"{epoch_ms:013d}-{slug}{_FILENAME_SUFFIX}"
    tmp_path = queue_dir / f"{final_name}.tmp"
    final_path = queue_dir / final_name

    try:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        compressed = gzip.compress(body)
        tmp_path.write_bytes(compressed)
        # Rename is atomic on POSIX; if the user is on Windows and
        # something else opened the temp file we accept the failure.
        os.replace(tmp_path, final_path)
    except OSError:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        return None

    _enforce_queue_cap(queue_dir)
    return final_path


def _enforce_queue_cap(queue_dir: Path) -> None:
    """Delete the oldest queue entries when the queue exceeds the cap.

    Triggered after every enqueue so the queue never grows beyond
    ``MAX_QUEUE_FILES``. Selecting the *oldest* (FIFO) means an offline
    user accumulates the most recent sessions, not the earliest — for
    a debugging workflow that is the right trade-off (a session from
    yesterday is more useful than one from a month ago).
    """
    try:
        entries = sorted(queue_dir.glob(f"*{_FILENAME_SUFFIX}"))
    except OSError:
        return
    excess = len(entries) - MAX_QUEUE_FILES
    if excess <= 0:
        return
    for stale in entries[:excess]:
        try:
            stale.unlink(missing_ok=True)
        except OSError:
            pass


def _prune_expired(queue_dir: Path) -> None:
    """Delete queue entries older than ``MAX_AGE_DAYS``."""
    cutoff = time.time() - (MAX_AGE_DAYS * 86400)
    try:
        entries = list(queue_dir.glob(f"*{_FILENAME_SUFFIX}"))
    except OSError:
        return
    for entry in entries:
        try:
            if entry.stat().st_mtime < cutoff:
                entry.unlink(missing_ok=True)
        except OSError:
            continue


def drain_queue(
    upload_fn: Callable[[dict[str, Any]], bool],
    *,
    queue_dir: Optional[Path] = None,
    max_to_send: int = MAX_DRAIN_PER_RUN,
) -> tuple[int, int]:
    """Replay queued sessions through ``upload_fn``.

    Args:
        upload_fn: Callable that takes the original payload dict and
            returns True on successful upload, False otherwise. The
            callable is responsible for any encoding (gzip on the wire,
            headers, retries) — this module only handles the disk side.
        queue_dir: Override directory; defaults to ``~/.adscan/telemetry-queue/``.
        max_to_send: Hard cap on uploads per drain. Prevents a backlog
            from blocking the user even if invoked synchronously.

    Returns:
        ``(sent, remaining)``. ``sent`` is how many uploads succeeded;
        ``remaining`` is how many entries are still in the queue after
        the drain (after TTL prune + this run's work).
    """
    target_dir = queue_dir or _resolve_queue_dir()
    if not target_dir.is_dir():
        return (0, 0)

    _prune_expired(target_dir)

    try:
        entries = sorted(target_dir.glob(f"*{_FILENAME_SUFFIX}"))
    except OSError:
        return (0, 0)

    sent = 0
    for entry in entries[:max_to_send]:
        try:
            with gzip.open(entry, "rt", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, ValueError):
            # Corrupt entry — discard so it does not block subsequent
            # drains. The original session is lost; the queue is best-
            # effort by design.
            try:
                entry.unlink(missing_ok=True)
            except OSError:
                pass
            continue

        try:
            ok = bool(upload_fn(payload))
        except Exception:  # noqa: BLE001
            ok = False

        if ok:
            try:
                entry.unlink(missing_ok=True)
            except OSError:
                pass
            sent += 1
        # Failed uploads stay on disk to be retried next time.

    try:
        remaining = len(list(target_dir.glob(f"*{_FILENAME_SUFFIX}")))
    except OSError:
        remaining = 0
    return (sent, remaining)


def start_background_drain(
    upload_fn: Callable[[dict[str, Any]], bool],
    *,
    delay_seconds: float = 5.0,
    queue_dir: Optional[Path] = None,
    max_to_send: int = MAX_DRAIN_PER_RUN,
) -> Optional[threading.Thread]:
    """Run ``drain_queue`` on a daemon background thread.

    The thread is daemonic so the CLI never waits for it on exit — if
    the user closes the terminal mid-drain, partially-uploaded entries
    stay in the queue and the next invocation finishes the job.

    A short ``delay_seconds`` (default 5s) defers the drain until after
    the foreground command has rendered its welcome panel, so the
    network noise of replaying old sessions does not delay the first
    user-visible output.

    Returns the thread object (mostly for tests). Returns ``None`` if
    the queue directory does not exist yet — there is nothing to drain.
    """
    target_dir = queue_dir or _resolve_queue_dir()
    if not target_dir.is_dir():
        return None

    def _runner() -> None:
        try:
            if delay_seconds > 0:
                time.sleep(delay_seconds)
            drain_queue(upload_fn, queue_dir=target_dir, max_to_send=max_to_send)
        except Exception:  # noqa: BLE001
            # Daemon thread errors must never escape — telemetry is
            # best-effort and silent on failure.
            return

    thread = threading.Thread(
        target=_runner,
        name="adscan-telemetry-drain",
        daemon=True,
    )
    thread.start()
    return thread


def queue_status() -> dict[str, Any]:
    """Return a quick status snapshot of the queue (for debug log)."""
    target_dir = _resolve_queue_dir()
    if not target_dir.is_dir():
        return {"present": False, "count": 0, "total_bytes": 0}
    try:
        entries = list(target_dir.glob(f"*{_FILENAME_SUFFIX}"))
    except OSError:
        return {"present": True, "count": 0, "total_bytes": 0}
    total_bytes = 0
    oldest_iso: Optional[str] = None
    oldest_mtime: Optional[float] = None
    for entry in entries:
        try:
            stat = entry.stat()
        except OSError:
            continue
        total_bytes += int(stat.st_size)
        if oldest_mtime is None or stat.st_mtime < oldest_mtime:
            oldest_mtime = stat.st_mtime
            oldest_iso = datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat()
    return {
        "present": True,
        "count": len(entries),
        "total_bytes": total_bytes,
        "oldest_iso": oldest_iso,
        "queue_dir": str(target_dir),
    }


__all__ = (
    "MAX_AGE_DAYS",
    "MAX_QUEUE_FILES",
    "MAX_DRAIN_PER_RUN",
    "drain_queue",
    "enqueue_session",
    "queue_status",
    "start_background_drain",
)
