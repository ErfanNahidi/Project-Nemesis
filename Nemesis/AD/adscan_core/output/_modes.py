"""Output mode + structured JSON sink.

Three modes (`docs/cli_style.md` §2):

* ``human`` — Rich panels/tables/progress to the operator's terminal.
* ``json``  — Rich rendering suppressed; one JSON envelope per operation
              emitted to stdout (NDJSON-compatible across operations).
* ``quiet`` — Rich rendering and JSON suppressed except the final envelope
              of the top-level operation; non-zero exit code on error.

The mode is process-global, set once from the CLI entry point via
:func:`set_output_mode`. Every premium primitive that produces operator-visible
result data accepts an optional ``json_payload: dict`` and routes it through
:func:`emit_json` when the mode is not human; this keeps the JSON contract
co-located with the human render at every call site.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class OutputMode(str, Enum):
    """Operator-visible output mode. Set once at CLI entry."""

    HUMAN = "human"
    JSON = "json"
    QUIET = "quiet"

    @classmethod
    def parse(cls, raw: str) -> "OutputMode":
        normalized = (raw or "").strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(
            f"Invalid output mode {raw!r}. Expected one of: "
            f"{', '.join(m.value for m in cls)}"
        )


_OUTPUT_MODE: OutputMode = OutputMode.HUMAN
_ENV_VAR = "ADSCAN_OUTPUT_MODE"


def _bootstrap_from_env() -> None:
    """Initialize the mode from ``ADSCAN_OUTPUT_MODE`` if set.

    Allows non-CLI entry points (subprocesses, container reentry, tests) to
    inherit the mode without having to thread the flag through every layer.
    Silent on invalid values — falls back to HUMAN — because the CLI entry
    point is the canonical setter and validates its own flag.
    """
    global _OUTPUT_MODE
    raw = os.environ.get(_ENV_VAR)
    if not raw:
        return
    try:
        _OUTPUT_MODE = OutputMode.parse(raw)
    except ValueError:
        _OUTPUT_MODE = OutputMode.HUMAN


_bootstrap_from_env()


def set_output_mode(mode: OutputMode | str) -> None:
    """Set the global output mode. Idempotent; safe to re-call."""
    global _OUTPUT_MODE
    _OUTPUT_MODE = mode if isinstance(mode, OutputMode) else OutputMode.parse(mode)
    os.environ[_ENV_VAR] = _OUTPUT_MODE.value


def get_output_mode() -> OutputMode:
    return _OUTPUT_MODE


def is_human() -> bool:
    return _OUTPUT_MODE == OutputMode.HUMAN


def is_json() -> bool:
    return _OUTPUT_MODE == OutputMode.JSON


def is_quiet() -> bool:
    return _OUTPUT_MODE == OutputMode.QUIET


def suppress_rich() -> bool:
    """True when Rich/console output must be suppressed (json or quiet)."""
    return _OUTPUT_MODE != OutputMode.HUMAN


# ---------------------------------------------------------------------------
# JSON sink
# ---------------------------------------------------------------------------


_JSON_ENVELOPE_VERSION = 1


def build_envelope(
    *,
    operation: str,
    target: Optional[Dict[str, Any]] = None,
    posture: Optional[Dict[str, Any]] = None,
    status: str = "ok",
    started_at: Optional[datetime] = None,
    duration_ms: Optional[int] = None,
    findings: Optional[Any] = None,
    saved_to: Optional[List[str]] = None,
    next_command: Optional[str] = None,
    error: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a JSON envelope per ``docs/cli_style.md`` §2.

    Schema is intentionally narrow — adding fields requires bumping the
    version constant so consumers (adscan_web, agents) can detect changes.

    ``extra`` is a free-form dict for operation-specific metadata that does
    not fit the canonical fields; consumers must treat unknown keys as
    advisory.
    """
    if started_at is None:
        started_at = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "operation": operation,
        "version": _JSON_ENVELOPE_VERSION,
        "target": target or {},
        "posture": posture or {},
        "status": status,
        "started_at": started_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "duration_ms": duration_ms,
        "findings": findings if findings is not None else [],
        "saved_to": saved_to or [],
        "next": next_command,
        "error": error,
    }
    if extra:
        payload["extra"] = extra
    return payload


def emit_json(payload: Dict[str, Any]) -> None:
    """Emit a JSON envelope to stdout when the mode is not human.

    The payload is written as a single line (NDJSON-compatible) so multiple
    operations chained in one process stream cleanly. In human mode this is
    a no-op — Rich primitives carry the user-facing render instead.
    """
    if is_human():
        return
    line = json.dumps(payload, separators=(",", ":"), default=_json_default, sort_keys=False)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return {k: v for k, v in vars(value).items() if not k.startswith("_")}
    return str(value)


__all__ = [
    "OutputMode",
    "set_output_mode",
    "get_output_mode",
    "is_human",
    "is_json",
    "is_quiet",
    "suppress_rich",
    "build_envelope",
    "emit_json",
]
