"""Embedded telemetry endpoints/tokens with lightweight obfuscation.

This module intentionally avoids reading telemetry endpoint/token values from
`.env` files so public distributions do not carry an obvious plaintext config
file. Values are still recoverable by reverse engineering and must be treated
as public ingest credentials on the backend.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
from typing import Any


_EMBEDDED_BLOB = (
    "sJzkv3DTL0tO-Tl9RLcqxWn_q9y1oVuTdoWa5s9yihWv2vX_epciG0yuPioWvSaXaK3xibCi"
    "XsEkhMjiynLfRqqG8qsrwzUFWOw3LwK_MMkvv-LMvehFy3_T17CdYN1Fpc7i8mSSeERV6zop"
    "SOp9ynS7_czzrwXCatmcp9s_nFSjzrKnaJljXQrvZWQP6yrPdar2zOSmBNU10teyln6RU67c"
    "-PIlmjhZFe8rI0_iP9EppPadq-UazWWH2_PVMc0G8Zz46T6BZBNVszFzTqtzxSio89H3tQWL"
    "JNKU_o523Eyk0fuyOZR5XQjlfWcC8zCbeaPmy_e0UIpo08G_13LaV6jf_u04njlKFfFwPEXn"
    "es40oL3J4rUJwCuQirSKYNdLpc2ysWidNRNY9Cs_UPYojnSlqtGppg7WJNyXoYt8kEek07_q"
    "L5N_RhX3cCpE9nHANZT-3uW0SIlly53zwzHWUL_O46dl3mRMCe82JE72PMA_uPHe6bcYymne"
    "lrzWcs5N5M317jmYeEcJviI="
)
_BLOB_KEY = hashlib.sha256(b"ADscan::telemetry::embedded::v1").digest()


@functools.lru_cache(maxsize=1)
def _payload() -> dict[str, Any]:
    """Return decoded telemetry payload (best-effort)."""
    try:
        raw = base64.urlsafe_b64decode(_EMBEDDED_BLOB.encode("ascii"))
        plain = bytes([byte ^ _BLOB_KEY[idx % len(_BLOB_KEY)] for idx, byte in enumerate(raw)])
        data = json.loads(plain.decode("utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _get(name: str) -> str | None:
    value = _payload().get(name)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def get_cli_shared_token() -> str | None:
    return _get("t")


def get_posthog_proxy_url_dev() -> str | None:
    return _get("phd")


def get_posthog_proxy_url_prod() -> str | None:
    return _get("php")


def get_posthog_proxy_url_legacy() -> str | None:
    return _get("ph")


def get_sentry_proxy_url() -> str | None:
    return _get("s")


def get_vercel_sessions_proxy_url() -> str | None:
    """Return the n8n-proxied sessions ingest URL (legacy path).

    Kept for backwards compatibility with deployments where the direct
    URL is not embedded yet, and to allow the CLI to fall back if the
    direct endpoint becomes unreachable.
    """
    return _get("v")


def get_vercel_sessions_direct_url() -> str | None:
    """Return the direct sessions ingest URL (preferred path).

    When this returns a non-empty URL, ``_upload_session_payload`` posts
    straight to ``sessions.adscanpro.com/api/sessions`` and skips the
    n8n proxy entirely. The server endpoint accepts the same
    ``X-CLI-Token`` header the CLI already sends, so no token rotation
    is needed during the rollout.

    ``None`` (or empty) means the CLI falls back to
    ``get_vercel_sessions_proxy_url`` — the legacy n8n path. Returning
    ``None`` from this getter is the migration kill-switch: drop the
    ``"vd"`` key from the embedded blob and every CLI instantly reverts
    to the proxy. The proxy stays alive in production until the
    direct path proves itself.
    """
    return _get("vd")


def get_labs_webhook_url() -> str | None:
    return _get("l")

