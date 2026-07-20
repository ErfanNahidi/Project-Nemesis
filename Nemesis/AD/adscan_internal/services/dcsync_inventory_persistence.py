"""Persist DCSync dump output as a workspace inventory artefact.

The DCSync flow in :mod:`adscan_internal.cli.secretsdump` builds the
in-memory list of cracked credentials (``raw_credentials``) plus the
post-cracking list (``creds_to_persist``). This helper writes that
material to ``<workspace>/domains/<domain>/inventory/dcsync_dump.json``
so the web ingestion pipeline can build the DCSync Intelligence KPIs.

Plaintext is **never** persisted, never logged, never returned. The
file contains only the NT hash plus a ``plaintext_recovered`` boolean
flag. Plaintext stays on disk in the cracking history / potfile only.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterable

from adscan_internal.workspaces import domain_subpath, write_json_file

INVENTORY_SCHEMA_VERSION = "inventory-1.0"
EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"


def _extract_rid(sid: str | None) -> int | None:
    if not sid:
        return None
    try:
        return int(str(sid).rsplit("-", 1)[1])
    except (ValueError, IndexError):
        return None


def _is_machine_account(sam: str) -> bool:
    return bool(sam) and sam.endswith("$")


def _normalize_domain(value: str | None) -> str:
    return str(value or "").strip().rstrip(".").lower()


def write_dcsync_dump_file(
    shell: object,
    *,
    domain: str,
    raw_credentials: Iterable[tuple[str, str]],
    plaintext_recovered_users: Iterable[str] = (),
    sid_by_account: dict[str, str] | None = None,
) -> str | None:
    """Persist DCSync dump for ``domain``.

    Args:
        shell: Runtime shell — used to resolve the workspace path.
        domain: Target domain whose secrets were dumped.
        raw_credentials: Iterable of ``(samaccountname, nt_hash)`` pairs
            as observed by the DCSync stream.
        plaintext_recovered_users: Iterable of samaccountnames whose
            plaintext was recovered (via cracking, GPP, gMSA, etc.).
        sid_by_account: Optional ``{lower(sam): SID}`` map so we can
            persist the RID without having to re-query LDAP.

    Returns:
        The absolute path of the file written, or ``None`` if the
        workspace path cannot be resolved (no-op for ad-hoc shells
        without a workspace).
    """
    workspace_cwd = (
        shell._get_workspace_cwd()  # noqa: SLF001
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", "")
    )
    if not workspace_cwd:
        return None
    domains_dir = getattr(shell, "domains_dir", "domains")
    inventory_dir = domain_subpath(workspace_cwd, domains_dir, domain, "inventory")
    os.makedirs(inventory_dir, exist_ok=True)

    domain_key = _normalize_domain(domain)
    plaintext_set = {str(u or "").strip().lower() for u in plaintext_recovered_users}
    sid_lookup = {k.lower(): v for k, v in (sid_by_account or {}).items()}

    seen: set[tuple[str, str]] = set()
    entries: list[dict] = []
    for sam_raw, nt_raw in raw_credentials:
        sam = str(sam_raw or "").strip()
        nt = str(nt_raw or "").strip().lower()
        if not sam or not nt:
            continue
        # Composite (sam, nt) dedup — DCSync streams may yield duplicates
        # when retried; keep the first observation.
        key = (sam.lower(), nt)
        if key in seen:
            continue
        seen.add(key)
        sid = sid_lookup.get(sam.lower())
        rid = _extract_rid(sid)
        entries.append(
            {
                "samaccountname": sam,
                "domain": domain_key,
                "rid": rid,
                "lm_hash": None,
                "nt_hash": nt,
                "is_blank": nt == EMPTY_NT_HASH,
                "is_machine_account": _is_machine_account(sam),
                "plaintext_recovered": sam.lower() in plaintext_set,
            }
        )

    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "domain": domain_key,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "record_type": "dcsync_dump",
        "count": len(entries),
        "entries": entries,
    }
    out_path = os.path.join(inventory_dir, "dcsync_dump.json")
    write_json_file(out_path, payload)
    return out_path
