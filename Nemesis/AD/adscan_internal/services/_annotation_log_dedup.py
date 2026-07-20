"""Per-batch deduplication for noisy annotation debug logs.

The attack-path annotation pipeline runs ``_annotate_execution_readiness``
once per path summary.  For a workspace with thousands of paths sharing
the same blocking target (e.g. ``EXCH01$@HTB.LOCAL`` repeated across
12k paths), the per-summary ``[viability-gate] inventory check ...`` and
``[target-access] relation=... target=...`` debug lines drown the
``--debug`` transcript in tens of thousands of identical entries.

This module ships a tiny ``ContextVar``-based dedup so those log sites
emit **one line per unique key** for the duration of an annotation
batch, while preserving the legacy per-call behaviour outside a batch
(other callers that hit the same code paths one-shot still see their
log line as before).

Usage at the orchestrator (`_annotate_execution_readiness`):

    with annotation_log_dedup_scope():
        for summary in summaries:
            annotate_summary_execution_readiness(summary)

Usage at a noisy log site:

    if not annotation_log_seen(("viability-gate", requested_target)):
        print_info_debug("[viability-gate] inventory check: ...")

Outside the scope (``ContextVar`` unset), ``annotation_log_seen`` always
returns ``False`` so per-call logging is unchanged.

Thread- and async-safe via ``contextvars``; the dedup set is implicitly
isolated per asyncio Task / thread context.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator


# When set, the dedup set tracks the (category, ...key parts...) tuples that
# have already been logged in the current batch. None means "no batch active"
# — the helper short-circuits to "not seen" so callers log as usual.
_ANNOTATION_BATCH_LOG_DEDUP: ContextVar[set[tuple[str, ...]] | None] = ContextVar(
    "_annotation_batch_log_dedup",
    default=None,
)


def annotation_log_seen(key: tuple[str, ...]) -> bool:
    """Return ``True`` when ``key`` was already recorded in the current batch.

    Outside an active ``annotation_log_dedup_scope`` (``ContextVar`` unset),
    always returns ``False`` so the call site logs unconditionally — the
    helper introduces no behavior change for one-shot callers.

    Args:
        key: A tuple identifying the log group, e.g.
            ``("viability-gate", "EXCH01$@HTB.LOCAL")`` or
            ``("target-access", "EXCH01$@HTB.LOCAL", "genericall")``. The
            first element should be a stable category name so different
            log groups don't collide.

    Returns:
        ``True`` when this key has already been logged in this batch and
        the caller should suppress its log line; ``False`` otherwise.
        The key is added to the set as a side effect on first sight.
    """
    dedup = _ANNOTATION_BATCH_LOG_DEDUP.get()
    if dedup is None:
        return False
    if key in dedup:
        return True
    dedup.add(key)
    return False


@contextmanager
def annotation_log_dedup_scope() -> Iterator[set[tuple[str, ...]]]:
    """Enter a batch annotation log-dedup scope.

    Inside the ``with`` block, every call site that consults
    :func:`annotation_log_seen` will emit at most one log line per unique
    key.  On exit, the ``ContextVar`` is reset so subsequent one-shot
    annotation calls log as before.

    Yields:
        The dedup set, so the orchestrator can inspect ``len(dedup)`` to
        report how many unique log groups were suppressed.
    """
    dedup: set[tuple[str, ...]] = set()
    token = _ANNOTATION_BATCH_LOG_DEDUP.set(dedup)
    try:
        yield dedup
    finally:
        _ANNOTATION_BATCH_LOG_DEDUP.reset(token)


__all__ = [
    "annotation_log_seen",
    "annotation_log_dedup_scope",
]
