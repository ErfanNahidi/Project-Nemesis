"""Helpers for calling async service code from synchronous ADscan entry points."""

from __future__ import annotations

import asyncio
import concurrent.futures
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


def run_async_sync(awaitable: Awaitable[T]) -> T:
    """Run an awaitable from sync code, even if the caller already owns a loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(awaitable)).result()


def run_sync_off_loop(fn: Callable[..., T], *args: object, **kwargs: object) -> T:
    """Run a SYNC callable that internally drives its own event loop.

    Some synchronous helpers (e.g. ``ADscanLDAPConnection`` via
    ``execute_with_ldap_fallback``) create a private event loop with
    ``asyncio.new_event_loop()`` + ``run_until_complete()``. ``asyncio``
    forbids driving a loop while another loop is already running in the same
    thread, so calling such helpers from inside an active event loop raises
    ``RuntimeError: Cannot run the event loop while another loop is running``.

    This helper offloads the *entire* synchronous callable to a single worker
    thread that has no running loop of its own, so the inner
    ``new_event_loop()`` + ``run_until_complete()`` works. When the caller does
    NOT already own a running loop, the callable is invoked directly with no
    thread offload — behaviour is identical to calling ``fn`` itself.

    Concurrency note: ``max_workers=1`` and the blocking ``.result()`` keep the
    offload strictly sequential — one operation at a time. Do not rely on this
    for parallel LDAP work; process-global state (e.g. the gssapi/KRB5CCNAME
    default credential cache binding) is set inside the offloaded callable and
    must not be shared across concurrent operations.

    Args:
        fn: The synchronous callable to run.
        *args: Positional arguments forwarded to ``fn``.
        **kwargs: Keyword arguments forwarded to ``fn``.

    Returns:
        The return value of ``fn(*args, **kwargs)``.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return fn(*args, **kwargs)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: fn(*args, **kwargs)).result()
