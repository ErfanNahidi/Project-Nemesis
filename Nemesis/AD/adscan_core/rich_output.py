"""Compatibility re-exporter — canonical implementation in ``adscan_core.output``.

All public symbols live in ``adscan_core/output/_*.py`` submodules and are
exposed here via star import.  Private helpers that external callers reference
directly (e.g. ``_get_console``, ``_telemetry_console`` PyInstaller shim,
prompt-logging internals) are re-imported explicitly below so the historical
``adscan_core.rich_output`` import surface remains stable.

For new code, import from ``adscan_core.output`` (or one of its submodules)
directly; this module exists for backward compatibility.
"""

from __future__ import annotations

from adscan_core.output import *  # noqa: F401,F403

# ---------------------------------------------------------------------------
# Private symbols — not picked up by ``import *`` but referenced by callers.
# Keep this list aligned with the previous explicit re-import blocks so any
# ``from adscan_core.rich_output import _foo`` continues to resolve.
# ---------------------------------------------------------------------------
from adscan_core.output._state import (  # noqa: F401
    _get_console,
    _get_telemetry_console,
    _diag_enabled,
    _diag_log,
    _should_disable_prompt_interaction,
    _should_use_questionary_prompt,
    _emit_prompt_interrupt_debug,
    _mark_operation_details,
)
from adscan_core.output._log import (  # noqa: F401
    _handle_spacing,
    _extract_plain_text,
    _get_logger,
    _log_to_file,
    _build_persisted_message,
    _print_logger_format_fallback,
    _format_exception_context,
    _log_exception_to_file,
)
from adscan_core.output._prompts import (  # noqa: F401
    _classify_prompt_answer,
    _logged_prompt_ask,
    _logged_confirm_ask,
    _questionary_style,
    _fallback_numeric_select_index,
)
from adscan_core.output._attack_paths import (  # noqa: F401
    _fallback_format_attack_path_node_label,
    _fallback_format_attack_path_relation_label,
    _fallback_format_attack_path_relation_display,
    _fallback_format_attack_path_source_context,
    _get_attack_path_narrative_formatters,
    _format_attack_step_details,
    _build_attack_steps_table,
    _format_effective_target_basis_compact,
)


def __getattr__(name: str):
    """Module-level ``__getattr__`` for dynamic attribute access.

    Preserves the PyInstaller hook: ``adscan_internal.rich_output`` imports
    ``_telemetry_console`` from this module.  We forward it to the canonical
    location in ``_state`` so callers always see the live value.
    """
    if name == "_telemetry_console":
        from adscan_core.output import _state

        return _state._telemetry_console
    raise AttributeError(name)
