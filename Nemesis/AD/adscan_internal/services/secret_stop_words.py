"""Minimal stop-word list for filename-aware extraction.

This list is intentionally narrow. It contains ONLY tokens that are
mathematically never passwords: null/boolean sentinels, developer placeholders,
keyboard walks, and visual separators.

Natural-language vocabulary (Spanish, Catalan, English IT terms) has been
removed. Those words now receive a dictionary penalty via
``secret_dictionary.is_dictionary_word()`` instead of being silently suppressed.
This means real passwords that happen to be common words (e.g. a user who chose
``Socioadicciones`` or a vendor default like ``chocolate``) are no longer lost.

Single Responsibility: this module owns only tokens that are structurally
incapable of being real credentials. ``secret_dictionary.py`` owns the
natural-language vocabulary scoring signal.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Generic — tokens that are NEVER passwords by definition
# ---------------------------------------------------------------------------
STOP_WORDS_GENERIC: frozenset[str] = frozenset({
    # Null / boolean sentinels
    "null", "none", "true", "false", "yes", "no",
    # Developer placeholders
    "todo", "fixme", "xxxxx", "dummy", "test", "temp",
    "sample", "example", "placeholder",
    # Keyboard walks / well-known weak dummy passwords
    "asdf", "qwerty",
    # Visual separators that can land in a stripped line
    "----", "====", "....",
})

# ---------------------------------------------------------------------------
# Combined master set — the only symbol callers should import
# ---------------------------------------------------------------------------
ALL_STOP_WORDS: frozenset[str] = STOP_WORDS_GENERIC

__all__ = [
    "ALL_STOP_WORDS",
    "STOP_WORDS_GENERIC",
]
