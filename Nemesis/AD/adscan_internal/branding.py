"""Compatibility shim — canonical implementation moved to adscan_core.branding."""

from __future__ import annotations

from adscan_core.branding import *  # noqa: F403
from adscan_core.branding import (  # noqa: F401
    ADSCAN_ASCII_WIDE,
    ADSCAN_COPYRIGHT,
    ADSCAN_LINKS,
    ADSCAN_MARK,
    ADSCAN_TAGLINE,
    build_gradient_ascii,
    build_intro_lines,
)
