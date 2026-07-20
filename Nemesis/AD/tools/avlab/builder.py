"""Variant builder — compiles adscan_loader.exe for a given ToggleSpec.

This is the bridge between the avlab toggle-ablation matrix and the
ADscan Tier-3 build pipeline (``adscan_internal/services/exploitation/
binary_ops/loader.py``).

Usage::

    from avlab.builder import build_variant
    from avlab.core.models import ToggleSpec

    spec = ToggleSpec(etw_patch=False, amsi_patch=False)
    variant = build_variant(
        spec=spec,
        payload_path="/opt/payloads/GodPotato-NET4.exe",
        payload_args="",
        payload_name="godpotato-net4",
        workspace=ws,
    )
    # variant.artefact_path → compiled .exe stashed in the run workspace

Calling code (avlab CLI, toggle_ablation method) only talks to this module.
It never touches loader.py directly, so if the build pipeline changes
(different C compiler, new SW4 API, cross-compilation for ARM) only this
file needs updating.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from avlab.core.models import ToggleSpec, Variant
from avlab.core.workspace import Workspace

# Ensure adscan_internal is importable when running from tools/ directory.
# In the container the package is already on sys.path via the venv;
# this guard is a local-dev convenience only.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def build_variant(
    *,
    spec: ToggleSpec,
    payload_path: str | Path,
    payload_args: str,
    payload_name: str,
    workspace: Workspace,
    run_id_prefix: str = "avlab",
) -> Variant | None:
    """Build one adscan_loader.exe variant from ``spec`` and stash it.

    Args:
        spec:          OPSEC layer configuration for this variant.
        payload_path:  Local path to the PE that donut will wrap.
        payload_args:  CLI arguments baked into the donut shellcode.
        payload_name:  Human-readable payload identifier (e.g.
                       ``"godpotato-net4"``).  Appears in reports.
        workspace:     Run workspace for stashing the artefact.
        run_id_prefix: Used to namespace the loader output directory
                       under ``~/.adscan/tools/windows-tools/``.

    Returns:
        :class:`Variant` with the stashed artefact, or ``None`` on build
        failure.
    """
    from adscan_internal.services.exploitation.binary_ops.loader import (
        LoaderMode,
        build_loader,
        loader_available,
    )

    if not loader_available():
        raise RuntimeError(
            "Tier-3 build prerequisites missing (donut / sw4 / mingw). "
            "Run inside the adscan-lite-dev:edge container."
        )

    variant_name = f"adscan_loader_{spec.slug}"
    tool_label = f"{run_id_prefix}_{spec.slug}"

    t0 = time.monotonic()
    artifact = build_loader(
        str(payload_path),
        payload_args,
        tool_name=tool_label,
        mode=LoaderMode.EXEC,
        extra_compile_flags=spec.compile_flags(),
        xor_encrypt=spec.xor_encrypt,
    )
    build_seconds = time.monotonic() - t0

    if artifact is None:
        return None

    stashed = workspace.stash_artefact(
        variant_name, Path(artifact.exe_path)
    )
    return Variant.from_path(
        name=variant_name,
        artefact_path=stashed,
        toggles=spec,
        payload_name=payload_name,
        build_seconds=build_seconds,
    )


def build_all_variants(
    *,
    specs: list[ToggleSpec],
    payload_path: str | Path,
    payload_args: str,
    payload_name: str,
    workspace: Workspace,
    run_id_prefix: str = "avlab",
) -> list[Variant]:
    """Build one variant per ``ToggleSpec`` in *specs*.

    Skips failed builds (``None``) with a warning; caller decides whether
    to abort or continue with the partial set.
    """
    import warnings

    variants: list[Variant] = []
    for spec in specs:
        variant = build_variant(
            spec=spec,
            payload_path=payload_path,
            payload_args=payload_args,
            payload_name=payload_name,
            workspace=workspace,
            run_id_prefix=run_id_prefix,
        )
        if variant is None:
            warnings.warn(
                f"Build failed for toggle spec: {spec.slug}",
                stacklevel=2,
            )
        else:
            variants.append(variant)
    return variants


def load_catalog(name_or_path: str) -> dict:
    """Load a catalog YAML by name (``"adscan_loader"``) or file path."""
    import yaml  # PyYAML — in the runtime venv

    p = Path(name_or_path)
    if not p.suffix:
        p = Path(__file__).parent / "catalogs" / f"{name_or_path}.yaml"
    if not p.is_file():
        raise FileNotFoundError(f"catalog not found: {p}")
    with p.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def catalog_to_specs(catalog: dict) -> list[tuple[str, ToggleSpec, str]]:
    """Parse catalog variants → list of (name, ToggleSpec, notes)."""
    result: list[tuple[str, ToggleSpec, str]] = []
    for entry in catalog.get("variants", []):
        name: str = entry["name"]
        notes: str = entry.get("notes", "")
        raw: dict = entry.get("toggles", {})
        spec = ToggleSpec(**raw) if raw else ToggleSpec()
        result.append((name, spec, notes))
    return result


__all__ = ["build_variant", "build_all_variants", "load_catalog", "catalog_to_specs"]
