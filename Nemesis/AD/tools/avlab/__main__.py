"""avlab — AV/EDR validation lab CLI.

Usage examples
--------------

Run toggle-ablation against castelblack with the adscan_loader catalog::

    python -m avlab ablate \\
        --catalog catalogs/adscan_loader.yaml \\
        --payload /opt/payloads/GodPotato-NET4.exe \\
        --payload-args "" \\
        --scanner defender \\
        --scanner-host 192.168.180.22 \\
        --scanner-domain north.sevenkingdoms.local \\
        --scanner-user jon.snow \\
        --scanner-password iknownothing

Run truncation bisect on a single binary::

    python -m avlab bisect \\
        --binary /path/to/loader.exe \\
        --scanner defender \\
        --scanner-host 192.168.180.22 \\
        --scanner-domain north.sevenkingdoms.local \\
        --scanner-user jon.snow \\
        --scanner-password iknownothing

List all variants in a catalog without building::

    python -m avlab list-catalog --catalog catalogs/adscan_loader.yaml
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import asdict
from pathlib import Path

import yaml

from avlab.core.models import MatrixRun, ToggleSpec, Variant
from avlab.core.reporting import write_matrix_report
from avlab.core.workspace import Workspace
from avlab.methods.toggle_ablation import build_ablation_summary, run_toggle_ablation
from avlab.methods.truncation_bisect import run_truncation_bisect
from avlab.scanners.registry import create as create_scanner


def _scanner_config(args: argparse.Namespace) -> dict:
    return {
        "host": args.scanner_host,
        "domain": args.scanner_domain,
        "username": args.scanner_user,
        "password": args.scanner_password,
        "remote_dir": getattr(args, "scanner_remote_dir", r"C:\avlab"),
        "scan_mode": getattr(args, "scan_mode", "rtp"),
        "rtp_wait_seconds": int(getattr(args, "rtp_wait_seconds", 3)),
        "smb_username": getattr(args, "smb_username", ""),
        "smb_password": getattr(args, "smb_password", ""),
    }


# ---------------------------------------------------------------------------
# list-catalog
# ---------------------------------------------------------------------------

def cmd_list_catalog(args: argparse.Namespace) -> int:
    catalog = _load_catalog(args.catalog)
    print(f"Catalog: {catalog['catalog']}")
    print(f"Description: {catalog.get('description', '').strip()}")
    print(f"\n{'Variant':<40} {'Toggle slug':<40} Notes")
    print("-" * 100)
    for entry in catalog["variants"]:
        spec = _spec_from_entry(entry)
        print(f"{entry['name']:<40} {spec.slug:<40} {entry.get('notes', '')}")
    return 0


# ---------------------------------------------------------------------------
# bisect
# ---------------------------------------------------------------------------

def cmd_bisect(args: argparse.Namespace) -> int:
    binary = Path(args.binary)
    if not binary.is_file():
        print(f"[!] file not found: {binary}", file=sys.stderr)
        return 1

    run_id = MatrixRun.now(prefix="bisect_")
    ws = Workspace.create_for(run_id)

    scanner = create_scanner(args.scanner, _scanner_config(args), ws)

    # Wrap the standalone binary as a minimal Variant so the bisect method
    # can use the shared _scan_bytes helper.
    variant = Variant.from_path(
        name=binary.stem,
        artefact_path=binary,
        toggles=ToggleSpec(),
        payload_name=binary.stem,
        build_seconds=0.0,
    )

    print(f"[*] bisect run_id: {run_id}")
    print(f"[*] binary: {binary} ({binary.stat().st_size:,} bytes)")
    print(f"[*] scanner: {args.scanner}")

    scanner.setup()
    try:
        outcome = run_truncation_bisect(
            scanner=scanner,
            variant=variant,
            workspace=ws,
            scan_timeout_s=int(getattr(args, "timeout", 60)),
        )
    finally:
        scanner.teardown()

    f = outcome.finding
    print()
    if f.inconclusive:
        print(f"[!] INCONCLUSIVE after {f.iterations} iterations ({f.elapsed_seconds:.1f}s)")
        print(f"    {f.notes}")
        print()
        print("    Next step: run 'avlab ablate' to identify which OPSEC layer")
        print("    the ML model is keying on.")
    else:
        print(f"[+] SIGNATURE BOUNDARY: offset 0x{f.end_offset:x} ({f.end_offset})")
        print(f"    iterations={f.iterations}  elapsed={f.elapsed_seconds:.1f}s")
        print()
        print(f.hex_window)

    print(f"\n[*] run dir: {ws.run_dir}")
    return 0 if not f.inconclusive else 1


# ---------------------------------------------------------------------------
# ablate
# ---------------------------------------------------------------------------

def cmd_ablate(args: argparse.Namespace) -> int:
    catalog = _load_catalog(args.catalog)
    catalog_name = catalog["catalog"]
    entries = catalog["variants"]

    run_id = MatrixRun.now(prefix=f"{catalog_name}_")
    ws = Workspace.create_for(run_id)

    print(f"[*] run_id:  {run_id}")
    print(f"[*] catalog: {catalog_name} ({len(entries)} variants)")
    print(f"[*] scanner: {args.scanner}")
    print(f"[*] payload: {args.payload}")
    print(f"[*] run dir: {ws.run_dir}")
    print()

    # Build all variants first, then scan.
    from avlab.builder import build_all_variants

    specs = [_spec_from_entry(e) for e in entries]
    print(f"[*] building {len(specs)} loader variants …")
    variants = build_all_variants(
        specs=specs,
        payload_path=args.payload,
        payload_args=getattr(args, "payload_args", ""),
        payload_name=Path(args.payload).stem,
        workspace=ws,
        run_id_prefix=run_id,
    )
    if not variants:
        print("[!] all builds failed — aborting.", file=sys.stderr)
        return 1
    print(f"[+] built {len(variants)}/{len(specs)} variants")
    print()

    scanner = create_scanner(args.scanner, _scanner_config(args), ws)

    print(f"[*] scanning {len(variants)} variants …")
    run = run_toggle_ablation(
        scanner=scanner,
        variants=variants,
        workspace=ws,
        catalog_name=catalog_name,
        run_id=run_id,
        scan_timeout_s=int(getattr(args, "timeout", 60)),
        notes=catalog.get("description", "").strip(),
    )

    write_matrix_report(ws, run)
    ablation = build_ablation_summary(run)

    # Print summary table.
    print()
    print(f"{'Variant':<42} {'Slug':<30} {'Verdict':<12} Threats")
    print("-" * 100)
    by_name = {v.name: v for v in run.variants}
    for r in run.results:
        v = by_name.get(r.variant_name)
        slug = v.toggles.slug if v else "—"
        threats = ", ".join(r.threat_names) if r.threat_names else "—"
        print(f"{r.variant_name:<42} {slug:<30} {r.verdict.value:<12} {threats}")

    from avlab.core.reporting import _summary_block
    summary = _summary_block(run.results)
    print()
    print(
        f"Result: {summary['clean']}/{summary['total']} clean "
        f"({summary['pass_rate']*100:.0f}%)  "
        f"detected={summary['detected']}  "
        f"inconclusive={summary['inconclusive']}"
    )
    print(f"\nReports: {ws.matrix_json}")
    print(f"         {ws.matrix_md}")
    return 0


# ---------------------------------------------------------------------------
# Catalog helpers
# ---------------------------------------------------------------------------

def _load_catalog(path: str) -> dict:
    p = Path(path)
    if not p.is_file():
        # Try relative to avlab root.
        p = Path(__file__).parent / path
    with p.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _spec_from_entry(entry: dict) -> ToggleSpec:
    toggles = entry.get("toggles") or {}
    return ToggleSpec(**toggles)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m avlab",
        description="AV/EDR validation lab — bisect and toggle-ablation runner",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # -- list-catalog --
    lc = sub.add_parser("list-catalog", help="List variants in a catalog YAML")
    lc.add_argument("--catalog", required=True)

    # -- shared scanner args --
    def _add_scanner_args(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--scanner", default="defender")
        sp.add_argument("--scanner-host", required=True)
        sp.add_argument("--scanner-domain", required=True)
        sp.add_argument("--scanner-user", required=True)
        sp.add_argument("--scanner-password", required=True)
        sp.add_argument("--scanner-remote-dir", default=r"C:\avlab")
        sp.add_argument("--scan-mode", default="rtp",
                        choices=["rtp", "mpcmdrun"],
                        help="rtp=real-time protection (catches ML/cloud), "
                             "mpcmdrun=static scan (faster, misses cloud)")
        sp.add_argument("--rtp-wait-seconds", type=int, default=3,
                        help="Seconds to wait for RTP to scan after upload")
        sp.add_argument("--timeout", type=int, default=60)
        sp.add_argument("--smb-username", default="",
                        help="Local-admin SMB user for upload (bypasses MSSQL "
                             "upload when Defender intercepts PowerShell writes). "
                             "Example: eddard.stark")
        sp.add_argument("--smb-password", default="")

    # -- bisect --
    bs = sub.add_parser("bisect", help="Truncation-bisect one binary")
    bs.add_argument("--binary", required=True)
    _add_scanner_args(bs)

    # -- ablate --
    ab = sub.add_parser("ablate", help="Toggle-ablation matrix run")
    ab.add_argument("--catalog", required=True)
    ab.add_argument("--payload", required=True)
    ab.add_argument("--payload-args", default="")
    _add_scanner_args(ab)

    return p


def main() -> int:
    args = _build_parser().parse_args()
    if args.command == "list-catalog":
        return cmd_list_catalog(args)
    if args.command == "bisect":
        return cmd_bisect(args)
    if args.command == "ablate":
        return cmd_ablate(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
