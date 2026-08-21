#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
REPORT = ROOT / "reports" / "tool-output"
PREP = REPORT / "firmware-preparation.json"
WORK = ROOT / "work"
TMP = WORK / "tmp"
SAT_HOME = Path(os.environ.get("SAT_HOME", Path.home() / ".local/share/security-agent-toolkit"))
SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra"


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def load_authorized_rootfs() -> Path:
    if not TARGET.is_file():
        fail("target/TARGET.toml missing")
    with TARGET.open("rb") as handle:
        cfg = tomllib.load(handle)
    if not cfg.get("engagement", {}).get("authorized", False):
        fail("engagement.authorized=false")
    if not PREP.is_file():
        fail("firmware preparation missing; run tools/firmware_prepare.py first")
    prep = json.loads(PREP.read_text())
    raw = prep.get("primary_rootfs")
    if not raw:
        fail("firmware preparation did not establish a primary rootfs")
    raw_path = Path(str(raw))
    if raw_path.is_absolute() or ".." in raw_path.parts or raw_path.parts[:2] != ("work", "extracted"):
        fail(f"unsafe prepared rootfs path: {raw}")
    rootfs = (ROOT / raw_path).resolve()
    try:
        mode = rootfs.lstat().st_mode
    except OSError:
        fail(f"prepared rootfs missing: {raw}")
    if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        fail(f"prepared rootfs is not a real directory: {raw}")
    return rootfs


def dependency_path() -> str:
    return f"{SAT_HOME / 'bin'}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:{os.environ.get('PATH', '')}"


def which(name: str) -> str | None:
    return shutil.which(name, path=dependency_path())


def real_dir_inside(rootfs: Path, relative: str) -> Path | None:
    candidate = rootfs / relative
    try:
        st = candidate.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return None
    resolved = candidate.resolve()
    try:
        resolved.relative_to(rootfs)
    except ValueError:
        return None
    return resolved


def firmware_library_paths(rootfs: Path) -> list[Path]:
    # Ordered paths only from the prepared target rootfs. Ghidra uses these
    # during ELF import so target libraries can resolve imports instead of
    # accidentally consulting unrelated host libraries.
    candidates = [
        "lib", "usr/lib", "usr/local/lib", "usr/local/samba/lib",
        "opt/lib", "opt/usr/lib",
    ]
    paths: list[Path] = []
    for relative in candidates:
        path = real_dir_inside(rootfs, relative)
        if path and path not in paths:
            paths.append(path)
    return paths


def resolve_binary(rootfs: Path, raw: str) -> Path:
    supplied = Path(raw)
    if supplied.is_absolute():
        candidate = supplied.resolve()
    elif supplied.parts[:2] == ("work", "extracted"):
        candidate = (ROOT / supplied).resolve()
    else:
        candidate = (rootfs / supplied).resolve()
    try:
        candidate.relative_to(rootfs)
    except ValueError:
        fail(f"binary escapes prepared rootfs: {candidate}")
    try:
        st = candidate.lstat()
    except OSError:
        fail(f"binary not found: {candidate}")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        fail(f"binary must be a regular non-symlink file: {candidate}")
    try:
        with candidate.open("rb") as handle:
            magic = handle.read(4)
    except OSError as exc:
        fail(f"cannot read binary: {exc}")
    if magic != b"\x7fELF":
        fail(f"target is not an ELF file: {candidate}")
    return candidate


def slug_for(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.name)[:60] or "binary"
    return f"{stem}-{digest}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Focused Ghidra decompilation for one firmware ELF")
    parser.add_argument("--binary", required=True, help="Path relative to primary rootfs, or prepared-rootfs path")
    parser.add_argument("--needle", action="append", default=[], help="String/symbol needle; repeat as needed")
    parser.add_argument("--max-functions", type=int, default=12)
    parser.add_argument("--timeout", type=int, default=900, help="Ghidra analysis timeout per file in seconds")
    parser.add_argument(
        "--decompile-timeout", type=int, default=180,
        help="Decompiler timeout per selected function in seconds",
    )
    args = parser.parse_args()

    if not args.needle:
        fail("at least one --needle is required")
    if not 1 <= args.max_functions <= 40:
        fail("--max-functions must be in range 1..40")
    if not 60 <= args.timeout <= 3600:
        fail("--timeout must be in range 60..3600 seconds")
    if not 30 <= args.decompile_timeout <= 600:
        fail("--decompile-timeout must be in range 30..600 seconds")

    rootfs = load_authorized_rootfs()
    binary = resolve_binary(rootfs, args.binary)
    analyze_headless = which("analyzeHeadless")
    if not analyze_headless:
        fail("analyzeHeadless not found; run toolkit install firmware / doctor firmware")
    script = SCRIPT_DIR / "SatDecompileRefs.java"
    if not script.is_file():
        fail(f"Ghidra post-script missing: {script}")

    slug = slug_for(binary)
    project_root = WORK / "ghidra" / "projects"
    slice_root = WORK / "ghidra" / "slices"
    ghidra_state = WORK / "cache" / "ghidra"
    ghidra_config = ghidra_state / "config"
    ghidra_cache = ghidra_state / "cache"
    project_root.mkdir(parents=True, exist_ok=True)
    slice_root.mkdir(parents=True, exist_ok=True)
    ghidra_config.mkdir(parents=True, exist_ok=True)
    ghidra_cache.mkdir(parents=True, exist_ok=True)
    TMP.mkdir(parents=True, exist_ok=True)
    REPORT.mkdir(parents=True, exist_ok=True)

    output = slice_root / f"{slug}.txt"
    log = REPORT / f"ghidra-{slug}.log"
    project_name = f"sat-{slug}"
    library_paths = firmware_library_paths(rootfs)

    command = [
        analyze_headless,
        str(project_root),
        project_name,
        "-import", str(binary),
        "-overwrite",
        "-analysisTimeoutPerFile", str(args.timeout),
    ]
    if library_paths:
        command.extend(["-librarySearchPaths", ";".join(str(path) for path in library_paths)])
    command.extend([
        "-scriptPath", str(SCRIPT_DIR),
        "-postScript", script.name, str(output), str(args.max_functions),
        str(args.decompile_timeout), *args.needle,
    ])

    env = os.environ.copy()
    env["PATH"] = dependency_path()
    env["TMPDIR"] = str(TMP)
    env["TMP"] = str(TMP)
    env["TEMP"] = str(TMP)
    env["XDG_CONFIG_HOME"] = str(ghidra_config)
    env["XDG_CACHE_HOME"] = str(ghidra_cache)

    # Ghidra's launcher officially honors these application directory system
    # properties. Keep settings/cache/temp under the assessment workspace and
    # append rather than replace any operator-provided headless JVM options.
    existing_headless_opts = env.get("GHIDRA_HEADLESS_JAVA_OPTIONS", "").strip()
    local_opts = " ".join([
        f"-Dapplication.settingsdir={ghidra_config}",
        f"-Dapplication.cachedir={ghidra_cache}",
        f"-Dapplication.tempdir={TMP}",
        f"-Djava.io.tmpdir={TMP}",
    ])
    env["GHIDRA_HEADLESS_JAVA_OPTIONS"] = f"{existing_headless_opts} {local_opts}".strip()

    # Overall wrapper budget includes auto-analysis plus multiple selected
    # function decompilations. Keep it bounded but do not cut off legitimate
    # per-function retries for large stripped vendor dispatchers.
    wrapper_timeout = args.timeout + (min(args.max_functions, 12) * args.decompile_timeout) + 180
    wrapper_timeout = min(wrapper_timeout, 5400)

    try:
        proc = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=wrapper_timeout,
            check=False,
        )
        stdout = proc.stdout or ""
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        log.write_text(stdout + "\n[!] wrapper timeout\n", encoding="utf-8")
        print(f"[!] Ghidra timed out; log: {log}", file=sys.stderr)
        return 124

    header = [
        "# SAT Ghidra invocation",
        f"binary: {binary.relative_to(rootfs)}",
        f"project: {project_root / project_name}",
        f"slice: {output}",
        f"needles: {', '.join(args.needle)}",
        f"library_search_paths: {', '.join(str(path.relative_to(rootfs)) for path in library_paths) or '(none)'}",
        f"ghidra_state: {ghidra_state.relative_to(ROOT)}",
        f"analysis_timeout_seconds: {args.timeout}",
        f"decompile_timeout_seconds: {args.decompile_timeout}",
        f"exit_code: {proc.returncode}",
        "",
        "# analyzeHeadless output",
    ]
    log.write_text("\n".join(header) + "\n" + stdout, encoding="utf-8")

    if proc.returncode != 0:
        print(f"[!] Ghidra failed with exit code {proc.returncode}; log: {log}", file=sys.stderr)
        return proc.returncode
    if not output.is_file():
        print(f"[!] Ghidra exited successfully but produced no slice; log: {log}", file=sys.stderr)
        return 3

    print("[+] Focused Ghidra slice complete")
    print(f"    binary: {binary.relative_to(rootfs)}")
    print(f"    slice: {output.relative_to(ROOT)}")
    print(f"    log: {log.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
