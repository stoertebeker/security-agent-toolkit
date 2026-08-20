#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
REPORT_DIR = ROOT / "reports" / "tool-output"
TMP_DIR = ROOT / "work" / "tmp"
JADX_DIR = ROOT / "extracted" / "jadx"
APKTOOL_DIR = ROOT / "extracted" / "apktool"
XAPK_DIR = ROOT / "extracted" / "xapk"
SAT_HOME = Path(os.environ.get("SAT_HOME", Path.home() / ".local/share/security-agent-toolkit"))
MAX_XAPK_ENTRIES = 10000
MAX_XAPK_UNCOMPRESSED = 12 * 1024 * 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def first_hash(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8", errors="replace").strip().split()[0]
    except (OSError, IndexError):
        return None
    return value.lower() if re.fullmatch(r"[0-9A-Fa-f]{64}", value) else None


def safe_slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return value[:120] or "split"


def safe_zip_members(archive: zipfile.ZipFile, label: str, max_uncompressed: int = MAX_XAPK_UNCOMPRESSED) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    if len(infos) > MAX_XAPK_ENTRIES:
        fail(f"{label} contains too many archive entries ({len(infos)} > {MAX_XAPK_ENTRIES})")
    total = sum(info.file_size for info in infos)
    if total > max_uncompressed:
        fail(f"{label} expands to more than {max_uncompressed // (1024**3)} GiB; refusing automatic extraction")
    checked: list[zipfile.ZipInfo] = []
    for info in infos:
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        if not name or path.is_absolute() or re.match(r"^[A-Za-z]:", name):
            fail(f"Unsafe absolute archive entry in {label}: {info.filename!r}")
        if any(part in ("..", "") for part in path.parts):
            fail(f"Unsafe traversal archive entry in {label}: {info.filename!r}")
        if stat.S_ISLNK(unix_mode):
            fail(f"Symlink archive entry is not allowed in {label}: {info.filename!r}")
        checked.append(info)
    return checked


def safe_extract_zip(path: Path, destination: Path, label: str, max_uncompressed: int = MAX_XAPK_UNCOMPRESSED) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    with zipfile.ZipFile(path) as archive:
        for info in safe_zip_members(archive, label, max_uncompressed=max_uncompressed):
            name = info.filename.replace("\\", "/")
            target = (destination / PurePosixPath(name)).resolve()
            try:
                target.relative_to(destination_root)
            except ValueError:
                fail(f"Archive entry escaped extraction directory in {label}: {info.filename!r}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)


with TARGET.open("rb") as handle:
    config = tomllib.load(handle)
if not config.get("engagement", {}).get("authorized", False):
    fail("engagement.authorized=false")

input_path = (ROOT / config["apk"]["path"]).resolve()
try:
    input_path.relative_to(ROOT.resolve())
except ValueError:
    fail("APK/XAPK path must remain inside the project workspace")
if not input_path.is_file():
    fail(f"APK/XAPK missing: {input_path}")

for directory in (TMP_DIR, JADX_DIR, APKTOOL_DIR, REPORT_DIR):
    directory.mkdir(parents=True, exist_ok=True)

env = os.environ.copy()
env.update({
    "TMPDIR": str(TMP_DIR),
    "TMP": str(TMP_DIR),
    "TEMP": str(TMP_DIR),
    "PATH": f"{SAT_HOME / 'bin'}:{env.get('PATH', '')}",
    "JAVA_TOOL_OPTIONS": (env.get("JAVA_TOOL_OPTIONS", "") + f" -Djava.io.tmpdir={TMP_DIR}").strip(),
})


def which(executable: str) -> str | None:
    return shutil.which(executable, path=env["PATH"])


required_tools = ["file", "apksigner", "jadx", "apktool"]
missing = [tool for tool in required_tools if not which(tool)]
if missing:
    fail("Required APK tools missing: " + ", ".join(missing) + ". Run './toolkit install apk' in the toolkit repository.")
metadata_tools = [tool for tool in ("aapt2", "aapt") if which(tool)]
if not metadata_tools:
    fail("Required APK metadata tool missing: neither aapt2 nor aapt is available")

current_input_sha = sha256_file(input_path)
previous_input_sha = first_hash(REPORT_DIR / ("xapk.sha256" if input_path.suffix.lower() == ".xapk" else "apk.sha256"))
same_input_as_previous = previous_input_sha == current_input_sha


def prepare_input() -> tuple[Path, list[dict], list[Path], dict | None]:
    suffix = input_path.suffix.lower()
    if suffix == ".apk":
        (REPORT_DIR / "apk.sha256").write_text(f"{current_input_sha}  {input_path.relative_to(ROOT)}\n", encoding="utf-8")
        return input_path, [], [], None
    if suffix != ".xapk":
        fail("Unsupported APK input. Use a .apk or .xapk file.")
    if not zipfile.is_zipfile(input_path):
        fail("XAPK is not a valid ZIP container")
    if XAPK_DIR.exists():
        shutil.rmtree(XAPK_DIR)
    safe_extract_zip(input_path, XAPK_DIR, "XAPK container")
    (REPORT_DIR / "xapk.sha256").write_text(f"{current_input_sha}  {input_path.relative_to(ROOT)}\n", encoding="utf-8")

    manifest: dict | None = None
    manifest_path = XAPK_DIR / "manifest.json"
    if manifest_path.is_file():
        try:
            parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                manifest = parsed
        except (OSError, json.JSONDecodeError) as exc:
            fail(f"Invalid XAPK manifest.json: {exc}")

    apk_entries: list[dict] = []
    if manifest and isinstance(manifest.get("split_apks"), list):
        for index, item in enumerate(manifest["split_apks"]):
            if not isinstance(item, dict) or not isinstance(item.get("file"), str):
                continue
            relative = PurePosixPath(item["file"].replace("\\", "/"))
            if relative.is_absolute() or ".." in relative.parts:
                fail(f"Unsafe APK path in XAPK manifest: {item.get('file')!r}")
            file_path = (XAPK_DIR / relative).resolve()
            try:
                file_path.relative_to(XAPK_DIR.resolve())
            except ValueError:
                fail(f"APK path escaped XAPK directory: {item.get('file')!r}")
            if not file_path.is_file():
                fail(f"XAPK manifest references missing APK: {item.get('file')}")
            apk_entries.append({"id": str(item.get("id") or f"split-{index}"), "file": file_path})
    if not apk_entries:
        apk_entries = [{"id": path.stem, "file": path} for path in sorted(XAPK_DIR.rglob("*.apk"))]
    if not apk_entries:
        fail("XAPK contains no APK files")

    base_entry = next((entry for entry in apk_entries if entry["id"].lower() == "base"), None)
    package_name = str(manifest.get("package_name", "")) if manifest else ""
    if base_entry is None and package_name:
        base_entry = next((entry for entry in apk_entries if entry["file"].name == f"{package_name}.apk"), None)
    if base_entry is None:
        base_entry = next((entry for entry in apk_entries if entry["file"].name.lower() == "base.apk"), None)
    if base_entry is None:
        non_config = [entry for entry in apk_entries if not re.match(r"^(?:split_)?config[._]", entry["file"].stem, re.IGNORECASE)]
        if len(non_config) == 1:
            base_entry = non_config[0]
    if base_entry is None and len(apk_entries) == 1:
        base_entry = apk_entries[0]
    if base_entry is None:
        fail("Could not identify base APK in XAPK. A split_apks entry with id=base is recommended.")

    base_apk = base_entry["file"]
    split_entries = [entry for entry in apk_entries if entry is not base_entry]
    obb_files = sorted(XAPK_DIR.rglob("*.obb"))
    inventory = {
        "format": "xapk",
        "container": str(input_path.relative_to(ROOT)),
        "container_sha256": current_input_sha,
        "xapk_version": manifest.get("xapk_version") if manifest else None,
        "package_name": manifest.get("package_name") if manifest else None,
        "version_name": manifest.get("version_name") if manifest else None,
        "version_code": manifest.get("version_code") if manifest else None,
        "base_apk": str(base_apk.relative_to(ROOT)),
        "base_sha256": sha256_file(base_apk),
        "splits": [{"id": entry["id"], "file": str(entry["file"].relative_to(ROOT)), "sha256": sha256_file(entry["file"]), "size": entry["file"].stat().st_size} for entry in split_entries],
        "obb_files": [{"file": str(path.relative_to(ROOT)), "sha256": sha256_file(path), "size": path.stat().st_size, "zip_compatible": zipfile.is_zipfile(path)} for path in obb_files],
    }
    (REPORT_DIR / "xapk-inventory.json").write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# XAPK inventory", f"container: {inventory['container']}", f"package: {inventory['package_name'] or 'unknown'}", f"version: {inventory['version_name'] or 'unknown'} ({inventory['version_code'] or 'unknown'})", f"base: {inventory['base_apk']}", f"splits: {len(split_entries)}", f"obb files: {len(obb_files)}", ""]
    lines += [f"split {entry['id']}: {entry['file'].relative_to(ROOT)}" for entry in split_entries]
    lines += [f"obb: {path.relative_to(ROOT)} zip_compatible={zipfile.is_zipfile(path)}" for path in obb_files]
    (REPORT_DIR / "xapk-inventory.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (REPORT_DIR / "apk.sha256").write_text(f"{sha256_file(base_apk)}  {base_apk.relative_to(ROOT)}\n", encoding="utf-8")
    return base_apk, split_entries, obb_files, inventory


base_apk, split_entries, obb_files, xapk_inventory = prepare_input()
all_apks = [base_apk] + [entry["file"] for entry in split_entries]


def run(label: str, command: list[str], log_name: str) -> int:
    log_path = REPORT_DIR / log_name
    command[0] = which(command[0]) or command[0]
    print(f"[*] {label}", flush=True)
    print(f"    log: {log_path.relative_to(ROOT)}", flush=True)
    started = time.monotonic()
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        log.write("Command: " + " ".join(map(str, command)) + "\n\n")
        log.flush()
        process = subprocess.Popen(command, cwd=ROOT, env=env, text=True, stdout=log, stderr=subprocess.STDOUT)
        try:
            return_code = process.wait()
        except KeyboardInterrupt:
            print(f"\n[!] Interrupted while running {label}; terminating child process ...", flush=True)
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.write("\nInterrupted by user.\n")
            raise
    elapsed = time.monotonic() - started
    if return_code == 0:
        print(f"[+] {label} finished ({elapsed:.1f}s)", flush=True)
    else:
        print(f"[!] {label} exited with code {return_code} ({elapsed:.1f}s); see {log_path.relative_to(ROOT)}", flush=True)
    return return_code


warnings: list[str] = []
failures: list[str] = []


def run_badging(label: str, apk_path: Path, log_name: str) -> bool:
    attempted: list[str] = []
    for index, tool in enumerate(metadata_tools):
        attempted.append(tool)
        attempt_log = log_name if index == 0 else log_name.replace(".txt", f"-{tool}.txt")
        rc = run(f"{label} ({tool})", [tool, "dump", "badging", str(apk_path)], attempt_log)
        if rc == 0:
            if attempt_log != log_name:
                shutil.copyfile(REPORT_DIR / attempt_log, REPORT_DIR / log_name)
            return True
    warnings.append(f"{label} failed with {' and '.join(attempted)}; manifest metadata coverage is degraded.")
    return False


if run("File identification", ["file", str(base_apk)], "file.txt") != 0:
    failures.append("File identification")
if run("Base APK signature verification", ["apksigner", "verify", "--verbose", "--print-certs", str(base_apk)], "apksigner.txt") != 0:
    warnings.append("Base APK signature verification failed; static analysis can continue.")
run_badging("Base APK metadata", base_apk, "aapt.txt")

for index, entry in enumerate(split_entries, 1):
    slug = safe_slug(entry["id"])
    if run(f"Split {entry['id']} signature verification", ["apksigner", "verify", "--verbose", "--print-certs", str(entry["file"])], f"xapk-split-{index:02d}-{slug}-apksigner.txt") != 0:
        warnings.append(f"Could not verify signature for split {entry['id']}.")
    run_badging(f"Split {entry['id']} metadata", entry["file"], f"xapk-split-{index:02d}-{slug}-aapt.txt")

java_files_existing = sum(1 for _ in JADX_DIR.rglob("*.java"))
reuse_jadx = same_input_as_previous and java_files_existing > 0 and (REPORT_DIR / "jadx.txt").is_file()
reuse_apktool = same_input_as_previous and ((APKTOOL_DIR / "AndroidManifest.xml").is_file() or (APKTOOL_DIR / "apktool.yml").is_file())

if reuse_jadx:
    log_text = (REPORT_DIR / "jadx.txt").read_text(encoding="utf-8", errors="replace")
    match = re.search(r"finished with errors, count:\s*(\d+)", log_text)
    error_count = match.group(1) if match else None
    note = f"Reusing existing JADX output ({java_files_existing} Java files"
    if error_count:
        note += f"; prior decompiler errors: {error_count}"
    warnings.append(note + ") for unchanged input.")
else:
    rc = run("JADX decompilation", ["jadx", "--no-res", "-d", str(JADX_DIR), *map(str, all_apks)], "jadx.txt")
    if rc != 0:
        java_files = sum(1 for _ in JADX_DIR.rglob("*.java"))
        log_text = (REPORT_DIR / "jadx.txt").read_text(encoding="utf-8", errors="replace")
        match = re.search(r"finished with errors, count:\s*(\d+)", log_text)
        error_count = match.group(1) if match else "unknown"
        if java_files > 0:
            warnings.append(f"JADX produced usable partial output ({java_files} Java files; decompiler errors: {error_count}). Use Apktool/Smali to verify affected security-relevant paths.")
        else:
            failures.append("JADX decompilation")

if reuse_apktool:
    warnings.append("Reusing existing base Apktool decode for unchanged input.")
else:
    if run("Base Apktool decode", ["apktool", "d", "-f", "-o", str(APKTOOL_DIR), str(base_apk)], "apktool.txt") != 0:
        failures.append("Base Apktool decode")

if not failures:
    split_root = APKTOOL_DIR / "splits"
    for index, entry in enumerate(split_entries, 1):
        slug = safe_slug(entry["id"])
        output = split_root / f"{index:02d}-{slug}"
        already_decoded = same_input_as_previous and output.exists() and ((output / "AndroidManifest.xml").is_file() or (output / "apktool.yml").is_file())
        if already_decoded:
            continue
        if run(f"Apktool decode split {entry['id']}", ["apktool", "d", "-f", "-o", str(output), str(entry["file"])], f"xapk-split-{index:02d}-{slug}-apktool.txt") != 0:
            warnings.append(f"Apktool could not decode split {entry['id']}; split coverage is degraded.")

    obb_root = APKTOOL_DIR / "xapk-obb"
    for index, obb in enumerate(obb_files, 1):
        if zipfile.is_zipfile(obb):
            destination = obb_root / f"{index:02d}-{safe_slug(obb.stem)}"
            if same_input_as_previous and destination.exists():
                continue
            try:
                safe_extract_zip(obb, destination, f"OBB {obb.name}")
                print(f"[+] Extracted ZIP-compatible OBB: {obb.relative_to(ROOT)}", flush=True)
            except SystemExit:
                raise
            except Exception as exc:
                warnings.append(f"Could not extract OBB {obb.name}: {exc}")
        else:
            warnings.append(f"OBB {obb.name} is opaque/non-ZIP; inventoried but not automatically unpacked.")


def signer_digest(log_path: Path) -> str | None:
    if not log_path.is_file():
        return None
    text = log_path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Signer #1 certificate SHA-256 digest:\s*([0-9A-Fa-f]+)", text)
    return match.group(1).lower() if match else None


if split_entries:
    base_digest = signer_digest(REPORT_DIR / "apksigner.txt")
    for index, entry in enumerate(split_entries, 1):
        slug = safe_slug(entry["id"])
        digest = signer_digest(REPORT_DIR / f"xapk-split-{index:02d}-{slug}-apksigner.txt")
        if base_digest and digest and digest != base_digest:
            warnings.append(f"Split {entry['id']} signer differs from base APK signer.")

if not failures:
    if run("Deterministic secret candidate scan", [sys.executable, str(ROOT / "tools" / "apk_secret_scan.py")], "secret-scan.txt") != 0:
        failures.append("Deterministic secret candidate scan")

if not failures:
    state = {
        "input": str(input_path.relative_to(ROOT)),
        "input_sha256": current_input_sha,
        "format": "xapk" if xapk_inventory else "apk",
        "base_apk": str(base_apk.relative_to(ROOT)),
        "split_count": len(split_entries),
        "obb_count": len(obb_files),
        "metadata_tool_preferred": metadata_tools[0],
    }
    (REPORT_DIR / "prepare-state.json").write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

print(f"\n[+] APK preparation completed: {input_path.relative_to(ROOT)}")
if xapk_inventory:
    print(f"    Input format:      XAPK ({len(split_entries)} split APKs, {len(obb_files)} OBB files)")
    print("    XAPK inventory:    reports/tool-output/xapk-inventory.json")
else:
    print("    Input format:      APK")
print(f"    Metadata tool:     {metadata_tools[0]} (fallback: {', '.join(metadata_tools[1:]) or 'none'})")
print("    JADX output:       extracted/jadx/")
print("    Apktool output:    extracted/apktool/")
print("    Tool logs:         reports/tool-output/")
print("    Secret candidates: reports/tool-output/secret-candidates.txt")

if warnings:
    print("\n[!] Preparation completed with degraded or noteworthy coverage:")
    for warning in warnings:
        print(f"    - {warning}")
if failures:
    print("\n[!] Preparation failed in required steps:")
    for failure in failures:
        print(f"    - {failure}")
    print("    Review the corresponding log files before starting the analysis.")
    sys.exit(1)
