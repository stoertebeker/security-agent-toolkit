#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
REPORT = ROOT / "reports" / "tool-output"
PREP = REPORT / "firmware-preparation.json"
BINARIES = REPORT / "firmware-binaries.json"


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def load_rootfs() -> Path:
    if not TARGET.is_file():
        fail("target/TARGET.toml missing")
    with TARGET.open("rb") as handle:
        cfg = tomllib.load(handle)
    if not cfg.get("engagement", {}).get("authorized", False):
        fail("engagement.authorized=false")
    if not PREP.is_file():
        fail("firmware preparation missing")
    prep = json.loads(PREP.read_text())
    raw = prep.get("primary_rootfs")
    if not raw:
        fail("preparation did not establish a primary rootfs")
    raw_path = Path(str(raw))
    if raw_path.is_absolute() or ".." in raw_path.parts or raw_path.parts[:2] != ("work", "extracted"):
        fail(f"unsafe rootfs path: {raw}")
    rootfs = (ROOT / raw_path).resolve()
    if not rootfs.is_dir():
        fail(f"rootfs missing: {raw}")
    return rootfs


def safe_regular(rootfs: Path, path: Path) -> Path | None:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(rootfs)
        mode = resolved.lstat().st_mode
    except (OSError, ValueError):
        return None
    return resolved if stat.S_ISREG(mode) else None


def resolve_binary(rootfs: Path, raw: str) -> Path:
    supplied = Path(raw)
    candidate = (ROOT / supplied).resolve() if supplied.parts[:2] == ("work", "extracted") else (rootfs / str(supplied).lstrip("/")).resolve()
    safe = safe_regular(rootfs, candidate)
    if not safe:
        fail(f"binary is not a regular file inside rootfs: {raw}")
    return safe


def run(command: list[str], timeout: int = 20) -> str:
    try:
        proc = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return ""
    return proc.stdout or ""


def needed_libraries(binary: Path) -> list[str]:
    text = run(["readelf", "-dW", str(binary)])
    return re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", text)


def defined_symbols(path: Path) -> set[str]:
    text = run(["readelf", "-Ws", str(path)])
    out: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[6] == "UND":
            continue
        name = parts[-1].split("@", 1)[0]
        if name:
            out.add(name)
    return out


def candidate_libraries(rootfs: Path, needed: set[str], max_scan: int) -> list[tuple[int, Path]]:
    candidates: list[tuple[int, Path]] = []
    seen: set[Path] = set()
    if BINARIES.is_file():
        try:
            entries = json.loads(BINARIES.read_text())
        except Exception:
            entries = []
        for item in entries:
            workspace_path = str(item.get("path", ""))
            name = Path(workspace_path).name
            if ".so" not in name and name not in needed:
                continue
            candidate = safe_regular(rootfs, ROOT / workspace_path)
            if not candidate or candidate in seen:
                continue
            priority = 0 if name in needed else 10
            candidates.append((priority, candidate))
            seen.add(candidate)
            if len(candidates) >= max_scan:
                break
    return sorted(candidates, key=lambda item: (item[0], str(item[1])))


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve the owning rootfs library for one or more external firmware symbols")
    parser.add_argument("--binary", required=True, help="ELF path relative to primary rootfs or prepared-rootfs path")
    parser.add_argument("--symbol", action="append", default=[], help="Exact symbol name to resolve; repeat as needed")
    parser.add_argument("--max-libraries", type=int, default=400)
    args = parser.parse_args()
    if not args.symbol:
        fail("at least one --symbol is required")
    if not 1 <= args.max_libraries <= 1000:
        fail("--max-libraries must be in range 1..1000")

    rootfs = load_rootfs()
    binary = resolve_binary(rootfs, args.binary)
    needed = needed_libraries(binary)
    candidates = candidate_libraries(rootfs, set(needed), args.max_libraries)
    wanted = [symbol.split("@", 1)[0] for symbol in args.symbol]
    owners: list[dict] = []
    for priority, candidate in candidates:
        symbols = defined_symbols(candidate)
        matched = sorted(set(wanted).intersection(symbols))
        if not matched:
            continue
        owners.append({
            "path": str(candidate.relative_to(rootfs)),
            "filename": candidate.name,
            "needed_by_source": candidate.name in needed,
            "symbols": matched,
            "priority": priority,
        })

    material = json.dumps({"binary": str(binary.relative_to(rootfs)), "symbols": wanted}, sort_keys=True).encode()
    query = hashlib.sha256(material).hexdigest()[:10]
    output = REPORT / f"firmware-symbol-owners-{binary.name}-{query}.json"
    result = {
        "schema_version": 1,
        "source_binary": str(binary.relative_to(rootfs)),
        "dt_needed": needed,
        "requested_symbols": wanted,
        "libraries_scanned": len(candidates),
        "owners": sorted(owners, key=lambda item: (item["priority"], item["path"])),
    }
    REPORT.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"[+] Symbol-owner resolution complete: {len(owners)} owner match(es)")
    for owner in result["owners"][:20]:
        print(f"    {owner['path']}: {', '.join(owner['symbols'])} needed={owner['needed_by_source']}")
    print(f"    report: {output.relative_to(ROOT)}")
    return 0 if owners else 1


if __name__ == "__main__":
    raise SystemExit(main())
