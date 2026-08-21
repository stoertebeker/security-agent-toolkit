#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "tool-output"
PREP = REPORT / "firmware-preparation.json"
OUT = REPORT / "firmware-component-fingerprints.json"
TXT = REPORT / "firmware-component-fingerprints.txt"

NAME_HINTS = {
    "busybox", "dropbear", "sshd", "openssl", "libssl", "libcrypto", "dnsmasq",
    "lighttpd", "nginx", "uhttpd", "boa", "hostapd", "wpa_supplicant", "curl",
    "wget", "miniupnpd", "upnpd", "pppd", "mosquitto", "sqlite", "php", "lua",
}

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("busybox", re.compile(r"\bBusyBox v(\d+\.\d+(?:\.\d+)?(?:[^\s)]*)?)")),
    ("dropbear", re.compile(r"\bDropbear(?: sshd)? v?([0-9]{4}\.[0-9]+|\d+\.\d+(?:\.\d+)?)", re.I)),
    ("openssl", re.compile(r"\bOpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z0-9.-]*)", re.I)),
    ("openssh", re.compile(r"\bOpenSSH[_-]([0-9]+\.[0-9]+(?:p[0-9]+)?)", re.I)),
    ("dnsmasq", re.compile(r"\bdnsmasq(?:-| version )([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("lighttpd", re.compile(r"\blighttpd[/ -]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("nginx", re.compile(r"\bnginx[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("hostapd", re.compile(r"\bhostapd v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("curl", re.compile(r"\bcurl[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("miniupnpd", re.compile(r"\bminiupnpd[/ -]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("sqlite", re.compile(r"\bSQLite(?: version)?\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
]


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def lstat_mode(path: Path) -> int | None:
    try:
        return path.lstat().st_mode
    except OSError:
        return None


def real_dir(path: Path) -> bool:
    mode = lstat_mode(path)
    return bool(mode is not None and stat.S_ISDIR(mode))


def rootfs() -> Path:
    if not PREP.is_file():
        fail("firmware preparation missing")
    prep = json.loads(PREP.read_text())
    raw = prep.get("primary_rootfs") or prep.get("extraction_root")
    if not raw:
        fail("no rootfs/extraction root")
    raw_path = Path(str(raw))
    if raw_path.is_absolute() or ".." in raw_path.parts or raw_path.parts[:2] != ("work", "extracted"):
        fail(f"unsafe prepared rootfs path: {raw}")
    path = ROOT / raw_path
    if not real_dir(path):
        fail(f"prepared rootfs is not a real directory: {raw}")
    return path


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def strings(path: Path) -> str:
    try:
        proc = subprocess.run(
            ["strings", "-a", "-n", "5", str(path)],
            cwd=ROOT,
            text=True,
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
        return proc.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def main() -> int:
    base = rootfs()
    fingerprints: dict[tuple[str, str, str], dict] = {}
    scanned = 0

    for current, dirnames, filenames in os.walk(base, followlinks=False):
        current_path = Path(current)
        dirnames[:] = [name for name in dirnames if real_dir(current_path / name)]

        try:
            current_rel = current_path.relative_to(base).as_posix()
        except ValueError:
            continue
        if current_rel.startswith("lib/modules/"):
            parts = Path(current_rel).parts
            if len(parts) == 3 and re.search(r"\d+\.\d+", parts[2]):
                version = parts[2]
                key = ("linux-kernel", version, rel(current_path))
                fingerprints[key] = {
                    "component": "linux-kernel",
                    "version": version,
                    "path": rel(current_path),
                    "evidence": "module-directory",
                }

        for filename in filenames:
            path = current_path / filename
            try:
                st = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size > 64 * 1024 * 1024:
                continue
            lowered = filename.lower()
            if not any(hint in lowered for hint in NAME_HINTS):
                continue
            text = strings(path)
            if not text:
                continue
            scanned += 1
            for component, pattern in PATTERNS:
                for match in pattern.finditer(text):
                    version = match.group(1).strip()
                    key = (component, version, rel(path))
                    fingerprints[key] = {
                        "component": component,
                        "version": version,
                        "path": rel(path),
                        "evidence": "static-string",
                    }

    result = sorted(fingerprints.values(), key=lambda item: (item["component"], item["version"], item["path"]))
    OUT.write_text(json.dumps({"schema_version": 2, "scanned_named_files": scanned, "fingerprints": result}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    TXT.write_text("\n".join([
        "# Firmware component version fingerprints",
        f"named files scanned: {scanned}",
        f"fingerprints: {len(result)}",
        "",
        "These are local version/research anchors, not vulnerability findings.",
        "",
    ] + [f"- {item['component']} {item['version']} :: {item['path']} ({item['evidence']})" for item in result]) + "\n", encoding="utf-8")
    print(f"[+] Firmware component fingerprints: {len(result)} from {scanned} named files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
