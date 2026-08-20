#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
REPORT_DIR = ROOT / "reports" / "tool-output"
TMP_DIR = ROOT / "work" / "tmp"
SAT_HOME = Path(os.environ.get("SAT_HOME", Path.home() / ".local/share/security-agent-toolkit"))


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


with TARGET.open("rb") as handle:
    config = tomllib.load(handle)

if not config.get("engagement", {}).get("authorized", False):
    fail("engagement.authorized=false")

apk = (ROOT / config["apk"]["path"]).resolve()
try:
    apk.relative_to(ROOT.resolve())
except ValueError:
    fail("APK path must remain inside the project workspace")

if not apk.is_file():
    fail(f"APK missing: {apk}")

for directory in (
    TMP_DIR,
    ROOT / "extracted" / "jadx",
    ROOT / "extracted" / "apktool",
    REPORT_DIR,
):
    directory.mkdir(parents=True, exist_ok=True)

env = os.environ.copy()
env.update(
    {
        "TMPDIR": str(TMP_DIR),
        "TMP": str(TMP_DIR),
        "TEMP": str(TMP_DIR),
        "PATH": f"{SAT_HOME / 'bin'}:{env.get('PATH', '')}",
        "JAVA_TOOL_OPTIONS": (
            env.get("JAVA_TOOL_OPTIONS", "") + f" -Djava.io.tmpdir={TMP_DIR}"
        ).strip(),
    }
)

# Resolve tools using the same PATH that child processes receive.
def which(executable: str) -> str | None:
    return shutil.which(executable, path=env["PATH"])


required_tools = ["file", "apksigner", "aapt", "jadx", "apktool"]
missing = [tool for tool in required_tools if not which(tool)]
if missing:
    fail(
        "Required APK tools missing: "
        + ", ".join(missing)
        + ". Run './toolkit install apk' in the toolkit repository."
    )

sha256 = hashlib.sha256()
with apk.open("rb") as handle:
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        sha256.update(block)
(REPORT_DIR / "apk.sha256").write_text(
    f"{sha256.hexdigest()}  {apk.relative_to(ROOT)}\n", encoding="utf-8"
)


def run(label: str, command: list[str], log_name: str) -> int:
    log_path = REPORT_DIR / log_name
    command[0] = which(command[0]) or command[0]

    print(f"[*] {label}", flush=True)
    print(f"    log: {log_path.relative_to(ROOT)}", flush=True)
    started = time.monotonic()

    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        log.write("Command: " + " ".join(map(str, command)) + "\n\n")
        log.flush()
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
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
        print(
            f"[!] {label} exited with code {return_code} ({elapsed:.1f}s); see {log_path.relative_to(ROOT)}",
            flush=True,
        )
    return return_code


steps = [
    ("File identification", ["file", str(apk)], "file.txt"),
    (
        "APK signature verification",
        ["apksigner", "verify", "--verbose", "--print-certs", str(apk)],
        "apksigner.txt",
    ),
    ("AAPT metadata", ["aapt", "dump", "badging", str(apk)], "aapt.txt"),
    (
        "JADX decompilation",
        ["jadx", "-d", str(ROOT / "extracted" / "jadx"), str(apk)],
        "jadx.txt",
    ),
    (
        "Apktool decode",
        [
            "apktool",
            "d",
            "-f",
            "-o",
            str(ROOT / "extracted" / "apktool"),
            str(apk),
        ],
        "apktool.txt",
    ),
]

failures: list[str] = []
for label, command, log_name in steps:
    if run(label, command, log_name) != 0:
        failures.append(label)

print(f"\n[+] APK preparation completed: {apk.relative_to(ROOT)}")
print(f"    JADX output:    extracted/jadx/")
print(f"    Apktool output: extracted/apktool/")
print(f"    Tool logs:      reports/tool-output/")

if failures:
    print("\n[!] Some preparation steps returned errors:")
    for failure in failures:
        print(f"    - {failure}")
    print("    Review the corresponding log files before starting the analysis.")
    sys.exit(1)
