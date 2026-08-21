#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
REPORT = ROOT / "reports" / "tool-output"
SENSITIVE = ROOT / "reports" / "sensitive"
PREP = REPORT / "firmware-preparation.json"
OUT = REPORT / "firmware-secret-candidates.json"
SUMMARY = REPORT / "firmware-secret-candidates.txt"

MAX_FILE_SIZE = 4 * 1024 * 1024
MAX_CONTEXT = 180

RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "HIGH"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "HIGH"),
    ("github_token", re.compile(r"\bgh[opurs]_[A-Za-z0-9_]{20,}\b"), "HIGH"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "HIGH"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "MEDIUM"),
    ("url_embedded_credentials", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:]{1,80}:[^\s/@]{1,160}@"), "HIGH"),
    ("password_assignment", re.compile(r"(?i)\b(?:password|passwd|pwd|passphrase|psk|wpa_passphrase)\b\s*(?:=|:|\s+)\s*[\"']?([^\s\"';#]{3,200})"), "MEDIUM"),
    ("secret_assignment", re.compile(r"(?i)\b(?:client_secret|app_secret|api[_-]?key|auth[_-]?token|access[_-]?token|secret)\b\s*(?:=|:)\s*[\"']?([^\s\"';#]{6,240})"), "MEDIUM"),
    ("bearer_literal", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{12,})"), "MEDIUM"),
]

SENSITIVE_FILENAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "ssh_host_rsa_key",
    "ssh_host_dsa_key", "ssh_host_ecdsa_key", "ssh_host_ed25519_key",
    "dropbear_rsa_host_key", "dropbear_ecdsa_host_key", "dropbear_ed25519_host_key",
}


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def load_config() -> tuple[dict, dict]:
    if not TARGET.is_file():
        fail("target/TARGET.toml missing")
    with TARGET.open("rb") as handle:
        cfg = tomllib.load(handle)
    if not cfg.get("engagement", {}).get("authorized", False):
        fail("engagement.authorized=false")
    return cfg, cfg.get("secrets", {})


def load_rootfs() -> Path:
    if not PREP.is_file():
        fail("firmware preparation missing")
    prep = json.loads(PREP.read_text())
    raw = prep.get("primary_rootfs") or prep.get("extraction_root")
    if not raw:
        fail("no prepared rootfs/extraction root")
    path = ROOT / raw
    if not path.is_dir():
        fail(f"prepared path missing: {raw}")
    return path


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def redact_context(line: str, value: str | None = None) -> str:
    text = line.strip().replace("\x00", "")
    if value:
        text = text.replace(value, f"<redacted:{len(value)}>")
    # Catch values accidentally adjacent to common credential keys even when the
    # regex captured only part of the assignment.
    text = re.sub(
        r"(?i)((?:password|passwd|pwd|passphrase|psk|secret|token|api[_-]?key)\s*(?:=|:)\s*)[^\s,;]+",
        r"\1<redacted>", text,
    )
    return text[:MAX_CONTEXT]


def text_file(path: Path) -> bool:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_SIZE:
            return False
        with path.open("rb") as handle:
            sample = handle.read(4096)
        if not sample:
            return True
        if b"\x00" in sample:
            return False
        printable = sum(byte in b"\t\n\r" or 32 <= byte < 127 for byte in sample)
        return printable / len(sample) >= 0.70
    except OSError:
        return False


def value_from_match(match: re.Match[str]) -> str:
    if match.lastindex:
        for index in range(match.lastindex, 0, -1):
            value = match.group(index)
            if value:
                return value
    return match.group(0)


def add_candidate(candidates: list[dict], sensitive: list[dict], *, rule: str, priority: str, path: Path, line: int | None, value: str, context: str, kind: str = "text") -> None:
    if not value:
        return
    candidates.append({
        "rule": rule,
        "initial_priority": priority,
        "path": rel(path),
        "line": line,
        "fingerprint": fingerprint(value),
        "value_length": len(value),
        "kind": kind,
        "context": redact_context(context, value),
    })
    sensitive.append({"rule": rule, "path": rel(path), "line": line, "value": value})


def scan_shadow(path: Path, candidates: list[dict], sensitive: list[dict]) -> None:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for number, line in enumerate(lines, 1):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        username, credential = parts[0], parts[1]
        if credential in {"", "!", "!!", "*", "!*"}:
            if credential == "":
                add_candidate(candidates, sensitive, rule="empty_shadow_password", priority="HIGH", path=path, line=number, value=f"{username}:<empty>", context=f"{username}:<empty-password>", kind="account")
            continue
        add_candidate(candidates, sensitive, rule="shadow_credential", priority="MEDIUM", path=path, line=number, value=credential, context=f"{username}:<shadow-credential>", kind="account")


def main() -> int:
    _, secrets_cfg = load_config()
    rootfs = load_rootfs()
    REPORT.mkdir(parents=True, exist_ok=True)
    candidates: list[dict] = []
    sensitive_values: list[dict] = []
    scanned = skipped_large_binary = 0

    shadow = rootfs / "etc/shadow"
    if shadow.is_file():
        scan_shadow(shadow, candidates, sensitive_values)

    for current, _, filenames in os.walk(rootfs, followlinks=False):
        current_path = Path(current)
        for filename in filenames:
            path = current_path / filename
            if path == shadow or path.is_symlink():
                continue
            try:
                st = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue

            if filename in SENSITIVE_FILENAMES:
                try:
                    data = path.read_bytes()
                except OSError:
                    data = b""
                value = hashlib.sha256(data).hexdigest() if data else rel(path)
                add_candidate(
                    candidates, sensitive_values, rule="private_key_file", priority="HIGH",
                    path=path, line=None, value=value, context=f"private-key-like file {filename}", kind="file",
                )
                continue

            if not text_file(path):
                skipped_large_binary += 1
                continue
            scanned += 1
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for number, line in enumerate(text.splitlines(), 1):
                for rule, pattern, priority in RULES:
                    for match in pattern.finditer(line):
                        value = value_from_match(match)
                        # Very low-entropy templating placeholders are not useful
                        # secret candidates even when they match a generic key.
                        if value.lower() in {"password", "passwd", "secret", "token", "changeme", "example", "null", "none"}:
                            continue
                        add_candidate(
                            candidates, sensitive_values, rule=rule, priority=priority,
                            path=path, line=number, value=value, context=line,
                        )

    OUT.write_text(json.dumps(candidates, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    counts: dict[str, int] = {}
    for item in candidates:
        counts[item["rule"]] = counts.get(item["rule"], 0) + 1
    SUMMARY.write_text("\n".join([
        "# Firmware secret candidate scan",
        f"rootfs: {rel(rootfs)}",
        f"text files scanned: {scanned}",
        f"large/binary files skipped: {skipped_large_binary}",
        f"raw candidates: {len(candidates)}",
        "",
        "## Rules",
    ] + [f"- {rule}: {count}" for rule, count in sorted(counts.items())]) + "\n", encoding="utf-8")

    if secrets_cfg.get("store_plaintext", False):
        SENSITIVE.mkdir(parents=True, exist_ok=True)
        sensitive_path = SENSITIVE / "firmware-secrets.json"
        sensitive_path.write_text(json.dumps(sensitive_values, indent=2) + "\n", encoding="utf-8")
        os.chmod(sensitive_path, 0o600)

    print(f"[+] Firmware secret scan: {len(candidates)} redacted candidates from {scanned} text files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
