#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
OUT_DIR = ROOT / "reports" / "tool-output"
MAX_TEXT_FILE_BYTES = 5 * 1024 * 1024
MAX_CANDIDATES = 5000


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    pattern: re.Pattern[str]
    value_group: int = 0


RULES = [
    Rule(
        "private_key_pem",
        "HIGH_CONFIDENCE_SECRET",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    Rule(
        "aws_access_key_id",
        "CREDENTIAL_CANDIDATE",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    Rule(
        "github_token",
        "CREDENTIAL_CANDIDATE",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    ),
    Rule(
        "slack_token",
        "CREDENTIAL_CANDIDATE",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    Rule(
        "stripe_secret_key",
        "CREDENTIAL_CANDIDATE",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ),
    Rule(
        "google_api_key",
        "PUBLIC_CLIENT_CONFIG_CANDIDATE",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    Rule(
        "jwt_literal",
        "TOKEN_CANDIDATE",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    ),
    Rule(
        "basic_auth_url",
        "CREDENTIAL_CANDIDATE",
        re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:([^/\s@]+)@"),
        1,
    ),
    Rule(
        "authorization_basic_literal",
        "CREDENTIAL_CANDIDATE",
        re.compile(r"(?i)\bBasic\s+([A-Za-z0-9+/]{8,}={0,2})\b"),
        1,
    ),
    Rule(
        "authorization_bearer_literal",
        "TOKEN_CANDIDATE",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{12,})"),
        1,
    ),
    Rule(
        "generic_secret_assignment",
        "CREDENTIAL_CANDIDATE",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|client_secret|api_secret|secret_key|access_token|refresh_token|auth_token|api_key|apikey)\b"
            r"\s*[:=]\s*[\"']([^\"'\r\n]{4,})[\"']"
        ),
        1,
    ),
    Rule(
        "android_sensitive_string_resource",
        "CREDENTIAL_CANDIDATE",
        re.compile(
            r"(?i)<string\s+name=[\"'][^\"']*(?:password|passwd|secret|token|api_key|apikey|client_secret)[^\"']*[\"'][^>]*>\s*([^<]{4,})\s*</string>"
        ),
        1,
    ),
]

TEXT_SUFFIXES = {
    ".java", ".kt", ".kts", ".smali", ".xml", ".json", ".properties",
    ".gradle", ".txt", ".conf", ".cfg", ".ini", ".yaml", ".yml",
    ".html", ".htm", ".js", ".ts", ".pem", ".key", ".crt", ".cer",
    ".md", ".csv",
}


def load_config() -> dict:
    with TARGET.open("rb") as handle:
        config = tomllib.load(handle)
    if not config.get("engagement", {}).get("authorized", False):
        raise SystemExit("[!] engagement.authorized=false")
    return config


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def candidate_records(line: str, source: str, locator: int | str, source_kind: str):
    for rule in RULES:
        for match in rule.pattern.finditer(line):
            value = match.group(rule.value_group)
            if not value or len(value) > 16384:
                continue
            yield {
                "rule": rule.name,
                "category": rule.category,
                "source": source,
                "locator": locator,
                "source_kind": source_kind,
                "value_length": len(value),
                "value_sha256_prefix": fingerprint(value),
            }


def looks_textual(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\x00" not in sample


def scan_text_file(path: Path, root: Path):
    try:
        if path.stat().st_size > MAX_TEXT_FILE_BYTES or not looks_textual(path):
            return [], False
        records = []
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, 1):
                records.extend(
                    candidate_records(
                        line,
                        str(path.relative_to(ROOT)),
                        line_number,
                        "text",
                    )
                )
                if len(records) >= MAX_CANDIDATES:
                    return records, True
        return records, False
    except (OSError, ValueError):
        return [], False


def scan_native_strings(path: Path, strings_bin: str):
    records = []
    try:
        process = subprocess.Popen(
            [strings_bin, "-a", "-n", "4", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
        assert process.stdout is not None
        for string_number, line in enumerate(process.stdout, 1):
            records.extend(
                candidate_records(
                    line,
                    str(path.relative_to(ROOT)),
                    string_number,
                    "native_strings",
                )
            )
            if len(records) >= MAX_CANDIDATES:
                process.kill()
                break
        process.wait()
    except (OSError, ValueError):
        pass
    return records


def main() -> int:
    load_config()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    roots = [ROOT / "extracted" / "jadx", ROOT / "extracted" / "apktool"]
    records = []
    scanned_files = 0
    skipped_large_or_binary = 0
    truncated = False
    seen = set()

    for scan_root in roots:
        if not scan_root.exists():
            continue
        for path in scan_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() == ".so":
                continue
            found, hit_limit = scan_text_file(path, scan_root)
            scanned_files += 1
            if not found and (path.stat().st_size > MAX_TEXT_FILE_BYTES or not looks_textual(path)):
                skipped_large_or_binary += 1
            for record in found:
                key = (
                    record["rule"], record["source"], record["locator"],
                    record["value_sha256_prefix"],
                )
                if key not in seen:
                    seen.add(key)
                    records.append(record)
            if hit_limit or len(records) >= MAX_CANDIDATES:
                truncated = True
                break
        if truncated:
            break

    strings_bin = shutil.which("strings")
    if strings_bin and not truncated:
        native_root = ROOT / "extracted" / "apktool" / "lib"
        if native_root.exists():
            for path in native_root.rglob("*.so"):
                scanned_files += 1
                for record in scan_native_strings(path, strings_bin):
                    key = (
                        record["rule"], record["source"], record["locator"],
                        record["value_sha256_prefix"],
                    )
                    if key not in seen:
                        seen.add(key)
                        records.append(record)
                    if len(records) >= MAX_CANDIDATES:
                        truncated = True
                        break
                if truncated:
                    break

    records = records[:MAX_CANDIDATES]
    counts = Counter(record["category"] for record in records)

    payload = {
        "candidate_only": True,
        "raw_values_stored": False,
        "scanned_files": scanned_files,
        "skipped_large_or_binary": skipped_large_or_binary,
        "candidate_count": len(records),
        "truncated": truncated,
        "category_counts": dict(sorted(counts.items())),
        "candidates": records,
    }
    (OUT_DIR / "secret-candidates.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lines = [
        "# Deterministic APK secret/credential candidate scan",
        "",
        "Candidate hits are NOT findings. Raw candidate values are intentionally not stored here.",
        "The security agent must inspect each relevant local source location and classify it as a",
        "real secret/credential, public client configuration, certificate/trust material, test data,",
        "or false positive before reporting impact.",
        "",
        f"Scanned files: {scanned_files}",
        f"Skipped large/binary files: {skipped_large_or_binary}",
        f"Candidates: {len(records)}",
        f"Truncated at safety cap: {'yes' if truncated else 'no'}",
        "",
    ]
    for category, count in sorted(counts.items()):
        lines.append(f"- {category}: {count}")
    lines.append("")

    for record in sorted(
        records,
        key=lambda item: (item["category"], item["source"], str(item["locator"]), item["rule"]),
    ):
        locator_label = "line" if record["source_kind"] == "text" else "string"
        lines.append(
            f"{record['category']} {record['rule']} {record['source']}:{locator_label}={record['locator']} "
            f"len={record['value_length']} sha256-prefix={record['value_sha256_prefix']}"
        )

    (OUT_DIR / "secret-candidates.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"secret candidate scan complete: {len(records)} candidates across {scanned_files} files")
    print("candidate list: reports/tool-output/secret-candidates.txt")
    print("machine-readable: reports/tool-output/secret-candidates.json")
    if truncated:
        print("warning: candidate safety cap reached; coverage is degraded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
