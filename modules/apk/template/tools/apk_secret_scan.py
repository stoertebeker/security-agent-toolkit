#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote_to_bytes

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
OUT_DIR = ROOT / "reports" / "tool-output"
SENSITIVE_DIR = ROOT / "reports" / "sensitive"
MAX_TEXT_FILE_BYTES = 5 * 1024 * 1024
MAX_CANDIDATES = 5000


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    pattern: re.Pattern[str]
    value_group: int = 0


RULES = [
    Rule("bcrypt", "HASH_OR_KDF_CANDIDATE", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")),
    Rule("argon2", "HASH_OR_KDF_CANDIDATE", re.compile(r"\$argon2(?:id|i|d)\$[^\s\"']{16,}")),
    Rule("md5crypt", "HASH_OR_KDF_CANDIDATE", re.compile(r"\$1\$[^\s\"']{3,}")),
    Rule("sha256crypt", "HASH_OR_KDF_CANDIDATE", re.compile(r"\$5\$[^\s\"']{3,}")),
    Rule("sha512crypt", "HASH_OR_KDF_CANDIDATE", re.compile(r"\$6\$[^\s\"']{3,}")),
    Rule("phpass", "HASH_OR_KDF_CANDIDATE", re.compile(r"\$[PH]\$[./0-9A-Za-z]{31}")),
    Rule("private_key_pem_header", "HIGH_CONFIDENCE_SECRET", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    Rule("aws_access_key_id", "CREDENTIAL_CANDIDATE", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("github_token", "CREDENTIAL_CANDIDATE", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
    Rule("slack_token", "CREDENTIAL_CANDIDATE", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("stripe_secret_key", "CREDENTIAL_CANDIDATE", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    Rule("google_api_key", "PUBLIC_CLIENT_CONFIG_CANDIDATE", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    Rule("jwt_literal", "TOKEN_CANDIDATE", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")),
    Rule("basic_auth_url", "CREDENTIAL_CANDIDATE", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:([^/\s@]+)@"), 1),
    Rule("authorization_basic_literal", "CREDENTIAL_CANDIDATE", re.compile(r"(?i)\bBasic\s+([A-Za-z0-9+/]{8,}={0,2})\b"), 1),
    Rule("authorization_bearer_literal", "TOKEN_CANDIDATE", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{12,})"), 1),
    Rule(
        "generic_secret_assignment",
        "CREDENTIAL_CANDIDATE",
        re.compile(r"(?i)\b(?:password|passwd|pwd|client_secret|api_secret|secret_key|access_token|refresh_token|auth_token|api_key|apikey)\b\s*[:=]\s*[\"']([^\"'\r\n]{4,})[\"']"),
        1,
    ),
    Rule(
        "hash_named_assignment",
        "HASH_OR_KDF_CANDIDATE",
        re.compile(r"(?i)\b(?:password_hash|passwd_hash|pwd_hash|hash|digest|checksum|md5|sha1|sha_?1|sha224|sha256|sha_?256|sha384|sha512|sha_?512)\b\s*[:=]\s*[\"']([^\"'\r\n]{16,512})[\"']"),
        1,
    ),
    Rule(
        "android_sensitive_string_resource",
        "CREDENTIAL_CANDIDATE",
        re.compile(r"(?i)<string\s+name=[\"'][^\"']*(?:password|passwd|secret|token|api_key|apikey|client_secret)[^\"']*[\"'][^>]*>\s*([^<]{4,})\s*</string>"),
        1,
    ),
    Rule(
        "android_hash_string_resource",
        "HASH_OR_KDF_CANDIDATE",
        re.compile(r"(?i)<string\s+name=[\"'][^\"']*(?:password_hash|hash|digest|checksum|md5|sha1|sha256|sha512)[^\"']*[\"'][^>]*>\s*([^<]{16,512})\s*</string>"),
        1,
    ),
]

PRIVATE_KEY_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \1-----", re.DOTALL)

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


def fingerprint(value: str | bytes) -> str:
    data = value.encode("utf-8", errors="replace") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()[:16]


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
                "_value": value,
            }


def looks_textual(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\x00" not in sample


def scan_text_file(path: Path):
    try:
        if path.stat().st_size > MAX_TEXT_FILE_BYTES or not looks_textual(path):
            return [], False
        text = path.read_text(encoding="utf-8", errors="replace")
        source = str(path.relative_to(ROOT))
        records = []
        for line_number, line in enumerate(text.splitlines(), 1):
            records.extend(candidate_records(line, source, line_number, "text"))
            if len(records) >= MAX_CANDIDATES:
                return records, True
        for match in PRIVATE_KEY_BLOCK_RE.finditer(text):
            value = match.group(0)
            line_number = text.count("\n", 0, match.start()) + 1
            records.append({
                "rule": "private_key_pem_block",
                "category": "HIGH_CONFIDENCE_SECRET",
                "source": source,
                "locator": line_number,
                "source_kind": "text",
                "value_length": len(value),
                "value_sha256_prefix": fingerprint(value),
                "_value": value,
            })
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
            records.extend(candidate_records(line, str(path.relative_to(ROOT)), string_number, "native_strings"))
            if len(records) >= MAX_CANDIDATES:
                process.kill()
                break
        process.wait()
    except (OSError, ValueError):
        pass
    return records


def printable_text(data: bytes) -> str | None:
    if not data or b"\x00" in data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return text if printable / max(len(text), 1) >= 0.9 else None


def attempt_decodings(value: str, max_depth: int) -> list[dict]:
    if max_depth <= 0:
        return []
    results: list[dict] = []
    queue: list[tuple[str, int, list[str]]] = [(value, 0, [])]
    seen = {value}
    while queue:
        current, depth, chain = queue.pop(0)
        if depth >= max_depth:
            continue
        attempts: list[tuple[str, bytes]] = []
        if re.search(r"%[0-9A-Fa-f]{2}", current):
            try:
                decoded = unquote_to_bytes(current)
                if decoded != current.encode("utf-8", errors="replace"):
                    attempts.append(("percent", decoded))
            except Exception:
                pass
        compact = current.strip()
        if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
            try:
                attempts.append(("hex", bytes.fromhex(compact)))
            except ValueError:
                pass
        if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
            padded = compact + "=" * ((4 - len(compact) % 4) % 4)
            try:
                attempts.append(("base64", base64.b64decode(padded, validate=True)))
            except Exception:
                pass
        if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", compact):
            padded = compact + "=" * ((4 - len(compact) % 4) % 4)
            try:
                attempts.append(("base64url", base64.urlsafe_b64decode(padded)))
            except Exception:
                pass
        for encoding, decoded in attempts:
            if not decoded:
                continue
            text = printable_text(decoded)
            item = {
                "encoding_chain": chain + [encoding],
                "decoded_length": len(decoded),
                "decoded_sha256_prefix": fingerprint(decoded),
                "printable_text": text is not None,
            }
            if text is not None:
                item["_decoded_text"] = text
                if text not in seen:
                    seen.add(text)
                    queue.append((text, depth + 1, chain + [encoding]))
            results.append(item)
    unique = []
    keys = set()
    for item in results:
        key = (tuple(item["encoding_chain"]), item["decoded_sha256_prefix"], item["decoded_length"])
        if key not in keys:
            keys.add(key)
            unique.append(item)
    return unique[:12]


def hash_candidates(value: str) -> list[dict]:
    value = value.strip()
    result: list[dict] = []

    def add(type_name: str, confidence: str, modes: list[int] | None, reason: str):
        result.append({
            "type": type_name,
            "confidence": confidence,
            "hashcat_candidate_modes": modes or [],
            "reason": reason,
        })

    if re.fullmatch(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", value):
        add("bcrypt", "HIGH", [3200], "structured $2*$ bcrypt format")
        return result
    if value.startswith("$1$"):
        add("md5crypt", "HIGH", [500], "structured $1$ Unix crypt format")
        return result
    if value.startswith("$5$"):
        add("sha256crypt", "HIGH", [7400], "structured $5$ Unix crypt format")
        return result
    if value.startswith("$6$"):
        add("sha512crypt", "HIGH", [1800], "structured $6$ Unix crypt format")
        return result
    if re.fullmatch(r"\$[PH]\$[./0-9A-Za-z]{31}", value):
        add("phpass", "HIGH", [400], "structured phpass format")
        return result
    if re.match(r"^\$argon2(?:id|i|d)\$", value):
        add("Argon2 encoded hash", "HIGH", [34000], "structured Argon2 PHC string; confirm local hashcat version/mode before use")
        return result
    if value.startswith("$scrypt$"):
        add("scrypt encoded hash", "HIGH", [8900], "structured scrypt string; confirm exact serialized format against local hashcat")
        return result
    if re.fullmatch(r"[0-9A-Fa-f]+", value):
        n = len(value)
        if n == 32:
            add("128-bit bare hex digest", "LOW", [0, 900, 1000], "compatible with MD5, MD4, NTLM and other 128-bit digests; type is ambiguous")
        elif n == 40:
            add("160-bit bare hex digest", "LOW", [100], "compatible with SHA-1 and other 160-bit digests; type is ambiguous")
        elif n == 56:
            add("224-bit bare hex digest", "LOW", [1300], "compatible with SHA2-224 and other 224-bit digests")
        elif n == 64:
            add("256-bit bare hex digest", "LOW", [1400], "compatible with SHA2-256 and other 256-bit digests; type is ambiguous")
        elif n == 96:
            add("384-bit bare hex digest", "LOW", [10800], "compatible with SHA2-384 and other 384-bit digests")
        elif n == 128:
            add("512-bit bare hex digest", "LOW", [1700], "compatible with SHA2-512 and other 512-bit digests; type is ambiguous")
    return result


def public_record(record: dict, analyze_encodings: bool, analyze_hashes: bool, max_decode_depth: int) -> dict:
    item = {k: v for k, v in record.items() if not k.startswith("_")}
    value = record["_value"]
    encodings = attempt_decodings(value, max_decode_depth) if analyze_encodings else []
    if analyze_encodings:
        clean = []
        for enc in encodings:
            enc = dict(enc)
            enc.pop("_decoded_text", None)
            clean.append(enc)
        item["encoding_analysis"] = clean
    if analyze_hashes:
        hashes = hash_candidates(value)
        for enc in encodings:
            decoded = enc.get("_decoded_text")
            if decoded:
                hashes.extend({**candidate, "after_encoding_chain": enc["encoding_chain"]} for candidate in hash_candidates(decoded))
        item["hash_analysis"] = hashes
    return item


def sensitive_record(record: dict, analyze_encodings: bool, analyze_hashes: bool, max_decode_depth: int) -> dict:
    item = {k: v for k, v in record.items() if not k.startswith("_")}
    value = record["_value"]
    item["value"] = value
    encodings = attempt_decodings(value, max_decode_depth) if analyze_encodings else []
    if encodings:
        clean = []
        for enc in encodings:
            enc = dict(enc)
            decoded = enc.pop("_decoded_text", None)
            if decoded is not None:
                enc["decoded_text"] = decoded
            clean.append(enc)
        item["encoding_analysis"] = clean
    if analyze_hashes:
        hashes = hash_candidates(value)
        for enc in encodings:
            decoded = enc.get("_decoded_text")
            if decoded:
                hashes.extend({**candidate, "after_encoding_chain": enc["encoding_chain"], "decoded_value": decoded} for candidate in hash_candidates(decoded))
        item["hash_analysis"] = hashes
    return item


def write_sensitive_outputs(records: list[dict], analyze_encodings: bool, analyze_hashes: bool, max_decode_depth: int):
    SENSITIVE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(SENSITIVE_DIR, 0o700)
    except OSError:
        pass
    sensitive = [sensitive_record(record, analyze_encodings, analyze_hashes, max_decode_depth) for record in records]
    payload = {"warning": "CONTAINS RAW SECRETS/CREDENTIAL MATERIAL. KEEP LOCAL.", "candidates": sensitive}
    values_json = SENSITIVE_DIR / "secret-values.json"
    values_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# RAW APK secret / credential material", "# CONTAINS SENSITIVE VALUES. KEEP LOCAL.", ""]
    hash_lines = ["# Hash / KDF candidates for later offline review", "# No cracking is performed by this toolkit.", "# Hashcat modes are candidates only; LOW-confidence bare digests are ambiguous.", ""]
    for item in sensitive:
        lines.append(f"[{item['category']}] {item['rule']} {item['source']}:{item['locator']}")
        lines.append("value:")
        lines.append(item["value"])
        for enc in item.get("encoding_analysis", []):
            if "decoded_text" in enc:
                lines.append(f"decoded ({' -> '.join(enc['encoding_chain'])}): {enc['decoded_text']}")
        for hc in item.get("hash_analysis", []):
            chain = hc.get("after_encoding_chain")
            prefix = f" after {' -> '.join(chain)}" if chain else ""
            lines.append(f"hash candidate{prefix}: {hc['type']} confidence={hc['confidence']} hashcat_modes={hc['hashcat_candidate_modes']} reason={hc['reason']}")
            raw_hash = hc.get("decoded_value", item["value"])
            hash_lines.append(f"type={hc['type']} confidence={hc['confidence']} modes={','.join(str(m) for m in hc['hashcat_candidate_modes']) or '?'} source={item['source']}:{item['locator']} value={raw_hash}")
        lines.append("")
    values_txt = SENSITIVE_DIR / "secret-values.txt"
    values_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    hash_txt = SENSITIVE_DIR / "hash-material.txt"
    hash_txt.write_text("\n".join(hash_lines) + "\n", encoding="utf-8")
    for path in (values_json, values_txt, hash_txt):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def main() -> int:
    config = load_config()
    secret_cfg = config.get("secrets", {})
    store_plaintext = bool(secret_cfg.get("store_plaintext", False))
    analyze_encodings = bool(secret_cfg.get("analyze_encodings", True))
    analyze_hashes = bool(secret_cfg.get("analyze_hashes", True))
    max_decode_depth = secret_cfg.get("max_decode_depth", 2)
    if not isinstance(max_decode_depth, int):
        raise SystemExit("[!] secrets.max_decode_depth must be an integer")
    max_decode_depth = max(0, min(max_decode_depth, 3))
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
            found, hit_limit = scan_text_file(path)
            scanned_files += 1
            try:
                skipped = path.stat().st_size > MAX_TEXT_FILE_BYTES or not looks_textual(path)
            except OSError:
                skipped = True
            if not found and skipped:
                skipped_large_or_binary += 1
            for record in found:
                key = (record["source"], record["locator"], record["value_sha256_prefix"])
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
                    key = (record["source"], record["locator"], record["value_sha256_prefix"])
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
    public_records = [public_record(record, analyze_encodings, analyze_hashes, max_decode_depth) for record in records]
    payload = {
        "candidate_only": True,
        "raw_values_stored": store_plaintext,
        "raw_values_location": "reports/sensitive/" if store_plaintext else None,
        "analyze_encodings": analyze_encodings,
        "analyze_hashes": analyze_hashes,
        "max_decode_depth": max_decode_depth,
        "scanned_files": scanned_files,
        "skipped_large_or_binary": skipped_large_or_binary,
        "candidate_count": len(records),
        "truncated": truncated,
        "category_counts": dict(sorted(counts.items())),
        "candidates": public_records,
    }
    (OUT_DIR / "secret-candidates.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Deterministic APK secret/credential/hash candidate scan",
        "",
        "Candidate hits are NOT findings.",
        "Raw values are stored under reports/sensitive/ because secrets.store_plaintext=true." if store_plaintext else "Raw candidate values are intentionally not stored in this report.",
        "Encoding/hash guesses are hints only and require local context validation.",
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
    for record in sorted(public_records, key=lambda item: (item["category"], item["source"], str(item["locator"]), item["rule"])):
        locator_label = "line" if record["source_kind"] == "text" else "string"
        lines.append(f"{record['category']} {record['rule']} {record['source']}:{locator_label}={record['locator']} len={record['value_length']} sha256-prefix={record['value_sha256_prefix']}")
        for hc in record.get("hash_analysis", []):
            chain = hc.get("after_encoding_chain")
            suffix = f" after={'->'.join(chain)}" if chain else ""
            lines.append(f"  hash_guess={hc['type']} confidence={hc['confidence']} hashcat_modes={hc['hashcat_candidate_modes']}{suffix}")
        for enc in record.get("encoding_analysis", []):
            if enc.get("printable_text"):
                lines.append(f"  encoding={'->'.join(enc['encoding_chain'])} decoded_len={enc['decoded_length']} decoded_sha256-prefix={enc['decoded_sha256_prefix']}")
    (OUT_DIR / "secret-candidates.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if store_plaintext:
        write_sensitive_outputs(records, analyze_encodings, analyze_hashes, max_decode_depth)
    print(f"secret/material scan complete: {len(records)} candidates across {scanned_files} files")
    print("redacted candidate list: reports/tool-output/secret-candidates.txt")
    print("machine-readable: reports/tool-output/secret-candidates.json")
    if store_plaintext:
        print("RAW sensitive values: reports/sensitive/secret-values.txt")
        print("hash material: reports/sensitive/hash-material.txt")
    if truncated:
        print("warning: candidate safety cap reached; coverage is degraded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
