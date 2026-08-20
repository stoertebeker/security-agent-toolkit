#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APKTOOL_ROOT = ROOT / "extracted" / "apktool"
OUT_DIR = ROOT / "reports" / "tool-output"
OUT_JSON = OUT_DIR / "native-baseline.json"
OUT_TXT = OUT_DIR / "native-baseline.txt"

DANGEROUS_IMPORTS = {
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "scanf",
    "sscanf",
    "system",
    "popen",
    "execl",
    "execle",
    "execlp",
    "execv",
    "execve",
    "execvp",
}

SECRET_PATTERNS = [
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_secret", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")),
    ("authorization_bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}")),
]


def run_text(command: list[str]) -> str:
    try:
        proc = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            errors="replace",
            timeout=45,
            check=False,
        )
        return proc.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def first_match(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1).strip() if match else None


def symbol_names(symbols: str) -> set[str]:
    names: set[str] = set()
    for line in symbols.splitlines():
        fields = line.split()
        if fields:
            name = fields[-1]
            if name and name not in {"UND", "ABS"}:
                names.add(name)
    return names


def undefined_symbols(symbols: str) -> set[str]:
    names: set[str] = set()
    for line in symbols.splitlines():
        if " UND " not in f" {line} ":
            continue
        fields = line.split()
        if fields:
            names.add(fields[-1].split("@", 1)[0])
    return names


def scan_string_leads(path: Path, strings_bin: str | None) -> list[dict]:
    if not strings_bin:
        return []
    leads: list[dict] = []
    try:
        proc = subprocess.Popen(
            [strings_bin, "-a", "-n", "6", str(path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            errors="replace",
        )
        assert proc.stdout is not None
        for index, line in enumerate(proc.stdout, 1):
            value = line.rstrip("\n")
            for name, pattern in SECRET_PATTERNS:
                if pattern.search(value):
                    leads.append({
                        "rule": name,
                        "string_index": index,
                        "value_length": len(value),
                    })
                    break
            if len(leads) >= 100:
                proc.kill()
                break
        proc.wait()
    except OSError:
        return []
    return leads


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    libs = sorted(APKTOOL_ROOT.rglob("*.so")) if APKTOOL_ROOT.exists() else []

    file_bin = shutil.which("file")
    readelf_bin = shutil.which("readelf")
    strings_bin = shutil.which("strings")
    missing = [name for name, value in (("file", file_bin), ("readelf", readelf_bin)) if not value]
    if missing:
        raise SystemExit("[!] native baseline requires: " + ", ".join(missing))

    records: list[dict] = []
    for path in libs:
        rel = str(path.relative_to(ROOT))
        file_out = run_text([file_bin, "-b", str(path)])
        header = run_text([readelf_bin, "-W", "-h", str(path)])
        program = run_text([readelf_bin, "-W", "-l", str(path)])
        dynamic = run_text([readelf_bin, "-W", "-d", str(path)])
        symbols = run_text([readelf_bin, "-W", "-s", str(path)])

        names = symbol_names(symbols)
        undefined = undefined_symbols(symbols)
        jni_exports = sorted(name for name in names if name == "JNI_OnLoad" or name.startswith("Java_"))[:100]
        dangerous = sorted(undefined.intersection(DANGEROUS_IMPORTS))
        fortified = sorted(name for name in undefined if name.endswith("_chk") or "__fortify" in name)[:50]

        stack_line = next((line for line in program.splitlines() if "GNU_STACK" in line), "")
        executable_stack = bool(re.search(r"\bRWE\b", stack_line))
        relro = "GNU_RELRO" in program
        bind_now = "BIND_NOW" in dynamic or bool(re.search(r"FLAGS(?:_1)?[^\n]*\bNOW\b", dynamic))
        textrel = "TEXTREL" in dynamic
        canary = "__stack_chk_fail" in names or "__stack_chk_fail" in undefined
        stripped = "stripped" in file_out.lower() and "not stripped" not in file_out.lower()

        split_match = re.search(r"extracted/apktool/splits/([^/]+)/", rel)
        records.append({
            "file": rel,
            "size": path.stat().st_size,
            "container_scope": "split" if split_match else "base",
            "split": split_match.group(1) if split_match else None,
            "file_description": file_out.strip(),
            "elf_class": first_match(r"Class:\s*(.+)", header),
            "machine": first_match(r"Machine:\s*(.+)", header),
            "elf_type": first_match(r"Type:\s*(.+)", header),
            "hardening": {
                "gnu_relro": relro,
                "bind_now": bind_now,
                "full_relro": relro and bind_now,
                "executable_stack": executable_stack,
                "textrel": textrel,
                "stack_canary_reference": canary,
                "fortify_import_count": len(fortified),
                "stripped": stripped,
            },
            "jni_exports": jni_exports,
            "dangerous_imports": dangerous,
            "secret_string_leads": scan_string_leads(path, strings_bin),
        })

    counts = Counter(record["container_scope"] for record in records)
    result = {
        "library_count": len(records),
        "base_library_count": counts.get("base", 0),
        "split_library_count": counts.get("split", 0),
        "libraries_with_jni_exports": sum(bool(record["jni_exports"]) for record in records),
        "libraries_with_executable_stack": sum(record["hardening"]["executable_stack"] for record in records),
        "libraries_with_textrel": sum(record["hardening"]["textrel"] for record in records),
        "libraries_with_dangerous_import_leads": sum(bool(record["dangerous_imports"]) for record in records),
        "native_secret_string_lead_count": sum(len(record["secret_string_leads"]) for record in records),
        "note": "Baseline indicators are review leads, not vulnerabilities. Native string leads omit raw values.",
        "libraries": records,
    }
    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# APK native baseline",
        "",
        f"libraries: {result['library_count']}",
        f"base libraries: {result['base_library_count']}",
        f"split libraries: {result['split_library_count']}",
        f"JNI-export libraries: {result['libraries_with_jni_exports']}",
        f"executable-stack libraries: {result['libraries_with_executable_stack']}",
        f"TEXTREL libraries: {result['libraries_with_textrel']}",
        f"dangerous-import lead libraries: {result['libraries_with_dangerous_import_leads']}",
        f"native secret-string leads: {result['native_secret_string_lead_count']}",
        "",
        "Indicators below are triage leads, not findings.",
        "",
    ]
    for record in records:
        h = record["hardening"]
        flags = []
        if record["jni_exports"]:
            flags.append(f"jni={len(record['jni_exports'])}")
        if record["dangerous_imports"]:
            flags.append("imports=" + ",".join(record["dangerous_imports"][:8]))
        if h["executable_stack"]:
            flags.append("execstack")
        if h["textrel"]:
            flags.append("textrel")
        if record["secret_string_leads"]:
            flags.append(f"secret-string-leads={len(record['secret_string_leads'])}")
        lines.append(
            f"{record['file']} scope={record['container_scope']} machine={record['machine'] or '?'} "
            f"relro={'full' if h['full_relro'] else 'partial' if h['gnu_relro'] else 'none'} "
            f"canary_ref={'yes' if h['stack_canary_reference'] else 'no'} "
            f"stripped={'yes' if h['stripped'] else 'no'}"
            + (" flags=[" + "; ".join(flags) + "]" if flags else "")
        )
    OUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"native baseline complete: {len(records)} libraries")
    print(f"report: {OUT_TXT.relative_to(ROOT)}")
    print(f"machine-readable: {OUT_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
