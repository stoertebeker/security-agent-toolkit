#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "tool-output"
PREP = REPORT / "firmware-preparation.json"
WEB_FILES = REPORT / "firmware-web-files.json"
OUT_JSON = REPORT / "firmware-web-surface.json"
OUT_TXT = REPORT / "firmware-web-surface.txt"

MAX_TEXT_SIZE = 2 * 1024 * 1024
FIELD_TAG_RE = re.compile(r"<(input|textarea|select)\b([^>]*)>", re.I | re.S)
FORM_RE = re.compile(r"<form\b([^>]*)>", re.I | re.S)
ATTR_RE = re.compile(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.S)
QUERY_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.-]{1,80})=")
PARAM_TOKEN_RE = re.compile(r"\b(?:url|uri|host|hostname|domain|addr|address|ip|cmd|command|exec|script|shell|path|file|filename|target|server|remote|query|name|comment)_[0-9]+\b", re.I)
CLIENT_VALIDATION_RE = re.compile(r"(?i)\b(?:alert|confirm|is_domain|is_ip|isIp|check\w*|validate\w*|return\s+false|onSubmit)\b")

PATH_TERMS = {
    "diagnostic": 5, "ping": 5, "traceroute": 5, "parent": 6,
    "access": 4, "control": 4, "remote": 4, "manage": 3, "admin": 4,
    "upload": 5, "firmware": 6, "upgrade": 6, "restore": 5, "backup": 4,
    "ddns": 3, "virtualserver": 4, "dmz": 4, "upnp": 4, "security": 4,
    "password": 5, "login": 4, "system": 3, "route": 3, "firewall": 5,
}
FIELD_TERMS = {
    "cmd": 8, "command": 8, "exec": 8, "script": 7, "shell": 8,
    "url": 6, "uri": 6, "host": 5, "hostname": 5, "domain": 5,
    "addr": 5, "address": 5, "ip": 4, "path": 6, "file": 5,
    "filename": 5, "target": 4, "server": 4, "remote": 4, "query": 4,
}
FREEFORM_TYPES = {"", "text", "password", "search", "url", "email", "tel", "textarea", "unknown"}


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def attrs(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in ATTR_RE.finditer(raw):
        value = next((group for group in match.groups()[1:] if group is not None), "")
        result[match.group(1).lower()] = html.unescape(value)
    return result


def load_rootfs() -> tuple[Path, dict]:
    if not PREP.is_file():
        fail("firmware preparation missing")
    prep = json.loads(PREP.read_text())
    raw = prep.get("primary_rootfs") or prep.get("extraction_root")
    if not raw:
        fail("preparation did not establish a rootfs")
    raw_path = Path(str(raw))
    if raw_path.is_absolute() or ".." in raw_path.parts or raw_path.parts[:2] != ("work", "extracted"):
        fail(f"unsafe rootfs path: {raw}")
    rootfs = ROOT / raw_path
    try:
        st = rootfs.lstat()
    except OSError:
        fail(f"rootfs missing: {raw}")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        fail(f"rootfs is not a real directory: {raw}")
    return rootfs, prep


def score_name(name: str, table: dict[str, int]) -> tuple[int, list[str]]:
    lowered = name.lower()
    score = 0
    hits: list[str] = []
    for term, weight in table.items():
        if term in lowered:
            score += weight
            hits.append(term)
    return score, hits


def read_text(path: Path) -> str:
    try:
        st = path.lstat()
        if st.st_size > MAX_TEXT_SIZE:
            return ""
        data = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in data[:4096]:
        return ""
    return data.decode("utf-8", errors="replace")


def field_weight(name: str, field_type: str) -> tuple[int, list[str]]:
    score, hits = score_name(name, FIELD_TERMS)
    if hits and field_type in FREEFORM_TYPES:
        score += 4
    return score, hits


def analyze_file(path: Path, rootfs: Path) -> dict | None:
    text = read_text(path)
    if not text:
        return None
    relative = path.relative_to(rootfs).as_posix()
    path_score, path_hits = score_name(relative, PATH_TERMS)

    forms: list[dict] = []
    for match in FORM_RE.finditer(text):
        a = attrs(match.group(1))
        forms.append({"method": a.get("method", "GET").upper(), "action": a.get("action", "")})

    fields: dict[str, dict] = {}
    for match in FIELD_TAG_RE.finditer(text):
        tag = match.group(1).lower()
        a = attrs(match.group(2))
        name = a.get("name") or a.get("id") or ""
        if not name:
            continue
        field_type = "textarea" if tag == "textarea" else a.get("type", "unknown").lower()
        weight, hits = field_weight(name, field_type)
        fields[name] = {"name": name, "type": field_type, "risk_terms": hits, "risk_score": weight}

    discovered = set(QUERY_PARAM_RE.findall(text)) | set(PARAM_TOKEN_RE.findall(text))
    for name in discovered:
        if name not in fields:
            weight, hits = field_weight(name, "unknown")
            fields[name] = {"name": name, "type": "unknown", "risk_terms": hits, "risk_score": weight}

    risky_fields = sorted((item for item in fields.values() if item["risk_score"] > 0), key=lambda item: (-item["risk_score"], item["name"]))
    client_validation = bool(CLIENT_VALIDATION_RE.search(text))
    score = path_score
    if risky_fields:
        score += min(18, risky_fields[0]["risk_score"] + max(0, len(risky_fields) - 1))
    if forms:
        score += 2
    if client_validation and risky_fields:
        score += 2
    if any(form.get("method") == "GET" for form in forms) and risky_fields:
        score += 1
    if score <= 0 and not risky_fields:
        return None

    lead_id = "WS-" + hashlib.sha256(relative.encode("utf-8")).hexdigest()[:10]
    return {
        "lead_id": lead_id,
        "path": rel(path),
        "rootfs_relative": relative,
        "score": score,
        "path_risk_terms": path_hits,
        "forms": forms[:20],
        "fields": sorted(fields.values(), key=lambda item: item["name"])[:160],
        "risky_fields": risky_fields[:40],
        "client_validation_clues": client_validation,
        "evidence_role": "prioritization-only",
    }


def main() -> int:
    rootfs, prep = load_rootfs()
    try:
        listed = json.loads(WEB_FILES.read_text())
    except Exception:
        listed = []
    paths: list[Path] = []
    for value in listed:
        path = ROOT / str(value)
        try:
            path.relative_to(rootfs)
            st = path.lstat()
        except (ValueError, OSError):
            continue
        if stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode):
            paths.append(path)

    leads = [item for path in sorted(set(paths)) if (item := analyze_file(path, rootfs))]
    leads.sort(key=lambda item: (-int(item["score"]), str(item["rootfs_relative"])))
    high = [item for item in leads if int(item["score"]) >= 12]
    result = {
        "schema_version": 1,
        "firmware_sha256": prep.get("sha256"),
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "web_files_considered": len(paths),
        "lead_count": len(leads),
        "high_priority_count": len(high),
        "leads": leads[:300],
        "limitations": [
            "HTML/JavaScript parsing is conservative prioritization, not semantic proof",
            "client-side validation clues do not establish server-side validation or vulnerability",
            "parameter/page names require handler and source-to-sink correlation",
        ],
    }
    REPORT.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [f"firmware_sha256: {result['firmware_sha256']}", f"web_files_considered: {len(paths)}", f"lead_count: {len(leads)}", f"high_priority_count: {len(high)}", "", "# Ranked web attack-surface leads"]
    for item in leads[:80]:
        risky = ",".join(field["name"] for field in item["risky_fields"][:8]) or "-"
        lines.append(f"- {item['lead_id']} score={item['score']} path={item['rootfs_relative']} risky_fields={risky}")
    OUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Firmware web surface complete: files={len(paths)} leads={len(leads)} high={len(high)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
