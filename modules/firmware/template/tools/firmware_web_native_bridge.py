#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "reports" / "tool-output"
PREP = TOOL / "firmware-preparation.json"
SURFACE = TOOL / "firmware-web-surface.json"
BINARIES = TOOL / "firmware-binaries.json"
OUT_JSON = TOOL / "firmware-web-native-bridge.json"
OUT_TXT = TOOL / "firmware-web-native-bridge.txt"

MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_LEADS = 24
MAX_BRIDGES_PER_LEAD = 8

SENSITIVE_IMPORTS = {
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp",
    "fork", "vfork", "posix_spawn", "posix_spawnp",
    "open", "fopen", "write", "ioctl",
    "socket", "connect", "send", "sendto", "recv", "recvfrom",
}

INDEXED_FIELD_RE = re.compile(r"^(?P<prefix>[A-Za-z][A-Za-z0-9_-]*?[_-])\d+$")


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        fail(f"cannot read {path.relative_to(ROOT)}: {exc}")


def load_rootfs() -> Path:
    prep = load_json(PREP)
    raw = prep.get("primary_rootfs") or prep.get("extraction_root")
    if not raw:
        fail("preparation did not establish a rootfs")
    relative = Path(str(raw))
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:2] != ("work", "extracted"):
        fail(f"unsafe rootfs path: {raw}")
    rootfs = ROOT / relative
    try:
        st = rootfs.lstat()
    except OSError:
        fail(f"rootfs missing: {raw}")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        fail(f"rootfs is not a real directory: {raw}")
    return rootfs


def resolve_binary(rootfs: Path, workspace_path: str) -> Path | None:
    try:
        candidate = (ROOT / workspace_path).resolve()
        candidate.relative_to(rootfs.resolve())
        st = candidate.lstat()
    except (ValueError, OSError):
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BINARY_BYTES:
        return None
    return candidate


def token_variants(lead: dict) -> list[dict]:
    tokens: dict[tuple[str, str], dict] = {}

    def add(value: str, kind: str, weight: int, exact: bool = True) -> None:
        value = value.strip()
        if len(value) < 3 or len(value) > 120:
            return
        key = (value.lower(), kind)
        current = tokens.get(key)
        item = {"value": value, "kind": kind, "weight": weight, "exact": exact}
        if current is None or weight > int(current["weight"]):
            tokens[key] = item

    relative = str(lead.get("rootfs_relative") or "")
    name = Path(relative).name
    stem = Path(relative).stem
    if name:
        add(name, "route-file", 9)
    if stem and stem != name:
        add(stem, "route-stem", 6)

    for form in lead.get("forms") or []:
        action = str(form.get("action") or "").strip()
        if not action:
            continue
        add(action, "form-action", 8)
        action_name = Path(action.split("?", 1)[0]).name
        if action_name and action_name != action:
            add(action_name, "form-action-file", 7)

    risky_names = {str(item.get("name") or "") for item in lead.get("risky_fields") or []}
    for field in lead.get("fields") or []:
        name = str(field.get("name") or "").strip()
        if not name:
            continue
        risky = name in risky_names or int(field.get("risk_score") or 0) > 0
        add(name, "request-field-risky" if risky else "request-field", 12 if risky else 6)
        indexed = INDEXED_FIELD_RE.match(name)
        if indexed:
            add(indexed.group("prefix"), "request-field-prefix", 5, exact=False)

    return sorted(tokens.values(), key=lambda item: (-int(item["weight"]), item["kind"], item["value"].lower()))


def raw_contains(data: bytes, token: str) -> tuple[bool, bool]:
    ascii_token = token.encode("utf-8", errors="ignore")
    ascii_hit = bool(ascii_token and ascii_token in data)
    try:
        wide = token.encode("utf-16le")
    except UnicodeEncodeError:
        wide = b""
    wide_hit = bool(wide and wide in data)
    return ascii_hit, wide_hit


def bridge_score(matches: list[dict], sensitive_imports: list[str], priority_reasons: list[str]) -> int:
    score = sum(int(item["weight"]) for item in matches)
    kinds = {item["kind"] for item in matches}
    if any(kind.startswith("request-field") for kind in kinds) and any(kind.startswith("route") or kind.startswith("form-action") for kind in kinds):
        score += 10
    if "request-field-risky" in kinds:
        score += 8
    if sensitive_imports:
        score += min(8, len(sensitive_imports) * 2)
    if any("startup/service correlation" in reason for reason in priority_reasons):
        score += 2
    return score


def main() -> int:
    rootfs = load_rootfs()
    surface = load_json(SURFACE)
    binary_doc = load_json(BINARIES)
    if not isinstance(binary_doc, list):
        fail("firmware-binaries.json is not a list")

    binaries: list[tuple[dict, Path, bytes]] = []
    for item in binary_doc:
        if not isinstance(item, dict) or not item.get("path"):
            continue
        path = resolve_binary(rootfs, str(item["path"]))
        if path is None:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        binaries.append((item, path, data))

    leads_out: list[dict] = []
    all_bridges: list[dict] = []
    for lead in (surface.get("leads") or [])[:MAX_LEADS]:
        lead_id = str(lead.get("lead_id") or "")
        if not lead_id:
            continue
        tokens = token_variants(lead)
        bridges: list[dict] = []
        for meta, path, data in binaries:
            matches: list[dict] = []
            for token in tokens:
                ascii_hit, wide_hit = raw_contains(data, token["value"])
                if not ascii_hit and not wide_hit:
                    continue
                matches.append({
                    **token,
                    "encoding": "ascii+utf16le" if ascii_hit and wide_hit else "ascii" if ascii_hit else "utf16le",
                })
            if not matches:
                continue
            sensitive = sorted(set(meta.get("dangerous_imports") or []).union(meta.get("network_imports") or []).intersection(SENSITIVE_IMPORTS))
            priority_reasons = list(meta.get("priority_reasons") or meta.get("reasons") or [])
            score = bridge_score(matches, sensitive, priority_reasons)
            exact_fields = [m["value"] for m in matches if m["kind"] in {"request-field-risky", "request-field"} and m.get("exact")]
            risky_fields = [m["value"] for m in matches if m["kind"] == "request-field-risky" and m.get("exact")]
            routes = [m["value"] for m in matches if m["kind"].startswith("route") or m["kind"].startswith("form-action")]
            trace_needles: list[str] = []
            for value in risky_fields + exact_fields + routes:
                if value not in trace_needles:
                    trace_needles.append(value)
                if len(trace_needles) >= 6:
                    break
            bridge_id = "WB-" + hashlib.sha256(f"{lead_id}\0{meta['path']}".encode()).hexdigest()[:10]
            bridges.append({
                "bridge_id": bridge_id,
                "lead_id": lead_id,
                "binary": str(meta["path"]),
                "score": score,
                "matches": matches,
                "exact_request_fields": exact_fields,
                "exact_risky_fields": risky_fields,
                "route_tokens": routes,
                "sensitive_imports": sensitive,
                "trace_needles": trace_needles,
                "trace_ready": bool(risky_fields and routes),
                "evidence_role": "native-correlation-prioritization-only",
            })
        bridges.sort(key=lambda item: (-int(item["score"]), str(item["binary"])))
        bridges = bridges[:MAX_BRIDGES_PER_LEAD]
        leads_out.append({
            "lead_id": lead_id,
            "web_path": lead.get("rootfs_relative"),
            "web_score": lead.get("score"),
            "bridge_count": len(bridges),
            "bridges": bridges,
        })
        all_bridges.extend(bridges)

    all_bridges.sort(key=lambda item: (-int(item["score"]), item["lead_id"], item["binary"]))
    result = {
        "schema_version": 1,
        "firmware_sha256": surface.get("firmware_sha256"),
        "surface_tool_sha256": surface.get("tool_sha256"),
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "lead_count": len(leads_out),
        "binary_count_considered": len(binaries),
        "bridge_count": len(all_bridges),
        "trace_ready_count": sum(1 for item in all_bridges if item.get("trace_ready")),
        "leads": leads_out,
        "ranked_bridges": all_bridges[:120],
        "limitations": [
            "exact string co-occurrence links web tokens to candidate ELFs but does not prove control flow",
            "absence of a token match does not exclude generated names, hashed dispatch, structured IPC, or runtime decoding",
            "sensitive imports are prioritization only; a focused native trace must establish source-to-sink flow",
        ],
    }
    TOOL.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        f"firmware_sha256: {result['firmware_sha256']}",
        f"leads: {len(leads_out)} binaries: {len(binaries)} bridges: {len(all_bridges)} trace_ready: {result['trace_ready_count']}",
        "",
        "# Ranked web -> native bridge candidates",
    ]
    for item in all_bridges[:80]:
        fields = ",".join(item["exact_risky_fields"] or item["exact_request_fields"][:4]) or "-"
        routes = ",".join(item["route_tokens"][:3]) or "-"
        imports = ",".join(item["sensitive_imports"][:6]) or "-"
        lines.append(f"- {item['bridge_id']} lead={item['lead_id']} score={item['score']} trace_ready={str(item['trace_ready']).lower()} binary={item['binary']} fields={fields} routes={routes} imports={imports}")
    OUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Firmware web/native bridge complete: leads={len(leads_out)} binaries={len(binaries)} bridges={len(all_bridges)} trace_ready={result['trace_ready_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
