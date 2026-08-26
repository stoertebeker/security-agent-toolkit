#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "reports" / "tool-output"
REPORTS = ROOT / "reports"
FINDINGS = ROOT / "findings"
TARGET = ROOT / "target" / "TARGET.toml"


def read_many(paths: list[Path]) -> str:
    chunks = []
    for path in paths:
        if path.is_file():
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def load_json(path: Path, errors: list[str]) -> dict:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except Exception as exc:
        errors.append(f"invalid/missing {path.relative_to(ROOT)}: {exc}")
        return {}


def scout_seed_blocks(text: str) -> dict[str, str]:
    matches = list(re.finditer(r"(?im)^Seed-ID:\s*(CVE-\d{4}-\d{4,7})\s*$", text))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        blocks[match.group(1).upper()] = text[match.start():end]
    return blocks


def disclosed_local_anchor(block: str) -> bool:
    for field in ("Feature", "Endpoint", "Parameter"):
        match = re.search(rf"(?im)^{field}:\s*(.+?)\s*$", block)
        if match and match.group(1).strip().upper() not in {"UNKNOWN", "NONE", "N/A", "NOT DISCLOSED"}:
            return True
    return False


def web_disposition(text: str, lead_id: str) -> tuple[str, str] | None:
    match = re.search(
        rf"(?im)^Web disposition:\s*{re.escape(lead_id)}\s*->\s*(INVESTIGATE|DEPRIORITIZE)\s*;\s*reason=(.+)$",
        text,
    )
    return (match.group(1).upper(), match.group(2).strip()) if match else None


def bridge_disposition(text: str, bridge_id: str) -> tuple[str, str, str] | None:
    match = re.search(
        rf"(?im)^Bridge disposition:\s*{re.escape(bridge_id)}\s*->\s*(TRACE|DEPRIORITIZE)\s*;\s*local-hypothesis=([^;\n]+)\s*;\s*reason=(.+)$",
        text,
    )
    return (match.group(1).upper(), match.group(2).strip(), match.group(3).strip()) if match else None


def main() -> int:
    errors: list[str] = []
    checks: list[str] = []
    try:
        cfg = tomllib.loads(TARGET.read_text())
    except Exception as exc:
        print(f"Firmware hypothesis coverage check: FAIL\nFAIL: target config: {exc}")
        return 2

    subagent_paths = sorted((REPORTS / "subagents").glob("*.md")) if (REPORTS / "subagents").is_dir() else []
    finding_paths = sorted(FINDINGS.glob("*.md")) if FINDINGS.is_dir() else []
    coverage_text = read_many(subagent_paths + finding_paths + [REPORTS / "STATIC_SECURITY_REPORT.md"])

    surface = load_json(TOOL / "firmware-web-surface.json", errors)
    bridge_doc = load_json(TOOL / "firmware-web-native-bridge.json", errors)

    if surface:
        tool_path = ROOT / "tools" / "firmware_web_surface.py"
        current_tool_hash = hashlib.sha256(tool_path.read_bytes()).hexdigest() if tool_path.is_file() else ""
        if str(surface.get("tool_sha256") or "") != current_tool_hash:
            errors.append("firmware web-surface artifact is stale for current tool code; refresh firmware_baseline.py")
        else:
            checks.append("web-surface-provenance")

    if bridge_doc:
        bridge_tool = ROOT / "tools" / "firmware_web_native_bridge.py"
        current_bridge_hash = hashlib.sha256(bridge_tool.read_bytes()).hexdigest() if bridge_tool.is_file() else ""
        if str(bridge_doc.get("tool_sha256") or "") != current_bridge_hash:
            errors.append("firmware web/native bridge artifact is stale for current tool code; refresh firmware_baseline.py")
        elif surface and str(bridge_doc.get("firmware_sha256") or "") != str(surface.get("firmware_sha256") or ""):
            errors.append("firmware web/native bridge target hash does not match web-surface target")
        elif surface and str(bridge_doc.get("surface_tool_sha256") or "") != str(surface.get("tool_sha256") or ""):
            errors.append("firmware web/native bridge was generated from different web-surface tool provenance")
        else:
            checks.append("web-native-bridge-provenance")

    if surface:
        cap = int(cfg.get("analysis", {}).get("max_web_hypotheses", 6))
        leads = (surface.get("leads") or [])[:cap]
        bridge_by_lead = {
            str(item.get("lead_id")): item
            for item in (bridge_doc.get("leads") or [])
            if isinstance(item, dict) and item.get("lead_id")
        }
        web_ok = 0
        bridge_required = 0
        bridge_ok = 0
        for item in leads:
            lead_id = str(item.get("lead_id") or "")
            if not lead_id:
                continue
            disposition = web_disposition(coverage_text, lead_id)
            if not disposition:
                errors.append(f"top web lead lacks structured disposition: {lead_id}")
                continue
            web_ok += 1
            status, _reason = disposition
            if status != "INVESTIGATE":
                continue

            bridge_record = bridge_by_lead.get(lead_id) or {}
            trace_ready = [b for b in (bridge_record.get("bridges") or []) if isinstance(b, dict) and b.get("trace_ready")]
            if not trace_ready:
                continue
            bridge_required += 1
            strongest = trace_ready[0]
            bridge_id = str(strongest.get("bridge_id") or "")
            if not bridge_id:
                errors.append(f"trace-ready bridge for {lead_id} lacks bridge_id")
                continue
            bdisp = bridge_disposition(coverage_text, bridge_id)
            if not bdisp:
                errors.append(f"investigated web lead {lead_id} lacks disposition for strongest trace-ready bridge {bridge_id}")
                continue
            bstatus, hypothesis, _breason = bdisp
            bridge_ok += 1
            if bstatus == "TRACE":
                if hypothesis.lower() in {"none", "n/a", "unknown", "-"}:
                    errors.append(f"traced bridge {bridge_id} has no stable local hypothesis")
                # Explorer disposition plus at least one propagated downstream reference.
                if len(re.findall(rf"\b{re.escape(bridge_id)}\b", coverage_text)) < 2:
                    errors.append(f"traced bridge {bridge_id} was not propagated beyond its disposition")
                exact_fields = [str(value) for value in strongest.get("exact_risky_fields") or []]
                if exact_fields and not any(re.search(rf"\b{re.escape(field)}\b", coverage_text) for field in exact_fields):
                    errors.append(f"traced bridge {bridge_id} lost its exact risky request-field token(s)")

        if web_ok == len([item for item in leads if item.get("lead_id")]):
            checks.append(f"web-lead-disposition {web_ok}/{web_ok}")
        if bridge_required:
            checks.append(f"trace-ready-bridge-disposition {bridge_ok}/{bridge_required}")
        else:
            checks.append("trace-ready-bridge-disposition none-required")

    if cfg.get("orchestration", {}).get("advisory_scout", False):
        identity = load_json(TOOL / "firmware-identity.json", errors)
        if identity:
            canonical = identity.get("canonical") or {}
            summary = ", ".join(f"{key}={value.get('value')}[{value.get('confidence')}]" for key, value in canonical.items() if isinstance(value, dict))
            checks.append(f"firmware-identity advisory_ready={bool(identity.get('advisory_ready'))} exact={bool(identity.get('exact_identity'))}: {summary[:240]}")

        research_dir = REPORTS / "research"
        scouts = sorted(research_dir.glob("RQ-ADVISORY-SCOUT*.md")) if research_dir.is_dir() else []
        if not scouts:
            errors.append("advisory_scout enabled but RQ-ADVISORY-SCOUT artifact missing")
        else:
            scout_text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in scouts)
            seed_blocks = scout_seed_blocks(scout_text)
            mentioned = sorted(set(cve.upper() for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", scout_text, re.I)))
            missing_blocks = [cve for cve in mentioned if cve not in seed_blocks]
            if missing_blocks:
                errors.append("advisory scout CVEs lack structured Seed-ID blocks: " + ", ".join(missing_blocks))

            for cve, block in seed_blocks.items():
                match = re.search(
                    rf"(?im)^Seed disposition:\s*{re.escape(cve)}\s*->\s*(INVESTIGATED|REJECTED|DEFERRED_CVE_IDENTITY)\s*;\s*local-hypothesis=([^;\n]+)\s*;\s*reason=(.+)$",
                    coverage_text,
                )
                if not match:
                    errors.append(f"advisory seed lacks structured local disposition: {cve}")
                    continue
                status = match.group(1).upper()
                hypothesis = match.group(2).strip()
                if status == "DEFERRED_CVE_IDENTITY" and identity.get("exact_identity"):
                    errors.append(f"{cve} deferred for identity even though firmware-identity exact_identity=true")
                if status == "DEFERRED_CVE_IDENTITY" and disclosed_local_anchor(block) and hypothesis.lower() in {"none", "n/a", "unknown", "-"}:
                    errors.append(f"{cve} discloses a local feature/endpoint/parameter but identity deferral has no local hypothesis")
            if seed_blocks:
                checks.append(f"advisory-seed-dispositions={len(seed_blocks)}")
    else:
        checks.append("advisory-scout disabled (blind discovery)")

    status = "PASS" if not errors else "FAIL"
    print(f"Firmware hypothesis coverage check: {status}")
    for item in checks:
        print(f"PASS: {item}")
    for item in errors:
        print(f"FAIL: {item}")
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
