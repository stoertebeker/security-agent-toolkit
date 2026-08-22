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


def main() -> int:
    errors: list[str] = []
    checks: list[str] = []
    try:
        cfg = tomllib.loads(TARGET.read_text())
    except Exception as exc:
        print(f"Firmware hypothesis coverage check: FAIL\nFAIL: target config: {exc}")
        return 2

    surface_path = TOOL / "firmware-web-surface.json"
    if not surface_path.is_file():
        errors.append("firmware-web-surface.json missing")
    else:
        try:
            surface = json.loads(surface_path.read_text())
        except Exception as exc:
            errors.append(f"invalid web surface: {exc}")
            surface = {}
        tool_path = ROOT / "tools" / "firmware_web_surface.py"
        if tool_path.is_file():
            current_tool_hash = hashlib.sha256(tool_path.read_bytes()).hexdigest()
            recorded_tool_hash = str(surface.get("tool_sha256") or "")
            if recorded_tool_hash != current_tool_hash:
                errors.append("firmware web-surface artifact is stale for current tool code; refresh firmware_baseline.py")
            else:
                checks.append("web-surface-provenance")
        cap = int(cfg.get("analysis", {}).get("max_web_hypotheses", 6))
        leads = (surface.get("leads") or [])[:cap]
        coverage = read_many([
            REPORTS / "subagents" / "firmware-explorer-review.md",
            REPORTS / "subagents" / "firmware-service-review.md",
            FINDINGS / "attack-surface.md",
            FINDINGS / "findings.md",
        ])
        missing = [str(item.get("lead_id")) for item in leads if item.get("lead_id") and str(item.get("lead_id")) not in coverage]
        if missing:
            errors.append("top web leads lack explicit disposition: " + ", ".join(missing))
        else:
            checks.append(f"web-lead-disposition {len(leads)}/{len(leads)}")

    if cfg.get("orchestration", {}).get("advisory_scout", False):
        research_dir = REPORTS / "research"
        scouts = sorted(research_dir.glob("RQ-ADVISORY-SCOUT*.md")) if research_dir.is_dir() else []
        if not scouts:
            errors.append("advisory_scout enabled but RQ-ADVISORY-SCOUT artifact missing")
        else:
            scout_text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in scouts)
            cves = sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", scout_text, re.I)))
            disposition = read_many(list(FINDINGS.glob("*.md")) + list((REPORTS / "subagents").glob("*.md")) + [REPORTS / "STATIC_SECURITY_REPORT.md"])
            missing = [cve for cve in cves if cve.lower() not in disposition.lower()]
            if missing:
                errors.append("advisory seeds lack local disposition: " + ", ".join(missing))
            else:
                checks.append(f"advisory-scout seeds-dispositioned={len(cves)}")

    status = "PASS" if not errors else "FAIL"
    print(f"Firmware hypothesis coverage check: {status}")
    for item in checks:
        print(f"PASS: {item}")
    for item in errors:
        print(f"FAIL: {item}")
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
