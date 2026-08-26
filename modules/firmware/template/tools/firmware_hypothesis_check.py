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


def main() -> int:
    errors: list[str] = []
    checks: list[str] = []
    try:
        cfg = tomllib.loads(TARGET.read_text())
    except Exception as exc:
        print(f"Firmware hypothesis coverage check: FAIL\nFAIL: target config: {exc}")
        return 2

    surface_path = TOOL / "firmware-web-surface.json"
    surface = load_json(surface_path, errors)
    if surface:
        tool_path = ROOT / "tools" / "firmware_web_surface.py"
        current_tool_hash = hashlib.sha256(tool_path.read_bytes()).hexdigest() if tool_path.is_file() else ""
        if str(surface.get("tool_sha256") or "") != current_tool_hash:
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
            # Backward compatibility for a scout that names CVEs but omitted structured blocks is intentionally rejected:
            # the checker needs machine-auditable seed semantics, not mere CVE mentions.
            mentioned = sorted(set(cve.upper() for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", scout_text, re.I)))
            missing_blocks = [cve for cve in mentioned if cve not in seed_blocks]
            if missing_blocks:
                errors.append("advisory scout CVEs lack structured Seed-ID blocks: " + ", ".join(missing_blocks))

            disposition_text = read_many(list(FINDINGS.glob("*.md")) + list((REPORTS / "subagents").glob("*.md")) + [REPORTS / "STATIC_SECURITY_REPORT.md"])
            for cve, block in seed_blocks.items():
                match = re.search(
                    rf"(?im)^Seed disposition:\s*{re.escape(cve)}\s*->\s*(INVESTIGATED|REJECTED|DEFERRED_CVE_IDENTITY)\s*;\s*local-hypothesis=([^;\n]+)\s*;\s*reason=(.+)$",
                    disposition_text,
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
            if seed_blocks and not any(error.startswith("advisory seed") for error in errors):
                checks.append(f"advisory-seed-dispositions={len(seed_blocks)}")

    status = "PASS" if not errors else "FAIL"
    print(f"Firmware hypothesis coverage check: {status}")
    for item in checks:
        print(f"PASS: {item}")
    for item in errors:
        print(f"FAIL: {item}")
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
