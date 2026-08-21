#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
REPORT = ROOT / "reports" / "tool-output"
SOURCE = REPORT / "firmware-secret-candidates.json"
OUT = REPORT / "firmware-secret-groups.json"
TXT = REPORT / "firmware-secret-groups.txt"

CLASS_HINTS = {
    "private_key_header": "PRIVATE_KEY_MATERIAL",
    "private_key_file": "PRIVATE_KEY_MATERIAL",
    "empty_shadow_password": "LOCAL_LOGIN_CREDENTIAL",
    "shadow_credential": "PASSWORD_HASH_OR_CREDENTIAL_FIELD",
    "password_assignment": "HARDCODED_PASSWORD_OR_CONFIGURATION",
    "url_embedded_credentials": "EMBEDDED_SERVICE_CREDENTIAL",
    "aws_access_key": "CLOUD_CREDENTIAL",
    "github_token": "SERVICE_TOKEN",
    "slack_token": "SERVICE_TOKEN",
    "jwt": "TOKEN_LIKE_MATERIAL",
    "bearer_literal": "TOKEN_LIKE_MATERIAL",
    "secret_assignment": "SECRET_LIKE_CONFIGURATION",
}


def config() -> dict:
    if not TARGET.is_file():
        return {}
    with TARGET.open("rb") as handle:
        return tomllib.load(handle).get("secrets", {})


def dependency_hint(path: str) -> bool:
    lowered = path.lower()
    return any(token in lowered for token in (
        "/node_modules/", "/usr/share/", "/www/lib/", "/www/js/vendor/",
        "/htdocs/js/vendor/", "/licenses/", "/examples/", "/test/", "/tests/",
    ))


def group_id(rule: str, fingerprint: str) -> str:
    digest = hashlib.sha256(f"{rule}:{fingerprint}".encode()).hexdigest()[:16]
    return f"FG-{digest}"


def main() -> int:
    if not SOURCE.is_file():
        raise SystemExit("[!] firmware-secret-candidates.json missing; run firmware_secret_scan.py")
    raw = json.loads(SOURCE.read_text())
    cfg = config()
    representative_limit = int(cfg.get("ai_representative_locations", 3))

    buckets: dict[tuple[str, str], list[dict]] = {}
    for item in raw:
        rule = str(item.get("rule", "unknown"))
        fingerprint = str(item.get("fingerprint", ""))
        if not fingerprint:
            continue
        buckets.setdefault((rule, fingerprint), []).append(item)

    groups = []
    for (rule, fingerprint), items in buckets.items():
        priorities = [str(item.get("initial_priority", "LOW")) for item in items]
        priority = "HIGH" if "HIGH" in priorities else "MEDIUM" if "MEDIUM" in priorities else "LOW"
        locations = []
        for item in items[:representative_limit]:
            locations.append({
                "path": item.get("path"),
                "line": item.get("line"),
                "context": item.get("context"),
                "kind": item.get("kind"),
            })
        groups.append({
            "group_id": group_id(rule, fingerprint),
            "rule": rule,
            "fingerprint": fingerprint,
            "occurrences": len(items),
            "initial_priority": priority,
            "classification_hint": CLASS_HINTS.get(rule, "SECRET_LIKE_MATERIAL"),
            "dependency_or_sample_hint": all(dependency_hint(str(item.get("path", ""))) for item in items),
            "value_length_min": min(int(item.get("value_length", 0)) for item in items),
            "value_length_max": max(int(item.get("value_length", 0)) for item in items),
            "representative_locations": locations,
        })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    groups.sort(key=lambda item: (order.get(item["initial_priority"], 9), -item["occurrences"], item["group_id"]))
    summary = {
        "schema_version": 1,
        "raw_candidate_count": len(raw),
        "semantic_group_count": len(groups),
        "groups": groups,
    }
    OUT.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# Firmware secret semantic groups",
        f"raw candidates: {len(raw)}",
        f"semantic groups: {len(groups)}",
        "",
    ]
    for item in groups:
        location = item["representative_locations"][0] if item["representative_locations"] else {}
        lines.append(
            f"- {item['group_id']} {item['initial_priority']} {item['rule']} occurrences={item['occurrences']} "
            f"hint={item['classification_hint']} sample={location.get('path', '-')}"
        )
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Firmware secret grouping: {len(raw)} raw -> {len(groups)} semantic groups")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
