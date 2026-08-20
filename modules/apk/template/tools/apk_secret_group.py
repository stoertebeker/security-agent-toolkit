#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "reports" / "tool-output" / "secret-candidates.json"
OUT_JSON = ROOT / "reports" / "tool-output" / "secret-groups.json"
OUT_TXT = ROOT / "reports" / "tool-output" / "secret-groups.txt"

CATEGORY_SCORE = {
    "HIGH_CONFIDENCE_SECRET": 100,
    "CREDENTIAL_CANDIDATE": 80,
    "TOKEN_CANDIDATE": 75,
    "HASH_OR_KDF_CANDIDATE": 60,
    "PUBLIC_CLIENT_CONFIG_CANDIDATE": 30,
}

RULE_SCORE = {
    "private_key_pem_block": 100,
    "private_key_pem_header": 100,
    "aws_access_key_id": 95,
    "github_token": 95,
    "slack_token": 95,
    "stripe_secret_key": 95,
    "authorization_basic_literal": 90,
    "authorization_bearer_literal": 90,
    "basic_auth_url": 90,
    "jwt_literal": 80,
    "generic_secret_assignment": 75,
    "android_sensitive_string_resource": 70,
    "bcrypt": 70,
    "argon2": 70,
    "md5crypt": 70,
    "sha256crypt": 70,
    "sha512crypt": 70,
    "phpass": 70,
    "hash_named_assignment": 55,
    "android_hash_string_resource": 55,
    "google_api_key": 35,
}

LOW_CONTEXT_MARKERS = (
    "/test/", "/tests/", "/androidtest/", "/fixture", "/fixtures/",
    "/sample/", "/samples/", "/demo/", "/example/", "/examples/",
    "/mock/", "/mocks/",
)


def initial_score(candidate: dict) -> int:
    score = max(
        CATEGORY_SCORE.get(str(candidate.get("category", "")), 40),
        RULE_SCORE.get(str(candidate.get("rule", "")), 40),
    )
    source = "/" + str(candidate.get("source", "")).lower().replace("\\", "/")
    if any(marker in source for marker in LOW_CONTEXT_MARKERS):
        score -= 20
    encoding = candidate.get("encoding_analysis") or []
    if any(item.get("printable_text") for item in encoding if isinstance(item, dict)):
        score += 5
    hashes = candidate.get("hash_analysis") or candidate.get("hash_candidates") or []
    if any(str(item.get("confidence", "")).upper() == "HIGH" for item in hashes if isinstance(item, dict)):
        score += 5
    return max(0, min(score, 100))


def priority(score: int) -> str:
    if score >= 85:
        return "HIGH"
    if score >= 55:
        return "MEDIUM"
    return "LOW"


def main() -> int:
    if not SOURCE.is_file():
        raise SystemExit(f"[!] missing {SOURCE.relative_to(ROOT)}; run apk_secret_scan.py first")

    payload = json.loads(SOURCE.read_text(encoding="utf-8"))
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        raise SystemExit("[!] secret-candidates.json has no candidates array")

    grouped: dict[tuple[str, int], dict] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        fingerprint = str(candidate.get("value_sha256_prefix", "unknown"))
        value_length = int(candidate.get("value_length") or 0)
        key = (fingerprint, value_length)
        group = grouped.setdefault(
            key,
            {
                "group_id": f"SG-{fingerprint}",
                "value_sha256_prefix": fingerprint,
                "value_length": value_length,
                "rules": set(),
                "categories": set(),
                "occurrences": [],
                "initial_score": 0,
                "encoding_analysis": [],
                "hash_analysis": [],
            },
        )
        group["rules"].add(str(candidate.get("rule", "unknown")))
        group["categories"].add(str(candidate.get("category", "unknown")))
        group["initial_score"] = max(group["initial_score"], initial_score(candidate))
        occurrence = {
            "source": candidate.get("source"),
            "locator": candidate.get("locator"),
            "source_kind": candidate.get("source_kind"),
            "rule": candidate.get("rule"),
            "category": candidate.get("category"),
        }
        if occurrence not in group["occurrences"]:
            group["occurrences"].append(occurrence)
        for field in ("encoding_analysis",):
            for item in candidate.get(field) or []:
                if item not in group[field]:
                    group[field].append(item)
        hashes = candidate.get("hash_analysis") or candidate.get("hash_candidates") or []
        for item in hashes:
            if item not in group["hash_analysis"]:
                group["hash_analysis"].append(item)

    groups = []
    for group in grouped.values():
        group["rules"] = sorted(group["rules"])
        group["categories"] = sorted(group["categories"])
        group["occurrence_count"] = len(group["occurrences"])
        group["source_count"] = len({str(item.get("source")) for item in group["occurrences"]})
        group["initial_priority"] = priority(group["initial_score"])
        groups.append(group)

    groups.sort(key=lambda item: (-item["initial_score"], -item["occurrence_count"], item["group_id"]))
    counts = Counter(group["initial_priority"] for group in groups)

    result = {
        "raw_candidate_count": len(candidates),
        "unique_group_count": len(groups),
        "initial_priority_counts": dict(sorted(counts.items())),
        "note": "Initial priority is deterministic ordering only; AI/local-context triage owns plausibility and final classification.",
        "groups": groups,
    }
    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# Grouped APK secret/material candidates",
        "",
        f"Raw hits: {len(candidates)}",
        f"Unique value groups: {len(groups)}",
        "Initial priority is only an ordering hint; it is not a security verdict.",
        "",
    ]
    for name in ("HIGH", "MEDIUM", "LOW"):
        lines.append(f"- {name}: {counts.get(name, 0)}")
    lines.append("")
    for group in groups:
        reps = group["occurrences"][:3]
        locations = ", ".join(
            f"{item.get('source')}:{item.get('locator')}" for item in reps
        )
        lines.append(
            f"{group['initial_priority']} score={group['initial_score']:3d} {group['group_id']} "
            f"occurrences={group['occurrence_count']} sources={group['source_count']} "
            f"rules={','.join(group['rules'])} reps=[{locations}]"
        )
    OUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"secret grouping complete: {len(candidates)} raw hits -> {len(groups)} unique groups")
    print(f"group list: {OUT_TXT.relative_to(ROOT)}")
    print(f"machine-readable: {OUT_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
