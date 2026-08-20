#!/usr/bin/env python3
from __future__ import annotations

import json
import re
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

DEPENDENCY_PATH_MARKERS = (
    "/com/fasterxml/", "/com/google/", "/com/facebook/", "/com/flurry/",
    "/com/appsflyer/", "/com/squareup/", "/okhttp3/", "/retrofit2/",
    "/androidx/", "/kotlin/", "/kotlinx/", "/org/apache/", "/org/json/",
)

# Scanner versions before this grouper used deliberately broad crypt prefixes.
# Generated Kotlin/Java/Smali names such as Foo$stateMachine$1$5$1 therefore
# produced false md5crypt/sha256crypt/sha512crypt hits. Before an AI ever sees
# those candidates, require the complete serialized Unix-crypt shape.
STRICT_CRYPT_PATTERNS = {
    "md5crypt": re.compile(
        r"(?<![A-Za-z0-9_$])\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}(?![./A-Za-z0-9])"
    ),
    "sha256crypt": re.compile(
        r"(?<![A-Za-z0-9_$])\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}(?![./A-Za-z0-9])"
    ),
    "sha512crypt": re.compile(
        r"(?<![A-Za-z0-9_$])\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}(?![./A-Za-z0-9])"
    ),
}

ANDROID_STRING_RE = re.compile(
    r"<string\s+name=[\"']([^\"']+)[\"'][^>]*>\s*(.*?)\s*</string>",
    re.IGNORECASE,
)

UI_RESOURCE_NAME_MARKERS = (
    "label", "title", "hint", "message", "error", "warning", "description",
    "summary", "button", "dialog", "toast", "text", "prompt", "forgot",
    "change", "confirm", "invalid", "required", "empty", "login", "signup",
)


def read_source_line(candidate: dict) -> str | None:
    if candidate.get("source_kind") != "text":
        return None
    source = candidate.get("source")
    locator = candidate.get("locator")
    if not isinstance(source, str) or not isinstance(locator, int) or locator < 1:
        return None
    path = ROOT / source
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                if number == locator:
                    return line.rstrip("\n")
    except OSError:
        return None
    return None


def strict_crypt_candidate(candidate: dict) -> bool:
    rule = str(candidate.get("rule", ""))
    pattern = STRICT_CRYPT_PATTERNS.get(rule)
    if pattern is None:
        return True
    line = read_source_line(candidate)
    if line is None:
        # Do not silently discard a candidate if its source cannot be checked.
        return True
    return pattern.search(line) is not None


def android_resource_key(candidate: dict) -> str | None:
    if str(candidate.get("rule", "")) not in {
        "android_sensitive_string_resource", "android_hash_string_resource"
    }:
        return None
    line = read_source_line(candidate)
    if line is None:
        return None
    match = ANDROID_STRING_RE.search(line)
    return match.group(1) if match else None


def is_dependency_only(occurrences: list[dict]) -> bool:
    sources = [
        "/" + str(item.get("source", "")).lower().replace("\\", "/")
        for item in occurrences
    ]
    return bool(sources) and all(any(marker in src for marker in DEPENDENCY_PATH_MARKERS) for src in sources)


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

    filtered_candidates = []
    filtered_false_crypt = Counter()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        if not strict_crypt_candidate(candidate):
            filtered_false_crypt[str(candidate.get("rule", "unknown"))] += 1
            continue
        filtered_candidates.append(candidate)

    grouped: dict[tuple, dict] = {}
    android_resource_groups = 0
    android_resource_keys_seen: set[str] = set()

    for candidate in filtered_candidates:
        fingerprint = str(candidate.get("value_sha256_prefix", "unknown"))
        value_length = int(candidate.get("value_length") or 0)
        resource_key = android_resource_key(candidate)

        # Localized Android UI strings differ by translated value. Group them by
        # semantic resource key instead of fingerprint so "password_error" in 30
        # languages is one review unit, not 30 alleged credentials.
        if resource_key:
            key = ("android_string_resource", resource_key)
            group_id = "SR-" + __import__("hashlib").sha256(resource_key.encode()).hexdigest()[:16]
            group_kind = "android_string_resource"
            android_resource_keys_seen.add(resource_key)
        else:
            key = ("value", fingerprint, value_length)
            group_id = f"SG-{fingerprint}"
            group_kind = "value"

        group = grouped.setdefault(
            key,
            {
                "group_id": group_id,
                "group_kind": group_kind,
                "resource_key": resource_key,
                "value_sha256_prefixes": set(),
                "value_lengths": set(),
                "rules": set(),
                "categories": set(),
                "occurrences": [],
                "initial_score": 0,
                "encoding_analysis": [],
                "hash_analysis": [],
            },
        )
        group["value_sha256_prefixes"].add(fingerprint)
        group["value_lengths"].add(value_length)
        group["rules"].add(str(candidate.get("rule", "unknown")))
        group["categories"].add(str(candidate.get("category", "unknown")))
        group["initial_score"] = max(group["initial_score"], initial_score(candidate))

        occurrence = {
            "source": candidate.get("source"),
            "locator": candidate.get("locator"),
            "source_kind": candidate.get("source_kind"),
            "rule": candidate.get("rule"),
            "category": candidate.get("category"),
            "value_sha256_prefix": fingerprint,
        }
        if occurrence not in group["occurrences"]:
            group["occurrences"].append(occurrence)

        for item in candidate.get("encoding_analysis") or []:
            if item not in group["encoding_analysis"]:
                group["encoding_analysis"].append(item)
        hashes = candidate.get("hash_analysis") or candidate.get("hash_candidates") or []
        for item in hashes:
            if item not in group["hash_analysis"]:
                group["hash_analysis"].append(item)

    groups = []
    for group in grouped.values():
        group["rules"] = sorted(group["rules"])
        group["categories"] = sorted(group["categories"])
        group["value_sha256_prefixes"] = sorted(group["value_sha256_prefixes"])
        group["value_lengths"] = sorted(group["value_lengths"])
        group["distinct_value_count"] = len(group["value_sha256_prefixes"])
        group["occurrence_count"] = len(group["occurrences"])
        group["source_count"] = len({str(item.get("source")) for item in group["occurrences"]})

        flags = []
        if group["group_kind"] == "android_string_resource":
            resource_key = (group.get("resource_key") or "").lower()
            if any(marker in resource_key for marker in UI_RESOURCE_NAME_MARKERS):
                flags.append("localized-ui-resource")
                group["initial_score"] = min(group["initial_score"], 35)
            else:
                # Resource-name matches are still weaker than value-structured credentials.
                group["initial_score"] = min(group["initial_score"], 50)
        if is_dependency_only(group["occurrences"]):
            flags.append("dependency-only")
            group["initial_score"] = max(0, group["initial_score"] - 35)

        group["flags"] = flags
        group["initial_priority"] = priority(group["initial_score"])
        groups.append(group)

    android_resource_groups = len(android_resource_keys_seen)
    groups.sort(key=lambda item: (-item["initial_score"], -item["occurrence_count"], item["group_id"]))
    counts = Counter(group["initial_priority"] for group in groups)

    result = {
        "raw_candidate_count": len(candidates),
        "candidate_count_after_format_filter": len(filtered_candidates),
        "filtered_false_crypt_hits": dict(sorted(filtered_false_crypt.items())),
        "semantic_group_count": len(groups),
        "android_string_resource_group_count": android_resource_groups,
        "initial_priority_counts": dict(sorted(counts.items())),
        "note": "Initial priority is deterministic ordering only; AI/local-context triage owns plausibility and final classification.",
        "groups": groups,
    }
    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# Grouped APK secret/material candidates",
        "",
        f"Raw hits: {len(candidates)}",
        f"After strict format filter: {len(filtered_candidates)}",
        f"Filtered false crypt-prefix hits: {sum(filtered_false_crypt.values())}",
        f"Semantic groups: {len(groups)}",
        f"Android string-resource groups: {android_resource_groups}",
        "Localized Android strings are grouped by resource key rather than translated value.",
        "Initial priority is only an ordering hint; it is not a security verdict.",
        "",
    ]
    for rule, count in sorted(filtered_false_crypt.items()):
        lines.append(f"- filtered {rule}: {count}")
    if filtered_false_crypt:
        lines.append("")
    for name in ("HIGH", "MEDIUM", "LOW"):
        lines.append(f"- {name}: {counts.get(name, 0)}")
    lines.append("")

    for group in groups:
        reps = group["occurrences"][:3]
        locations = ", ".join(f"{item.get('source')}:{item.get('locator')}" for item in reps)
        resource = f" resource={group['resource_key']}" if group.get("resource_key") else ""
        flags = f" flags={','.join(group['flags'])}" if group.get("flags") else ""
        lines.append(
            f"{group['initial_priority']} score={group['initial_score']:3d} {group['group_id']} "
            f"kind={group['group_kind']}{resource} values={group['distinct_value_count']} "
            f"occurrences={group['occurrence_count']} sources={group['source_count']} "
            f"rules={','.join(group['rules'])}{flags} reps=[{locations}]"
        )

    OUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"secret grouping complete: {len(candidates)} raw hits -> {len(filtered_candidates)} format-valid hits -> {len(groups)} semantic groups"
    )
    if filtered_false_crypt:
        print("filtered false crypt-prefix hits:", ", ".join(f"{k}={v}" for k, v in sorted(filtered_false_crypt.items())))
    print(f"group list: {OUT_TXT.relative_to(ROOT)}")
    print(f"machine-readable: {OUT_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
