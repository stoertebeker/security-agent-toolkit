#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import linecache
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

# These are common vendored/generated dependency namespaces. They reduce only
# deterministic ordering priority. AI/local-context review still sees the group.
DEPENDENCY_PATH_MARKERS = (
    "/sources/com/fasterxml/",
    "/sources/com/google/",
    "/sources/androidx/",
    "/sources/kotlin/",
    "/sources/kotlinx/",
    "/sources/okhttp3/",
    "/sources/retrofit2/",
    "/sources/io/reactivex/",
    "/sources/org/apache/",
    "/sources/org/bouncycastle/",
    "/smali/com/fasterxml/",
    "/smali/com/google/",
    "/smali/androidx/",
    "/smali/kotlin/",
    "/smali/kotlinx/",
    "/smali/okhttp3/",
    "/smali/retrofit2/",
)

RESOURCE_NAME_RE = re.compile(r"<string\s+name=[\"']([^\"']+)[\"']", re.IGNORECASE)
RESOURCE_PATH_RE = re.compile(r"/(?:res/)?values(?:-[^/]+)?/strings\.xml$", re.IGNORECASE)
LOCALE_PATH_RE = re.compile(r"/(?:res/)?values-[^/]+/strings\.xml$", re.IGNORECASE)

STRONG_RESOURCE_NAME_RE = re.compile(
    r"(?:^|_)(?:client_secret|api_secret|secret_key|access_token|refresh_token|auth_token|private_key|signing_key)(?:$|_)",
    re.IGNORECASE,
)

EXPLICIT_CREDENTIAL_RULES = {
    "private_key_pem_block",
    "private_key_pem_header",
    "aws_access_key_id",
    "github_token",
    "slack_token",
    "stripe_secret_key",
    "authorization_basic_literal",
    "authorization_bearer_literal",
    "basic_auth_url",
    "jwt_literal",
}


def stable_id(prefix: str, material: str) -> str:
    digest = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def source_normalized(candidate: dict) -> str:
    return "/" + str(candidate.get("source", "")).lower().replace("\\", "/")


def resource_name(candidate: dict) -> str | None:
    source = str(candidate.get("source", ""))
    normalized = "/" + source.lower().replace("\\", "/")
    if not RESOURCE_PATH_RE.search(normalized):
        return None
    if str(candidate.get("source_kind", "")) != "text":
        return None
    try:
        locator = int(candidate.get("locator"))
    except (TypeError, ValueError):
        return None
    path = ROOT / source
    line = linecache.getline(str(path), locator)
    match = RESOURCE_NAME_RE.search(line)
    return match.group(1) if match else None


def candidate_base_score(candidate: dict) -> int:
    score = max(
        CATEGORY_SCORE.get(str(candidate.get("category", "")), 40),
        RULE_SCORE.get(str(candidate.get("rule", "")), 40),
    )
    source = source_normalized(candidate)
    if any(marker in source for marker in LOW_CONTEXT_MARKERS):
        score -= 25
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


def finalize_score(group: dict) -> int:
    score = int(group["raw_score"])
    rules = set(group["rules"])
    occurrences = group["occurrences"]
    sources = ["/" + str(item.get("source", "")).lower().replace("\\", "/") for item in occurrences]

    # A string resource named "password_*" is commonly a translated UI label or
    # error message. Treat the resource key as the semantic identity and do not
    # make every locale a separate medium-priority secret candidate.
    if group["group_kind"] == "android_string_resource":
        name = str(group.get("resource_name") or "")
        explicit = bool(rules & EXPLICIT_CREDENTIAL_RULES)
        if not explicit:
            if STRONG_RESOURCE_NAME_RE.search(name):
                score = min(score, 60)
            elif "google_api_key" in rules:
                score = min(score, 35)
            else:
                score = min(score, 25)

        locale_sources = sum(1 for source in sources if LOCALE_PATH_RE.search(source))
        if group.get("distinct_value_count", 1) > 1 and locale_sources >= 2:
            score -= 15
            group["likely_localized_ui_text"] = True
        else:
            group["likely_localized_ui_text"] = False

    # Dependency constants/Javadocs are common false-positive territory. This is
    # only a ranking penalty; the AI worker still reviews the semantic group.
    if sources and all(any(marker in source for marker in DEPENDENCY_PATH_MARKERS) for source in sources):
        score -= 40
        group["dependency_only_context"] = True
    else:
        group["dependency_only_context"] = False

    return max(0, min(score, 100))


def main() -> int:
    if not SOURCE.is_file():
        raise SystemExit(f"[!] missing {SOURCE.relative_to(ROOT)}; run apk_secret_scan.py first")

    payload = json.loads(SOURCE.read_text(encoding="utf-8"))
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        raise SystemExit("[!] secret-candidates.json has no candidates array")

    grouped: dict[tuple, dict] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue

        fingerprint = str(candidate.get("value_sha256_prefix", "unknown"))
        value_length = int(candidate.get("value_length") or 0)
        res_name = resource_name(candidate)
        if res_name:
            key = ("android_string_resource", res_name)
            group_id = stable_id("SR", res_name)
            group_kind = "android_string_resource"
        else:
            key = ("value", fingerprint, value_length)
            group_id = f"SG-{fingerprint}"
            group_kind = "value"

        group = grouped.setdefault(
            key,
            {
                "group_id": group_id,
                "group_kind": group_kind,
                "resource_name": res_name,
                "value_sha256_prefixes": set(),
                "value_lengths": set(),
                "rules": set(),
                "categories": set(),
                "occurrences": [],
                "raw_score": 0,
                "encoding_analysis": [],
                "hash_analysis": [],
            },
        )
        group["value_sha256_prefixes"].add(fingerprint)
        group["value_lengths"].add(value_length)
        group["rules"].add(str(candidate.get("rule", "unknown")))
        group["categories"].add(str(candidate.get("category", "unknown")))
        group["raw_score"] = max(group["raw_score"], candidate_base_score(candidate))
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
        group["initial_score"] = finalize_score(group)
        group["initial_priority"] = priority(group["initial_score"])
        group.pop("raw_score", None)
        groups.append(group)

    groups.sort(key=lambda item: (-item["initial_score"], -item["occurrence_count"], item["group_id"]))
    counts = Counter(group["initial_priority"] for group in groups)
    resource_groups = sum(1 for group in groups if group["group_kind"] == "android_string_resource")

    result = {
        "raw_candidate_count": len(candidates),
        "semantic_group_count": len(groups),
        "unique_group_count": len(groups),
        "android_string_resource_group_count": resource_groups,
        "initial_priority_counts": dict(sorted(counts.items())),
        "note": "Groups are semantic review units. Localized Android strings are grouped by resource name; other candidates are grouped by value fingerprint. Initial priority is ordering only; AI/local-context triage owns plausibility.",
        "groups": groups,
    }
    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# Grouped APK secret/material candidates",
        "",
        f"Raw hits: {len(candidates)}",
        f"Semantic groups: {len(groups)}",
        f"Android string-resource groups: {resource_groups}",
        "Localized Android strings are grouped by resource key rather than translated value.",
        "Initial priority is only an ordering hint; it is not a security verdict.",
        "",
    ]
    for name in ("HIGH", "MEDIUM", "LOW"):
        lines.append(f"- {name}: {counts.get(name, 0)}")
    lines.append("")
    for group in groups:
        reps = group["occurrences"][:3]
        locations = ", ".join(f"{item.get('source')}:{item.get('locator')}" for item in reps)
        identity = (
            f"resource={group['resource_name']} values={group['distinct_value_count']}"
            if group["group_kind"] == "android_string_resource"
            else f"values={group['distinct_value_count']}"
        )
        flags = []
        if group.get("likely_localized_ui_text"):
            flags.append("localized-ui")
        if group.get("dependency_only_context"):
            flags.append("dependency-only")
        flag_text = f" flags={','.join(flags)}" if flags else ""
        lines.append(
            f"{group['initial_priority']} score={group['initial_score']:3d} {group['group_id']} "
            f"kind={group['group_kind']} {identity} occurrences={group['occurrence_count']} "
            f"sources={group['source_count']} rules={','.join(group['rules'])}{flag_text} reps=[{locations}]"
        )
    OUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"secret grouping complete: {len(candidates)} raw hits -> {len(groups)} semantic groups")
    print(f"android string-resource groups: {resource_groups}")
    print(f"group list: {OUT_TXT.relative_to(ROOT)}")
    print(f"machine-readable: {OUT_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
