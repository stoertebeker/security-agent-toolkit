#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import tomllib
from dataclasses import dataclass

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
PREP = ROOT / "reports" / "tool-output" / "firmware-preparation.json"
OUT_JSON = ROOT / "reports" / "tool-output" / "firmware-identity.json"
OUT_TXT = ROOT / "reports" / "tool-output" / "firmware-identity.txt"

MAX_TARGET_BYTES = 32 * 1024 * 1024
MAX_ROOTFS_BYTES = 48 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_PER_FIELD = 12

VENDORS = {
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "netgear": "NETGEAR",
    "d-link": "D-Link",
    "dlink": "D-Link",
    "linksys": "Linksys",
    "asus": "ASUS",
    "zyxel": "Zyxel",
    "ubiquiti": "Ubiquiti",
    "mikrotik": "MikroTik",
}

FW_RE = re.compile(
    r"(?P<version>\d+\.\d+(?:\.\d+){1,2})\s+Build\s+(?P<build>\d{6,14})"
    r"(?:\s+Rel\.?\s*(?P<release>[A-Za-z0-9._-]+))?",
    re.I,
)
TP_STYLE_RE = re.compile(
    r"(?P<product>Archer\s+[A-Za-z0-9._-]+)\s*\((?P<region>[A-Z]{2,3})\)\s*[_ -]*V(?P<hw>\d+(?:\.\d+)?)"
    r"(?:[_ -]+(?P<build>\d{6,14}))?",
    re.I,
)
TP_STYLE_NO_REGION_RE = re.compile(
    r"(?P<product>Archer\s+[A-Za-z0-9._-]+)\s*[_ -]+V(?P<hw>\d+(?:\.\d+)?)"
    r"(?:[_ -]+(?P<build>\d{6,14}))?",
    re.I,
)
MODEL_RE = re.compile(
    r"(?:model(?:\s+name)?|product(?:\s+name)?|device(?:\s+(?:model|name))?)\s*[:=]\s*"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9 ._()/-]{1,48})",
    re.I,
)
ARCHER_RE = re.compile(r"\b(?P<value>Archer\s+[A-Za-z0-9._-]{1,16})\b", re.I)
HW_RE = re.compile(r"(?:hardware(?:\s+version)?|hw(?:\s+ver(?:sion)?)?)\s*[:=]\s*(?:V)?(?P<value>\d+(?:\.\d+)?)", re.I)
REGION_RE = re.compile(r"(?:region|country)\s*[:=]\s*(?P<value>EU|US|JP|UK|CA|AU|RU|BR|KR|TW|UN)\b", re.I)
PAREN_REGION_RE = re.compile(r"\((?P<value>EU|US|JP|UK|CA|AU|RU|BR|KR|TW|UN)\)")
VERSION_RE = re.compile(r"(?:firmware|software|soft)[ _-]*(?:version|ver)?\s*[:=]\s*(?P<value>\d+\.\d+(?:\.\d+){1,2})", re.I)
BUILD_RE = re.compile(r"\bBuild\s*(?P<value>\d{6,14})\b", re.I)
REL_RE = re.compile(r"\bRel\.?\s*(?P<value>[A-Za-z0-9._-]{3,24})", re.I)


@dataclass(frozen=True)
class Source:
    name: str
    weight: int
    text: str


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def printable_strings(data: bytes, minimum: int = 4) -> str:
    chunks: list[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
        chunks.append(match.group().decode("ascii", "replace"))
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum, data):
        try:
            chunks.append(match.group().decode("utf-16le", "replace"))
        except UnicodeDecodeError:
            pass
    return "\n".join(chunks)


def real_dir(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)


def load_rootfs() -> Path | None:
    if not PREP.is_file():
        return None
    try:
        prep = json.loads(PREP.read_text())
    except Exception:
        return None
    raw = prep.get("primary_rootfs")
    if not raw:
        return None
    rel = Path(str(raw))
    if rel.is_absolute() or ".." in rel.parts or rel.parts[:2] != ("work", "extracted"):
        return None
    rootfs = ROOT / rel
    return rootfs if real_dir(rootfs) else None


def read_source(path: Path, limit: int) -> str:
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return ""
    if b"\x00" not in data[:4096]:
        try:
            return data.decode("utf-8", "replace")
        except Exception:
            pass
    return printable_strings(data)


def source_weight(relative: str) -> int:
    low = relative.lower()
    if low.startswith("etc/") and any(token in low for token in ("version", "release", "product", "model", "board")):
        return 88
    if "/status" in low or "/upgrade" in low or "/system" in low or "/help" in low:
        return 82
    if Path(low).name in {"httpd", "uhttpd", "boa", "lighttpd", "nginx"}:
        return 78
    if low.startswith("web/") or low.startswith("www/"):
        return 76
    return 66


def collect_sources(cfg: dict) -> list[Source]:
    sources: list[Source] = []
    firmware_rel = Path(str(cfg.get("firmware", {}).get("path", "")))
    if firmware_rel and not firmware_rel.is_absolute() and ".." not in firmware_rel.parts:
        firmware = ROOT / firmware_rel
        if firmware.is_file():
            sources.append(Source("configured-filename", 92, firmware.name))
            sources.append(Source("firmware-printable", 84, printable_strings(firmware.read_bytes()[:MAX_TARGET_BYTES])))

    identity_cfg = cfg.get("identity", {}) if isinstance(cfg, dict) else {}
    source_filename = str(identity_cfg.get("source_filename") or "").strip()
    if source_filename:
        sources.append(Source("identity.source_filename", 98, source_filename))

    rootfs = load_rootfs()
    if rootfs:
        total = 0
        for current, dirnames, filenames in os.walk(rootfs, followlinks=False):
            current_path = Path(current)
            safe_dirs = []
            for dirname in dirnames:
                if dirname.endswith("_extract"):
                    continue
                child = current_path / dirname
                if real_dir(child):
                    safe_dirs.append(dirname)
            dirnames[:] = safe_dirs
            for filename in filenames:
                path = current_path / filename
                try:
                    st = path.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_size <= 0:
                    continue
                remaining = MAX_ROOTFS_BYTES - total
                if remaining <= 0:
                    break
                amount = min(st.st_size, MAX_FILE_BYTES, remaining)
                relative = path.relative_to(rootfs).as_posix()
                text = read_source(path, amount)
                total += amount
                if text:
                    sources.append(Source(f"rootfs:{relative}", source_weight(relative), text))
            if total >= MAX_ROOTFS_BYTES:
                break
    return sources


def clean_context(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()[:180]


def norm_product(value: str) -> str:
    value = clean_context(value)
    value = re.sub(r"\s*\((?:EU|US|JP|UK|CA|AU|RU|BR|KR|TW|UN)\)\s*$", "", value, flags=re.I)
    value = re.sub(r"[_ -]+V\d+(?:\.\d+)?(?:[_ -]+\d{6,14})?$", "", value, flags=re.I)
    return value.strip(" _-")


def norm_hw(value: str) -> str:
    value = value.strip().upper()
    if value.startswith("V"):
        value = value[1:]
    if value.endswith(".0"):
        value = value[:-2]
    return "V" + value


def add(evidence: dict[str, list[dict]], field: str, value: str | None, source: Source, context: str) -> None:
    if not value:
        return
    value = clean_context(value)
    if not value or len(value) > 80:
        return
    if field == "product":
        value = norm_product(value)
    elif field == "hardware_revision":
        value = norm_hw(value)
    elif field == "region":
        value = value.upper()
    item = {"value": value, "source": source.name, "weight": source.weight, "context": clean_context(context)}
    bucket = evidence.setdefault(field, [])
    if not any(existing["value"].lower() == value.lower() and existing["source"] == source.name for existing in bucket):
        bucket.append(item)


def parse_sources(sources: list[Source], cfg: dict) -> dict[str, list[dict]]:
    evidence: dict[str, list[dict]] = {}
    identity_cfg = cfg.get("identity", {}) if isinstance(cfg, dict) else {}
    override_source = Source("operator-identity", 100, "")
    for field in ("vendor", "product", "hardware_revision", "region", "firmware_version", "build", "release"):
        raw = str(identity_cfg.get(field) or "").strip()
        if raw:
            add(evidence, field, raw, override_source, f"operator identity override: {field}")

    for source in sources:
        text = source.text
        low = text.lower()
        for token, canonical in VENDORS.items():
            if token in low:
                add(evidence, "vendor", canonical, source, token)
        for match in TP_STYLE_RE.finditer(text):
            add(evidence, "product", match.group("product"), source, match.group(0))
            add(evidence, "region", match.group("region"), source, match.group(0))
            add(evidence, "hardware_revision", match.group("hw"), source, match.group(0))
            add(evidence, "build", match.group("build"), source, match.group(0))
            add(evidence, "vendor", "TP-Link", source, match.group(0))
        for match in TP_STYLE_NO_REGION_RE.finditer(text):
            add(evidence, "product", match.group("product"), source, match.group(0))
            add(evidence, "hardware_revision", match.group("hw"), source, match.group(0))
            add(evidence, "build", match.group("build"), source, match.group(0))
            add(evidence, "vendor", "TP-Link", source, match.group(0))
        for match in FW_RE.finditer(text):
            add(evidence, "firmware_version", match.group("version"), source, match.group(0))
            add(evidence, "build", match.group("build"), source, match.group(0))
            add(evidence, "release", match.group("release"), source, match.group(0))
        for regex, field in (
            (MODEL_RE, "product"), (ARCHER_RE, "product"), (HW_RE, "hardware_revision"),
            (REGION_RE, "region"), (VERSION_RE, "firmware_version"), (BUILD_RE, "build"), (REL_RE, "release"),
        ):
            for match in regex.finditer(text):
                add(evidence, field, match.group("value"), source, match.group(0))
        for line in text.splitlines():
            if any(key in line.lower() for key in ("archer", "model", "product", "firmware", "hardware", "version")):
                for match in PAREN_REGION_RE.finditer(line):
                    add(evidence, "region", match.group("value"), source, line)
    return evidence


def canonical_field(items: list[dict]) -> dict | None:
    if not items:
        return None
    grouped: dict[str, dict] = {}
    for item in items:
        key = item["value"].lower()
        entry = grouped.setdefault(key, {"value": item["value"], "score": 0, "sources": set(), "evidence": []})
        if item["source"] not in entry["sources"]:
            entry["score"] += int(item["weight"])
            entry["sources"].add(item["source"])
        if len(entry["evidence"]) < MAX_EVIDENCE_PER_FIELD:
            entry["evidence"].append(item)
    ordered = sorted(grouped.values(), key=lambda e: (-e["score"], -len(e["sources"]), e["value"].lower()))
    top = ordered[0]
    runner_score = ordered[1]["score"] if len(ordered) > 1 else 0
    confidence = "HIGH" if top["score"] >= 140 or (top["score"] >= 95 and runner_score == 0) else "MEDIUM" if top["score"] >= 75 else "LOW"
    ambiguous = bool(runner_score and runner_score >= top["score"] - 15)
    return {
        "value": top["value"],
        "confidence": "AMBIGUOUS" if ambiguous else confidence,
        "score": top["score"],
        "source_count": len(top["sources"]),
        "alternatives": [{"value": item["value"], "score": item["score"]} for item in ordered[1:4]],
        "evidence": top["evidence"],
    }


def main() -> int:
    try:
        cfg = tomllib.loads(TARGET.read_text())
    except Exception as exc:
        fail(f"cannot read target/TARGET.toml: {exc}")
    if not cfg.get("engagement", {}).get("authorized", False):
        fail("engagement.authorized=false")

    evidence = parse_sources(collect_sources(cfg), cfg)
    canonical = {field: canonical_field(items) for field, items in evidence.items()}
    canonical = {field: value for field, value in canonical.items() if value is not None}

    def usable(field: str) -> bool:
        item = canonical.get(field)
        return bool(item and item.get("confidence") in {"HIGH", "MEDIUM"})

    advisory_ready = usable("product") and usable("hardware_revision") and (usable("build") or usable("firmware_version"))
    exact_identity = advisory_ready and usable("vendor") and usable("region") and usable("build")
    search_parts = []
    for field in ("vendor", "product", "region", "hardware_revision", "firmware_version", "build"):
        item = canonical.get(field)
        if item and item.get("confidence") != "AMBIGUOUS":
            search_parts.append(str(item["value"]))

    result = {
        "schema_version": 1,
        "canonical": canonical,
        "advisory_ready": advisory_ready,
        "exact_identity": exact_identity,
        "advisory_search_terms": " ".join(search_parts),
        "limitations": [],
    }
    if not advisory_ready:
        missing = [field for field in ("product", "hardware_revision") if not usable(field)]
        if not (usable("build") or usable("firmware_version")):
            missing.append("build-or-firmware-version")
        result["limitations"].append("advisory identity incomplete: " + ", ".join(missing))
    if advisory_ready and not usable("region"):
        result["limitations"].append("region not established; region-specific advisory applicability requires correlation")

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# Firmware identity", f"advisory_ready: {str(advisory_ready).lower()}", f"exact_identity: {str(exact_identity).lower()}"]
    for field in ("vendor", "product", "region", "hardware_revision", "firmware_version", "build", "release"):
        item = canonical.get(field)
        lines.append(f"{field}: {item['value']} [{item['confidence']}; score={item['score']}; sources={item['source_count']}]" if item else f"{field}: UNKNOWN")
    lines.append(f"advisory_search_terms: {result['advisory_search_terms']}")
    lines.extend(f"limitation: {item}" for item in result["limitations"])
    OUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Firmware identity: advisory_ready={advisory_ready} exact={exact_identity} search={result['advisory_search_terms']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
