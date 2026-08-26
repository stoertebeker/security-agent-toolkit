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

MAX_ROOTFS_BYTES = 24 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE = 10

VENDORS = {
    "tp-link": "TP-Link", "tplink": "TP-Link", "netgear": "NETGEAR",
    "d-link": "D-Link", "dlink": "D-Link", "linksys": "Linksys",
    "asus": "ASUS", "zyxel": "Zyxel", "ubiquiti": "Ubiquiti",
    "mikrotik": "MikroTik",
}

# Examples:
# ArcherC7v2_en_eu_3_15_3_up_boot(180305).bin
# Archer_C7(EU)_V2_180305.bin
ARCHER_COMPACT = re.compile(
    r"(?i)\bArcher[_ -]?(?P<model>[A-Z]+\d+)[_ -]?v(?P<hw>\d+(?:\.\d+)?)"
    r"(?:[_ -]+[a-z]{2})?[_ -]+(?P<region>eu|us|jp|uk|ca|au|ru|br|kr|tw|un)"
    r"[_ -]+(?P<version>\d+[_-]\d+[_-]\d+(?:[_-]\d+)?)"
    r".*?(?:\(|[_-])(?P<build>\d{6,14})(?:\)|\b)"
)
ARCHER_PAREN = re.compile(
    r"(?i)\bArcher\s*[_ -]?(?P<model>[A-Z]+\d+)\s*\((?P<region>EU|US|JP|UK|CA|AU|RU|BR|KR|TW|UN)\)"
    r"\s*[_ -]*V(?P<hw>\d+(?:\.\d+)?)(?:[_ -]+(?P<build>\d{6,14}))?"
)
FW_BUILD = re.compile(
    r"(?i)\b(?P<version>\d+\.\d+(?:\.\d+){1,2})\s+Build\s+(?P<build>\d{6,14})"
    r"(?:\s+Rel\.?\s*(?P<release>\d{3,}[A-Za-z0-9._-]*))?"
)
PRODUCT_LABEL = re.compile(
    r"(?i)(?:model(?:\s+name)?|product(?:\s+name)?|device\s+model)\s*[:=]\s*"
    r"(?P<value>Archer\s*[A-Z]+\d+|[A-Z][A-Za-z0-9._-]{2,24}\s+[A-Z0-9][A-Za-z0-9._-]{1,16})"
)
HW_LABEL = re.compile(r"(?i)(?:hardware(?:\s+version)?|hw\s*ver(?:sion)?)\s*[:=]\s*V?(?P<value>\d+(?:\.\d+)?)\b")
REGION_LABEL = re.compile(r"(?i)(?:region|country)\s*[:=]\s*(?P<value>EU|US|JP|UK|CA|AU|RU|BR|KR|TW|UN)\b")
VERSION_LABEL = re.compile(r"(?i)(?:firmware|software)\s*(?:version|ver)?\s*[:=]\s*(?P<value>\d+\.\d+(?:\.\d+){1,2})\b")
BUILD_LABEL = re.compile(r"(?i)\bBuild\s*(?P<value>\d{6,14})\b")
RELEASE_LABEL = re.compile(r"(?i)\bRel\.?\s*(?P<value>\d{3,}[A-Za-z0-9._-]*)\b")
ARCHER_ANY = re.compile(r"(?i)\bArcher\s*[_ -]?(?P<model>[A-Z]+\d+)\b")

GENERIC_FILENAMES = {"firmware.bin", "firmware.img", "image.bin", "image.img", "update.bin"}
HIGH_VALUE_NAMES = ("version", "release", "model", "product", "board", "device", "status", "system", "upgrade")

@dataclass(frozen=True)
class Evidence:
    field: str
    value: str
    source: str
    strength: int
    context: str


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def norm_product(value: str) -> str:
    value = re.sub(r"[_-]+", " ", value).strip()
    value = re.sub(r"(?i)^Archer\s*([A-Z]+)(\d+)$", r"Archer \1\2", value)
    return re.sub(r"\s+", " ", value)[:64]


def norm_hw(value: str) -> str:
    value = value.strip().upper().lstrip("V")
    if value.endswith(".0"):
        value = value[:-2]
    return "V" + value


def norm_version(value: str) -> str:
    return re.sub(r"[_-]", ".", value)


def printable_strings(data: bytes) -> str:
    chunks = [m.group().decode("ascii", "replace") for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]
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
        raw = json.loads(PREP.read_text()).get("primary_rootfs")
    except Exception:
        return None
    if not raw:
        return None
    rel = Path(str(raw))
    if rel.is_absolute() or ".." in rel.parts or rel.parts[:2] != ("work", "extracted"):
        return None
    rootfs = ROOT / rel
    return rootfs if real_dir(rootfs) else None


def add(items: list[Evidence], field: str, value: str | None, source: str, strength: int, context: str) -> None:
    if not value:
        return
    value = value.strip()
    if field == "product":
        value = norm_product(value)
    elif field == "hardware_revision":
        value = norm_hw(value)
    elif field == "region":
        value = value.upper()
    elif field == "firmware_version":
        value = norm_version(value)
    if not value or len(value) > 80:
        return
    items.append(Evidence(field, value, source, strength, re.sub(r"\s+", " ", context).strip()[:180]))


def parse_text(text: str, source: str, strength: int, items: list[Evidence], filename_mode: bool = False) -> None:
    for match in ARCHER_COMPACT.finditer(text):
        add(items, "vendor", "TP-Link", source, strength + 8, match.group(0))
        add(items, "product", "Archer " + match.group("model"), source, strength + 12, match.group(0))
        add(items, "hardware_revision", match.group("hw"), source, strength + 12, match.group(0))
        add(items, "region", match.group("region"), source, strength + 12, match.group(0))
        add(items, "firmware_version", match.group("version"), source, strength + 12, match.group(0))
        add(items, "build", match.group("build"), source, strength + 12, match.group(0))
    for match in ARCHER_PAREN.finditer(text):
        add(items, "vendor", "TP-Link", source, strength + 8, match.group(0))
        add(items, "product", "Archer " + match.group("model"), source, strength + 12, match.group(0))
        add(items, "hardware_revision", match.group("hw"), source, strength + 12, match.group(0))
        add(items, "region", match.group("region"), source, strength + 12, match.group(0))
        add(items, "build", match.group("build"), source, strength + 12, match.group(0))
    for match in FW_BUILD.finditer(text):
        add(items, "firmware_version", match.group("version"), source, strength + 8, match.group(0))
        add(items, "build", match.group("build"), source, strength + 8, match.group(0))
        add(items, "release", match.group("release"), source, strength + 8, match.group(0))

    # Generic labels are accepted only from metadata-oriented sources, never as
    # strong evidence merely because the same token appears in many binaries.
    if filename_mode or source.startswith("metadata:") or source == "operator-identity":
        for regex, field in ((PRODUCT_LABEL, "product"), (HW_LABEL, "hardware_revision"), (REGION_LABEL, "region"), (VERSION_LABEL, "firmware_version"), (BUILD_LABEL, "build"), (RELEASE_LABEL, "release")):
            for match in regex.finditer(text):
                add(items, field, match.group("value"), source, strength, match.group(0))
    for match in ARCHER_ANY.finditer(text):
        add(items, "product", "Archer " + match.group("model"), source, strength, match.group(0))
        add(items, "vendor", "TP-Link", source, strength - 2, match.group(0))
    low = text.lower()
    for token, canonical in VENDORS.items():
        if token in low:
            add(items, "vendor", canonical, source, strength - 4, token)


def collect(cfg: dict) -> list[Evidence]:
    items: list[Evidence] = []
    identity = cfg.get("identity", {}) if isinstance(cfg, dict) else {}
    for field in ("vendor", "product", "hardware_revision", "region", "firmware_version", "build", "release"):
        value = str(identity.get(field) or "").strip()
        if value:
            add(items, field, value, "operator-identity", 120, f"operator override {field}")

    source_filename = str(identity.get("source_filename") or "").strip()
    if source_filename:
        parse_text(source_filename, "source-filename", 115, items, filename_mode=True)

    fw_rel = Path(str(cfg.get("firmware", {}).get("path", "")))
    if fw_rel and not fw_rel.is_absolute() and ".." not in fw_rel.parts:
        fw = ROOT / fw_rel
        if fw.is_file() and fw.name.lower() not in GENERIC_FILENAMES:
            parse_text(fw.name, "configured-filename", 110, items, filename_mode=True)
        if fw.is_file():
            try:
                # Binary strings may corroborate a structured identity, but never
                # overpower filename/metadata evidence by repetition.
                parse_text(printable_strings(fw.read_bytes()[:16 * 1024 * 1024]), "firmware-strings", 54, items)
            except OSError:
                pass

    rootfs = load_rootfs()
    if rootfs:
        consumed = 0
        for current, dirnames, filenames in os.walk(rootfs, followlinks=False):
            current_path = Path(current)
            dirnames[:] = [d for d in dirnames if not d.endswith("_extract") and real_dir(current_path / d)]
            for filename in filenames:
                if consumed >= MAX_ROOTFS_BYTES:
                    break
                path = current_path / filename
                try:
                    st = path.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_size <= 0:
                    continue
                rel = path.relative_to(rootfs).as_posix()
                high_value = any(token in rel.lower() for token in HIGH_VALUE_NAMES)
                if not high_value and st.st_size > 512 * 1024:
                    continue
                amount = min(st.st_size, MAX_FILE_BYTES, MAX_ROOTFS_BYTES - consumed)
                consumed += amount
                try:
                    data = path.read_bytes()[:amount]
                except OSError:
                    continue
                if b"\x00" not in data[:4096]:
                    text = data.decode("utf-8", "replace")
                else:
                    text = printable_strings(data)
                source = ("metadata:" if high_value else "rootfs:") + rel
                parse_text(text, source, 86 if high_value else 48, items)
    return items


def choose(field: str, items: list[Evidence]) -> dict | None:
    matches = [item for item in items if item.field == field]
    if not matches:
        return None
    grouped: dict[str, list[Evidence]] = {}
    for item in matches:
        grouped.setdefault(item.value.lower(), []).append(item)
    ranked = []
    for value_items in grouped.values():
        strongest = max(item.strength for item in value_items)
        source_count = len({item.source for item in value_items})
        # Repeated weak strings can corroborate a value, but can add at most 18
        # points. They can never swamp one strong structured source.
        score = strongest + min(18, max(0, source_count - 1) * 3)
        ranked.append((score, strongest, source_count, value_items[0].value, value_items))
    ranked.sort(key=lambda row: (-row[0], -row[1], -row[2], row[3].lower()))
    score, strongest, source_count, value, evidence = ranked[0]
    runner = ranked[1][0] if len(ranked) > 1 else 0
    ambiguous = runner >= score - 8
    if ambiguous:
        confidence = "AMBIGUOUS"
    elif strongest >= 105:
        confidence = "HIGH"
    elif strongest >= 82:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    return {
        "value": value,
        "confidence": confidence,
        "score": score,
        "strongest_source": strongest,
        "source_count": source_count,
        "alternatives": [{"value": row[3], "score": row[0]} for row in ranked[1:4]],
        "evidence": [{"source": item.source, "strength": item.strength, "context": item.context} for item in sorted(evidence, key=lambda e: -e.strength)[:MAX_EVIDENCE]],
    }


def main() -> int:
    try:
        cfg = tomllib.loads(TARGET.read_text())
    except Exception as exc:
        fail(f"cannot read target/TARGET.toml: {exc}")
    if not cfg.get("engagement", {}).get("authorized", False):
        fail("engagement.authorized=false")

    evidence = collect(cfg)
    fields = {name: choose(name, evidence) for name in ("vendor", "product", "region", "hardware_revision", "firmware_version", "build", "release")}
    fields = {name: value for name, value in fields.items() if value is not None}

    def usable(name: str) -> bool:
        item = fields.get(name)
        return bool(item and item.get("confidence") in {"HIGH", "MEDIUM"})

    identity_complete = usable("vendor") and usable("product") and usable("hardware_revision") and (usable("build") or usable("firmware_version"))
    exact_identity = identity_complete and usable("region") and usable("build")
    result = {
        "schema_version": 2,
        "purpose": "target provenance/reporting; not a vulnerability-discovery oracle",
        "blind_discovery": not bool(cfg.get("orchestration", {}).get("advisory_scout", False)),
        "advisory_ready": identity_complete,
        "exact_identity": exact_identity,
        "fields": fields,
        "limitations": [],
    }
    missing = [name for name in ("vendor", "product", "hardware_revision") if not usable(name)]
    if not (usable("build") or usable("firmware_version")):
        missing.append("build-or-firmware-version")
    if missing:
        result["limitations"].append("identity incomplete: " + ", ".join(missing))

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# Firmware identity", f"purpose: {result['purpose']}", f"blind_discovery: {str(result['blind_discovery']).lower()}", f"advisory_ready: {str(identity_complete).lower()}", f"exact_identity: {str(exact_identity).lower()}"]
    for name in ("vendor", "product", "region", "hardware_revision", "firmware_version", "build", "release"):
        item = fields.get(name)
        if item:
            lines.append(f"{name}: {item['value']} [{item['confidence']}; score={item['score']}; strongest={item['strongest_source']}; sources={item['source_count']}]")
        else:
            lines.append(f"{name}: UNKNOWN")
    for limitation in result["limitations"]:
        lines.append("limitation: " + limitation)
    OUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("[+] Firmware identity complete: " + ", ".join(f"{k}={v['value']}" for k, v in fields.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
