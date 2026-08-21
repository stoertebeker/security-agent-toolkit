#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import time
import tomllib
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

import apk_dynamic as runtime

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
MANIFEST = ROOT / "extracted" / "apktool" / "AndroidManifest.xml"
ACTION_LOG = ROOT / "reports" / "dynamic" / "actions.jsonl"
ANDROID = "{http://schemas.android.com/apk/res/android}"


def config() -> dict:
    with TARGET.open("rb") as handle:
        cfg = tomllib.load(handle)
    if not cfg.get("engagement", {}).get("authorized", False):
        raise SystemExit("[!] engagement.authorized=false")
    dynamic = cfg.get("dynamic", {})
    if not dynamic.get("enabled", False):
        raise SystemExit("[!] dynamic.enabled=false")
    if not dynamic.get("allow_active_validation", False):
        raise SystemExit("[!] dynamic.allow_active_validation=false")
    return dynamic


def manifest_tree() -> ET.Element:
    if not MANIFEST.is_file():
        raise SystemExit("[!] decoded AndroidManifest.xml missing; run apk_prepare.py first")
    try:
        return ET.parse(MANIFEST).getroot()
    except ET.ParseError as exc:
        raise SystemExit(f"[!] manifest parse failed: {exc}")


def declared_components(root: ET.Element) -> dict[str, set[str]]:
    package = root.attrib.get("package", runtime.package_name())
    app = root.find("application")
    result = {"activity": set(), "service": set(), "receiver": set()}
    if app is None:
        return result
    mapping = {"activity": ("activity", "activity-alias"), "service": ("service",), "receiver": ("receiver",)}
    for kind, tags in mapping.items():
        for tag in tags:
            for element in app.findall(tag):
                name = element.attrib.get(ANDROID + "name")
                if not name:
                    continue
                if name.startswith("."):
                    resolved = package + name
                elif "." not in name:
                    resolved = package + "." + name
                else:
                    resolved = name
                result[kind].update({name, resolved})
    return result


def declared_schemes(root: ET.Element) -> set[str]:
    app = root.find("application")
    schemes: set[str] = set()
    if app is None:
        return schemes
    for tag in ("activity", "activity-alias"):
        for component in app.findall(tag):
            for intent_filter in component.findall("intent-filter"):
                for data in intent_filter.findall("data"):
                    scheme = data.attrib.get(ANDROID + "scheme")
                    if scheme:
                        schemes.add(scheme.lower())
    return schemes


def redact_uri(uri: str) -> str:
    parts = urlsplit(uri)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "<redacted>" if parts.query else "", "<redacted>" if parts.fragment else ""))


def record(kind: str, details: dict, rc: int, output: str) -> None:
    ACTION_LOG.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "timestamp": int(time.time()),
        "kind": kind,
        "details": details,
        "returncode": rc,
        "output_excerpt": output[:1000],
    }
    with ACTION_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def deep_link(dynamic: dict, uri: str) -> int:
    parsed = urlsplit(uri)
    if not parsed.scheme or parsed.scheme.lower() in {"http", "https", "file", "content", "javascript", "intent"}:
        raise SystemExit("[!] deep-link action accepts only non-web custom schemes declared by the app")
    schemes = declared_schemes(manifest_tree())
    if parsed.scheme.lower() not in schemes:
        raise SystemExit(f"[!] scheme {parsed.scheme!r} is not declared in the decoded manifest")
    proc = runtime.adb(dynamic, "shell", "am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", uri, "-p", runtime.package_name(), timeout=60)
    record("deep-link", {"uri": redact_uri(uri), "declared_scheme": parsed.scheme.lower()}, proc.returncode, proc.stdout or "")
    print(proc.stdout or "")
    return proc.returncode


def component(dynamic: dict, kind: str, name: str) -> int:
    declared = declared_components(manifest_tree())
    if name not in declared[kind]:
        raise SystemExit(f"[!] {kind} {name!r} is not declared in the decoded manifest")
    package = runtime.package_name()
    target = f"{package}/{name}"
    if kind == "activity":
        args = ["shell", "am", "start", "-W", "-n", target]
    elif kind == "service":
        args = ["shell", "am", "startservice", "-n", target]
    else:
        args = ["shell", "am", "broadcast", "-n", target]
    proc = runtime.adb(dynamic, *args, timeout=60)
    record("component", {"component_kind": kind, "component": name}, proc.returncode, proc.stdout or "")
    print(proc.stdout or "")
    return proc.returncode


def tap(dynamic: dict, x: int, y: int) -> int:
    proc = runtime.adb(dynamic, "shell", "input", "tap", str(x), str(y), timeout=30)
    record("tap", {"x": x, "y": y}, proc.returncode, proc.stdout or "")
    return proc.returncode


def keyevent(dynamic: dict, key: str) -> int:
    if not re.fullmatch(r"[A-Za-z0-9_]+", key):
        raise SystemExit("[!] invalid keyevent token")
    proc = runtime.adb(dynamic, "shell", "input", "keyevent", key, timeout=30)
    record("keyevent", {"key": key}, proc.returncode, proc.stdout or "")
    return proc.returncode


def text_input(dynamic: dict, value: str) -> int:
    encoded = value.replace("%", "%25").replace(" ", "%s")
    proc = runtime.adb(dynamic, "shell", "input", "text", encoded, timeout=30)
    record("text", {"value_length": len(value)}, proc.returncode, proc.stdout or "")
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Audited emulator-local APK validation actions")
    sub = parser.add_subparsers(dest="action", required=True)
    dl = sub.add_parser("deep-link"); dl.add_argument("uri")
    comp = sub.add_parser("component"); comp.add_argument("kind", choices=["activity", "service", "receiver"]); comp.add_argument("name")
    tp = sub.add_parser("tap"); tp.add_argument("x", type=int); tp.add_argument("y", type=int)
    key = sub.add_parser("keyevent"); key.add_argument("key")
    txt = sub.add_parser("text"); txt.add_argument("value")
    args = parser.parse_args()
    dynamic = config()
    runtime.start()
    if args.action == "deep-link": return deep_link(dynamic, args.uri)
    if args.action == "component": return component(dynamic, args.kind, args.name)
    if args.action == "tap": return tap(dynamic, args.x, args.y)
    if args.action == "keyevent": return keyevent(dynamic, args.key)
    if args.action == "text": return text_input(dynamic, args.value)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
