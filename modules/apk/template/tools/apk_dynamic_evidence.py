#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DYNAMIC = ROOT / "reports" / "dynamic"
OUT_JSON = DYNAMIC / "evidence-summary.json"
OUT_TXT = DYNAMIC / "evidence-summary.txt"


def text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def pcap_summary() -> dict:
    pcap = DYNAMIC / "network.pcap"
    tcpdump = shutil.which("tcpdump")
    if not pcap.is_file():
        return {"available": False, "reason": "network.pcap missing"}
    if not tcpdump:
        return {"available": False, "reason": "tcpdump missing"}
    proc = subprocess.run(
        [tcpdump, "-nn", "-r", str(pcap)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        errors="replace",
        timeout=120,
        check=False,
    )
    flows: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    for line in proc.stdout.splitlines():
        if " IP6 " in f" {line} ":
            protocols["IPv6"] += 1
        elif " IP " in f" {line} ":
            protocols["IPv4"] += 1
        if ">" in line:
            m = re.search(r"\b([0-9a-fA-F:.]+(?:\.\d+)?)\s*>\s*([0-9a-fA-F:.]+(?:\.\d+)?):", line)
            if m:
                flows[f"{m.group(1)} -> {m.group(2)}"] += 1
    return {
        "available": True,
        "packet_lines": sum(protocols.values()),
        "protocol_counts": dict(protocols),
        "top_flows": [{"flow": flow, "count": count} for flow, count in flows.most_common(30)],
    }


def frida_summary() -> dict:
    path = DYNAMIC / "frida-events.txt"
    if not path.is_file():
        return {"available": False}
    kinds: Counter[str] = Counter()
    samples: dict[str, list[dict]] = {}
    for line in text(path).splitlines():
        marker = "SAT_EVENT "
        if marker not in line:
            continue
        payload = line.split(marker, 1)[1].strip()
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            continue
        kind = str(event.get("kind", "unknown"))
        kinds[kind] += 1
        samples.setdefault(kind, [])
        if len(samples[kind]) < 5:
            samples[kind].append(event.get("data") or {})
    return {"available": True, "event_counts": dict(kinds), "samples": samples}


def file_diff() -> dict:
    before = DYNAMIC / "states" / "postinstall" / "app-data-files.txt"
    after = DYNAMIC / "states" / "final" / "app-data-files.txt"
    if not after.is_file():
        return {"available": False}
    b = set(text(before).splitlines()) if before.is_file() else set()
    a = set(text(after).splitlines())
    created = sorted(a - b)
    return {"available": True, "created_file_count": len(created), "created_files": created[:500]}


def process_map_summary() -> dict:
    path = DYNAMIC / "states" / "final" / "process-maps.txt"
    if not path.is_file():
        return {"available": False}
    libs: set[str] = set()
    for line in text(path).splitlines():
        parts = line.split()
        if parts and parts[-1].endswith(".so"):
            libs.add(parts[-1])
    return {"available": True, "loaded_shared_libraries": sorted(libs)[:1000], "count": len(libs)}


def logcat_summary() -> dict:
    paths = [DYNAMIC / "launch-logcat.txt", DYNAMIC / "logcat-final.txt", DYNAMIC / "logcat-live.txt"]
    data = "\n".join(text(p) for p in paths if p.is_file())
    indicators = {
        "fatal_exception": r"FATAL EXCEPTION",
        "native_crash": r"Fatal signal|DEBUG\s+:.*backtrace",
        "cleartext_block": r"CLEARTEXT communication.*not permitted",
        "ssl_error": r"SSLHandshakeException|CERTIFICATE_VERIFY_FAILED|Trust anchor for certification path not found",
        "strictmode": r"StrictMode",
        "webview_console": r"chromium.*CONSOLE|WebView",
    }
    return {"available": bool(data), "indicator_counts": {name: len(re.findall(pattern, data, re.I)) for name, pattern in indicators.items()}}


def main() -> int:
    DYNAMIC.mkdir(parents=True, exist_ok=True)
    result = {
        "network": pcap_summary(),
        "frida": frida_summary(),
        "app_data_diff": file_diff(),
        "process_maps": process_map_summary(),
        "logcat": logcat_summary(),
        "note": "This is deterministic runtime evidence. Absence of an event does not prove the behavior is absent unless the relevant feature was exercised.",
    }
    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# APK dynamic evidence summary", "", result["note"], ""]
    net = result["network"]
    lines.append(f"network capture parsed: {'yes' if net.get('available') else 'no'}")
    if net.get("available"):
        lines.append(f"network packet lines: {net.get('packet_lines', 0)}")
        for item in net.get("top_flows", [])[:15]:
            lines.append(f"  flow {item['count']:>5}  {item['flow']}")
    frida = result["frida"]
    lines.append(f"frida events available: {'yes' if frida.get('available') else 'no'}")
    for kind, count in sorted(frida.get("event_counts", {}).items()):
        lines.append(f"  {kind}: {count}")
    diff = result["app_data_diff"]
    lines.append(f"app-data file diff available: {'yes' if diff.get('available') else 'no'}")
    if diff.get("available"):
        lines.append(f"new app-data files: {diff.get('created_file_count', 0)}")
    maps = result["process_maps"]
    lines.append(f"process maps available: {'yes' if maps.get('available') else 'no'}")
    if maps.get("available"):
        lines.append(f"loaded shared libraries: {maps.get('count', 0)}")
    lines.append("logcat indicators: " + json.dumps(result["logcat"].get("indicator_counts", {}), sort_keys=True))
    OUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"dynamic evidence summary: {OUT_TXT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
