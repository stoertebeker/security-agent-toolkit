#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "tool-output"
PREP = REPORT / "firmware-preparation.json"
BASELINE = REPORT / "firmware-baseline.json"
SERVICES = REPORT / "firmware-services.json"
UPDATES = REPORT / "firmware-update-leads.json"
UPDATE_UI = REPORT / "firmware-update-ui-paths.json"
WEB_FILES = REPORT / "firmware-web-files.json"

WEB_EXTENSIONS = {".cgi", ".lua", ".php", ".asp", ".aspx", ".shtml", ".sh", ".js", ".html", ".htm", ".css"}
UI_EXTENSIONS = {".html", ".htm", ".shtml", ".css", ".js"}
KNOWN_WEB_DIR_NAMES = {"www", "wwwroot", "htdocs", "web", "webroot", "html", "public_html"}
GENERIC_COMMANDS = {
    "ash", "sh", "bash", "busybox", "echo", "printf", "test", "true", "false", "sleep", "cat", "cp", "mv", "rm", "ln",
    "mkdir", "chmod", "chown", "grep", "egrep", "fgrep", "sed", "awk", "cut", "head", "tail", "sort", "uniq", "find",
    "mount", "umount", "insmod", "rmmod", "modprobe", "sysctl", "ifconfig", "route", "ip", "iptables", "ip6tables", "kill",
    "killall", "pkill", "start-stop-daemon", "service", "logger", "date", "touch", "export", "cd", "ulimit", "mknod", "dd",
}
STOP_RE = re.compile(r"(?:^|[;&|]\s*)(?:killall|pkill|kill)\b|\bstart-stop-daemon\b[^\n]*\b--stop\b|\bservice\s+\S+\s+stop\b", re.I)
UPDATE_WORD_RE = re.compile(r"\b(?:firmware|upgrade|update|flash|mtd|image)\b", re.I)


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def real_dir(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISDIR(mode) and not stat.S_ISLNK(mode)


def load_rootfs() -> Path:
    if not PREP.is_file():
        fail("firmware preparation missing")
    prep = json.loads(PREP.read_text())
    raw = prep.get("primary_rootfs") or prep.get("extraction_root")
    if not raw:
        fail("preparation did not establish an extraction root")
    raw_path = Path(str(raw))
    if raw_path.is_absolute() or ".." in raw_path.parts or raw_path.parts[:2] != ("work", "extracted"):
        fail(f"unsafe prepared rootfs path: {raw}")
    rootfs = ROOT / raw_path
    if not real_dir(rootfs):
        fail(f"prepared rootfs is not a real directory: {raw}")
    return rootfs


def walk_regular_files(rootfs: Path):
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
            if stat.S_ISREG(st.st_mode):
                yield path, st


def detect_web(rootfs: Path) -> tuple[list[str], list[str], set[str]]:
    web_paths: list[Path] = []
    parent_counts: dict[Path, int] = {}
    parent_active: dict[Path, int] = {}

    for path, _st in walk_regular_files(rootfs):
        suffix = path.suffix.lower()
        if suffix not in WEB_EXTENSIONS:
            continue
        web_paths.append(path)
        try:
            relative = path.relative_to(rootfs)
        except ValueError:
            continue
        parents = list(relative.parents)
        for parent in parents[:4]:
            if str(parent) == ".":
                continue
            parent_counts[parent] = parent_counts.get(parent, 0) + 1
            if suffix in {".html", ".htm", ".shtml", ".js", ".cgi", ".php", ".lua", ".asp", ".aspx"}:
                parent_active[parent] = parent_active.get(parent, 0) + 1

    candidate_rel: set[Path] = set()
    for path in web_paths:
        rel_path = path.relative_to(rootfs)
        for parent in rel_path.parents:
            if str(parent) == ".":
                continue
            if parent.name.lower() in KNOWN_WEB_DIR_NAMES:
                candidate_rel.add(parent)

    for parent, count in parent_counts.items():
        if len(parent.parts) <= 3 and count >= 6 and parent_active.get(parent, 0) >= 3:
            candidate_rel.add(parent)

    ordered = sorted(candidate_rel, key=lambda p: (len(p.parts), str(p)))
    roots: list[Path] = []
    for candidate in ordered:
        if any(candidate == root or root in candidate.parents for root in roots):
            continue
        roots.append(candidate)

    web_files: list[str] = []
    root_prefixes = tuple(root.parts for root in roots)
    for path in web_paths:
        relative = path.relative_to(rootfs)
        if root_prefixes and any(relative.parts[: len(parts)] == parts for parts in root_prefixes):
            web_files.append(rel(path))

    root_strings = [rel(rootfs / root) for root in roots]
    relative_roots = {root.as_posix().rstrip("/") for root in roots}
    return root_strings, sorted(set(web_files)), relative_roots


def path_is_web_ui(workspace_path: str, rootfs: Path, relative_roots: set[str]) -> bool:
    try:
        relative = (ROOT / workspace_path).relative_to(rootfs).as_posix()
    except (ValueError, OSError):
        return False
    if Path(relative).suffix.lower() not in UI_EXTENSIONS:
        return False
    return any(relative == root or relative.startswith(root + "/") for root in relative_roots)


def reclassify_update_ui(rootfs: Path, relative_roots: set[str]) -> tuple[list[dict], list[dict]]:
    updates = json.loads(UPDATES.read_text()) if UPDATES.is_file() else []
    ui = json.loads(UPDATE_UI.read_text()) if UPDATE_UI.is_file() else []
    kept: list[dict] = []
    moved: list[dict] = []
    for item in updates:
        path = str(item.get("path", ""))
        keywords = set(item.get("keywords") or [])
        mechanism = bool(keywords & {"mtd-write", "nandwrite", "flashcp", "sysupgrade", "fwupgrade", "ubiupdatevol", "verify-signature", "rsa-verify", "openssl-dgst", "sha256sum"})
        if path_is_web_ui(path, rootfs, relative_roots) and not mechanism:
            moved_item = dict(item)
            moved_item["keywords"] = sorted(set(moved_item.get("keywords") or []) | {"update-ui-content"})
            moved.append(moved_item)
        else:
            kept.append(item)
    known = {(str(item.get("path")), int(item.get("line", 0))) for item in ui + moved}
    for web_path in json.loads(WEB_FILES.read_text()) if WEB_FILES.is_file() else []:
        if not UPDATE_WORD_RE.search(Path(web_path).name):
            continue
        key = (str(web_path), 0)
        if key not in known:
            moved.append({"path": str(web_path), "line": 0, "keywords": ["update-ui-path"], "text": f"update-related UI path: {Path(web_path).name}"})
            known.add(key)
    return kept, ui + moved


def service_path(relative: str) -> bool:
    return bool(
        relative in {"etc/inittab", "etc/inetd.conf", "etc/crontab"}
        or relative.startswith("etc/init.d/")
        or re.match(r"etc/rc[^/]*/", relative)
        or relative.startswith("etc/xinetd.d/")
        or relative.startswith("etc/systemd/system/")
        or relative.startswith("usr/lib/systemd/system/")
        or relative.startswith("lib/systemd/system/")
        or relative.startswith("etc/config/")
        or relative.startswith("etc/cron.")
    )


def executable_index(rootfs: Path) -> tuple[dict[str, str], dict[str, list[str]]]:
    by_relative: dict[str, str] = {}
    by_name: dict[str, list[str]] = {}
    binaries = json.loads((REPORT / "firmware-binaries.json").read_text()) if (REPORT / "firmware-binaries.json").is_file() else []
    for item in binaries:
        workspace_path = str(item.get("path", ""))
        try:
            relative = (ROOT / workspace_path).relative_to(rootfs).as_posix()
        except (ValueError, OSError):
            continue
        by_relative[relative] = workspace_path
        by_name.setdefault(Path(relative).name, []).append(workspace_path)
    return by_relative, by_name


def strip_shell_prefixes(tokens: list[str]) -> list[str]:
    while tokens and (tokens[0] in {"if", "then", "elif", "else", "do", "while", "until", "!", "exec", "nohup"} or "=" in tokens[0] and not tokens[0].startswith("/")):
        tokens = tokens[1:]
    return tokens


def generic_launch_candidates(rootfs: Path, existing: list[dict]) -> list[dict]:
    by_relative, by_name = executable_index(rootfs)
    existing_keys = {(str(item.get("path")), int(item.get("line", 0)), tuple(item.get("daemons") or [])) for item in existing}
    additions: list[dict] = []
    for path, st in walk_regular_files(rootfs):
        relative = path.relative_to(rootfs).as_posix()
        if not service_path(relative) or st.st_size > 1024 * 1024:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, raw in enumerate(text.splitlines(), 1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or STOP_RE.search(stripped):
                continue
            for segment in re.split(r"(?:&&|\|\||;)", stripped):
                segment = segment.strip()
                if not segment or segment.startswith("#"):
                    continue
                try:
                    tokens = shlex.split(segment, comments=True, posix=True)
                except ValueError:
                    continue
                tokens = strip_shell_prefixes(tokens)
                if not tokens:
                    continue
                command = tokens[0]
                if command in {"[", "[[", "{"}:
                    continue
                base = Path(command).name
                if base in GENERIC_COMMANDS:
                    continue
                resolved: str | None = None
                if command.startswith("/"):
                    resolved = by_relative.get(command.lstrip("/"))
                elif "/" in command:
                    resolved = by_relative.get(command.lstrip("./"))
                else:
                    matches = by_name.get(base, [])
                    if len(matches) == 1:
                        resolved = matches[0]
                if not resolved:
                    continue
                key = (rel(path), line_no, (base,))
                if key in existing_keys:
                    continue
                additions.append({
                    "path": rel(path), "line": line_no, "daemons": [base], "kind": "start-candidate",
                    "text": stripped[:300], "source": "generic-executable-launch", "executable": resolved,
                })
                existing_keys.add(key)
    return additions


def update_binary_priority(baseline: dict, additions: list[dict]) -> None:
    launch_paths = {item.get("executable") for item in additions if item.get("executable")}
    for item in baseline.get("binary_priority_leads", []):
        if item.get("path") not in launch_paths:
            continue
        reasons = list(item.get("reasons") or [])
        if "startup/service correlation" not in reasons:
            reasons.insert(0, "startup/service correlation")
            item["reasons"] = reasons
            item["score"] = int(item.get("score", 0)) + 4
    baseline["binary_priority_leads"] = sorted(
        baseline.get("binary_priority_leads", []), key=lambda item: (-int(item.get("score", 0)), str(item.get("path", ""))),
    )


def baseline_tool_sha256() -> str:
    digest = hashlib.sha256()
    for path in (Path(__file__).resolve().parent / "firmware_baseline_core.py", Path(__file__).resolve()):
        if path.is_file():
            digest.update(path.name.encode("utf-8") + b"\0" + path.read_bytes())
    return digest.hexdigest()


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_services_txt(services: list[dict]) -> None:
    lines = ["# Service/lifecycle leads"]
    for item in services:
        lines.append(f"- {item.get('path')}:{item.get('line')} kind={item.get('kind')} daemons={','.join(item.get('daemons') or []) or '-'} :: {item.get('text', '')}")
    (REPORT / "firmware-services.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_update_txt(filename: str, title: str, items: list[dict]) -> None:
    lines = [title]
    for item in items:
        lines.append(f"- {item.get('path')}:{item.get('line')} keywords={','.join(item.get('keywords') or []) or '-'} :: {item.get('text', '')}")
    (REPORT / filename).write_text("\n".join(lines) + "\n", encoding="utf-8")


def patch_baseline_txt(baseline: dict) -> None:
    path = REPORT / "firmware-baseline.txt"
    if not path.is_file():
        return
    replacements = {
        "web roots:": len(baseline.get("webroots") or []),
        "web files:": int((baseline.get("counts") or {}).get("web_files", 0)),
        "service lifecycle leads:": int(baseline.get("service_lifecycle_lead_count", 0)),
        "service startup/config leads:": int(baseline.get("service_startup_config_lead_count", 0)),
        "update/security leads:": int(baseline.get("update_security_lead_count", 0)),
        "update UI/path anchors:": int(baseline.get("update_ui_path_count", 0)),
    }
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        replaced = False
        for prefix, value in replacements.items():
            if line.startswith(prefix):
                out.append(f"{prefix} {value}")
                replaced = True
                break
        if not replaced:
            out.append(line)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main() -> int:
    if not BASELINE.is_file():
        fail("firmware baseline missing")
    rootfs = load_rootfs()
    baseline = json.loads(BASELINE.read_text())

    webroots, web_files, relative_roots = detect_web(rootfs)
    baseline["webroots"] = webroots
    baseline.setdefault("counts", {})["web_files"] = len(web_files)
    write_json(WEB_FILES, web_files)

    services = json.loads(SERVICES.read_text()) if SERVICES.is_file() else []
    additions = generic_launch_candidates(rootfs, services)
    services.extend(additions)
    services.sort(key=lambda item: (str(item.get("path", "")), int(item.get("line", 0)), str(item.get("kind", ""))))
    write_json(SERVICES, services)
    write_services_txt(services)
    baseline["service_lifecycle_lead_count"] = len(services)
    baseline["service_startup_config_lead_count"] = sum(1 for item in services if item.get("kind") in {"start", "start-candidate", "network-config"})
    baseline["service_stop_lead_count"] = sum(1 for item in services if item.get("kind") == "stop")
    update_binary_priority(baseline, additions)

    kept_updates, ui_updates = reclassify_update_ui(rootfs, relative_roots)
    write_json(UPDATES, kept_updates)
    write_json(UPDATE_UI, ui_updates)
    write_update_txt("firmware-update-leads.txt", "# Firmware update/security leads", kept_updates)
    write_update_txt("firmware-update-ui-paths.txt", "# Firmware update UI/path anchors", ui_updates)
    baseline["update_security_lead_count"] = len(kept_updates)
    baseline["update_ui_path_count"] = len(ui_updates)
    baseline["baseline_enrichment"] = {
        "schema_version": 1,
        "tool_sha256": baseline_tool_sha256(),
        "webroot_detection": "heuristic+known-directory",
        "generic_launch_candidates_added": len(additions),
        "update_ui_reclassified": len(ui_updates),
    }
    write_json(BASELINE, baseline)
    patch_baseline_txt(baseline)

    print(f"[+] Baseline enrichment complete: webroots={len(webroots)} web_files={len(web_files)} generic_launch_leads={len(additions)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
