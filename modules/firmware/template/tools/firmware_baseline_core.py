#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "tool-output"
PREP = REPORT / "firmware-preparation.json"

MAX_TEXT_SIZE = 2 * 1024 * 1024
MAX_SERVICE_LEADS = 250
MAX_UPDATE_LEADS = 160

KNOWN_DAEMONS = {
    "uhttpd", "httpd", "httpsd", "lighttpd", "nginx", "boa", "mini_httpd", "thttpd",
    "dropbear", "sshd", "telnetd", "utelnetd", "inetd", "xinetd", "ftpd", "vsftpd",
    "dnsmasq", "udhcpd", "dhcpd", "hostapd", "wpa_supplicant", "smbd", "nmbd",
    "miniupnpd", "upnpd", "cwmp", "tr069", "mqtt", "mosquitto", "rpcd",
    "ubusd", "dbus-daemon", "avahi-daemon", "avahi-dnsconfd", "snmpd", "ntpd",
    "openvpn", "afpd", "minidlna", "minidlna.exe", "eapd", "wps_monitor", "leafp2p",
}

DANGEROUS_IMPORTS = {
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp",
}
NETWORK_IMPORTS = {
    "socket", "bind", "listen", "accept", "connect", "recv", "recvfrom", "send",
    "sendto", "getaddrinfo", "inet_addr", "inet_aton",
}

UPDATE_STRONG_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sysupgrade", re.compile(r"\bsysupgrade\b", re.I)),
    ("firmware-upgrade", re.compile(r"\bfirmware[ _-]+(?:upgrade|update)\b", re.I)),
    ("firmware-image", re.compile(r"\b(?:firmware|upgrade)[._-]?(?:bin|img|chk)\b", re.I)),
    ("fwupgrade", re.compile(r"\bfwupgrade\b", re.I)),
    ("mtd-write", re.compile(r"\bmtd(?:_write|\s+write)\b", re.I)),
    ("nandwrite", re.compile(r"\bnandwrite\b", re.I)),
    ("flashcp", re.compile(r"\bflashcp\b", re.I)),
    ("swupdate", re.compile(r"\bswupdate\b", re.I)),
    ("rauc", re.compile(r"\brauc\b", re.I)),
    ("fw-env", re.compile(r"\bfw_(?:setenv|printenv)\b", re.I)),
    ("ubiupdatevol", re.compile(r"\bubiupdatevol\b", re.I)),
    ("verify-signature", re.compile(r"\bverify[ _-]?signature\b", re.I)),
    ("openssl-dgst", re.compile(r"\bopenssl\s+dgst\b", re.I)),
    ("rsa-verify", re.compile(r"\brsa[ _-]?verify\b", re.I)),
    ("sha256sum", re.compile(r"\bsha256sum\b", re.I)),
]
UPDATE_CONTEXT_RE = re.compile(r"\b(?:firmware|fw|upgrade|update|flash|mtd|image)\b", re.I)
UPDATE_CRYPTO_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("signature", re.compile(r"\bsignature\b", re.I)),
    ("public-key", re.compile(r"\bpublic[ _-]?key\b", re.I)),
    ("ecdsa", re.compile(r"\becdsa\b", re.I)),
]

NETWORK_CONFIG_PATTERNS = [
    re.compile(r"(?:^|\s)--(?:listen|port)(?:=|\s+)\S+", re.I),
    re.compile(r"\b(?:listen|bind)(?:_addr|_address|_port)?\s*[:=]\s*\S+", re.I),
    re.compile(r"\bport\s*[:=]\s*\d{1,5}\b", re.I),
    re.compile(r"(?:^|\s)-p\s+\d{1,5}(?:\s|$)", re.I),
]

WEB_EXTENSIONS = {".cgi", ".lua", ".php", ".asp", ".aspx", ".sh", ".js", ".html", ".htm"}
PACKAGE_DB_PATHS = {
    "usr/lib/opkg/status": "opkg",
    "var/lib/dpkg/status": "dpkg",
    "lib/apk/db/installed": "apk",
}
GENERIC_SYSTEM_TOOLS = {
    "ash", "sh", "busybox", "ip", "tc", "wget", "curl", "openssl", "grep", "sed", "awk",
    "mount", "umount", "ifconfig", "route", "ping", "kill", "cat", "cp", "mv", "rm", "ln",
}


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def redact_line(line: str) -> str:
    text = line.strip().replace("\x00", "")
    text = re.sub(
        r"(?i)((?:password|passwd|pwd|passphrase|psk|wpa_passphrase|secret|token|api[_-]?key|client_secret|app_secret)\s*(?:=|:)\s*)[^\s,;]+",
        r"\1<redacted>", text,
    )
    text = re.sub(
        r"(?i)(option\s+(?:key|password|passwd|psk|wpa_passphrase)\s+)[\"'][^\"']+[\"']",
        r"\1'<redacted>'", text,
    )
    text = re.sub(
        r"(?i)(--(?:password|passwd|passphrase|psk|secret|token|api[_-]?key)\s+)\S+",
        r"\1<redacted>", text,
    )
    text = re.sub(r"(://[^\s/:@]{1,80}:)[^\s/@]+@", r"\1<redacted>@", text)
    return text[:300]


def lstat_mode(path: Path) -> int | None:
    try:
        return path.lstat().st_mode
    except OSError:
        return None


def real_dir(path: Path) -> bool:
    mode = lstat_mode(path)
    return bool(mode is not None and stat.S_ISDIR(mode))


def unblob_artifact_dir(name: str) -> bool:
    return name.endswith("_extract")


def load_rootfs() -> tuple[Path, dict]:
    if not PREP.is_file():
        fail("firmware preparation missing; run tools/firmware_prepare.py first")
    prep = json.loads(PREP.read_text())
    raw = prep.get("primary_rootfs") or prep.get("extraction_root")
    if not raw:
        fail("preparation did not establish an extraction root")
    raw_path = Path(str(raw))
    if raw_path.is_absolute() or ".." in raw_path.parts or raw_path.parts[:2] != ("work", "extracted"):
        fail(f"unsafe prepared rootfs path: {raw}")
    rootfs = ROOT / raw_path
    if not real_dir(rootfs):
        fail(f"prepared rootfs/extraction path is not a real directory: {raw}")
    return rootfs, prep


def run(command: list[str], timeout: int = 60) -> str:
    proc = subprocess.run(
        command, cwd=ROOT, text=True, errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False,
    )
    return proc.stdout or ""


def read_regular_text(path: Path, st: os.stat_result) -> str:
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_TEXT_SIZE:
        return ""
    try:
        with path.open("rb") as handle:
            sample = handle.read(4096)
        if sample and b"\x00" in sample:
            return ""
        if sample:
            printable = sum(byte in b"\t\n\r" or 32 <= byte < 127 for byte in sample)
            if printable / len(sample) < 0.75:
                return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def is_elf_regular(path: Path, st: os.stat_result) -> bool:
    if not stat.S_ISREG(st.st_mode):
        return False
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def parse_elf(path: Path, st: os.stat_result) -> dict:
    header = run(["readelf", "-hW", str(path)])
    programs = run(["readelf", "-lW", str(path)])
    dynamic = run(["readelf", "-dW", str(path)])
    symbols = run(["readelf", "-sW", str(path)])
    sections = run(["readelf", "-SW", str(path)])

    def field(name: str) -> str | None:
        match = re.search(rf"^\s*{re.escape(name)}:\s*(.+)$", header, re.MULTILINE)
        return match.group(1).strip() if match else None

    interp_match = re.search(r"Requesting program interpreter:\s*([^\]]+)\]", programs)
    stack_line = next((line for line in programs.splitlines() if "GNU_STACK" in line), "")
    executable_stack = bool(re.search(r"\bRWE\b", stack_line))
    has_relro = "GNU_RELRO" in programs
    bind_now = "BIND_NOW" in dynamic or ("FLAGS_1" in dynamic and "NOW" in dynamic)
    elf_type = field("Type") or ""
    interpreter = interp_match.group(1).strip() if interp_match else None
    pie = bool(interpreter and elf_type.startswith("DYN"))

    imported: set[str] = set()
    for line in symbols.splitlines():
        if " UND " not in line:
            continue
        parts = line.split()
        if parts:
            imported.add(parts[-1].split("@", 1)[0])

    rpaths = [line.strip() for line in dynamic.splitlines() if "(RPATH)" in line or "(RUNPATH)" in line]
    return {
        "path": rel(path), "size": st.st_size, "mode": oct(stat.S_IMODE(st.st_mode)),
        "suid": bool(st.st_mode & stat.S_ISUID), "sgid": bool(st.st_mode & stat.S_ISGID),
        "class": field("Class"), "data": field("Data"), "machine": field("Machine"),
        "type": field("Type"), "interpreter": interpreter, "pie": pie,
        "relro": "full" if has_relro and bind_now else "partial" if has_relro else "none",
        "nx_stack": bool(stack_line) and not executable_stack, "executable_stack": executable_stack,
        "stack_canary_ref": "__stack_chk_fail" in symbols,
        "fortify_import_count": sum(1 for item in imported if item.endswith("_chk")),
        "stripped": ".symtab" not in sections, "rpath_runpath": rpaths,
        "dangerous_imports": sorted(imported.intersection(DANGEROUS_IMPORTS)),
        "network_imports": sorted(imported.intersection(NETWORK_IMPORTS)),
    }


def parse_passwd_text(text: str) -> list[dict]:
    result = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, passwd, uid, gid, _gecos, home, shell = parts[:7]
        result.append({
            "username": username, "uid": uid, "gid": gid, "home": home, "shell": shell,
            "password_field": "placeholder" if passwd in {"x", "*", "!", "!!"} else "empty" if passwd == "" else "embedded-value",
        })
    return result


def shadow_scheme(value: str) -> str:
    if value in {"", "!", "!!", "*", "!*"}:
        return "empty" if value == "" else "locked"
    for prefix, name in {"$1$": "md5crypt", "$2": "bcrypt", "$5$": "sha256crypt", "$6$": "sha512crypt", "$y$": "yescrypt"}.items():
        if value.startswith(prefix):
            return name
    return "hash-or-password-field"


def parse_shadow_text(text: str) -> list[dict]:
    result = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            result.append({"username": parts[0], "credential_state": shadow_scheme(parts[1])})
    return result


def parse_package_text(text: str, manager: str, source: str) -> list[dict]:
    packages: list[dict] = []
    current: dict[str, str] = {}
    for line in text.splitlines() + [""]:
        if not line.strip():
            name = current.get("Package") or current.get("P")
            version = current.get("Version") or current.get("V")
            if name:
                packages.append({"manager": manager, "name": name, "version": version, "source": source})
            current = {}
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = value.strip()
    return packages


def service_path(relative: str) -> bool:
    return bool(
        relative in {"etc/inittab", "etc/inetd.conf", "etc/crontab"}
        or relative.startswith("etc/init.d/") or re.match(r"etc/rc[^/]*/", relative)
        or relative.startswith("etc/xinetd.d/") or relative.startswith("etc/systemd/system/")
        or relative.startswith("usr/lib/systemd/system/") or relative.startswith("lib/systemd/system/")
        or relative.startswith("etc/config/") or relative.startswith("etc/cron.")
    )


def service_leads(path: Path, text: str) -> list[dict]:
    leads = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lower = stripped.lower()
        matched = sorted(
            name for name in KNOWN_DAEMONS
            if re.search(rf"(?<![A-Za-z0-9_.+-])(?:[^\s/]+/)?{re.escape(name)}(?![A-Za-z0-9_.+-])", lower)
        )
        network_config = any(pattern.search(stripped) for pattern in NETWORK_CONFIG_PATTERNS)
        if matched or network_config:
            leads.append({
                "path": rel(path), "line": number, "daemons": matched,
                "kind": "daemon" if matched else "network-config", "text": redact_line(stripped),
            })
    return leads


def update_noise_path(relative: str) -> bool:
    lower = relative.lower()
    name = Path(lower).name
    if name.startswith(("genie_strtab_", "string_table", "jquery")):
        return True
    if name.startswith(("gpl", "opensource", "open_source")):
        return True
    if lower.startswith("share/oui") or "/share/oui" in lower:
        return True
    return False


def update_path_hint(relative: str) -> bool:
    lower = relative.lower()
    name = Path(lower).name
    return bool(
        re.search(r"(?:^|[._-])(?:firmware|fw)(?:[._-]?(?:upgrade|update))?(?:[._-]|$)", name)
        or re.search(r"(?:^|[._-])(?:upgrade|sysupgrade|flash)(?:[._-]|$)", name)
        or any(part in {"upgrade", "update", "firmware"} for part in Path(lower).parts)
    )


def update_leads(path: Path, relative: str, text: str) -> list[dict]:
    if update_noise_path(relative):
        return []
    result: list[dict] = []
    path_hint = update_path_hint(relative)
    if path_hint:
        result.append({"path": rel(path), "line": 0, "keywords": ["update-path"], "text": f"update-relevant path: {relative}"})

    cert_like = Path(relative).suffix.lower() in {".crt", ".cer", ".pem", ".key"}
    for number, line in enumerate(text.splitlines(), 1):
        matches = [label for label, pattern in UPDATE_STRONG_PATTERNS if pattern.search(line)]
        if not matches and (path_hint or UPDATE_CONTEXT_RE.search(line)) and not cert_like:
            matches = [label for label, pattern in UPDATE_CRYPTO_PATTERNS if pattern.search(line)]
        if matches:
            result.append({"path": rel(path), "line": number, "keywords": matches[:5], "text": redact_line(line)})
    return result


def lead_mentions_binary(basename: str, leads: list[dict]) -> bool:
    if not basename:
        return False
    if len(basename) <= 3:
        pattern = re.compile(rf"(?:^|[\s;/|&])(?:/[^\s]*/)?{re.escape(basename)}(?:$|[\s;&|])", re.I)
    else:
        pattern = re.compile(rf"(?<![A-Za-z0-9_.+-])(?:[^\s/]+/)?{re.escape(basename)}(?![A-Za-z0-9_.+-])", re.I)
    return any(pattern.search(item.get("text", "")) for item in leads)


def shared_library(path: str) -> bool:
    relative = path.lower()
    name = Path(relative).name
    return ".so" in name or "/lib/" in f"/{relative}" or relative.startswith("lib/") or relative.startswith("usr/lib/")


def write_txt(name: str, lines: list[str]) -> None:
    (REPORT / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    rootfs, prep = load_rootfs()
    REPORT.mkdir(parents=True, exist_ok=True)

    file_count = dir_count = symlink_count = executable_count = script_count = 0
    artifact_dirs_pruned = 0
    suid_files: list[str] = []
    sgid_files: list[str] = []
    world_writable: list[str] = []
    scripts: list[dict] = []
    webroots: set[str] = set()
    web_files: list[str] = []
    elfs: list[dict] = []
    services: list[dict] = []
    updates: list[dict] = []
    passwd: list[dict] = []
    shadow: list[dict] = []
    packages: list[dict] = []

    for current, dirnames, filenames in os.walk(rootfs, followlinks=False):
        current_path = Path(current)
        safe_dirs = []
        for dirname in dirnames:
            if unblob_artifact_dir(dirname):
                artifact_dirs_pruned += 1
                continue
            child = current_path / dirname
            mode = lstat_mode(child)
            if mode is not None and stat.S_ISDIR(mode):
                safe_dirs.append(dirname)
                if dirname.lower() in {"www", "wwwroot", "htdocs"}:
                    webroots.add(rel(child))
        dirnames[:] = safe_dirs
        dir_count += len(safe_dirs)

        for filename in filenames:
            path = current_path / filename
            try:
                st = path.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                symlink_count += 1
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            file_count += 1
            try:
                relative = path.relative_to(rootfs).as_posix()
            except ValueError:
                continue

            if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                executable_count += 1
            if st.st_mode & stat.S_ISUID:
                suid_files.append(rel(path))
            if st.st_mode & stat.S_ISGID:
                sgid_files.append(rel(path))
            if st.st_mode & stat.S_IWOTH:
                world_writable.append(rel(path))

            if is_elf_regular(path, st):
                try:
                    elfs.append(parse_elf(path, st))
                except (OSError, subprocess.TimeoutExpired):
                    elfs.append({"path": rel(path), "error": "ELF metadata parse failed"})
                continue

            text = read_regular_text(path, st)
            if not text:
                continue
            if text.startswith("#!"):
                script_count += 1
                scripts.append({"path": rel(path), "interpreter": text.splitlines()[0][:200]})

            if relative == "etc/passwd":
                passwd = parse_passwd_text(text)
            elif relative == "etc/shadow":
                shadow = parse_shadow_text(text)
            elif relative in PACKAGE_DB_PATHS:
                packages.extend(parse_package_text(text, PACKAGE_DB_PATHS[relative], rel(path)))

            if any(part.lower() in {"www", "wwwroot", "htdocs"} for part in Path(relative).parts) or relative.startswith("var/www/"):
                if path.suffix.lower() in WEB_EXTENSIONS:
                    web_files.append(rel(path))

            if service_path(relative) and len(services) < MAX_SERVICE_LEADS:
                services.extend(service_leads(path, text)[: max(0, MAX_SERVICE_LEADS - len(services))])
            if len(updates) < MAX_UPDATE_LEADS:
                updates.extend(update_leads(path, relative, text)[: max(0, MAX_UPDATE_LEADS - len(updates))])

    hardening = {
        "elf_count": len(elfs),
        "pie": sum(1 for item in elfs if item.get("pie")),
        "full_relro": sum(1 for item in elfs if item.get("relro") == "full"),
        "partial_relro": sum(1 for item in elfs if item.get("relro") == "partial"),
        "no_relro": sum(1 for item in elfs if item.get("relro") == "none"),
        "nx_stack": sum(1 for item in elfs if item.get("nx_stack")),
        "executable_stack": sum(1 for item in elfs if item.get("executable_stack")),
        "canary_ref": sum(1 for item in elfs if item.get("stack_canary_ref")),
        "suid_elf": sum(1 for item in elfs if item.get("suid")),
        "dangerous_import_lead_binaries": sum(1 for item in elfs if item.get("dangerous_imports")),
        "network_import_lead_binaries": sum(1 for item in elfs if item.get("network_imports")),
    }

    binary_leads = []
    for item in elfs:
        if item.get("error"):
            continue
        basename = Path(item["path"]).name.lower()
        service_corr = basename in {daemon for lead in services for daemon in lead.get("daemons", [])} or lead_mentions_binary(basename, services)
        update_corr = lead_mentions_binary(basename, updates)
        semantic_reason = bool(item.get("suid") or service_corr or update_corr or item.get("rpath_runpath"))
        if shared_library(item["path"]) and not (service_corr or update_corr):
            continue

        score = 0
        reasons = []
        if item.get("suid"):
            score += 7; reasons.append("setuid")
        if service_corr:
            score += 6; reasons.append("startup/service correlation")
        if update_corr:
            score += 5; reasons.append("update-flow correlation")
        if item.get("network_imports"):
            score += 2; reasons.append("network imports")
        if item.get("dangerous_imports"):
            score += 1; reasons.append("dangerous imports")
        if item.get("rpath_runpath"):
            score += 2; reasons.append("RPATH/RUNPATH")
        if item.get("executable_stack"):
            score += 2; reasons.append("executable stack")
        elif item.get("relro") == "none" or not item.get("stack_canary_ref"):
            score += 1; reasons.append("hardening gap")
        if basename in GENERIC_SYSTEM_TOOLS and not (service_corr or update_corr or item.get("suid")):
            score -= 4
        if not semantic_reason and not (item.get("network_imports") and item.get("dangerous_imports")):
            continue
        if score > 1:
            binary_leads.append({"path": item["path"], "score": score, "reasons": reasons})
    binary_leads.sort(key=lambda item: (-item["score"], item["path"]))

    baseline = {
        "schema_version": 4,
        "rootfs": rel(rootfs), "preparation_coverage": prep.get("coverage"),
        "analysis_artifact_dirs_pruned": artifact_dirs_pruned,
        "counts": {
            "files": file_count, "directories": dir_count, "symlinks": symlink_count,
            "executables": executable_count, "scripts": script_count, "elfs": len(elfs),
            "web_files": len(web_files), "packages": len(packages),
        },
        "users": passwd, "shadow_accounts": shadow,
        "suid_files": suid_files, "sgid_files": sgid_files,
        "world_writable_files": world_writable[:1000], "webroots": sorted(webroots),
        "hardening": hardening, "service_lead_count": len(services), "update_lead_count": len(updates),
        "binary_priority_leads": binary_leads[:100],
    }

    (REPORT / "firmware-baseline.json").write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (REPORT / "firmware-binaries.json").write_text(json.dumps(elfs, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (REPORT / "firmware-services.json").write_text(json.dumps(services, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (REPORT / "firmware-update-leads.json").write_text(json.dumps(updates, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (REPORT / "firmware-components.json").write_text(json.dumps(packages, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (REPORT / "firmware-scripts.json").write_text(json.dumps(scripts, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (REPORT / "firmware-web-files.json").write_text(json.dumps(web_files[:10000], indent=2) + "\n", encoding="utf-8")

    write_txt("firmware-baseline.txt", [
        "# Firmware deterministic baseline",
        f"rootfs: {rel(rootfs)}", f"preparation coverage: {prep.get('coverage')}",
        f"analysis artifact dirs pruned: {artifact_dirs_pruned}",
        f"files: {file_count}", f"executables: {executable_count}", f"ELF binaries/libraries: {len(elfs)}",
        f"scripts: {script_count}", f"SUID files: {len(suid_files)}", f"SGID files: {len(sgid_files)}",
        f"world-writable files: {len(world_writable)}", f"web roots: {len(webroots)}", f"web files: {len(web_files)}",
        f"service/startup leads: {len(services)}", f"update/security leads: {len(updates)}",
        f"package-db components: {len(packages)}", f"full RELRO: {hardening['full_relro']}/{len(elfs)}",
        f"NX stack: {hardening['nx_stack']}/{len(elfs)}", f"executable stack: {hardening['executable_stack']}/{len(elfs)}",
        f"stack-canary references: {hardening['canary_ref']}/{len(elfs)}",
        f"dangerous-import lead binaries: {hardening['dangerous_import_lead_binaries']}",
        f"network-import lead binaries: {hardening['network_import_lead_binaries']}",
        "", "## Highest-priority binary review leads",
    ] + [f"- score={item['score']:2d} {item['path']} ({', '.join(item['reasons'])})" for item in binary_leads[:25]])

    write_txt("firmware-services.txt", ["# Service/startup leads"] + [
        f"- {item['path']}:{item['line']} kind={item['kind']} daemons={','.join(item['daemons']) or '-'} :: {item['text']}" for item in services[:150]
    ])
    write_txt("firmware-update-leads.txt", ["# Firmware update/security leads"] + [
        f"- {item['path']}:{item['line']} keywords={','.join(item['keywords'])} :: {item['text']}" for item in updates[:150]
    ])
    write_txt("firmware-components.txt", ["# Package database components"] + [
        f"- {item['manager']} {item['name']} {item.get('version') or '?'}" for item in packages[:500]
    ])

    print("[+] Firmware deterministic baseline complete")
    print(f"    rootfs: {rel(rootfs)}")
    print(f"    files={file_count} elfs={len(elfs)} services={len(services)} update_leads={len(updates)} pruned_artifact_dirs={artifact_dirs_pruned}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
