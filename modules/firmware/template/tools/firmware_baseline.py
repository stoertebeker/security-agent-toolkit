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
MAX_SERVICE_LEADS = 400
MAX_UPDATE_LEADS = 300
MAX_BINARY_TEXT = 2 * 1024 * 1024

KNOWN_DAEMONS = {
    "uhttpd", "httpd", "lighttpd", "nginx", "boa", "mini_httpd", "thttpd",
    "dropbear", "sshd", "telnetd", "inetd", "xinetd", "ftpd", "vsftpd",
    "dnsmasq", "udhcpd", "dhcpd", "hostapd", "wpa_supplicant", "smbd", "nmbd",
    "miniupnpd", "upnpd", "cwmp", "tr069", "mqtt", "mosquitto", "rpcd",
    "ubusd", "dbus-daemon", "avahi-daemon", "snmpd", "ntpd", "openvpn",
}

DANGEROUS_IMPORTS = {
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp",
}

NETWORK_IMPORTS = {
    "socket", "bind", "listen", "accept", "connect", "recv", "recvfrom", "send",
    "sendto", "getaddrinfo", "inet_addr", "inet_aton",
}

UPDATE_KEYWORDS = (
    "sysupgrade", "firmware upgrade", "firmware_update", "fwupgrade", "mtd write",
    "mtd_write", "nandwrite", "flashcp", "swupdate", "rauc", "fw_setenv", "fw_printenv",
    "ubiupdatevol", "upgrade.bin", "firmware.bin", "signature", "verify_signature",
    "openssl dgst", "rsa_verify", "ecdsa", "public key", "public_key", "sha256sum",
)

WEB_EXTENSIONS = {".cgi", ".lua", ".php", ".asp", ".aspx", ".sh", ".js", ".html", ".htm"}


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def run(command: list[str], timeout: int = 60) -> str:
    proc = subprocess.run(
        command, cwd=ROOT, text=True, errors="replace", stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=timeout, check=False,
    )
    return proc.stdout or ""


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def load_rootfs() -> tuple[Path, dict]:
    if not PREP.is_file():
        fail("firmware preparation missing; run tools/firmware_prepare.py first")
    prep = json.loads(PREP.read_text())
    raw = prep.get("primary_rootfs") or prep.get("extraction_root")
    if not raw:
        fail("preparation did not establish an extraction root")
    rootfs = ROOT / raw
    if not rootfs.is_dir():
        fail(f"prepared rootfs/extraction path missing: {raw}")
    return rootfs, prep


def is_elf(path: Path) -> bool:
    try:
        if path.is_symlink() or not path.is_file():
            return False
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def likely_text(path: Path) -> bool:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_TEXT_SIZE:
            return False
        with path.open("rb") as handle:
            sample = handle.read(4096)
        if not sample:
            return True
        if b"\x00" in sample:
            return False
        printable = sum(byte in b"\t\n\r" or 32 <= byte < 127 for byte in sample)
        return printable / max(1, len(sample)) >= 0.75
    except OSError:
        return False


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def parse_elf(path: Path, mode: int) -> dict:
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
    has_relro = "GNU_RELRO" in programs
    bind_now = "BIND_NOW" in dynamic or "FLAGS_1" in dynamic and "NOW" in dynamic
    elf_type = field("Type") or ""
    interpreter = interp_match.group(1).strip() if interp_match else None
    pie = bool(interpreter and elf_type.startswith("DYN"))

    imported = set()
    for line in symbols.splitlines():
        if " UND " not in line:
            continue
        parts = line.split()
        if parts:
            symbol = parts[-1].split("@", 1)[0]
            imported.add(symbol)

    rpaths = []
    for line in dynamic.splitlines():
        if "(RPATH)" in line or "(RUNPATH)" in line:
            rpaths.append(line.strip())

    return {
        "path": rel(path),
        "size": path.stat().st_size,
        "mode": oct(stat.S_IMODE(mode)),
        "suid": bool(mode & stat.S_ISUID),
        "sgid": bool(mode & stat.S_ISGID),
        "class": field("Class"),
        "data": field("Data"),
        "machine": field("Machine"),
        "type": field("Type"),
        "interpreter": interpreter,
        "pie": pie,
        "relro": "full" if has_relro and bind_now else "partial" if has_relro else "none",
        "nx_stack": bool(stack_line and " E " not in f" {stack_line} "),
        "stack_canary_ref": "__stack_chk_fail" in symbols,
        "fortify_import_count": sum(1 for item in imported if item.endswith("_chk")),
        "stripped": ".symtab" not in sections,
        "rpath_runpath": rpaths,
        "dangerous_imports": sorted(imported.intersection(DANGEROUS_IMPORTS)),
        "network_imports": sorted(imported.intersection(NETWORK_IMPORTS)),
    }


def parse_passwd(rootfs: Path) -> list[dict]:
    path = rootfs / "etc/passwd"
    result = []
    if not path.is_file():
        return result
    for line in read_text(path).splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, passwd, uid, gid, gecos, home, shell = parts[:7]
        result.append({
            "username": username,
            "uid": uid,
            "gid": gid,
            "home": home,
            "shell": shell,
            "password_field": "placeholder" if passwd in {"x", "*", "!", "!!"} else "empty" if passwd == "" else "embedded-value",
        })
    return result


def shadow_scheme(value: str) -> str:
    if value in {"", "!", "!!", "*", "!*"}:
        return "empty" if value == "" else "locked"
    mapping = {"$1$": "md5crypt", "$2": "bcrypt", "$5$": "sha256crypt", "$6$": "sha512crypt", "$y$": "yescrypt"}
    for prefix, name in mapping.items():
        if value.startswith(prefix):
            return name
    return "hash-or-password-field"


def parse_shadow(rootfs: Path) -> list[dict]:
    path = rootfs / "etc/shadow"
    result = []
    if not path.is_file():
        return result
    for line in read_text(path).splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            result.append({"username": parts[0], "credential_state": shadow_scheme(parts[1])})
    return result


def service_path(path: Path, rootfs: Path) -> bool:
    try:
        relative = path.relative_to(rootfs).as_posix()
    except ValueError:
        return False
    return bool(
        relative == "etc/inittab"
        or relative == "etc/inetd.conf"
        or relative == "etc/crontab"
        or relative.startswith("etc/init.d/")
        or re.match(r"etc/rc[^/]*/", relative)
        or relative.startswith("etc/xinetd.d/")
        or relative.startswith("etc/systemd/system/")
        or relative.startswith("usr/lib/systemd/system/")
        or relative.startswith("lib/systemd/system/")
        or relative.startswith("etc/config/")
        or relative.startswith("etc/cron.")
    )


def service_leads(path: Path, text: str) -> list[dict]:
    leads = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lower = stripped.lower()
        matched = sorted(name for name in KNOWN_DAEMONS if re.search(rf"(^|[/\s]){re.escape(name)}($|\s)", lower))
        if matched or any(token in lower for token in ("listen", "bind", "port=", "--port", " -p ")):
            leads.append({"path": rel(path), "line": number, "daemons": matched, "text": stripped[:300]})
    return leads


def update_leads(path: Path, text: str) -> list[dict]:
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        lower = line.lower()
        matches = [keyword for keyword in UPDATE_KEYWORDS if keyword in lower]
        if matches:
            result.append({"path": rel(path), "line": number, "keywords": matches[:5], "text": line.strip()[:300]})
    return result


def parse_package_db(rootfs: Path) -> list[dict]:
    packages: list[dict] = []
    candidates = [
        (rootfs / "usr/lib/opkg/status", "opkg"),
        (rootfs / "var/lib/dpkg/status", "dpkg"),
        (rootfs / "lib/apk/db/installed", "apk"),
    ]
    for path, manager in candidates:
        if not path.is_file():
            continue
        current: dict[str, str] = {}
        for line in read_text(path).splitlines() + [""]:
            if not line.strip():
                name = current.get("Package") or current.get("P")
                version = current.get("Version") or current.get("V")
                if name:
                    packages.append({"manager": manager, "name": name, "version": version, "source": rel(path)})
                current = {}
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                current[key.strip()] = value.strip()
    return packages


def write_txt(name: str, lines: list[str]) -> None:
    (REPORT / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    rootfs, prep = load_rootfs()
    REPORT.mkdir(parents=True, exist_ok=True)

    file_count = dir_count = symlink_count = executable_count = script_count = 0
    suid_files: list[str] = []
    sgid_files: list[str] = []
    world_writable: list[str] = []
    scripts: list[dict] = []
    webroots: set[str] = set()
    web_files: list[str] = []
    elfs: list[dict] = []
    services: list[dict] = []
    updates: list[dict] = []

    for current, dirnames, filenames in os.walk(rootfs, followlinks=False):
        current_path = Path(current)
        dir_count += len(dirnames)
        for dirname in dirnames:
            if dirname.lower() in {"www", "wwwroot", "htdocs"}:
                webroots.add(rel(current_path / dirname))
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
            mode = st.st_mode
            if mode & stat.S_IXUSR or mode & stat.S_IXGRP or mode & stat.S_IXOTH:
                executable_count += 1
            if mode & stat.S_ISUID:
                suid_files.append(rel(path))
            if mode & stat.S_ISGID:
                sgid_files.append(rel(path))
            if mode & stat.S_IWOTH:
                world_writable.append(rel(path))

            if is_elf(path):
                try:
                    elfs.append(parse_elf(path, mode))
                except (OSError, subprocess.TimeoutExpired):
                    elfs.append({"path": rel(path), "error": "ELF metadata parse failed"})
                continue

            text_candidate = likely_text(path)
            text = read_text(path) if text_candidate else ""
            if text.startswith("#!"):
                script_count += 1
                scripts.append({"path": rel(path), "interpreter": text.splitlines()[0][:200]})

            try:
                relative = path.relative_to(rootfs)
            except ValueError:
                relative = Path(filename)
            if any(part.lower() in {"www", "wwwroot", "htdocs"} for part in relative.parts) or relative.as_posix().startswith("var/www/"):
                if path.suffix.lower() in WEB_EXTENSIONS:
                    web_files.append(rel(path))

            if text and service_path(path, rootfs) and len(services) < MAX_SERVICE_LEADS:
                services.extend(service_leads(path, text)[: max(0, MAX_SERVICE_LEADS - len(services))])
            if text and len(updates) < MAX_UPDATE_LEADS:
                updates.extend(update_leads(path, text)[: max(0, MAX_UPDATE_LEADS - len(updates))])

    passwd = parse_passwd(rootfs)
    shadow = parse_shadow(rootfs)
    packages = parse_package_db(rootfs)

    hardening = {
        "elf_count": len(elfs),
        "pie": sum(1 for item in elfs if item.get("pie")),
        "full_relro": sum(1 for item in elfs if item.get("relro") == "full"),
        "partial_relro": sum(1 for item in elfs if item.get("relro") == "partial"),
        "no_relro": sum(1 for item in elfs if item.get("relro") == "none"),
        "nx_stack": sum(1 for item in elfs if item.get("nx_stack")),
        "canary_ref": sum(1 for item in elfs if item.get("stack_canary_ref")),
        "suid_elf": sum(1 for item in elfs if item.get("suid")),
        "dangerous_import_lead_binaries": sum(1 for item in elfs if item.get("dangerous_imports")),
        "network_import_lead_binaries": sum(1 for item in elfs if item.get("network_imports")),
    }

    # Prioritize binaries without pretending these scores are vulnerability severity.
    binary_leads = []
    service_text = "\n".join(item.get("text", "") for item in services).lower()
    update_text = "\n".join(item.get("text", "") for item in updates).lower()
    common = {"busybox", "libc.so", "libpthread.so", "ld-uclibc.so", "ld-linux.so"}
    for item in elfs:
        if item.get("error"):
            continue
        basename = Path(item["path"]).name.lower()
        score = 0
        reasons = []
        if item.get("suid"):
            score += 6; reasons.append("setuid")
        if item.get("network_imports"):
            score += 3; reasons.append("network imports")
        if item.get("dangerous_imports"):
            score += 2; reasons.append("dangerous imports")
        if basename and basename in service_text:
            score += 5; reasons.append("startup/service correlation")
        if basename and basename in update_text:
            score += 4; reasons.append("update-flow correlation")
        if item.get("rpath_runpath"):
            score += 2; reasons.append("RPATH/RUNPATH")
        if item.get("relro") == "none" or not item.get("nx_stack") or not item.get("stack_canary_ref"):
            score += 1; reasons.append("hardening gap")
        if basename in common:
            score -= 2
        if score > 0:
            binary_leads.append({"path": item["path"], "score": score, "reasons": reasons})
    binary_leads.sort(key=lambda item: (-item["score"], item["path"]))

    baseline = {
        "schema_version": 1,
        "rootfs": rel(rootfs),
        "preparation_coverage": prep.get("coverage"),
        "counts": {
            "files": file_count, "directories": dir_count, "symlinks": symlink_count,
            "executables": executable_count, "scripts": script_count, "elfs": len(elfs),
            "web_files": len(web_files), "packages": len(packages),
        },
        "users": passwd,
        "shadow_accounts": shadow,
        "suid_files": suid_files,
        "sgid_files": sgid_files,
        "world_writable_files": world_writable[:1000],
        "webroots": sorted(webroots),
        "hardening": hardening,
        "service_lead_count": len(services),
        "update_lead_count": len(updates),
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
        f"rootfs: {rel(rootfs)}",
        f"preparation coverage: {prep.get('coverage')}",
        f"files: {file_count}",
        f"executables: {executable_count}",
        f"ELF binaries/libraries: {len(elfs)}",
        f"scripts: {script_count}",
        f"SUID files: {len(suid_files)}",
        f"SGID files: {len(sgid_files)}",
        f"world-writable files: {len(world_writable)}",
        f"web roots: {len(webroots)}",
        f"web files: {len(web_files)}",
        f"service/startup leads: {len(services)}",
        f"update/security leads: {len(updates)}",
        f"package-db components: {len(packages)}",
        f"full RELRO: {hardening['full_relro']}/{len(elfs)}",
        f"NX stack: {hardening['nx_stack']}/{len(elfs)}",
        f"stack-canary references: {hardening['canary_ref']}/{len(elfs)}",
        f"dangerous-import lead binaries: {hardening['dangerous_import_lead_binaries']}",
        f"network-import lead binaries: {hardening['network_import_lead_binaries']}",
        "",
        "## Highest-priority binary review leads",
    ] + [f"- score={item['score']:2d} {item['path']} ({', '.join(item['reasons'])})" for item in binary_leads[:30]])

    write_txt("firmware-services.txt", ["# Service/startup leads"] + [
        f"- {item['path']}:{item['line']} daemons={','.join(item['daemons']) or '-'} :: {item['text']}" for item in services[:200]
    ])
    write_txt("firmware-update-leads.txt", ["# Firmware update/security leads"] + [
        f"- {item['path']}:{item['line']} keywords={','.join(item['keywords'])} :: {item['text']}" for item in updates[:200]
    ])
    write_txt("firmware-components.txt", ["# Package database components"] + [
        f"- {item['manager']} {item['name']} {item.get('version') or '?'}" for item in packages[:500]
    ])

    print("[+] Firmware deterministic baseline complete")
    print(f"    rootfs: {rel(rootfs)}")
    print(f"    files={file_count} elfs={len(elfs)} services={len(services)} update_leads={len(updates)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
