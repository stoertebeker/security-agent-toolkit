#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import lzma
import os
import platform
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
SAT_HOME = Path(os.environ.get("SAT_HOME", Path.home() / ".local/share/security-agent-toolkit"))
SDK_ROOT = SAT_HOME / "android-sdk"
WORK = ROOT / "work" / "android"
TMP = ROOT / "work" / "tmp"
REPORT = ROOT / "reports" / "dynamic"
TOOL_REPORT = ROOT / "reports" / "tool-output"
SETUP_JSON = REPORT / "setup.json"
CAP_JSON = TOOL_REPORT / "dynamic-capabilities.json"
CAP_TXT = TOOL_REPORT / "dynamic-capabilities.txt"
EMULATOR_PID = WORK / "emulator.pid"
LOGCAT_PID = WORK / "logcat.pid"
EMULATOR_LOG = REPORT / "emulator.log"
LOGCAT_LOG = REPORT / "logcat-live.txt"

DEFAULTS = {
    "backend": "auto",
    "api_level": 36,
    "image_tag": "auto",
    "allow_software_emulation": True,
    "allow_frida": False,
    "allow_active_validation": False,
    "headless": True,
    "wipe_data_on_start": True,
    "grant_runtime_permissions": False,
    "request_root": True,
    "memory_mb": 4096,
    "cores": 4,
    "boot_timeout_seconds": 600,
    "observation_seconds": 15,
    "emulator_port": 5554,
}


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def load_config(require_dynamic: bool = False) -> tuple[dict, dict]:
    with TARGET.open("rb") as handle:
        cfg = tomllib.load(handle)
    if not cfg.get("engagement", {}).get("authorized", False):
        fail("engagement.authorized=false")
    dynamic = dict(DEFAULTS)
    dynamic.update(cfg.get("dynamic", {}))
    if require_dynamic and not dynamic.get("enabled", False):
        fail("dynamic.enabled=false")
    return cfg, dynamic


def env() -> dict[str, str]:
    e = os.environ.copy()
    e.update({
        "PATH": f"{SAT_HOME / 'bin'}:{e.get('PATH', '')}",
        "ANDROID_SDK_ROOT": str(SDK_ROOT),
        "ANDROID_HOME": str(SDK_ROOT),
        "ANDROID_AVD_HOME": str(WORK / "avd"),
        "ANDROID_EMULATOR_HOME": str(WORK / "emulator-home"),
        "ANDROID_USER_HOME": str(WORK / "user-home"),
        "TMPDIR": str(TMP), "TMP": str(TMP), "TEMP": str(TMP),
        "JAVA_HOME": str(SAT_HOME / "java" / "jdk-21"),
    })
    return e


def mkdirs() -> None:
    for path in (WORK, WORK / "avd", WORK / "emulator-home", WORK / "user-home", TMP, REPORT, TOOL_REPORT):
        path.mkdir(parents=True, exist_ok=True)


def run(command: list[str], *, timeout: int | None = 120, input_text: str | None = None, binary: bool = False) -> subprocess.CompletedProcess:
    kwargs = dict(cwd=ROOT, env=env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    if binary:
        return subprocess.run(command, input=input_text.encode() if input_text else None, **kwargs)
    return subprocess.run(command, text=True, errors="replace", input=input_text, **kwargs)


def which(name: str) -> str | None:
    return shutil.which(name, path=env()["PATH"])


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def detect_virtualization() -> tuple[str, str]:
    detector = shutil.which("systemd-detect-virt")
    if detector:
        for kind, flag in (("container", "--container"), ("vm", "--vm")):
            proc = run([detector, flag], timeout=10)
            value = (proc.stdout or "").strip()
            if proc.returncode == 0 and value and value != "none":
                return kind, value
        proc = run([detector], timeout=10)
        value = (proc.stdout or "").strip()
        if proc.returncode == 0 and value and value != "none":
            return "virtualized", value
    cgroup = read_text(Path("/proc/1/cgroup")).lower()
    for token in ("lxc", "docker", "podman", "containerd", "kubepods"):
        if token in cgroup:
            return "container", token
    return "bare", "none"


def target_abis() -> list[str]:
    aliases = {"arm64_v8a": "arm64-v8a", "armeabi_v7a": "armeabi-v7a"}
    values: set[str] = set()
    apktool = ROOT / "extracted" / "apktool"
    if apktool.exists():
        for so in apktool.rglob("*.so"):
            parts = so.parts
            if "lib" in parts:
                idx = len(parts) - 1 - list(reversed(parts)).index("lib")
                if idx + 1 < len(parts):
                    abi = aliases.get(parts[idx + 1], parts[idx + 1])
                    if abi in {"arm64-v8a", "armeabi-v7a", "x86_64", "x86"}:
                        values.add(abi)
    xapk = TOOL_REPORT / "xapk-inventory.json"
    if xapk.is_file():
        try:
            data = json.loads(xapk.read_text())
            for item in data.get("splits", []):
                sid = str(item.get("id", ""))
                if sid.startswith("config."):
                    raw = sid.removeprefix("config.")
                    abi = aliases.get(raw, raw)
                    if abi in {"arm64-v8a", "armeabi-v7a", "x86_64", "x86"}:
                        values.add(abi)
        except Exception:
            pass
    return sorted(values)


def package_metadata() -> dict:
    result = {"package": None, "min_sdk": None, "target_sdk": None}
    xapk = TOOL_REPORT / "xapk-inventory.json"
    if xapk.is_file():
        try:
            result["package"] = json.loads(xapk.read_text()).get("package_name")
        except Exception:
            pass
    aapt = read_text(TOOL_REPORT / "aapt.txt")
    if not result["package"]:
        m = re.search(r"package:\s+name='([^']+)'", aapt)
        if m: result["package"] = m.group(1)
    for key, pattern in (("min_sdk", r"sdkVersion:'?(\d+)'?"), ("target_sdk", r"targetSdkVersion:'?(\d+)'?")):
        m = re.search(pattern, aapt)
        if m: result[key] = int(m.group(1))
    return result


def choose_image_abi(host_arch: str, abis: list[str]) -> str:
    if not abis: return "x86_64" if host_arch == "x86_64" else "arm64-v8a"
    if host_arch == "x86_64" and "x86_64" in abis: return "x86_64"
    if "arm64-v8a" in abis: return "arm64-v8a"
    if "x86_64" in abis: return "x86_64"
    if "x86" in abis: return "x86"
    return abis[0]


def probe() -> dict:
    mkdirs(); _, dynamic = load_config(False)
    virt_kind, virt_name = detect_virtualization()
    host_arch = platform.machine().lower()
    cpuinfo = read_text(Path("/proc/cpuinfo"))
    virt_flag = bool(re.search(r"\b(vmx|svm)\b", cpuinfo))
    kvm = Path("/dev/kvm"); emulator = which("emulator")
    accel_output = ""; accel_rc = None
    if emulator:
        proc = run([emulator, "-accel-check"], timeout=30)
        accel_rc = proc.returncode; accel_output = (proc.stdout or "").strip()
    kvm_usable = bool(emulator and accel_rc == 0)
    abis = target_abis(); image_abi = choose_image_abi(host_arch, abis)
    allow_sw = bool(dynamic.get("allow_software_emulation", True)); backend = str(dynamic.get("backend", "auto"))
    notes: list[str] = []; available = True; acceleration = "software"
    if backend == "none": available = False; notes.append("dynamic.backend=none")
    elif host_arch != "x86_64": available = False; notes.append("managed Android Emulator v1 currently supports Linux x86_64 hosts only")
    elif image_abi in {"x86_64", "x86"} and kvm_usable: acceleration = "kvm"
    elif not allow_sw: available = False; notes.append("KVM/cross-architecture acceleration unavailable and software emulation is disabled")
    if image_abi == "arm64-v8a" and host_arch == "x86_64": notes.append("ARM64 native target requires software CPU emulation on x86_64")
    if virt_kind == "container" and not kvm.exists(): notes.append(f"{virt_name} container has no /dev/kvm; host must pass the KVM device for acceleration")
    elif virt_kind == "container" and kvm.exists() and not os.access(kvm, os.R_OK | os.W_OK): notes.append(f"{virt_name} exposes /dev/kvm but current user lacks read/write access")
    elif virt_kind == "vm" and not kvm.exists(): notes.append(f"{virt_name} VM has no /dev/kvm; nested virtualization is likely not exposed")
    elif virt_kind == "bare" and virt_flag and not kvm.exists(): notes.append("CPU virtualization flags exist but /dev/kvm is absent")
    if not emulator: notes.append("Android Emulator tooling is not installed; run toolkit install apk --with-optional")
    if emulator and accel_rc not in (None, 0): notes.append("emulator -accel-check did not report usable KVM")
    result = {
        "host_arch": host_arch, "virtualization_kind": virt_kind, "virtualization_name": virt_name,
        "cpu_virtualization_flag": virt_flag, "dev_kvm_exists": kvm.exists(), "dev_kvm_rw": kvm.exists() and os.access(kvm, os.R_OK | os.W_OK),
        "emulator_installed": bool(emulator), "sdkmanager_installed": bool(which("sdkmanager")), "avdmanager_installed": bool(which("avdmanager")), "adb_installed": bool(which("adb")),
        "emulator_accel_check_rc": accel_rc, "emulator_accel_check": accel_output, "kvm_usable": kvm_usable,
        "target_abis": abis, "selected_image_abi": image_abi, "selected_acceleration": acceleration,
        "dynamic_available": available, "notes": notes,
    }
    CAP_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    lines = ["# APK dynamic capability probe", f"host architecture: {host_arch}", f"virtualization: {virt_kind}/{virt_name}", f"cpu virtualization flag: {'yes' if virt_flag else 'no'}", f"/dev/kvm: {'rw' if result['dev_kvm_rw'] else 'present-no-rw' if kvm.exists() else 'absent'}", f"emulator installed: {'yes' if emulator else 'no'}", f"KVM usable by emulator: {'yes' if kvm_usable else 'no'}", f"target ABIs: {', '.join(abis) if abis else 'no native ABI requirement'}", f"selected image ABI: {image_abi}", f"selected acceleration: {acceleration}", f"dynamic available: {'yes' if available else 'no'}", ""] + [f"- {n}" for n in notes]
    CAP_TXT.write_text("\n".join(lines) + "\n")
    return result


def sdk_available_packages() -> str:
    sdkmanager = which("sdkmanager")
    if not sdkmanager: fail("sdkmanager missing; run ./toolkit install apk --with-optional")
    proc = run([sdkmanager, "--sdk_root=" + str(SDK_ROOT), "--list"], timeout=180)
    if proc.returncode != 0: fail("sdkmanager --list failed")
    return proc.stdout or ""


def choose_system_image(cap: dict, dynamic: dict, meta: dict) -> tuple[str, int, str]:
    listing = sdk_available_packages(); requested = int(dynamic.get("api_level") or 0)
    if requested <= 0: requested = int(meta.get("target_sdk") or 36)
    min_sdk = int(meta.get("min_sdk") or 26); apis = list(range(requested, max(min_sdk, requested - 3) - 1, -1))
    configured_tag = str(dynamic.get("image_tag", "auto")); tags = ["default", "google_apis"] if configured_tag == "auto" else [configured_tag]
    abi = cap["selected_image_abi"]
    for api in apis:
        for tag in tags:
            package = f"system-images;android-{api};{tag};{abi}"
            if package in listing: return package, api, tag
    fail(f"No compatible system image for ABI={abi}, APIs={apis}, tags={tags}")


def write_avd_config(avd_dir: Path, dynamic: dict) -> None:
    cfg = avd_dir / "config.ini"; text = read_text(cfg)
    updates = {"hw.ramSize": str(int(dynamic.get("memory_mb", 4096))), "hw.cpu.ncore": str(int(dynamic.get("cores", 4))), "hw.keyboard": "yes", "showDeviceFrame": "no", "disk.dataPartition.size": "4G", "hw.gpu.enabled": "yes", "hw.gpu.mode": "swiftshader_indirect"}
    lines = text.splitlines(); seen = set(); out = []
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line else None
        if key in updates: out.append(f"{key}={updates[key]}"); seen.add(key)
        else: out.append(line)
    for key, value in updates.items():
        if key not in seen: out.append(f"{key}={value}")
    cfg.write_text("\n".join(out) + "\n")


def setup() -> dict:
    mkdirs(); _, dynamic = load_config(True); cap = probe()
    if not cap["dynamic_available"]: fail("dynamic capability probe reports UNAVAILABLE; see reports/tool-output/dynamic-capabilities.txt")
    for tool in ("emulator", "sdkmanager", "avdmanager", "adb"):
        if not which(tool): fail(f"{tool} missing; run ./toolkit install apk --with-optional")
    meta = package_metadata(); image_package, api, tag = choose_system_image(cap, dynamic, meta)
    print(f"[*] Installing/reusing system image: {image_package}", flush=True)
    proc = run([which("sdkmanager") or "sdkmanager", "--sdk_root=" + str(SDK_ROOT), "--install", image_package], timeout=1800, input_text="y\n" * 100)
    (REPORT / "sdkmanager-system-image.txt").write_text(proc.stdout or "")
    if proc.returncode != 0: fail("system image installation failed; see reports/dynamic/sdkmanager-system-image.txt")
    project_slug = re.sub(r"[^A-Za-z0-9_-]+", "-", ROOT.name).strip("-")[:40] or "apk"; abi_slug = cap["selected_image_abi"].replace("-", "_")
    avd_name = f"sat-{project_slug}-api{api}-{abi_slug}"; avd_home = Path(env()["ANDROID_AVD_HOME"]); avd_dir = avd_home / f"{avd_name}.avd"
    if avd_dir.exists(): shutil.rmtree(avd_dir)
    (avd_home / f"{avd_name}.ini").unlink(missing_ok=True)
    proc = run([which("avdmanager") or "avdmanager", "create", "avd", "--force", "--name", avd_name, "--package", image_package], timeout=180, input_text="no\n")
    (REPORT / "avd-create.txt").write_text(proc.stdout or "")
    if proc.returncode != 0 or not avd_dir.exists(): fail("AVD creation failed; see reports/dynamic/avd-create.txt")
    write_avd_config(avd_dir, dynamic)
    result = {"avd_name": avd_name, "avd_dir": str(avd_dir.relative_to(ROOT)), "system_image_package": image_package, "api_level": api, "image_tag": tag, "image_abi": cap["selected_image_abi"], "acceleration": cap["selected_acceleration"], "root_expected": tag == "default", "package": meta.get("package"), "target_abis": cap["target_abis"], "virtualization_kind": cap["virtualization_kind"], "virtualization_name": cap["virtualization_name"]}
    SETUP_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"[+] Dynamic AVD ready: {avd_name}\n    image: {image_package}\n    acceleration: {result['acceleration']}")
    return result


def read_setup() -> dict:
    if not SETUP_JSON.is_file(): return setup()
    try: return json.loads(SETUP_JSON.read_text())
    except Exception: return setup()


def adb_serial(dynamic: dict) -> str: return f"emulator-{int(dynamic.get('emulator_port', 5554))}"

def adb(dynamic: dict, *args: str, timeout: int | None = 120) -> subprocess.CompletedProcess:
    if not which("adb"): fail("adb missing")
    return run([which("adb") or "adb", "-s", adb_serial(dynamic), *args], timeout=timeout)


def pid_alive(path: Path) -> bool:
    try:
        pid = int(path.read_text().strip()); os.kill(pid, 0); return True
    except Exception: return False


def start_logcat(dynamic: dict) -> None:
    if pid_alive(LOGCAT_PID): return
    out = LOGCAT_LOG.open("ab")
    proc = subprocess.Popen([which("adb") or "adb", "-s", adb_serial(dynamic), "logcat", "-v", "threadtime"], cwd=ROOT, env=env(), stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
    LOGCAT_PID.write_text(str(proc.pid) + "\n")


def device_info(dynamic: dict) -> dict:
    props = {}; proc = adb(dynamic, "shell", "getprop", timeout=30)
    for line in (proc.stdout or "").splitlines():
        m = re.match(r"\[([^\]]+)\]: \[(.*)\]", line)
        if m: props[m.group(1)] = m.group(2)
    ident = (adb(dynamic, "shell", "id", timeout=30).stdout or "").strip()
    result = {"serial": adb_serial(dynamic), "id": ident, "sdk": props.get("ro.build.version.sdk"), "release": props.get("ro.build.version.release"), "abi": props.get("ro.product.cpu.abi"), "abilist": props.get("ro.product.cpu.abilist"), "build_type": props.get("ro.build.type"), "build_tags": props.get("ro.build.tags"), "model": props.get("ro.product.model"), "fingerprint": props.get("ro.build.fingerprint")}
    (REPORT / "device-info.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n"); return result


def package_name() -> str:
    pkg = package_metadata().get("package")
    if pkg: return str(pkg)
    fail("could not determine package name from preparation output")


def capture_state(dynamic: dict, label: str) -> None:
    pkg = package_name(); outdir = REPORT / "states" / label; outdir.mkdir(parents=True, exist_ok=True)
    commands = {"package.txt": ["shell", "dumpsys", "package", pkg], "appops.txt": ["shell", "cmd", "appops", "get", pkg], "processes.txt": ["shell", "ps", "-A"], "activity.txt": ["shell", "dumpsys", "activity", "activities"], "webview.txt": ["shell", "dumpsys", "webviewupdate"]}
    for filename, args in commands.items(): (outdir / filename).write_text(adb(dynamic, *args, timeout=60).stdout or "")
    ident = adb(dynamic, "shell", "id", timeout=30).stdout or ""
    if "uid=0(" in ident:
        files = adb(dynamic, "shell", "sh", "-c", f"find /data/user/0/{pkg} -maxdepth 4 -type f 2>/dev/null | sort | head -5000", timeout=60)
        (outdir / "app-data-files.txt").write_text(files.stdout or "")
        pids = (adb(dynamic, "shell", "pidof", pkg, timeout=30).stdout or "").strip().split()
        if pids: (outdir / "process-maps.txt").write_text(adb(dynamic, "shell", "cat", f"/proc/{pids[0]}/maps", timeout=30).stdout or "")


def start() -> None:
    mkdirs(); _, dynamic = load_config(True); setup_data = read_setup()
    if pid_alive(EMULATOR_PID): print("[=] Emulator already running"); return
    emulator = which("emulator")
    if not emulator: fail("emulator missing")
    port = int(dynamic.get("emulator_port", 5554))
    cmd = [emulator, "@" + setup_data["avd_name"], "-port", str(port), "-no-audio", "-no-boot-anim", "-no-snapshot", "-gpu", "swiftshader_indirect", "-accel", "on" if setup_data["acceleration"] == "kvm" else "off", "-tcpdump", str(REPORT / "network.pcap")]
    if dynamic.get("headless", True): cmd.append("-no-window")
    if dynamic.get("wipe_data_on_start", True): cmd.append("-wipe-data")
    log = EMULATOR_LOG.open("ab"); proc = subprocess.Popen(cmd, cwd=ROOT, env=env(), stdout=log, stderr=subprocess.STDOUT, start_new_session=True); EMULATOR_PID.write_text(str(proc.pid) + "\n")
    print(f"[*] Emulator PID {proc.pid}; waiting for boot ({setup_data['acceleration']})", flush=True)
    serial = adb_serial(dynamic); adb_bin = which("adb") or "adb"; timeout_s = int(dynamic.get("boot_timeout_seconds", 600)); deadline = time.monotonic() + timeout_s
    run([adb_bin, "-s", serial, "wait-for-device"], timeout=timeout_s)
    while time.monotonic() < deadline:
        completed = adb(dynamic, "shell", "getprop", "sys.boot_completed", timeout=30)
        if completed.returncode == 0 and (completed.stdout or "").strip() == "1": break
        if proc.poll() is not None: fail("emulator exited during boot; see reports/dynamic/emulator.log")
        time.sleep(3)
    else: fail("emulator boot timed out; see reports/dynamic/emulator.log")
    root_result = {"requested": bool(dynamic.get("request_root", True)), "available": False, "output": ""}
    if dynamic.get("request_root", True):
        r = adb(dynamic, "root", timeout=60); root_result["output"] = (r.stdout or "").strip(); time.sleep(2); run([adb_bin, "-s", serial, "wait-for-device"], timeout=60)
        root_result["available"] = "uid=0(" in (adb(dynamic, "shell", "id", timeout=30).stdout or "")
    (REPORT / "root-status.json").write_text(json.dumps(root_result, indent=2) + "\n")
    info = device_info(dynamic); start_logcat(dynamic); capture_state(dynamic, "preinstall")
    print(f"[+] Emulator booted: Android {info.get('release')} API {info.get('sdk')} ABI {info.get('abi')}\n    adb root: {'yes' if root_result['available'] else 'no'}")


def install_app() -> None:
    mkdirs(); cfg, dynamic = load_config(True); start(); pkg = package_name(); input_path = (ROOT / cfg["apk"]["path"]).resolve()
    if input_path.suffix.lower() == ".xapk":
        inv = TOOL_REPORT / "xapk-inventory.json"
        if not inv.is_file(): fail("XAPK inventory missing; run tools/apk_prepare.py first")
        data = json.loads(inv.read_text()); apks = [ROOT / data["base_apk"]] + [ROOT / item["file"] for item in data.get("splits", [])]
        args = ["install-multiple", "-r", "-t"] + (["-g"] if dynamic.get("grant_runtime_permissions", False) else []) + [str(p) for p in apks]
    else:
        args = ["install", "-r", "-t"] + (["-g"] if dynamic.get("grant_runtime_permissions", False) else []) + [str(input_path)]
    proc = adb(dynamic, *args, timeout=300); (REPORT / "install.txt").write_text(proc.stdout or "")
    if proc.returncode != 0 or "Success" not in (proc.stdout or ""): fail("APK installation failed; see reports/dynamic/install.txt")
    (REPORT / "installed-package-paths.txt").write_text(adb(dynamic, "shell", "pm", "path", pkg, timeout=60).stdout or ""); capture_state(dynamic, "postinstall"); print(f"[+] Installed {pkg}")


def screenshot(dynamic: dict) -> None:
    proc = run([which("adb") or "adb", "-s", adb_serial(dynamic), "exec-out", "screencap", "-p"], timeout=60, binary=True)
    if proc.returncode == 0: (REPORT / "screenshot.png").write_bytes(proc.stdout)


def ui_dump(dynamic: dict) -> None:
    adb(dynamic, "shell", "uiautomator", "dump", "/sdcard/sat-window.xml", timeout=60)
    (REPORT / "ui.xml").write_text(adb(dynamic, "exec-out", "cat", "/sdcard/sat-window.xml", timeout=60).stdout or "")


def launch() -> None:
    _, dynamic = load_config(True); start(); pkg = package_name(); adb(dynamic, "logcat", "-c", timeout=30)
    (REPORT / "launch.txt").write_text(adb(dynamic, "shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1", timeout=60).stdout or "")
    time.sleep(int(dynamic.get("observation_seconds", 15))); ui_dump(dynamic); screenshot(dynamic)
    (REPORT / "launch-logcat.txt").write_text(adb(dynamic, "logcat", "-d", "-v", "threadtime", timeout=60).stdout or ""); capture_state(dynamic, "postlaunch"); print(f"[+] Launched and observed {pkg}")


def ensure_frida_server(dynamic: dict) -> None:
    if not dynamic.get("allow_frida", False): fail("dynamic.allow_frida=false")
    if not which("frida") or not which("frida-ps"): fail("Frida host tools missing")
    root = json.loads((REPORT / "root-status.json").read_text()) if (REPORT / "root-status.json").is_file() else {}
    if not root.get("available"): fail("Frida injected mode requires adb-root/rooted emulator in this toolkit flow")
    version = (run([which("frida") or "frida", "--version"], timeout=30).stdout or "").strip().splitlines()[0]; info = device_info(dynamic); abi = info.get("abi") or ""
    frida_arch = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "x86_64": "x86_64", "x86": "x86"}.get(abi)
    if not frida_arch: fail(f"unsupported Frida server ABI: {abi}")
    cache = SAT_HOME / "cache"; tools = SAT_HOME / "tools" / "frida-server"; cache.mkdir(parents=True, exist_ok=True); tools.mkdir(parents=True, exist_ok=True)
    packed = cache / f"frida-server-{version}-android-{frida_arch}.xz"; binary = tools / f"frida-server-{version}-android-{frida_arch}"
    if not binary.is_file():
        url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{frida_arch}.xz"; print(f"[*] Downloading Frida server {version} for {frida_arch}", flush=True); urllib.request.urlretrieve(url, packed); binary.write_bytes(lzma.decompress(packed.read_bytes())); binary.chmod(0o755)
    remote = "/data/local/tmp/sat-fs"; adb(dynamic, "push", str(binary), remote, timeout=180); adb(dynamic, "shell", "chmod", "755", remote, timeout=30); adb(dynamic, "shell", "sh", "-c", f"pkill -f '{remote}' >/dev/null 2>&1 || true", timeout=30); adb(dynamic, "shell", "sh", "-c", f"{remote} >/data/local/tmp/sat-frida.log 2>&1 &", timeout=30); time.sleep(2)
    smoke = run([which("frida-ps") or "frida-ps", "-U"], timeout=60); (REPORT / "frida-smoke.txt").write_text(smoke.stdout or "")
    if smoke.returncode != 0: fail("frida-ps -U failed; see reports/dynamic/frida-smoke.txt")


def instrument_start() -> None:
    _, dynamic = load_config(True); start(); ensure_frida_server(dynamic); pkg = package_name(); script = ROOT / "tools" / "frida_observe.js"
    if not script.is_file(): fail("tools/frida_observe.js missing")
    output = REPORT / "frida-events.txt"; cmd = [which("frida") or "frida", "-U", "-f", pkg, "-l", str(script), "-q", "-t", "inf", "-o", str(output)]
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env(), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, start_new_session=True); (WORK / "frida.pid").write_text(str(proc.pid) + "\n"); print(f"[+] Frida observation started, PID {proc.pid}")


def instrument_stop() -> None:
    p = WORK / "frida.pid"
    if pid_alive(p): os.killpg(int(p.read_text().strip()), signal.SIGTERM); print("[+] Frida observation stopped")
    p.unlink(missing_ok=True)


def collect() -> None:
    _, dynamic = load_config(True); start(); pkg = package_name(); ui_dump(dynamic); screenshot(dynamic); (REPORT / "logcat-final.txt").write_text(adb(dynamic, "logcat", "-d", "-v", "threadtime", timeout=60).stdout or ""); capture_state(dynamic, "final")
    summary = {"package": pkg, "network_capture": "reports/dynamic/network.pcap", "logcat": "reports/dynamic/logcat-final.txt", "ui_dump": "reports/dynamic/ui.xml", "screenshot": "reports/dynamic/screenshot.png", "frida_events": "reports/dynamic/frida-events.txt" if (REPORT / "frida-events.txt").exists() else None}
    (REPORT / "collection.json").write_text(json.dumps(summary, indent=2) + "\n"); print("[+] Dynamic artifacts collected under reports/dynamic/")


def stop() -> None:
    instrument_stop()
    for pidfile in (LOGCAT_PID, EMULATOR_PID):
        if pid_alive(pidfile):
            try: os.killpg(int(pidfile.read_text().strip()), signal.SIGTERM)
            except ProcessLookupError: pass
        pidfile.unlink(missing_ok=True)
    print("[+] Dynamic processes stopped")


def status() -> None:
    cap = probe(); setup_data = json.loads(SETUP_JSON.read_text()) if SETUP_JSON.is_file() else None
    print(json.dumps({"capabilities": cap, "setup": setup_data, "emulator_running": pid_alive(EMULATOR_PID), "logcat_running": pid_alive(LOGCAT_PID), "frida_running": pid_alive(WORK / "frida.pid")}, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description="Toolkit-contained APK dynamic analysis runtime")
    parser.add_argument("action", choices=["probe", "setup", "start", "install", "launch", "collect", "frida-start", "frida-stop", "status", "stop"])
    action = parser.parse_args().action
    if action == "probe": print(json.dumps(probe(), indent=2))
    elif action == "setup": setup()
    elif action == "start": start()
    elif action == "install": install_app()
    elif action == "launch": launch()
    elif action == "collect": collect()
    elif action == "frida-start": instrument_start()
    elif action == "frida-stop": instrument_stop()
    elif action == "status": status()
    elif action == "stop": stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
