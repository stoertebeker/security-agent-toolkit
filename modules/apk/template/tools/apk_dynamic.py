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
    "allow_android11_multiabi_fallback": True,
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
        "JAVA_HOME": str(SAT_HOME / "java" / "jdk-21"),
        "TMPDIR": str(TMP), "TMP": str(TMP), "TEMP": str(TMP),
    })
    return e


def mkdirs() -> None:
    for path in (WORK, WORK / "avd", WORK / "emulator-home", WORK / "user-home", TMP, REPORT, TOOL_REPORT):
        path.mkdir(parents=True, exist_ok=True)


def run(command: list[str], *, timeout: int | None = 120, input_text: str | None = None, binary: bool = False) -> subprocess.CompletedProcess:
    common = dict(cwd=ROOT, env=env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    if binary:
        return subprocess.run(command, input=input_text.encode() if input_text else None, **common)
    return subprocess.run(command, text=True, errors="replace", input=input_text, **common)


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
    result: set[str] = set()
    apktool = ROOT / "extracted" / "apktool"
    if apktool.exists():
        for so in apktool.rglob("*.so"):
            parts = so.parts
            for index, part in enumerate(parts[:-1]):
                if part == "lib" and index + 1 < len(parts):
                    abi = aliases.get(parts[index + 1], parts[index + 1])
                    if abi in {"arm64-v8a", "armeabi-v7a", "x86_64", "x86"}:
                        result.add(abi)
    xapk = TOOL_REPORT / "xapk-inventory.json"
    if xapk.is_file():
        try:
            data = json.loads(xapk.read_text())
            for item in data.get("splits", []):
                split_id = str(item.get("id", ""))
                if split_id.startswith("config."):
                    raw = split_id.removeprefix("config.")
                    abi = aliases.get(raw, raw)
                    if abi in {"arm64-v8a", "armeabi-v7a", "x86_64", "x86"}:
                        result.add(abi)
        except Exception:
            pass
    return sorted(result)


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
        match = re.search(r"package:\s+name='([^']+)'", aapt)
        if match: result["package"] = match.group(1)
    for key, pattern in (("min_sdk", r"sdkVersion:'?(\d+)'?"), ("target_sdk", r"targetSdkVersion:'?(\d+)'?")):
        match = re.search(pattern, aapt)
        if match: result[key] = int(match.group(1))
    return result


def runtime_plan(host_arch: str, abis: list[str], meta: dict, dynamic: dict) -> dict:
    if host_arch != "x86_64":
        return {"supported": False, "reason": "managed Android Emulator v1 currently supports Linux x86_64 hosts only"}
    if not abis:
        return {"supported": True, "image_abi": "x86_64", "api_override": None, "abi_mode": "no-native-code"}
    if "x86_64" in abis:
        return {"supported": True, "image_abi": "x86_64", "api_override": None, "abi_mode": "native-x86_64"}
    min_sdk = int(meta.get("min_sdk") or 1)
    if dynamic.get("allow_android11_multiabi_fallback", True) and min_sdk <= 30:
        return {
            "supported": True, "image_abi": "x86_64", "api_override": 30,
            "abi_mode": "android11-x86_64-multiabi-translation",
            "reason": "Android 11 x86_64 emulator images provide x86/x86_64/ARMv7/ARM64 ABI support; runtime OS coverage is API 30",
        }
    return {
        "supported": False,
        "reason": f"package native ABIs {abis} have no x86_64 library and minSdk={min_sdk} prevents the Android 11 multi-ABI compatibility fallback",
    }


def probe() -> dict:
    mkdirs(); _, dynamic = load_config(False); meta = package_metadata(); abis = target_abis()
    host_arch = platform.machine().lower(); virt_kind, virt_name = detect_virtualization()
    virt_flag = bool(re.search(r"\b(vmx|svm)\b", read_text(Path("/proc/cpuinfo"))))
    kvm = Path("/dev/kvm"); emulator = which("emulator"); sdkmanager = which("sdkmanager"); avdmanager = which("avdmanager"); adb_bin = which("adb")
    accel_rc = None; accel_output = ""
    if emulator:
        proc = run([emulator, "-accel-check"], timeout=30); accel_rc = proc.returncode; accel_output = (proc.stdout or "").strip()
    kvm_usable = bool(emulator and accel_rc == 0)
    plan = runtime_plan(host_arch, abis, meta, dynamic); tooling_ready = bool(emulator and sdkmanager and avdmanager and adb_bin)
    notes: list[str] = []; available = bool(plan.get("supported", False)); acceleration = "unknown"
    if str(dynamic.get("backend", "auto")) == "none": available = False; notes.append("dynamic.backend=none")
    if plan.get("reason"): notes.append(str(plan["reason"]))
    if available and tooling_ready:
        if kvm_usable: acceleration = "kvm"
        elif dynamic.get("allow_software_emulation", True):
            acceleration = "software"; notes.append("KVM unavailable; x86_64 system image will use -accel off and may be dramatically slower")
        else: available = False; notes.append("KVM unavailable and dynamic.allow_software_emulation=false")
    elif available and not tooling_ready:
        available = False; notes.append("Android Emulator tooling is not installed; run ./toolkit install apk --with-optional")

    if virt_kind == "container" and not kvm.exists(): notes.append(f"{virt_name} container has no /dev/kvm; host-side KVM device passthrough is required for acceleration")
    elif virt_kind == "container" and kvm.exists() and not os.access(kvm, os.R_OK | os.W_OK): notes.append(f"{virt_name} exposes /dev/kvm but current user lacks read/write access")
    elif virt_kind == "vm" and not kvm.exists(): notes.append(f"{virt_name} VM has no /dev/kvm; nested virtualization is likely not exposed")
    elif virt_kind == "bare" and virt_flag and not kvm.exists(): notes.append("CPU virtualization flags exist but /dev/kvm is absent")
    if emulator and accel_rc not in (None, 0): notes.append("emulator -accel-check did not report usable KVM")

    result = {
        "host_arch": host_arch, "virtualization_kind": virt_kind, "virtualization_name": virt_name,
        "cpu_virtualization_flag": virt_flag, "dev_kvm_exists": kvm.exists(), "dev_kvm_rw": kvm.exists() and os.access(kvm, os.R_OK | os.W_OK),
        "emulator_installed": bool(emulator), "sdkmanager_installed": bool(sdkmanager), "avdmanager_installed": bool(avdmanager), "adb_installed": bool(adb_bin), "tooling_ready": tooling_ready,
        "emulator_accel_check_rc": accel_rc, "emulator_accel_check": accel_output, "kvm_usable": kvm_usable,
        "package": meta.get("package"), "min_sdk": meta.get("min_sdk"), "target_sdk": meta.get("target_sdk"), "target_abis": abis,
        "selected_image_abi": plan.get("image_abi"), "selected_api_override": plan.get("api_override"), "runtime_abi_mode": plan.get("abi_mode"),
        "selected_acceleration": acceleration, "dynamic_available": available, "notes": notes,
    }
    CAP_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# APK dynamic capability probe", f"host architecture: {host_arch}", f"virtualization: {virt_kind}/{virt_name}",
        f"cpu virtualization flag: {'yes' if virt_flag else 'no'}", f"/dev/kvm: {'rw' if result['dev_kvm_rw'] else 'present-no-rw' if kvm.exists() else 'absent'}",
        f"tooling ready: {'yes' if tooling_ready else 'no'}", f"KVM usable by emulator: {'yes' if kvm_usable else 'no'}",
        f"target ABIs: {', '.join(abis) if abis else 'no native ABI requirement'}", f"runtime ABI mode: {result.get('runtime_abi_mode') or 'unavailable'}",
        f"selected image ABI: {result.get('selected_image_abi') or 'none'}", f"selected API override: {result.get('selected_api_override') if result.get('selected_api_override') is not None else 'none'}",
        f"selected acceleration: {acceleration}", f"dynamic available: {'yes' if available else 'no'}", "",
    ] + [f"- {note}" for note in notes]
    CAP_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


def sdk_available_packages() -> str:
    sdkmanager = which("sdkmanager")
    if not sdkmanager: fail("sdkmanager missing; run ./toolkit install apk --with-optional")
    proc = run([sdkmanager, "--sdk_root=" + str(SDK_ROOT), "--list"], timeout=180)
    if proc.returncode != 0: fail("sdkmanager --list failed")
    return proc.stdout or ""


def choose_system_image(cap: dict, dynamic: dict, meta: dict) -> tuple[str, int, str]:
    listing = sdk_available_packages(); override = cap.get("selected_api_override")
    if override is not None: apis = [int(override)]
    else:
        requested = int(dynamic.get("api_level") or 0)
        if requested <= 0: requested = int(meta.get("target_sdk") or 36)
        min_sdk = int(meta.get("min_sdk") or 1); apis = list(range(requested, max(min_sdk, requested - 3) - 1, -1))
    configured_tag = str(dynamic.get("image_tag", "auto")); tags = ["default", "google_apis"] if configured_tag == "auto" else [configured_tag]
    abi = str(cap["selected_image_abi"])
    for api in apis:
        for tag in tags:
            package = f"system-images;android-{api};{tag};{abi}"
            if package in listing: return package, api, tag
    fail(f"No compatible system image found for ABI={abi}, APIs={apis}, tags={tags}")


def write_avd_config(avd_dir: Path, dynamic: dict) -> None:
    cfg = avd_dir / "config.ini"
    updates = {"hw.ramSize": str(int(dynamic.get("memory_mb", 4096))), "hw.cpu.ncore": str(int(dynamic.get("cores", 4))), "hw.keyboard": "yes", "showDeviceFrame": "no", "disk.dataPartition.size": "4G", "hw.gpu.enabled": "yes", "hw.gpu.mode": "software"}
    lines = read_text(cfg).splitlines(); seen: set[str] = set(); output: list[str] = []
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line else None
        if key in updates: output.append(f"{key}={updates[key]}"); seen.add(key)
        else: output.append(line)
    for key, value in updates.items():
        if key not in seen: output.append(f"{key}={value}")
    cfg.write_text("\n".join(output) + "\n", encoding="utf-8")


def setup() -> dict:
    mkdirs(); _, dynamic = load_config(True); cap = probe()
    if not cap["dynamic_available"]: fail("dynamic capability probe reports UNAVAILABLE; see reports/tool-output/dynamic-capabilities.txt")
    meta = package_metadata(); image_package, api, tag = choose_system_image(cap, dynamic, meta)
    print(f"[*] Installing/reusing system image: {image_package}", flush=True)
    proc = run([which("sdkmanager") or "sdkmanager", "--sdk_root=" + str(SDK_ROOT), "--install", image_package], timeout=1800, input_text="y\n" * 100)
    (REPORT / "sdkmanager-system-image.txt").write_text(proc.stdout or "", encoding="utf-8")
    if proc.returncode != 0: fail("system image installation failed; see reports/dynamic/sdkmanager-system-image.txt")

    project_slug = re.sub(r"[^A-Za-z0-9_-]+", "-", ROOT.name).strip("-")[:40] or "apk"; abi_slug = str(cap["selected_image_abi"]).replace("-", "_")
    avd_name = f"sat-{project_slug}-api{api}-{abi_slug}"; avd_home = Path(env()["ANDROID_AVD_HOME"]); avd_dir = avd_home / f"{avd_name}.avd"
    if avd_dir.exists(): shutil.rmtree(avd_dir)
    (avd_home / f"{avd_name}.ini").unlink(missing_ok=True)
    proc = run([which("avdmanager") or "avdmanager", "create", "avd", "--force", "--name", avd_name, "--package", image_package], timeout=180, input_text="no\n")
    (REPORT / "avd-create.txt").write_text(proc.stdout or "", encoding="utf-8")
    if proc.returncode != 0 or not avd_dir.exists(): fail("AVD creation failed; see reports/dynamic/avd-create.txt")
    write_avd_config(avd_dir, dynamic)

    result = {
        "avd_name": avd_name, "avd_dir": str(avd_dir.relative_to(ROOT)), "system_image_package": image_package,
        "api_level": api, "image_tag": tag, "image_abi": cap["selected_image_abi"], "runtime_abi_mode": cap["runtime_abi_mode"],
        "acceleration": cap["selected_acceleration"], "root_expected": tag == "default", "package": meta.get("package"),
        "target_abis": cap["target_abis"], "virtualization_kind": cap["virtualization_kind"], "virtualization_name": cap["virtualization_name"],
    }
    SETUP_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[+] Dynamic AVD ready: {avd_name}\n    image: {image_package}\n    ABI mode: {result['runtime_abi_mode']}\n    acceleration: {result['acceleration']}")
    return result


def read_setup() -> dict:
    if not SETUP_JSON.is_file(): return setup()
    try: return json.loads(SETUP_JSON.read_text())
    except Exception: return setup()


def adb_serial(dynamic: dict) -> str: return f"emulator-{int(dynamic.get('emulator_port', 5554))}"


def adb(dynamic: dict, *args: str, timeout: int | None = 120) -> subprocess.CompletedProcess:
    adb_bin = which("adb")
    if not adb_bin: fail("adb missing")
    return run([adb_bin, "-s", adb_serial(dynamic), *args], timeout=timeout)


def pid_alive(path: Path) -> bool:
    try:
        pid = int(path.read_text().strip()); os.kill(pid, 0); return True
    except Exception: return False


def wait_for_boot(dynamic: dict, emulator_process: subprocess.Popen, timeout_seconds: int) -> None:
    adb_bin = which("adb") or "adb"; serial = adb_serial(dynamic); deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if emulator_process.poll() is not None: fail("emulator exited during boot; see reports/dynamic/emulator.log")
        try:
            state = run([adb_bin, "-s", serial, "get-state"], timeout=5)
            if state.returncode == 0 and "device" in (state.stdout or ""):
                completed = run([adb_bin, "-s", serial, "shell", "getprop", "sys.boot_completed"], timeout=10)
                if completed.returncode == 0 and (completed.stdout or "").strip() == "1": return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(2)
    fail("emulator boot timed out; see reports/dynamic/emulator.log")


def wait_for_adb_reconnect(dynamic: dict, timeout_seconds: int = 60) -> None:
    adb_bin = which("adb") or "adb"; serial = adb_serial(dynamic); deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            state = run([adb_bin, "-s", serial, "get-state"], timeout=5)
            if state.returncode == 0 and "device" in (state.stdout or ""): return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(1)
    fail("ADB did not reconnect after root transition")


def start_logcat(dynamic: dict) -> None:
    if pid_alive(LOGCAT_PID): return
    handle = LOGCAT_LOG.open("ab")
    proc = subprocess.Popen([which("adb") or "adb", "-s", adb_serial(dynamic), "logcat", "-v", "threadtime"], cwd=ROOT, env=env(), stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
    LOGCAT_PID.write_text(str(proc.pid) + "\n", encoding="utf-8")


def device_info(dynamic: dict) -> dict:
    props: dict[str, str] = {}; proc = adb(dynamic, "shell", "getprop", timeout=30)
    for line in (proc.stdout or "").splitlines():
        match = re.match(r"\[([^\]]+)\]: \[(.*)\]", line)
        if match: props[match.group(1)] = match.group(2)
    ident = (adb(dynamic, "shell", "id", timeout=30).stdout or "").strip()
    result = {"serial": adb_serial(dynamic), "id": ident, "sdk": props.get("ro.build.version.sdk"), "release": props.get("ro.build.version.release"), "abi": props.get("ro.product.cpu.abi"), "abilist": props.get("ro.product.cpu.abilist"), "abilist64": props.get("ro.product.cpu.abilist64"), "abilist32": props.get("ro.product.cpu.abilist32"), "build_type": props.get("ro.build.type"), "build_tags": props.get("ro.build.tags"), "model": props.get("ro.product.model"), "fingerprint": props.get("ro.build.fingerprint")}
    (REPORT / "device-info.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def verify_runtime_abi(info: dict) -> None:
    required = target_abis()
    if not required: return
    supported = {item.strip() for item in str(info.get("abilist") or "").split(",") if item.strip()}; compatible = sorted(supported.intersection(required))
    result = {"required": required, "device_supported": sorted(supported), "compatible": compatible}
    (REPORT / "abi-compatibility.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not compatible: fail(f"emulator booted but exposes none of the package native ABIs {required}; see reports/dynamic/abi-compatibility.json")


def package_name() -> str:
    package = package_metadata().get("package")
    if package: return str(package)
    fail("could not determine package name from preparation output")


def capture_state(dynamic: dict, label: str) -> None:
    package = package_name(); outdir = REPORT / "states" / label; outdir.mkdir(parents=True, exist_ok=True)
    commands = {"package.txt": ["shell", "dumpsys", "package", package], "appops.txt": ["shell", "cmd", "appops", "get", package], "processes.txt": ["shell", "ps", "-A"], "activity.txt": ["shell", "dumpsys", "activity", "activities"], "webview.txt": ["shell", "dumpsys", "webviewupdate"]}
    for filename, args in commands.items(): (outdir / filename).write_text(adb(dynamic, *args, timeout=60).stdout or "", encoding="utf-8")
    if "uid=0(" in (adb(dynamic, "shell", "id", timeout=30).stdout or ""):
        files = adb(dynamic, "shell", "sh", "-c", f"find /data/user/0/{package} -maxdepth 4 -type f 2>/dev/null | sort | head -5000", timeout=60)
        (outdir / "app-data-files.txt").write_text(files.stdout or "", encoding="utf-8")
        pids = (adb(dynamic, "shell", "pidof", package, timeout=30).stdout or "").strip().split()
        if pids: (outdir / "process-maps.txt").write_text(adb(dynamic, "shell", "cat", f"/proc/{pids[0]}/maps", timeout=30).stdout or "", encoding="utf-8")


def start() -> None:
    mkdirs(); _, dynamic = load_config(True); setup_data = read_setup()
    if pid_alive(EMULATOR_PID): print("[=] Emulator already running"); return
    emulator = which("emulator")
    if not emulator: fail("emulator missing; run ./toolkit install apk --with-optional")
    cmd = [emulator, "@" + setup_data["avd_name"], "-port", str(int(dynamic.get("emulator_port", 5554))), "-no-audio", "-no-boot-anim", "-no-snapshot", "-gpu", "software", "-accel", "on" if setup_data["acceleration"] == "kvm" else "off", "-tcpdump", str(REPORT / "network.pcap")]
    if dynamic.get("headless", True): cmd.append("-no-window")
    if dynamic.get("wipe_data_on_start", True): cmd.append("-wipe-data")
    handle = EMULATOR_LOG.open("ab"); proc = subprocess.Popen(cmd, cwd=ROOT, env=env(), stdout=handle, stderr=subprocess.STDOUT, start_new_session=True); EMULATOR_PID.write_text(str(proc.pid) + "\n", encoding="utf-8")
    print(f"[*] Emulator PID {proc.pid}; waiting for boot ({setup_data['acceleration']})", flush=True)
    wait_for_boot(dynamic, proc, int(dynamic.get("boot_timeout_seconds", 600)))

    root_result = {"requested": bool(dynamic.get("request_root", True)), "available": False, "output": ""}
    if dynamic.get("request_root", True):
        root_proc = adb(dynamic, "root", timeout=60); root_result["output"] = (root_proc.stdout or "").strip(); time.sleep(1); wait_for_adb_reconnect(dynamic, 60)
        root_result["available"] = "uid=0(" in (adb(dynamic, "shell", "id", timeout=30).stdout or "")
    (REPORT / "root-status.json").write_text(json.dumps(root_result, indent=2) + "\n", encoding="utf-8")
    info = device_info(dynamic); verify_runtime_abi(info); start_logcat(dynamic); capture_state(dynamic, "preinstall")
    print(f"[+] Emulator booted: Android {info.get('release')} API {info.get('sdk')} ABI {info.get('abi')}\n    ABI list: {info.get('abilist')}\n    adb root: {'yes' if root_result['available'] else 'no'}")


def install_app() -> None:
    mkdirs(); cfg, dynamic = load_config(True); start(); package = package_name(); input_path = (ROOT / cfg["apk"]["path"]).resolve()
    if input_path.suffix.lower() == ".xapk":
        inventory = TOOL_REPORT / "xapk-inventory.json"
        if not inventory.is_file(): fail("XAPK inventory missing; run tools/apk_prepare.py first")
        data = json.loads(inventory.read_text()); apks = [ROOT / data["base_apk"]] + [ROOT / item["file"] for item in data.get("splits", [])]
        args = ["install-multiple", "-r", "-t"] + (["-g"] if dynamic.get("grant_runtime_permissions", False) else []) + [str(path) for path in apks]
    else:
        args = ["install", "-r", "-t"] + (["-g"] if dynamic.get("grant_runtime_permissions", False) else []) + [str(input_path)]
    proc = adb(dynamic, *args, timeout=300); (REPORT / "install.txt").write_text(proc.stdout or "", encoding="utf-8")
    if proc.returncode != 0 or "Success" not in (proc.stdout or ""): fail("APK installation failed; see reports/dynamic/install.txt")
    (REPORT / "installed-package-paths.txt").write_text(adb(dynamic, "shell", "pm", "path", package, timeout=60).stdout or "", encoding="utf-8"); capture_state(dynamic, "postinstall"); print(f"[+] Installed {package}")


def screenshot(dynamic: dict) -> None:
    proc = run([which("adb") or "adb", "-s", adb_serial(dynamic), "exec-out", "screencap", "-p"], timeout=60, binary=True)
    if proc.returncode == 0 and isinstance(proc.stdout, bytes): (REPORT / "screenshot.png").write_bytes(proc.stdout)


def ui_dump(dynamic: dict) -> None:
    adb(dynamic, "shell", "uiautomator", "dump", "/sdcard/sat-window.xml", timeout=60)
    (REPORT / "ui.xml").write_text(adb(dynamic, "exec-out", "cat", "/sdcard/sat-window.xml", timeout=60).stdout or "", encoding="utf-8")


def launch() -> None:
    _, dynamic = load_config(True); start(); package = package_name(); adb(dynamic, "logcat", "-c", timeout=30)
    (REPORT / "launch.txt").write_text(adb(dynamic, "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1", timeout=60).stdout or "", encoding="utf-8")
    time.sleep(int(dynamic.get("observation_seconds", 15))); ui_dump(dynamic); screenshot(dynamic)
    (REPORT / "launch-logcat.txt").write_text(adb(dynamic, "logcat", "-d", "-v", "threadtime", timeout=60).stdout or "", encoding="utf-8"); capture_state(dynamic, "postlaunch"); print(f"[+] Launched and observed {package}")


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
    smoke = run([which("frida-ps") or "frida-ps", "-U"], timeout=60); (REPORT / "frida-smoke.txt").write_text(smoke.stdout or "", encoding="utf-8")
    if smoke.returncode != 0: fail("frida-ps -U failed; see reports/dynamic/frida-smoke.txt")


def instrument_start() -> None:
    _, dynamic = load_config(True); start(); ensure_frida_server(dynamic); script = ROOT / "tools" / "frida_observe.js"
    if not script.is_file(): fail("tools/frida_observe.js missing")
    cmd = [which("frida") or "frida", "-U", "-f", package_name(), "-l", str(script), "-q", "-t", "inf", "-o", str(REPORT / "frida-events.txt")]
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env(), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, start_new_session=True); (WORK / "frida.pid").write_text(str(proc.pid) + "\n", encoding="utf-8"); print(f"[+] Frida observation started, PID {proc.pid}")


def instrument_stop() -> None:
    pidfile = WORK / "frida.pid"
    if pid_alive(pidfile): os.killpg(int(pidfile.read_text().strip()), signal.SIGTERM); print("[+] Frida observation stopped")
    pidfile.unlink(missing_ok=True)


def collect() -> None:
    _, dynamic = load_config(True); start(); ui_dump(dynamic); screenshot(dynamic)
    (REPORT / "logcat-final.txt").write_text(adb(dynamic, "logcat", "-d", "-v", "threadtime", timeout=60).stdout or "", encoding="utf-8"); capture_state(dynamic, "final")
    summary = {"package": package_name(), "network_capture": "reports/dynamic/network.pcap", "logcat": "reports/dynamic/logcat-final.txt", "ui_dump": "reports/dynamic/ui.xml", "screenshot": "reports/dynamic/screenshot.png", "frida_events": "reports/dynamic/frida-events.txt" if (REPORT / "frida-events.txt").exists() else None}
    (REPORT / "collection.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8"); print("[+] Dynamic artifacts collected under reports/dynamic/")


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
