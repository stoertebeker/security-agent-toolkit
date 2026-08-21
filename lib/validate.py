#!/usr/bin/env python3
from pathlib import Path
import importlib.util
import re
import sys, tomllib, json

SUPPORTED = {"ubuntu-24.04", "ubuntu-26.04", "debian-12", "debian-13", "kali-rolling", "parrot-7"}


def validate_python(path: Path, errors: list[str]) -> None:
    try:
        compile(path.read_text(), str(path), "exec")
    except Exception as exc:
        errors.append(f"bad Python {path.name}: {exc}")


def validate_apk_dynamic_logic(path: Path, errors: list[str]) -> None:
    try:
        spec = importlib.util.spec_from_file_location("sat_apk_dynamic_validate", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("could not create import spec")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        enabled = {"allow_android11_multiabi_fallback": True}
        cases = [
            ("x86_64", [], {"min_sdk": 26}, enabled, True, "x86_64", None, "no-native-code"),
            ("x86_64", ["x86_64"], {"min_sdk": 26}, enabled, True, "x86_64", None, "native-x86_64"),
            ("x86_64", ["arm64-v8a"], {"min_sdk": 26}, enabled, True, "x86_64", 30, "android11-x86_64-multiabi-translation"),
            ("x86_64", ["arm64-v8a"], {"min_sdk": 31}, enabled, False, None, None, None),
            ("aarch64", ["arm64-v8a"], {"min_sdk": 26}, enabled, False, None, None, None),
        ]
        for host, abis, meta, dynamic, supported, image_abi, api_override, abi_mode in cases:
            result = module.runtime_plan(host, abis, meta, dynamic)
            if bool(result.get("supported")) != supported:
                raise AssertionError(f"runtime_plan supported mismatch for {host}/{abis}/{meta}: {result}")
            if supported:
                if result.get("image_abi") != image_abi or result.get("api_override") != api_override or result.get("abi_mode") != abi_mode:
                    raise AssertionError(f"runtime_plan mismatch for {host}/{abis}/{meta}: {result}")
        disabled = module.runtime_plan("x86_64", ["arm64-v8a"], {"min_sdk": 26}, {"allow_android11_multiabi_fallback": False})
        if disabled.get("supported"):
            raise AssertionError("ARM-only plan should be unsupported when Android 11 multi-ABI fallback is disabled")
    except Exception as exc:
        errors.append(f"APK dynamic runtime-plan self-test failed: {exc}")


def validate_module(root: Path, module: str):
    errors = []
    module_file = root / "modules" / module / "module.toml"
    try:
        manifest = tomllib.loads(module_file.read_text())
    except Exception as exc:
        return [f"bad module.toml: {exc}"]

    template = module_file.parent / "template"
    for filename in ("AGENTS.md", "opencode.json", "start.sh", "target/TARGET.example.toml"):
        if not (template / filename).exists(): errors.append("missing template/" + filename)

    try:
        opencode = json.loads((template / "opencode.json").read_text())
    except Exception as exc:
        errors.append("bad opencode.json " + str(exc)); opencode = {}

    depth = opencode.get("subagent_depth")
    if depth not in (1, 2): errors.append("subagent_depth must be 1 or bounded depth 2")
    if opencode.get("permission", {}).get("external_directory") != "deny": errors.append("external_directory must be deny")
    if depth == 2:
        agent_dir = template / ".opencode" / "agents"; bounded_agents = []
        if agent_dir.exists():
            for agent_file in agent_dir.glob("*.md"):
                text = agent_file.read_text(errors="replace")
                if "steps:" in text and "permission:" in text and "task:" in text: bounded_agents.append(agent_file.name)
        if len(bounded_agents) < 2: errors.append("subagent_depth=2 requires bounded coordinator/worker agents")

    target_file = template / "target" / "TARGET.example.toml"; target = {}
    if target_file.exists():
        try:
            target = tomllib.loads(target_file.read_text()); maximum = target.get("orchestration", {}).get("max_parallel_agents")
            if not isinstance(maximum, int) or not 1 <= maximum <= 8: errors.append("TARGET.example.toml must define orchestration.max_parallel_agents in range 1..8")
        except Exception as exc: errors.append("bad TARGET.example.toml " + str(exc))

    if module == "apk":
        apk_required = (
            "tools/apk_prepare.py", "tools/apk_secret_scan.py", "tools/apk_secret_group.py", "tools/apk_native_baseline.py",
            "tools/apk_dynamic.py", "tools/apk_dynamic_smoke.py", "tools/apk_dynamic_action.py", "tools/apk_dynamic_evidence.py", "tools/frida_observe.js",
            ".opencode/agents/apk-secret-hunter.md", ".opencode/agents/apk-secret-review-worker.md", ".opencode/agents/apk-native-reverser.md",
            ".opencode/agents/apk-dynamic-analyst.md", ".opencode/agents/apk-researcher.md", ".opencode/agents/apk-web-worker.md",
            ".opencode/commands/research.md", ".opencode/commands/secrets.md", ".opencode/commands/native.md", ".opencode/commands/dynamic-setup.md", ".opencode/commands/dynamic.md",
            "findings/secrets.md", "findings/dynamic.md", "findings/research.md",
        )
        for relative in apk_required:
            if not (template / relative).exists(): errors.append("APK template missing " + relative)
        for relative in (
            "tools/apk_prepare.py", "tools/apk_secret_scan.py", "tools/apk_secret_group.py", "tools/apk_native_baseline.py",
            "tools/apk_dynamic.py", "tools/apk_dynamic_smoke.py", "tools/apk_dynamic_action.py", "tools/apk_dynamic_evidence.py",
        ):
            path = template / relative
            if path.exists(): validate_python(path, errors)
        dynamic_path = template / "tools" / "apk_dynamic.py"
        if dynamic_path.exists(): validate_apk_dynamic_logic(dynamic_path, errors)

        orchestration = target.get("orchestration", {}) if isinstance(target, dict) else {}
        for field, lower, upper in (("research_max_questions",1,20),("research_max_sources_per_question",1,20),("research_max_report_words",200,3000)):
            value = orchestration.get(field)
            if not isinstance(value, int) or not lower <= value <= upper: errors.append(f"APK TARGET.example.toml must define orchestration.{field} in range {lower}..{upper}")

        secret_cfg = target.get("secrets", {}) if isinstance(target, dict) else {}
        for field in ("store_plaintext", "analyze_encodings", "analyze_hashes", "ai_plausibility_triage"):
            if not isinstance(secret_cfg.get(field), bool): errors.append(f"APK TARGET.example.toml must define secrets.{field} as boolean")
        for field, lower, upper in (("max_decode_depth",0,3),("ai_triage_batch_size",5,50),("ai_representative_locations",1,5)):
            value = secret_cfg.get(field)
            if not isinstance(value, int) or not lower <= value <= upper: errors.append(f"APK TARGET.example.toml must define secrets.{field} in range {lower}..{upper}")

        dynamic = target.get("dynamic", {}) if isinstance(target, dict) else {}
        for field in ("enabled", "allow_software_emulation", "allow_android11_multiabi_fallback", "headless", "wipe_data_on_start", "grant_runtime_permissions", "request_root", "allow_frida", "allow_active_validation"):
            if not isinstance(dynamic.get(field), bool): errors.append(f"APK TARGET.example.toml must define dynamic.{field} as boolean")
        if dynamic.get("backend") not in ("auto", "none"): errors.append("APK dynamic.backend must be auto or none")
        if dynamic.get("image_tag") not in ("auto", "default", "google_apis"): errors.append("APK dynamic.image_tag must be auto, default, or google_apis")
        for field, lower, upper in (("api_level",0,100),("memory_mb",1024,32768),("cores",1,16),("boot_timeout_seconds",60,3600),("observation_seconds",1,600),("emulator_port",5554,5682)):
            value = dynamic.get(field)
            if not isinstance(value, int) or not lower <= value <= upper: errors.append(f"APK TARGET.example.toml must define dynamic.{field} in range {lower}..{upper}")
        if isinstance(dynamic.get("emulator_port"), int) and dynamic["emulator_port"] % 2: errors.append("APK dynamic.emulator_port must be even")

    if module == "firmware":
        firmware_required = (
            "tools/firmware_prepare.py",
            "tools/firmware_baseline.py", "tools/firmware_baseline_core.py",
            "tools/firmware_component_fingerprint.py", "tools/firmware_component_fingerprint_core.py",
            "tools/firmware_secret_scan.py", "tools/firmware_secret_scan_core.py", "tools/firmware_secret_group.py",
            "tools/firmware_ghidra_slice.py", "tools/ghidra/SatDecompileRefs.java",
            ".opencode/agents/firmware-explorer.md", ".opencode/agents/firmware-service-reviewer.md",
            ".opencode/agents/firmware-update-reviewer.md", ".opencode/agents/firmware-secret-hunter.md",
            ".opencode/agents/firmware-secret-review-worker.md", ".opencode/agents/binary-reverser.md",
            ".opencode/agents/firmware-researcher.md", ".opencode/agents/firmware-web-worker.md",
            ".opencode/agents/security-validator.md",
            ".opencode/commands/analyze.md", ".opencode/commands/prepare.md", ".opencode/commands/secrets.md", ".opencode/commands/services.md",
            ".opencode/commands/binaries.md", ".opencode/commands/update.md", ".opencode/commands/research.md",
            ".opencode/commands/summary.md",
            "findings/inventory.md", "findings/attack-surface.md", "findings/secrets.md",
            "findings/update-security.md", "findings/findings.md", "findings/coverage.md",
            "findings/research.md", "findings/analysis-log.md",
        )
        for relative in firmware_required:
            if not (template / relative).exists(): errors.append("Firmware template missing " + relative)
        for relative in (
            "tools/firmware_prepare.py",
            "tools/firmware_baseline.py", "tools/firmware_baseline_core.py",
            "tools/firmware_component_fingerprint.py", "tools/firmware_component_fingerprint_core.py",
            "tools/firmware_secret_scan.py", "tools/firmware_secret_scan_core.py", "tools/firmware_secret_group.py",
            "tools/firmware_ghidra_slice.py",
        ):
            path = template / relative
            if path.exists(): validate_python(path, errors)

        reverser_path = template / ".opencode" / "agents" / "binary-reverser.md"
        if reverser_path.exists():
            reverser_text = reverser_path.read_text(errors="replace")
            for token in ("analyzeHeadless", "work/ghidra/", "host `objdump`"):
                if token not in reverser_text:
                    errors.append(f"Firmware binary-reverser must enforce managed Ghidra fallback ({token})")
            steps_match = re.search(r"(?m)^steps:\s*(\d+)\s*$", reverser_text)
            if not steps_match or int(steps_match.group(1)) < 12:
                errors.append("Firmware binary-reverser needs at least 12 steps for lightweight triage plus Ghidra escalation")

        analyze_path = template / ".opencode" / "commands" / "analyze.md"
        if analyze_path.exists():
            analyze_text = analyze_path.read_text(errors="replace")
            for token in ("analyzeHeadless", "Ghidra-backed", "host `objdump`"):
                if token not in analyze_text:
                    errors.append(f"Firmware /analyze must enforce native Ghidra escalation ({token})")

        orchestration = target.get("orchestration", {}) if isinstance(target, dict) else {}
        for field, lower, upper in (("research_max_questions",1,20),("research_max_sources_per_question",1,20),("research_max_report_words",200,3000)):
            value = orchestration.get(field)
            if not isinstance(value, int) or not lower <= value <= upper: errors.append(f"Firmware TARGET.example.toml must define orchestration.{field} in range {lower}..{upper}")

        firmware_cfg = target.get("firmware", {}) if isinstance(target, dict) else {}
        if not isinstance(firmware_cfg.get("path"), str) or not firmware_cfg.get("path"):
            errors.append("Firmware TARGET.example.toml must define firmware.path")
        for field, lower, upper in (("extract_processes",1,32),("extract_depth",1,30),("extract_timeout_seconds",60,14400),("max_rootfs_candidates",1,100)):
            value = firmware_cfg.get(field)
            if not isinstance(value, int) or not lower <= value <= upper: errors.append(f"Firmware TARGET.example.toml must define firmware.{field} in range {lower}..{upper}")

        analysis_cfg = target.get("analysis", {}) if isinstance(target, dict) else {}
        for field in ("max_binary_deep_reviews", "max_service_deep_reviews", "max_update_deep_reviews"):
            value = analysis_cfg.get(field)
            if not isinstance(value, int) or not 0 <= value <= 50: errors.append(f"Firmware TARGET.example.toml must define analysis.{field} in range 0..50")

        secret_cfg = target.get("secrets", {}) if isinstance(target, dict) else {}
        for field in ("store_plaintext", "ai_plausibility_triage"):
            if not isinstance(secret_cfg.get(field), bool): errors.append(f"Firmware TARGET.example.toml must define secrets.{field} as boolean")
        for field, lower, upper in (("ai_triage_batch_size",5,50),("ai_representative_locations",1,5)):
            value = secret_cfg.get(field)
            if not isinstance(value, int) or not lower <= value <= upper: errors.append(f"Firmware TARGET.example.toml must define secrets.{field} in range {lower}..{upper}")

    if set(manifest.get("platforms", {}).get("supported", [])) != SUPPORTED: errors.append("platform set mismatch")

    catalog = tomllib.loads((root / "dependencies" / "catalog.toml").read_text())["dependencies"]
    required_deps = manifest.get("dependencies", {}).get("required", []); optional_deps = manifest.get("dependencies", {}).get("optional", [])
    for dependency in required_deps + optional_deps:
        if dependency not in catalog: errors.append("unknown dependency " + dependency)
        lowered = dependency.lower()
        if any(word in lowered for word in ("qemu", "docker", "firmae")): errors.append("forbidden emulation/container dependency " + dependency)
        if "emulator" in lowered and not (module == "apk" and dependency == "android-emulator" and dependency in optional_deps):
            errors.append("emulator dependency is allowed only as optional android-emulator for APK")

    return errors


root = Path(sys.argv[2])
modules = [sys.argv[3]] if sys.argv[1] == "module" else [path.parent.name for path in (root / "modules").glob("*/module.toml")]
all_errors = []
for module in sorted(modules):
    errors = validate_module(root, module); print(("✓" if not errors else "✗"), module); all_errors += errors
    for error in errors: print("  ", error)
if all_errors: raise SystemExit(1)
