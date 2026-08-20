#!/usr/bin/env python3
from pathlib import Path
import sys, tomllib, json

SUPPORTED = {
    "ubuntu-24.04",
    "ubuntu-26.04",
    "debian-12",
    "debian-13",
    "kali-rolling",
    "parrot-7",
}


def validate_python(path: Path, errors: list[str]) -> None:
    try:
        compile(path.read_text(), str(path), "exec")
    except Exception as exc:
        errors.append(f"bad Python {path.name}: {exc}")


def validate_module(root: Path, module: str):
    errors = []
    module_file = root / "modules" / module / "module.toml"
    try:
        manifest = tomllib.loads(module_file.read_text())
    except Exception as exc:
        return [f"bad module.toml: {exc}"]

    template = module_file.parent / "template"
    for filename in ("AGENTS.md", "opencode.json", "start.sh", "target/TARGET.example.toml"):
        if not (template / filename).exists():
            errors.append("missing template/" + filename)

    try:
        opencode = json.loads((template / "opencode.json").read_text())
    except Exception as exc:
        errors.append("bad opencode.json " + str(exc))
        opencode = {}

    depth = opencode.get("subagent_depth")
    if depth not in (1, 2):
        errors.append("subagent_depth must be 1 or bounded depth 2")
    if opencode.get("permission", {}).get("external_directory") != "deny":
        errors.append("external_directory must be deny")

    if depth == 2:
        agent_dir = template / ".opencode" / "agents"
        bounded_agents = []
        if agent_dir.exists():
            for agent_file in agent_dir.glob("*.md"):
                text = agent_file.read_text(errors="replace")
                if "steps:" in text and "permission:" in text and "task:" in text:
                    bounded_agents.append(agent_file.name)
        if len(bounded_agents) < 2:
            errors.append(
                "subagent_depth=2 requires at least coordinator/worker agents with steps and task permissions"
            )

    target_file = template / "target" / "TARGET.example.toml"
    target = {}
    if target_file.exists():
        try:
            target = tomllib.loads(target_file.read_text())
            orchestration = target.get("orchestration", {})
            maximum = orchestration.get("max_parallel_agents")
            if not isinstance(maximum, int) or not 1 <= maximum <= 8:
                errors.append("TARGET.example.toml must define orchestration.max_parallel_agents in range 1..8")
        except Exception as exc:
            errors.append("bad TARGET.example.toml " + str(exc))

    if module == "apk":
        apk_required = (
            "tools/apk_prepare.py",
            "tools/apk_secret_scan.py",
            "tools/apk_secret_group.py",
            "tools/apk_native_baseline.py",
            ".opencode/agents/apk-secret-hunter.md",
            ".opencode/agents/apk-secret-review-worker.md",
            ".opencode/agents/apk-native-reverser.md",
            ".opencode/agents/apk-researcher.md",
            ".opencode/agents/apk-web-worker.md",
            ".opencode/commands/research.md",
            ".opencode/commands/secrets.md",
            ".opencode/commands/native.md",
            "findings/secrets.md",
            "findings/research.md",
        )
        for relative in apk_required:
            if not (template / relative).exists():
                errors.append("APK template missing " + relative)

        for relative in (
            "tools/apk_prepare.py",
            "tools/apk_secret_scan.py",
            "tools/apk_secret_group.py",
            "tools/apk_native_baseline.py",
        ):
            path = template / relative
            if path.exists():
                validate_python(path, errors)

        orchestration = target.get("orchestration", {}) if isinstance(target, dict) else {}
        for field, lower, upper in (
            ("research_max_questions", 1, 20),
            ("research_max_sources_per_question", 1, 20),
            ("research_max_report_words", 200, 3000),
        ):
            value = orchestration.get(field)
            if not isinstance(value, int) or not lower <= value <= upper:
                errors.append(
                    f"APK TARGET.example.toml must define orchestration.{field} in range {lower}..{upper}"
                )

        secret_cfg = target.get("secrets", {}) if isinstance(target, dict) else {}
        for field in ("store_plaintext", "analyze_encodings", "analyze_hashes", "ai_plausibility_triage"):
            if not isinstance(secret_cfg.get(field), bool):
                errors.append(f"APK TARGET.example.toml must define secrets.{field} as boolean")
        for field, lower, upper in (
            ("max_decode_depth", 0, 3),
            ("ai_triage_batch_size", 5, 50),
            ("ai_representative_locations", 1, 5),
        ):
            value = secret_cfg.get(field)
            if not isinstance(value, int) or not lower <= value <= upper:
                errors.append(f"APK TARGET.example.toml must define secrets.{field} in range {lower}..{upper}")

    if set(manifest.get("platforms", {}).get("supported", [])) != SUPPORTED:
        errors.append("platform set mismatch")

    catalog = tomllib.loads((root / "dependencies" / "catalog.toml").read_text())["dependencies"]
    dependencies = manifest.get("dependencies", {}).get("required", []) + manifest.get("dependencies", {}).get("optional", [])
    for dependency in dependencies:
        if dependency not in catalog:
            errors.append("unknown dependency " + dependency)
        if any(word in dependency.lower() for word in ("qemu", "docker", "emulator", "firmae")):
            errors.append("forbidden emulation dependency " + dependency)

    return errors


root = Path(sys.argv[2])
modules = (
    [sys.argv[3]]
    if sys.argv[1] == "module"
    else [path.parent.name for path in (root / "modules").glob("*/module.toml")]
)

all_errors = []
for module in sorted(modules):
    errors = validate_module(root, module)
    print(("✓" if not errors else "✗"), module)
    all_errors += errors
    for error in errors:
        print("  ", error)

if all_errors:
    raise SystemExit(1)
