# Security Agent Toolkit

A modular OpenCode-based security-analysis toolkit for local assessment workspaces.

The Git repository contains framework code, module templates, dependency definitions, documentation, and tests only. **Real project data must never be stored in this repository.** APKs, firmware images, API credentials, customer scopes, reports, findings, captures, extracted files, and runtime state belong in separate local workspaces created with `./toolkit init`.

## Supported platforms

Static analysis supports:

- Ubuntu 24.04 / 26.04
- Debian 12 / 13
- Kali Rolling
- Parrot OS 7.x

The toolkit targets Debian/APT-family Linux systems and remains suitable for LXC-style static workers.

APK dynamic analysis is optional. Its managed Android Emulator runtime currently targets **Linux x86_64** and performs a capability probe before use. It does not assume KVM, nested virtualization, or `/dev/kvm` passthrough and never reconfigures the host hypervisor/container.

## Modules

```bash
./toolkit list
```

Current modules:

- `apk` - Android APK/XAPK static and optional managed-emulator dynamic security analysis
- `api` - authorized API security testing
- `firmware` - static embedded/firmware security analysis

## Installation

```bash
git clone https://github.com/stoertebeker/security-agent-toolkit.git
cd security-agent-toolkit
git checkout refactor/modular-toolkit-v1
```

Static APK tooling:

```bash
./toolkit install apk
./toolkit doctor apk
```

Install optional APK dynamic extras as well:

```bash
./toolkit install apk --with-optional
./toolkit doctor apk
```

`doctor` reports required and optional dependencies separately, so a static-only worker does not look broken merely because the emulator is absent.

Managed runtime components live under:

```text
~/.local/share/security-agent-toolkit/
```

This may contain OpenCode, uv/Python tools, JDK 21, Ghidra, JADX, Apktool and, when explicitly installed, Android SDK/Emulator/system images. Project AVD state never lives there; it stays in the project workspace.

## Local workspaces

Assessment projects must live outside the Git repository:

```bash
mkdir -p ~/security-work
./toolkit init apk ~/security-work/my-app
cd ~/security-work/my-app
```

Temporary and runtime project state stays under `work/`; assessment evidence stays under `findings/` and `reports/`.

## APK/XAPK workflow

```bash
cp /path/to/application.apk input/app.apk
# or: cp /path/to/application.xapk input/app.xapk
nano target/TARGET.toml
python3 tools/apk_prepare.py
./start.sh
```

Preparation accepts APK or XAPK. XAPK is safely unpacked by the toolkit; base and split APKs are treated as one application. Split code/resources/native libraries are included in coverage.

### Example target configuration

```toml
[engagement]
name = "APK review"
authorized = true

[orchestration]
max_parallel_agents = 2
research_max_questions = 3
research_max_sources_per_question = 5
research_max_report_words = 900

[secrets]
store_plaintext = false
analyze_encodings = true
analyze_hashes = true
max_decode_depth = 2
ai_plausibility_triage = true
ai_triage_batch_size = 20
ai_representative_locations = 3

[apk]
path = "input/app.apk"

[dynamic]
enabled = false
backend = "auto"
api_level = 36
image_tag = "auto"
allow_software_emulation = true
allow_android11_multiabi_fallback = true
headless = true
wipe_data_on_start = true
grant_runtime_permissions = false
request_root = true
allow_frida = false
allow_active_validation = false
memory_mb = 4096
cores = 4
boot_timeout_seconds = 600
observation_seconds = 15
emulator_port = 5554
```

## Static analysis architecture

### Secret/material pipeline

Raw deterministic scanner hits are **not** fed into LLM context:

```text
secret-candidates.json
        -> strict filtering + semantic grouping
        -> secret-groups.json
        -> apk-secret-hunter
        -> bounded plausibility workers
```

Repeated/decompiler/localization copies and invalid crypt-prefix noise are collapsed before AI review. The taxonomy distinguishes real confidential credentials from client signing material, client-SDK authentication material, public client configuration, runtime credentials, hashes/KDFs, encodings, identifiers and false positives.

If plaintext retention is explicitly enabled, exact material remains under `reports/sensitive/`; normal findings, dynamic instrumentation and public research stay redacted.

Inside OpenCode:

```text
/secrets
```

refreshes this path without broad re-analysis.

### Native/JNI pipeline

```bash
python3 tools/apk_native_baseline.py
```

The deterministic baseline recursively covers base and split `.so` libraries, recording ABI/ELF hardening/JNI/import/redacted string leads. Ghidra/deeper reversing is reserved for app-relevant or otherwise plausible security-sensitive paths.

Inside OpenCode:

```text
/native
```

refreshes focused native coverage.

### Public research

Research is local-first and bounded. Every web-worker question carries concrete non-sensitive local applicability facts and the exact external fact still needed. Workers fetch/read a primary source before broadening search. Unfetched search snippets remain `SOURCE_LEAD_ONLY` and cannot change findings.

```text
/research
```

performs targeted follow-up only.

## Toolkit-contained dynamic APK analysis

There is no external-device path in dynamic v1. The runtime is a managed Android Emulator installed with:

```bash
./toolkit install apk --with-optional
```

### Capability probe

Every dynamic setup starts with:

```bash
python3 tools/apk_dynamic.py probe
```

It records:

- host architecture;
- bare-metal / VM / container-LXC environment;
- CPU virtualization flags;
- `/dev/kvm` presence and permissions;
- `emulator -accel-check` result;
- prepared package native ABIs;
- chosen runtime ABI strategy;
- KVM / software / unavailable mode.

CPU `vmx`/`svm` flags alone are never treated as proof that KVM works.

For LXC without `/dev/kvm`, the report explains that the host must pass the KVM device into the container for acceleration. For a VM without `/dev/kvm`, it records likely missing nested virtualization. The toolkit does not modify either host configuration.

If KVM is unavailable, an x86_64 system image may use `-accel off` only when `allow_software_emulation=true`; this can be dramatically slower.

### Native ABI compatibility

On an x86_64 host:

- apps with x86_64 native code use an x86_64 system image;
- apps without native code use an x86_64 system image;
- if native code exists but no x86_64 library is supplied and `minSdk <= 30`, the toolkit may select an **Android 11/API 30 x86_64 multi-ABI image**, which supports x86/x86_64/ARMv7/ARM64 app binaries;
- if that compatibility fallback is impossible, the runtime is reported `UNAVAILABLE` rather than attempting an unverified cross-architecture setup.

The API-30 fallback is explicitly recorded as compatibility coverage and does not pretend to validate target-OS-specific behavior on Android 16/17.

### Real setup smoke test

OpenCode command:

```text
/dynamic-setup
```

performs the capability probe, downloads/creates a compatible AVD, then executes a real boot test through `sys.boot_completed=1`, verifies runtime ABI/root state, and shuts the emulator down. This catches LXC/seccomp/device/runtime problems that cannot be inferred from CPU flags alone.

Managed SDK/system images live under `$SAT_HOME/android-sdk`. AVD user/runtime state is project-local under:

```text
work/android/
```

### Dynamic collection

With `[dynamic].enabled=true`:

```text
/dynamic
```

runs the managed flow:

```text
probe -> setup -> boot -> install APK/base+splits -> launch
      -> optional Frida observation
      -> PCAP + logcat + UI/screenshot + app/process state
      -> deterministic evidence summary
      -> dynamic analyst
      -> validator for material finding changes
```

Key artifacts include:

```text
reports/tool-output/dynamic-capabilities.{json,txt}
reports/dynamic/setup.json
reports/dynamic/setup-smoke.json
reports/dynamic/device-info.json
reports/dynamic/root-status.json
reports/dynamic/abi-compatibility.json
reports/dynamic/network.pcap
reports/dynamic/*logcat*.txt
reports/dynamic/ui.xml
reports/dynamic/screenshot.png
reports/dynamic/states/
reports/dynamic/frida-events.txt
reports/dynamic/actions.jsonl
reports/dynamic/evidence-summary.{json,txt}
reports/subagents/dynamic-review.md
findings/dynamic.md
reports/DYNAMIC_SECURITY_REPORT.md
```

The emulator's PCAP is parsed locally with `tcpdump`; encrypted payloads are not assumed readable merely because a capture exists.

### Frida

When `allow_frida=true`, Frida is used only if the managed emulator actually provides root. A matching `frida-server` is downloaded and deployed without repackaging the target APK.

Default hooks are deliberately redacted. They can record WebView/navigation URLs without query/fragment, bridge names, network endpoint/method metadata, native-library and Dex loading, storage key/table names and value lengths, crypto algorithm names, subprocess execution metadata, and debugger-check execution. Passwords, tokens, request bodies and raw stored values are not copied into normal dynamic artifacts.

### Active validation

`allow_active_validation=true` permits only bounded emulator-local checks based on existing static hypotheses. Actions use the audited wrapper:

```text
python3 tools/apk_dynamic_action.py deep-link ...
python3 tools/apk_dynamic_action.py component ...
python3 tools/apk_dynamic_action.py tap ...
python3 tools/apk_dynamic_action.py keyevent ...
python3 tools/apk_dynamic_action.py text ...
```

Declared custom schemes/components are validated where applicable and every action is recorded in `reports/dynamic/actions.jsonl`. This gate does **not** authorize broad fuzzing or crafted/replayed/mutated backend/provider API calls. Backend testing remains a separately scoped API assessment.

Runtime behavior that was not observed is not treated as absent unless the relevant feature was actually exercised. Missing Google services, software-emulation slowness, API-30 compatibility mode, missing root/Frida, or inaccessible login-gated features are coverage limitations.

## Reporting

Durable APK state includes:

```text
findings/inventory.md
findings/attack-surface.md
findings/secrets.md
findings/findings.md
findings/dynamic.md
findings/coverage.md
findings/research.md
findings/analysis-log.md
```

The static report is:

```text
reports/STATIC_SECURITY_REPORT.md
```

When dynamic analysis runs, it also creates:

```text
reports/DYNAMIC_SECURITY_REPORT.md
```

A compact analyst summary near the top of the static report states whether confirmed Critical/High findings exist, highest supported severity, top risks, unusual behavior, concealment/anti-analysis state, and the main remaining limitation.

Detailed architecture and regression commands are documented in:

```text
docs/APK_ANALYSIS_PIPELINE.md
```

## Firmware workflow

```bash
./toolkit install firmware
./toolkit init firmware ~/security-work/router-review
cd ~/security-work/router-review
cp /path/to/router.bin input/firmware.bin
./start.sh
```

Firmware remains static/reverse-engineering focused and has no emulator dependency.

## API workflow

```bash
./toolkit install api
./toolkit init api ~/security-work/customer-api
cd ~/security-work/customer-api
nano target/TARGET.toml
./start.sh
```

API credentials/scope remain project-local. The module's request wrapper enforces configured scope and does not automatically follow redirects.

## Toolkit commands

```text
./toolkit list
./toolkit platform
./toolkit doctor <module>
./toolkit install <module> [--with-optional]
./toolkit init <module> <destination>
./toolkit validate-module <module>
./toolkit validate
./toolkit repo-guard
```

## Repository safety and module development

Read:

```text
AGENTS.md
docs/MODULE_CONTRACT.md
docs/ADDING_A_MODULE.md
```

Validate changes with:

```bash
./toolkit validate-module <module>
./toolkit validate
./toolkit repo-guard
```

The toolkit repository remains free of customer/target data; project data stays in generated workspaces.
