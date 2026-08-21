# APK / XAPK analysis

The `apk` module performs deterministic static Android analysis and can optionally run a toolkit-managed Android Emulator for bounded dynamic validation.

## Create a workspace

Install the module first as described in the repository README, then create a project outside the toolkit repository:

```bash
mkdir -p ~/security-work
./toolkit init apk ~/security-work/my-app
cd ~/security-work/my-app
```

Copy the target package into `input/`:

```bash
cp /path/to/application.apk input/app.apk
# or
cp /path/to/application.xapk input/app.xapk
```

Configure `target/TARGET.toml`. At minimum authorize the engagement and point `[apk].path` at the input file.

Example:

```toml
[engagement]
name = "APK review"
authorized = true

[orchestration]
max_parallel_agents = 2
research_max_questions = 3
research_max_sources_per_question = 5
research_max_report_words = 900

[apk]
path = "input/app.apk"

[secrets]
store_plaintext = false
analyze_encodings = true
analyze_hashes = true
max_decode_depth = 2
ai_plausibility_triage = true
ai_triage_batch_size = 20
ai_representative_locations = 3

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

## Static preparation and analysis

Run deterministic preparation before broad AI analysis:

```bash
python3 tools/apk_prepare.py
python3 tools/apk_native_baseline.py
python3 tools/apk_secret_scan.py
python3 tools/apk_secret_group.py
```

Then start OpenCode:

```bash
./start.sh
```

The static pipeline is evidence-first. Raw secret scanner hits are filtered/grouped before AI triage, and native ELF/JNI metadata is collected deterministically before selected binaries are sent to deeper reversing.

Useful focused OpenCode commands include:

```text
/secrets
/native
/research
/summary
```

XAPK packages are safely unpacked by the toolkit. Base and split APKs are treated as one application for code, resources and native-library coverage.

## Dynamic analysis

Dynamic analysis is optional and uses only the toolkit-managed Android Emulator. Install the optional dependencies from the repository directory:

```bash
./toolkit install apk --with-optional
./toolkit doctor apk
```

In the workspace enable `[dynamic].enabled=true` and run the setup smoke test from OpenCode:

```text
/dynamic-setup
```

The setup probes host/container/VM state, `/dev/kvm`, actual emulator acceleration and application ABI compatibility. It does not reconfigure the host hypervisor or LXC device passthrough.

A full managed dynamic run uses:

```text
/dynamic
```

The flow covers capability probing, AVD setup/boot, APK or split installation, launch, PCAP/logcat/UI/process evidence, optional root/Frida observation, deterministic evidence summarization and bounded validation.

`allow_active_validation=true` permits only the toolkit's bounded emulator-local actions. It does not authorize broad component fuzzing or backend/API replay/mutation.

## Workspace updates

A project is a snapshot of the module template at creation time. To refresh toolkit-managed scripts/agents without overwriting project state:

```bash
./toolkit sync apk ~/security-work/my-app
```

The sync refreshes managed `tools/`, `.opencode/`, launch/instruction files and `TARGET.example.toml`, while preserving the active `TARGET.toml`, `input/`, `work/`, `reports/` and existing findings.

## Reports and durable state

Static output culminates in:

```text
reports/STATIC_SECURITY_REPORT.md
```

A dynamic run additionally creates:

```text
reports/DYNAMIC_SECURITY_REPORT.md
```

Durable analysis state remains under `findings/`; detailed delegated evidence and raw/deterministic tool output remain under `reports/`.

## Detailed documentation

- [APK static analysis pipeline](APK_ANALYSIS_PIPELINE.md)
- [APK dynamic analysis](APK_DYNAMIC.md)
- [XAPK handling](XAPK.md)
