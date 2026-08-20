# Security Agent Toolkit

A modular OpenCode-based security-analysis toolkit for local assessment workspaces.

The Git repository contains only framework code, module templates, dependency definitions, documentation, and tests. **Real project data must never be stored in this repository.** APKs, firmware images, API credentials, customer scopes, reports, findings, captures, extracted files, and other assessment artifacts belong in a separate local workspace created with `./toolkit init`.

## Supported platforms

- Ubuntu 24.04
- Ubuntu 26.04
- Debian 12
- Debian 13
- Kali Rolling
- Parrot OS 7.x

The toolkit targets Debian/APT-family Linux systems and is designed for LXC-style workers. It deliberately does **not** install QEMU, KVM, Docker, FirmAE, Android emulators, or other emulation stacks.

## Modules

```bash
./toolkit list
```

Current modules:

- `apk` - Android APK security analysis
- `api` - authorized API security testing
- `firmware` - static embedded/firmware security analysis

Modules are installed and initialized independently.

## First installation

```bash
git clone https://github.com/stoertebeker/security-agent-toolkit.git
cd security-agent-toolkit
git checkout refactor/modular-toolkit-v1
```

Show help and platform detection:

```bash
./toolkit
./toolkit platform
```

Check and install one module:

```bash
./toolkit doctor apk
./toolkit install apk
./toolkit doctor apk
```

OpenCode is mandatory core software and is installed automatically when necessary. Managed runtime components live under:

```text
~/.local/share/security-agent-toolkit/
```

This may contain OpenCode, uv, managed Python runtimes/tools, JDK 21, Ghidra, JADX, Apktool and Rust/Binwalk where needed. Native Linux tools are installed through APT.

## Local workspaces

Assessment projects must live **outside the Git repository**:

```bash
mkdir -p ~/security-work
./toolkit init apk ~/security-work/my-app
```

The toolkit refuses to initialize a project inside its own checkout. Generated workspaces keep temporary analysis data under `work/tmp` and set `TMPDIR`, `TMP` and `TEMP` accordingly.

## Agent orchestration settings

Each local project has an `[orchestration]` section in `target/TARGET.toml`.

Common setting:

```toml
[orchestration]
max_parallel_agents = 2
```

This is the maximum number of delegated agent tasks that should execute concurrently. The default is 2 and the recommended range is 1-8. OpenCode currently has no native max-concurrency scheduler option, so the project agents enforce this policy from the target configuration.

The APK module also exposes bounded research controls:

```toml
[orchestration]
max_parallel_agents = 2
research_max_questions = 3
research_max_sources_per_question = 5
research_max_report_words = 900
```

APK research uses one additional, tightly bounded agent level:

```text
apk-security
  -> apk-researcher       (coordinator, steps: 8)
       -> apk-web-worker  (one narrow web question, steps: 5)
```

`apk-security` cannot call the web worker directly. The researcher can call only the web worker, and the worker cannot spawn further agents. Web access is denied globally for the APK project and enabled only for `apk-web-worker`. OpenCode `subagent_depth=2` is used only for bounded coordinator/worker patterns. Other modules default to depth 1.

Research is deliberately **local-first**. Existing Java/Smali/XML/resources, metadata, hashes, certificate parsing, and narrow local analysis are used before creating a web question. Each public question gets exactly one canonical report under `reports/research/RQ-XX-....md`; `findings/research.md` is only a compact index and no second coordinator/batch report is required. Search snippets are discovery leads; material conclusions should use fetched primary sources when reasonably available.

## APK workflow

```bash
./toolkit install apk
./toolkit init apk ~/security-work/example-apk
cd ~/security-work/example-apk
cp /path/to/application.apk input/app.apk
nano target/TARGET.toml
python3 tools/apk_prepare.py
./start.sh
```

A useful local target configuration is:

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
adb_serial = ""
allow_frida = false
```

The APK module is static-first. Dynamic Android testing is separately gated in `TARGET.toml` and can use an external ADB-connected device; no Android emulator is installed.

### Hard-coded secrets, credentials, encodings, and hashes

APK preparation performs deterministic secret/material preprocessing after JADX/Apktool extraction.

The scanner searches textual Java/Smali/XML/resources/assets plus native-library strings for high-signal private-key, credential, token, URL-auth, sensitive literal, structured hash/KDF, and related material. It also performs bounded local percent/hex/base64/base64url decoding and cautious hash/KDF format analysis when enabled.

The scanner writes redacted artifacts:

```text
reports/tool-output/secret-candidates.txt
reports/tool-output/secret-candidates.json
```

Candidate values are then strictly format-filtered and semantically grouped by `tools/apk_secret_group.py`. Repeated values, JADX/Apktool duplicates, and localized Android string resources are collapsed before AI review. The grouping artifacts are:

```text
reports/tool-output/secret-groups.txt
reports/tool-output/secret-groups.json
```

Deterministic priority is only an ordering hint. `apk-secret-hunter` delegates bounded batches to `apk-secret-review-worker`, which reviews every semantic group using a small number of representative local locations and assigns plausibility, final classification, confidence, evidence, and follow-up.

Typical final classes distinguish real reusable credentials/private material from public client configuration, certificates/trust anchors, non-secret digests/identifiers, localized UI resources, dependency constants, test/sample data, reversible encodings, ambiguous hash material, and false positives. Pattern hits and hash-shape guesses are never findings by themselves.

When working in a protected environment, plaintext retention can be explicitly enabled:

```toml
[secrets]
store_plaintext = true
analyze_encodings = true
analyze_hashes = true
max_decode_depth = 2
ai_plausibility_triage = true
ai_triage_batch_size = 20
ai_representative_locations = 3
```

Exact matched and printable decoded values are then confined to:

```text
reports/sensitive/
```

The toolkit attempts restrictive permissions for that directory/files. Normal findings, consolidated reports, agent summaries, and public research remain redacted even when plaintext retention is enabled.

Hash/KDF analysis may identify structured formats or cautious candidate Hashcat modes for later operator use. Bare hexadecimal digest lengths remain ambiguous unless local implementation context identifies the algorithm. The APK workflow does **not** run password/hash cracking automatically.

The canonical normal triage report is:

```text
reports/subagents/secrets-review.md
```

Durable secret classification is maintained in:

```text
findings/secrets.md
```

Inside OpenCode, run:

```text
/secrets
```

to run or refresh only the deterministic grouping and AI plausibility triage without repeating broad static analysis or public research.

### Reporting and follow-up research

Durable analysis state is stored under `findings/`, detailed delegated work under `reports/subagents/`, one canonical public-research report per question under `reports/research/`, and the final human-readable report at:

```text
reports/STATIC_SECURITY_REPORT.md
```

After an initial analysis, `/research` performs bounded follow-up research only for unresolved public questions that survive the local-first gate and could materially change severity, applicability, confidence or the next analysis step. If local evidence answers the outstanding questions, `/research` may correctly perform no web research at all and instead use focused local validation.

### Fresh APK end-to-end acceptance test

For a clean module test, use a new workspace and a different authorized APK. Do not copy extracted artifacts or findings from an older assessment.

Expected sequence:

```text
toolkit init apk
  -> configure TARGET.toml
  -> place input/app.apk
  -> tools/apk_prepare.py
       -> file/AAPT/apksigner
       -> JADX + Apktool
       -> deterministic secret/material scan
  -> start.sh
       -> primary static analysis
       -> grouped AI secret plausibility triage
       -> durable findings/coverage/provenance
       -> reports/STATIC_SECURITY_REPORT.md
  -> /research
       -> local-first unresolved-question review
       -> bounded web research only when still useful
```

A successful acceptance test should leave no required structured file as an empty stub, should record used/skipped tooling and degraded coverage honestly, should keep raw sensitive values under `reports/sensitive/` only when explicitly enabled, and should preserve the configured parallel-agent ceiling.

## Firmware workflow

```bash
./toolkit doctor firmware
./toolkit install firmware
./toolkit init firmware ~/security-work/router-review
cd ~/security-work/router-review
cp /path/to/router.bin input/firmware.bin
./start.sh
```

The firmware module intentionally focuses on static analysis and reverse engineering. The base toolkit does not install or rely on emulation software.

## API workflow

```bash
./toolkit doctor api
./toolkit install api
./toolkit init api ~/security-work/customer-api
cd ~/security-work/customer-api
nano target/TARGET.toml
./start.sh
```

The API module stores authorization metadata, explicit URL-prefix scope, allowed HTTP methods, and optional test credentials only in the **local project workspace**. Its request wrapper enforces the configured scope and does not automatically follow HTTP redirects.

## Toolkit commands

```text
./toolkit list
./toolkit platform
./toolkit doctor <module>
./toolkit install <module>
./toolkit init <module> <destination>
./toolkit validate-module <module>
./toolkit validate
./toolkit repo-guard
```

`./toolkit` or `./toolkit --help` prints a longer explanation and examples.

## Repository safety

The repository intentionally contains no real assessment data. `.gitignore` and `./toolkit repo-guard` provide additional safeguards against accidentally adding common target and artifact types.

Run:

```bash
./toolkit repo-guard
```

before publishing changes if you have been developing new modules locally.

## Developing a new module

Read:

```text
docs/MODULE_CONTRACT.md
docs/ADDING_A_MODULE.md
AGENTS.md
```

A module is discovered automatically from `modules/<module>/module.toml`; there is no hardcoded central list of module names.

When adding a dependency that does not yet exist, also extend the central dependency catalog and ensure it has a valid installation/check strategy for supported platforms.

The repository contains a dedicated OpenCode `module-developer` agent whose job is to keep module structure, dependency registration, templates, documentation, tests, project isolation, and shared security invariants consistent.

Validate development changes with:

```bash
./toolkit validate-module <module>
./toolkit validate
./toolkit repo-guard
```

## Design principles

Across all modules:

- OpenCode is the orchestration layer.
- Primary contexts stay small; bulky detail belongs in project files and delegated sessions.
- Parallelism is configurable per project through `TARGET.toml`.
- Default subagent depth is 1; bounded depth 2 is allowed only where it materially reduces parent-context growth.
- Findings are evidence-first and important candidates get independent validation.
- APK hard-coded-secret coverage is deterministic first, semantic-grouped second, and AI-plausibility-triaged third.
- Public research is local-first, narrow, source-backed, size-bounded, and isolated from sensitive assessment data.
- Sensitive plaintext retention is explicit opt-in and remains outside normal/public reporting paths.
- Project artifacts stay in generated local workspaces.
- The toolkit repository remains free of project/customer/target data.
