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

`apk-security` cannot call the web worker directly. The researcher can call only the web worker, and the worker cannot spawn further agents. Web access is denied globally for the APK project and enabled only for `apk-web-worker`. OpenCode `subagent_depth=2` is used only for this bounded coordinator/worker pattern. Other modules default to depth 1.

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

Minimal target configuration:

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
```

The APK module is static-first. Dynamic Android testing is separately gated in `TARGET.toml` and can use an external ADB-connected device; no Android emulator is installed.

### Hard-coded secrets and credentials

APK preparation performs a deterministic credential/secret candidate scan after JADX/Apktool extraction. It searches textual Java/Smali/XML/resources/assets plus native-library strings for high-signal private-key, credential, token, URL-auth and sensitive literal patterns.

The scan writes:

```text
reports/tool-output/secret-candidates.txt
reports/tool-output/secret-candidates.json
```

Raw candidate values are intentionally not copied into these reports. Candidates contain local source location, rule/category, value length and a short SHA-256 fingerprint. `apk-secret-hunter` then triages them into real secrets/credentials, sensitive password-equivalents, public client configuration, certificates/trust material, test data, false positives, or items requiring validation. Pattern hits alone are never findings.

Durable secret classification is maintained in:

```text
findings/secrets.md
```

### Reporting and follow-up research

Durable analysis state is stored under `findings/`, detailed delegated work under `reports/subagents/`, one canonical public-research report per question under `reports/research/`, and the final human-readable report at:

```text
reports/STATIC_SECURITY_REPORT.md
```

After an initial analysis, `/research` performs bounded follow-up research only for unresolved public questions that survive the local-first gate and could materially change severity, applicability, confidence or the next analysis step.

## Firmware workflow

```bash
./toolkit install firmware
./toolkit init firmware ~/security-work/router-review
cd ~/security-work/router-review
cp /path/to/router.bin input/firmware.bin
nano target/TARGET.toml
./start.sh
```

Firmware analysis is static and reverse-engineering focused; no emulation dependency is installed.

## API workflow

```bash
./toolkit install api
./toolkit init api ~/security-work/customer-api
cd ~/security-work/customer-api
nano target/TARGET.toml
./start.sh
```

The API module stores scope, methods and test credentials only in the local workspace. Active requests go through the module request wrapper, which enforces configured scope and does not automatically follow redirects.

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

`./toolkit` or `./toolkit --help` prints the longer command overview.

## Developing a module

Read:

```text
AGENTS.md
docs/MODULE_CONTRACT.md
docs/ADDING_A_MODULE.md
```

Modules are discovered automatically from `modules/<module>/module.toml`; there is no hardcoded registry. New dependencies belong in the central catalog. Every module template must expose `orchestration.max_parallel_agents`; do not hardcode a fixed parallel-agent count in prompts.

Use nested subagents only for a deliberate bounded coordinator -> worker design with explicit task allowlists and finite step budgets. Research modules should prefer local evidence first, cap source/report budgets, avoid duplicated summary artifacts, and keep public web access isolated from sensitive assessment data.

Validate changes with:

```bash
./toolkit validate-module <module>
./toolkit validate
./toolkit repo-guard
```

## Design principles

- OpenCode is the orchestration layer.
- Primary contexts stay small; bulky detail belongs in project files and delegated sessions.
- Parallelism is configurable per project through `TARGET.toml`.
- Default subagent depth is 1; bounded depth 2 is allowed only where it materially reduces context growth.
- Findings are evidence-first and important candidates get independent validation.
- APK hard-coded-secret coverage is deterministic first and agent-triaged second.
- Public research is local-first, narrow, source-backed, size-bounded and isolated from sensitive assessment data.
- Project artifacts stay in generated local workspaces.
- The toolkit repository remains free of project/customer/target data.
