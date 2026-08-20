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

- `apk` - Android APK/package security analysis
- `api` - authorized API security testing
- `firmware` - static embedded/firmware security analysis

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

```toml
[orchestration]
max_parallel_agents = 2
```

This is the maximum number of delegated agent tasks that should execute concurrently. OpenCode currently has no native global max-concurrency scheduler option, so project agents enforce the policy from target configuration.

The APK module also exposes bounded research controls:

```toml
[orchestration]
max_parallel_agents = 2
research_max_questions = 3
research_max_sources_per_question = 5
research_max_report_words = 900
```

APK research uses a tightly bounded extra agent level:

```text
apk-security
  -> apk-researcher
       -> apk-web-worker
```

Web access is denied globally for normal APK agents and enabled only for the narrow web worker.

Research is **local-first**. Every delegated research question must carry 2-5 concrete non-sensitive local facts, why the question matters, and the exact external fact still needed. The web worker performs one focused discovery search and then fetches/reads the strongest primary source before broadening search. Search snippets remain `SOURCE_LEAD_ONLY` and cannot change findings.

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

The module is static-first. Preparation supports a normal APK and supported package containers such as XAPK. When preparation produces a base APK plus splits, agents treat them as one application and include split code/resources/native libraries in coverage.

### Hard-coded secrets, credentials, encodings and hashes

Preparation creates a deterministic raw candidate set. **The LLM workflow does not review that raw array.** It is first filtered and semantically grouped:

```text
secret-candidates.json
        |
        v
apk_secret_group.py
        |
        v
secret-groups.json
        |
        v
apk-secret-hunter -> bounded review workers
```

Grouping removes structurally invalid crypt-prefix noise, collapses repeated values, deduplicates decompiler copies, and groups localized Android resources by resource key before AI plausibility review.

The grouped taxonomy distinguishes:
- `CONFIRMED_SECRET_OR_CREDENTIAL` for actually confidential/privileged reusable material;
- `EXPOSED_CLIENT_SIGNING_MATERIAL` for client-shipped signing material whose server trust/confidentiality semantics are conditional;
- `CLIENT_SDK_AUTH_MATERIAL` for mobile-SDK integration authentication material whose provider-side privilege/reusability is conditional;
- `PUBLIC_CLIENT_CONFIGURATION` and other runtime/hash/encoding/identifier/test/false-positive classes.

A field named `secret`, `APPSECRET` or `clientSecret` is not automatically a confidential backend credential.

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

Exact matched and printable decoded values are confined to:

```text
reports/sensitive/
```

Normal findings, consolidated reports, agent summaries and public research remain redacted. Hash/KDF analysis may identify structured formats or cautious Hashcat mode hints for later operator use. Bare digest lengths remain ambiguous unless implementation context identifies the algorithm. The workflow does not crack hashes automatically.

Inside OpenCode:

```text
/secrets
```

refreshes deterministic grouping and bounded AI plausibility triage without repeating broad analysis.

### Native/JNI baseline

The APK module uses a cheap deterministic native baseline before deeper reverse engineering:

```bash
python3 tools/apk_native_baseline.py
```

It recursively covers `.so` files under `extracted/apktool/`, including decoded ABI/split trees. The baseline records architecture, selected ELF hardening properties, JNI exports, dangerous-import leads and redacted native secret-string leads.

Baseline indicators are review leads, not vulnerabilities. `apk-native-reverser` and Ghidra are reserved for app-relevant, reachable or otherwise plausible security-sensitive native paths rather than every third-party library.

Inside OpenCode:

```text
/native
```

refreshes baseline/native coverage and performs focused follow-up without repeating the whole assessment.

### Reporting and follow-up research

Durable analysis state lives under `findings/`, delegated detail under `reports/subagents/`, one canonical public-research report per question under `reports/research/`, and the final report at:

```text
reports/STATIC_SECURITY_REPORT.md
```

After initial analysis, `/research` performs bounded follow-up only for unresolved public questions that survive the local-first gate. If local evidence answers the outstanding question, web research may correctly be skipped.

Each research worker receives an explicit packet:

```text
RQ-ID / narrow question
Why it matters
Local facts: 2-5 concrete non-sensitive facts
External fact needed
Source/report budgets
```

The worker should discover once, fetch/read the strongest primary source, try at most one alternate primary page if needed, and only then broaden search. An unfetched decisive source remains `SOURCE_LEAD_ONLY`.

Detailed APK pipeline contracts and targeted regression commands are documented in:

```text
docs/APK_ANALYSIS_PIPELINE.md
```

### Fresh APK end-to-end acceptance test

For a clean module test, use a new workspace and a different authorized application. Do not copy extracted artifacts or findings from an older assessment.

Expected sequence:

```text
toolkit init apk
  -> configure TARGET.toml
  -> place package input
  -> tools/apk_prepare.py
       -> metadata/signature
       -> JADX + Apktool
       -> deterministic secret/material scan
  -> start.sh
       -> attack-surface/static analysis
       -> strict group-first secret triage
       -> deterministic native baseline
       -> focused native review when justified
       -> durable findings/coverage/provenance
       -> reports/STATIC_SECURITY_REPORT.md
  -> /research
       -> local-first unresolved-question review
       -> bounded fetch-first web research only when useful
```

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

The API module stores authorization metadata, explicit URL-prefix scope, allowed HTTP methods, and optional test credentials only in the local project workspace. Its request wrapper enforces configured scope and does not automatically follow HTTP redirects.

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

## Repository safety

The repository intentionally contains no real assessment data. `.gitignore` and `./toolkit repo-guard` provide additional safeguards against accidentally adding common target and artifact types.

## Developing a new module

Read:

```text
docs/MODULE_CONTRACT.md
docs/ADDING_A_MODULE.md
AGENTS.md
```

A module is discovered automatically from `modules/<module>/module.toml`; there is no hardcoded central list of module names. New dependencies belong in the central dependency catalog.

Validate development changes with:

```bash
./toolkit validate-module <module>
./toolkit validate
./toolkit repo-guard
```

## Design principles

- OpenCode is the orchestration layer.
- Primary contexts stay small; bulky detail belongs in project files and delegated sessions.
- Parallelism is configurable per project through `TARGET.toml`.
- Default subagent depth is 1; bounded depth 2 is allowed only where it materially reduces parent-context growth.
- Findings are evidence-first and important candidates get independent validation.
- APK hard-coded material coverage is deterministic scan -> strict semantic grouping -> bounded AI plausibility triage.
- Native coverage is deterministic baseline -> focused deeper reverse engineering only where justified.
- Public research is local-first, local-facts-grounded, fetch-first, bounded and isolated from sensitive assessment data.
- Sensitive plaintext retention is explicit opt-in and remains outside normal/public reporting paths.
- Project artifacts stay in generated local workspaces.
- The toolkit repository remains free of project/customer/target data.
