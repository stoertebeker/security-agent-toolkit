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

The toolkit targets Debian/APT-family Linux systems and is designed to remain usable inside LXC-style workers. It deliberately does **not** install QEMU, KVM, Docker, FirmAE, Android emulators, or other emulation stacks.

## Available modules

```bash
./toolkit list
```

Current modules:

- `apk` - Android APK security analysis
- `api` - authorized API security testing
- `firmware` - static embedded/firmware security analysis

Each module is installed and initialized independently. Installing the APK module does not automatically install firmware tooling, and vice versa.

## First installation

Clone the toolkit repository:

```bash
git clone https://github.com/stoertebeker/security-agent-toolkit.git
cd security-agent-toolkit
```

During development/testing of the modular rewrite, use:

```bash
git checkout refactor/modular-toolkit-v1
```

Calling the CLI without parameters shows the complete command overview:

```bash
./toolkit
```

Check the detected platform:

```bash
./toolkit platform
```

## Dependency model

OpenCode is a mandatory core dependency and is installed by the toolkit when necessary.

Shared managed runtime files are stored under:

```text
~/.local/share/security-agent-toolkit/
```

This location may contain:

- OpenCode
- uv
- toolkit-managed Python runtimes and isolated Python tools
- JDK 21
- Ghidra
- JADX
- Apktool
- Rust/Binwalk when required

Only native tools that are better provided by the operating system are installed through APT.

The toolkit does not use one giant Python virtual environment. Python applications are installed as isolated uv tools and use a toolkit-managed Python baseline where possible.

### Check before installing

For example:

```bash
./toolkit doctor apk
```

This reports which dependencies are already available and which are missing.

### Install exactly one module

```bash
./toolkit install apk
```

or:

```bash
./toolkit install firmware
./toolkit install api
```

After installation, verify again:

```bash
./toolkit doctor apk
```

## Local workspaces

Analysis projects must be created **outside the Git repository**.

For example:

```bash
mkdir -p ~/security-work
./toolkit init apk ~/security-work/my-app
```

The toolkit refuses to initialize an assessment workspace inside its own Git checkout.

A generated workspace contains the OpenCode project configuration, agents, local temporary directories, reports/findings directories, target configuration examples, and module-specific helper tools.

All workspace temporary files are kept project-local. The generated start scripts set `TMPDIR`, `TMP`, and `TEMP` to the workspace's `work/tmp` directory rather than intentionally using `/tmp` for analysis artifacts.

## APK example

Install the module:

```bash
./toolkit doctor apk
./toolkit install apk
```

Create an external workspace:

```bash
./toolkit init apk ~/security-work/example-apk
cd ~/security-work/example-apk
```

Place the APK in the workspace:

```bash
cp /path/to/application.apk input/app.apk
```

Edit the local target configuration:

```bash
nano target/TARGET.toml
```

Minimal example:

```toml
[engagement]
name = "APK review"
authorized = true

[apk]
path = "input/app.apk"
```

Then start the prepared OpenCode environment:

```bash
./start.sh
```

The APK module uses static analysis by default. Dynamic Android testing remains explicitly gated in the project's `TARGET.toml` and can use an external ADB-connected device if desired. No Android emulator is installed by the toolkit.

## Firmware example

```bash
./toolkit doctor firmware
./toolkit install firmware
./toolkit init firmware ~/security-work/router-review
cd ~/security-work/router-review
cp /path/to/router.bin input/firmware.bin
./start.sh
```

The firmware module intentionally focuses on static analysis and reverse engineering. The base toolkit does not install or rely on emulation software.

## API example

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
- The primary agent should keep its context small.
- At most two subagents should be active concurrently by instruction.
- `subagent_depth` remains `1`.
- Detailed raw analysis belongs in project-local reports rather than the primary model context.
- Findings are evidence-first and should distinguish confirmed issues from hypotheses requiring validation.
- Targeted public research is delegated to specialized researcher agents.
- Important findings can be independently challenged by validator agents.
- Project artifacts stay local to the generated workspace.
- The toolkit repository itself remains free of project/customer/target data.
