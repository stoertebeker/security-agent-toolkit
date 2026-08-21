# Security Agent Toolkit

A modular OpenCode-based security-analysis toolkit for authorized local assessment workspaces.

The repository contains framework code, module templates, dependency definitions, documentation, and tests only. Real target/customer data belongs in local workspaces outside this repository.

## Installation

Supported static-analysis platforms:

- Ubuntu 24.04 / 26.04
- Debian 12 / 13
- Kali Rolling
- Parrot OS 7.x

Clone the toolkit:

```bash
git clone https://github.com/stoertebeker/security-agent-toolkit.git
cd security-agent-toolkit
git checkout refactor/modular-toolkit-v1
```

List available modules:

```bash
./toolkit list
```

Install the required runtime and dependencies for one module:

```bash
./toolkit install apk
./toolkit install firmware
./toolkit install api
```

APK dynamic analysis uses optional toolkit-managed emulator dependencies. Install them explicitly when needed:

```bash
./toolkit install apk --with-optional
```

Verify an installation with:

```bash
./toolkit doctor apk
./toolkit doctor firmware
./toolkit doctor api
```

Managed runtime components are installed below:

```text
~/.local/share/security-agent-toolkit/
```

This directory may contain OpenCode, uv/Python tools, JDK 21, Ghidra, JADX, Apktool, Binwalk/unblob support and, when explicitly requested for APK dynamic analysis, the Android SDK/Emulator and system images.

Assessment projects are created separately from the repository with `./toolkit init`; project input, extracted data, findings, reports and runtime state stay in those workspaces.

## Module documentation

- [APK / XAPK analysis](docs/apk.md)
- [Firmware analysis](docs/firmware.md)
- [API assessment](docs/api.md)

Toolkit/module-development documentation remains under [`docs/`](docs/), including the module contract, supported-platform notes and module-development guidance.
