# OpenCode Security Toolkit Handoff

This repository is a handoff package for continuing development in a Codex session and turning three existing OpenCode security-analysis kits into a more generic security-agent toolkit.

It contains the original distributable artifacts and the design/context needed to reproduce and evolve the editable workspaces.

## Included tools

| Tool | Purpose |
|---|---|
| Firmware Analysis | Embedded/router firmware extraction, attack-surface analysis, Ghidra/native reverse engineering, targeted public research, validation |
| API Pentest | Scope-controlled authorized API assessment with request wrapper, auth/authz/input testing, research and validation |
| APK Security | Android APK static analysis, Java/Kotlin/Smali review, native/JNI review, optional controlled dynamic testing, research and validation |

The ZIP distributions and setup scripts are under `artifacts/`. The setup scripts generate the complete editable OpenCode workspace for each tool.

## Start here in Codex

1. Read the root `AGENTS.md`.
2. Read `docs/SESSION_CONTEXT.md` for the reasoning and design decisions from the ChatGPT session that produced the kits.
3. Read `docs/NEXT_STEPS.md` for the intended direction toward a generic repository.
4. Inspect the three setup scripts and ZIP distributions before refactoring common functionality.
5. If desired, materialize editable workspaces locally by running the setup scripts into `tools/` subdirectories.

## Important design principle

These are not intended to be autonomous "scan everything" agents. The common architecture is:

```text
Primary orchestrator
      |
      +-- focused subagent A
      +-- focused subagent B      (maximum two concurrently by instruction)
      |
      +-- targeted research agent
      +-- independent validator
```

The primary session should stay small. Large listings, decompiler output, HTTP logs, scanner dumps and reverse-engineering notes belong in project-local report files or delegated subagent contexts.

## Repository layout

```text
security-agent-toolkit/
├── AGENTS.md
├── README.md
├── SHA256SUMS
├── artifacts/
│   ├── opencode-firmware-analysis-kit.zip
│   ├── setup-firmware-analysis.sh
│   ├── opencode-api-pentest-kit.zip
│   ├── setup-api-pentest.sh
│   ├── opencode-apk-security-kit.zip
│   └── setup-apk-security.sh
└── docs/
    ├── SESSION_CONTEXT.md
    ├── ARCHITECTURE.md
    └── NEXT_STEPS.md
```

## Security note

The kits contain example target/config files only. Real credentials, API keys, test accounts, customer data, firmware images and APKs must not be committed to Git. Preserve or improve the existing `.gitignore`, scope-control and dynamic-test-gating mechanisms when refactoring.
