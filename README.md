# OpenCode Security Agent Toolkit

This repository is the development handoff for three OpenCode security-analysis workflows and the starting point for turning them into a more generic worker-friendly toolkit.

## Current modules

| Tool | Purpose |
|---|---|
| Firmware Analysis | Embedded/router firmware extraction, attack-surface analysis, Ghidra/native reverse engineering, targeted public research, validation |
| API Pentest | Scope-controlled authorized API assessment with request wrapper, auth/authz/input testing, research and validation |
| APK Security | Android APK static analysis, Java/Kotlin/Smali review, native/JNI review, optional controlled dynamic testing, research and validation |

## Start here in Codex

1. Read `AGENTS.md`.
2. Read `docs/SESSION_CONTEXT.md`.
3. Read `docs/ARCHITECTURE.md` and `docs/NEXT_STEPS.md`.
4. Materialize the three editable source workspaces:

```bash
bash materialize-tools.sh
```

This produces:

```text
tools/
├── firmware-analysis/
├── api-pentest/
└── apk-security/
```

The workspaces are generated from the reference ZIP distributions under `artifacts/`. Individual modules can also be materialized directly:

```bash
bash artifacts/setup-firmware-analysis.sh ./tools/firmware-analysis
bash artifacts/setup-api-pentest.sh ./tools/api-pentest
bash artifacts/setup-apk-security.sh ./tools/apk-security
```

## Common architecture

```text
Primary orchestrator
      |
      +-- focused subagent A
      +-- focused subagent B      (maximum two concurrently by policy)
      |
      +-- targeted research agent
      +-- independent validator
```

The primary context stays deliberately small. Large listings, decompiler output, HTTP logs, scanner dumps and reverse-engineering notes belong in project-local report files or delegated subagent contexts.

Common controls include `subagent_depth: 1`, project-local temp directories instead of `/tmp`, `external_directory: deny`, protected target/original files, evidence-first findings, targeted online research and independent validation of important candidates.

## Repository layout

```text
security-agent-toolkit/
├── AGENTS.md
├── README.md
├── SHA256SUMS
├── materialize-tools.sh
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

The repository is public. Only templates and tooling belong here. Real credentials, API keys, test accounts, customer data, private API targets, firmware images and APKs must not be committed. Preserve or improve the module-specific `.gitignore`, scope-control and dynamic-test-gating mechanisms when refactoring.

## Suggested first Codex task

> Read AGENTS.md and all files under docs/. Materialize the three tools with `bash materialize-tools.sh`, then compare their layouts, OpenCode configuration, agent architecture, safety controls and bootstrap logic. Propose a concrete refactoring plan for a generic module-based toolkit before changing behavior. Preserve the standalone ZIP/setup-script outputs and do not weaken scope or workspace controls.
