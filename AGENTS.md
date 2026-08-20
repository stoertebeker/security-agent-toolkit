# AGENTS.md — OpenCode Security Toolkit Repository

## Mission

Develop and maintain a reusable repository of OpenCode-based security-analysis workspaces. The repository currently contains three working prototypes:

- firmware analysis
- authorized API pentesting
- Android APK security analysis

The goal is to preserve their useful security-specific behavior while extracting common orchestration, workspace, reporting, research, validation, and bootstrap concepts into a cleaner generic framework.

Before changing architecture, read `docs/SESSION_CONTEXT.md` and inspect all three tool artifacts/setup scripts.

## Core behavior that should be preserved

### 1. Primary agent is an orchestrator

The primary session should not ingest large raw data unnecessarily. It should plan, correlate, prioritize and maintain concise final findings.

Delegate self-contained work to specialized subagents whenever this keeps raw file listings, decompiled code, disassembly, scanner output, HTTP traces, logcat output or web research out of the primary context.

### 2. Maximum two concurrent subagents

The intended operating policy is at most **two delegated subagents concurrently**. This was chosen to balance useful parallelism against context sprawl and worker load.

OpenCode's `subagent_depth: 1` should remain a hard structural control to prevent subagents from recursively spawning more agents. The two-concurrent-worker limit is currently an instruction-level policy unless a future OpenCode version provides a reliable native concurrency limit.

### 3. No `/tmp` or external workspace artifacts

All files produced by an analysis must remain under the current project/work directory.

- Do not use `/tmp`.
- Do not use `/var/tmp`.
- Do not use `/dev/shm` for analysis artifacts.
- Set `TMPDIR`, `TMP`, and `TEMP` to a project-local `work/tmp/` directory in launch scripts.
- Keep tool caches project-local where practical.
- Preserve `external_directory: deny` where compatible with the workflow.

The purpose is reproducibility, worker isolation and easy cleanup/archive of a whole analysis.

### 4. Evidence before findings

A suspicious string, dangerous API, scanner hit, exported component, decompiler artifact, CVE match or old dependency version is not automatically a vulnerability.

For findings, establish as much as applicable:

```text
attacker-controlled source
→ parsing / transformation
→ validation / authorization boundary
→ security-sensitive sink
→ reachability
→ realistic impact
```

Explicitly distinguish confirmed results, likely issues, issues requiring validation, and false positives.

Never invent CVEs, versions, functions, credentials, data flows or vulnerabilities.

### 5. Independent validation

Important candidate findings, especially High/Critical issues, should be independently challenged by a validator agent whose job is to disprove the candidate when possible.

### 6. Online research is targeted and delegated

Research can save substantial reverse-engineering time, but should be performed after local identification gives a precise question.

Good examples:

- exact component/version and relevant CVEs
- vendor advisories
- upstream source code
- GPL source releases for firmware
- documented API/library behavior
- Android API-level behavior

Do not let public research replace local evidence. Do not leak private code, credentials, API keys, private endpoints or customer data into web queries.

### 7. Prefer focused deep dives over exhaustive dumping

Do not blindly send every ELF to Ghidra, every APK class to a model, or every API endpoint through every test. Triage the attack surface first, then perform deep analysis on the most relevant components.

## Current repository artifacts

The three current distributions and their full bootstrap generators live under `artifacts/`:

- firmware analysis
- API pentest
- APK security

The setup scripts contain the complete generated workspace contents and can materialize editable trees locally for development.

## Refactoring guidelines

When making the repository more generic:

1. Preserve behavior before deduplicating files.
2. Extract common concepts only when they are genuinely common across all or most tools.
3. Keep target-specific rules near the tool that owns them.
4. Avoid a giant universal system prompt. Use small role/system prompts plus project/workspace rules and task-specific start prompts.
5. Keep sensitive target configuration separate from committed templates.
6. Make all bootstrap/setup scripts deterministic and idempotent where practical.
7. Validate generated JSON/TOML/YAML and shell/Python syntax in CI.
8. Add tests for scope enforcement and workspace-path enforcement before broad refactors.
9. Do not weaken API scope controls or dynamic-test gates for convenience.
10. Document changes in a way that a fresh worker can clone the repo, select one tool, configure the target and start OpenCode without consulting the original ChatGPT conversation.

## Desired operator experience

Long term, a user should be able to clone this repository on a worker and do something roughly like:

```text
git clone <repo>
cd <repo>
./toolbox init firmware ./job-router
# or: api / apk / binary / future modules
cd ./job-router
edit target configuration / place artifact
./start-opencode.sh
```

Do not implement this interface blindly. First inventory existing behavior and propose a migration plan that preserves compatibility with current per-tool setup scripts and ZIP outputs.
