# Session Context and Design History

This document captures the important decisions from the ChatGPT session that created the first three security-agent workflows. It is intended to let a later Codex session continue development without repeating the original back-and-forth.

## 1. Starting point: TP-Link firmware analysis

The initial task was to analyze a TP-Link router firmware image using OpenCode with a local reasoning model behind the user's own inference stack.

The key architectural conclusion was that OpenCode should not be the firmware extractor itself. Deterministic tools should perform extraction and low-level inspection, while the model acts as analyst and orchestrator.

Recommended flow:

```text
firmware image
  → unblob / binwalk
  → extracted filesystem
  → static inventory / attack-surface triage
  → OpenCode orchestration
  → targeted Ghidra analysis of interesting native binaries
  → optional QEMU user-mode validation
  → optional deeper/full-system emulation elsewhere
```

EMBA was considered useful, but the worker is an Ubuntu LXC container. The chosen first-line workflow therefore keeps OpenCode, unblob, Binwalk, Ghidra, file/strings/readelf/objdump/nm/xxd/ripgrep/yara, QEMU user mode, gdb-multiarch and strace/ltrace inside the LXC. Full-system firmware emulation can move to a separate VM if container restrictions become annoying.

For Ubuntu 26.04 the discussion specifically moved from the older `qemu-user-static` assumption to explicit `qemu-user` usage. binfmt registration is not required when QEMU is invoked explicitly.

## 2. Prompt-design lesson

An early firmware system prompt became extremely long and enumerated many bug classes, dangerous C functions, paths and algorithms.

The user challenged that design. The conclusion was that the prompt was too large as a system prompt because of instruction dilution.

The preferred split became:

```text
agent/system prompt
  = role, goals, evidence requirements, orchestration behavior

AGENTS.md / project rules
  = workspace layout, available tools, file policies, analysis conventions

start prompt / custom command
  = what to analyze now and what to do first
```

Avoid universal security encyclopedias in the system prompt. Models already know common dangerous APIs. General rules such as source-to-sink tracing, controllability, reachability and evidence quality are more useful.

## 3. OpenCode orchestration model

The common architecture evolved into a primary-agent plus specialized-subagent model.

The primary agent should:

- keep its own context small
- plan and prioritize
- delegate focused work
- correlate results
- choose the next investigation
- maintain concise durable findings

The user explicitly requested a maximum of **two subagents concurrently**. This remains an instruction-level policy unless OpenCode gains a reliable native concurrency control.

`subagent_depth: 1` is used as the hard structural control preventing recursive agent trees. Subagents additionally get `permission.task: deny`.

Detailed raw output belongs in files such as `reports/subagents/` rather than being returned wholesale to the primary context.

## 4. Workspace isolation

The user explicitly requires all analysis files to remain in the current working directory.

Common policy:

- never use `/tmp`
- never use `/var/tmp`
- never use `/dev/shm` for analysis artifacts
- set `TMPDIR`, `TMP` and `TEMP` to `./work/tmp`
- keep caches project-local where practical
- use `external_directory: deny`
- protect original target inputs/configuration from agent edits

This requirement is about reproducibility, cleanup, worker isolation and avoiding analysis artifacts scattered across the host.

## 5. Evidence-first security analysis

Across all modules, a scanner match or suspicious primitive is only a lead.

Where applicable the analysis should establish:

```text
attacker-controlled source
→ parsing / transformation
→ validation / authorization boundary
→ security-sensitive sink
→ reachability
→ realistic impact
```

Findings should distinguish confirmed issues, likely issues, issues requiring validation, and false positives.

The agents must not invent CVEs, versions, functions, credentials, data flows or vulnerabilities.

## 6. Independent validator pattern

A dedicated validator agent was added because LLM-based reverse engineering can produce plausible-looking false positives.

For important candidate findings, especially High/Critical, the validator receives a narrow claim and is explicitly told to try to disprove it by checking controllability, validation, reachability, auth requirements, privileges/configuration and realistic impact.

A finding that survives an adversarial second pass is much more valuable than a one-agent observation.

## 7. Online research pattern

Online research was added as a dedicated subagent rather than giving every agent unrestricted web access.

Research should be targeted after local identification produces a precise question, for example:

- exact component and version plus known CVEs
- vendor advisories
- upstream source code
- GPL source releases for router firmware
- exact Android API behavior
- third-party SDK/library documentation

Research can save substantial reverse-engineering effort, but public claims never replace verification against the actual local target.

Sensitive material, credentials, private source code, private endpoints and customer data must never be placed into web searches.

When OpenCode is used with a non-OpenCode model/provider, the workflows set `OPENCODE_ENABLE_EXA=1` to make the websearch integration available to the researcher agent.

## 8. Firmware workflow

The firmware prototype uses a primary `firmware-security` orchestrator and focused agents for exploration, native reverse engineering, online research and independent validation.

Priorities include:

- firmware/filesystem inventory
- CPU architecture, libc, init and services
- network-facing attack surface
- web interface/API/authentication
- hardcoded credentials/secrets/keys
- privileged daemons and IPC
- firmware update/signature mechanisms
- native binaries that process attacker-controlled input

Do not blindly reverse engineer every ELF file. Triage first, then use Ghidra on a small set of meaningful targets.

## 9. API pentest workflow

The second prototype generalized the architecture for explicitly authorized API security testing.

A text configuration file, `target/TARGET.toml`, defines:

- engagement authorization metadata
- base URLs / URL-prefix scope
- allowed HTTP methods per scope rule
- request spacing/timeouts
- pause behavior for 429/repeated 5xx
- credential profiles/test accounts

A local request wrapper enforces scope and method restrictions before sending active traffic. Redirects are not blindly followed, credential headers are redacted in logs, and repeated server stress signals can create a local paused state.

The design intentionally avoids giving the agent unrestricted `curl` as the normal active-test path.

Specialized agents cover reconnaissance, authorization, input handling, research and validation.

## 10. APK security workflow

The third prototype adapts the same architecture to Android APK analysis.

Static preparation uses tools such as JADX, Apktool, aapt/apksigner and optional native/Ghidra analysis.

Coverage is guided by OWASP MASVS/MASTG concepts and includes:

- manifest/exported components
- intents and deep links
- authentication/authorization
- hardcoded secrets
- WebView/JavaScript interfaces
- TLS/Network Security Config
- local storage, logs and backup behavior
- ContentProvider/FileProvider
- PendingIntent/IPC boundaries
- dynamic code loading/reflection
- JNI/native libraries
- third-party SDKs and vulnerable versions

Dynamic testing is disabled by default and separately gated for install, launch, logcat, Frida, clear-data and uninstall operations. External app network activity requires explicit authorization and host allowlisting.

Because the worker is an LXC, an Android emulator is not assumed to run inside the container. A separate emulator/device can be connected via ADB when needed.

## 11. Shared OpenCode configuration ideas

The prototypes commonly use or aim to preserve:

- project-local `.opencode/agents/`
- a small primary agent prompt
- specialized hidden subagents
- `default_agent`
- `subagent_depth: 1`
- `compaction.auto: true`
- `compaction.prune: true`
- `snapshot: false` for large analysis trees where appropriate
- `external_directory: deny`
- target/original edit protection
- broad web access denied except for the researcher
- nested task execution denied on subagents
- custom start commands/prompts where useful

## 12. Desired generic repository

The user wants these three prototypes in one Git repository that can be cloned onto a worker. The long-term operator experience should be approximately:

```bash
git clone <repo>
cd <repo>
./toolbox init firmware ./jobs/router
# or api / apk / future binary/module types
cd ./jobs/router
configure target / place artifact
./start-opencode.sh
```

Do not rush into a universal schema or one enormous prompt. First compare the three existing implementations and identify genuine commonality.

Good shared candidates:

- workspace/temp/cache bootstrap
- common orchestration wording
- researcher/validator base policies
- reporting conventions
- target authorization metadata where applicable
- syntax/config validation
- distribution ZIP/setup-script generation
- CI tests for workspace/scope controls

Things that should remain module-specific include firmware extraction/emulation, API network scope enforcement, and APK/ADB/Frida mechanics.

## 13. Compatibility requirement

During refactoring, continue to support standalone distributions:

- one ZIP per tool
- one self-contained setup `.sh` per tool

The artifacts under `artifacts/` are reference outputs and should be used to verify that future generic abstractions do not silently weaken or lose existing behavior.
