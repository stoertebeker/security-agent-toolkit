# Architecture Across the Three Current Tools

## Shared control plane

```text
operator
  |
  +-- target/input configuration
  |
  +-- start-opencode.sh
          |
          +-- local TMP/cache environment
          +-- primary OpenCode agent
                   |
                   +-- focused subagents (max two concurrently by policy)
                   +-- targeted research
                   +-- independent validation
                   |
                   +-- project-local reports/findings
```

## Shared responsibilities

### Primary agent

- orchestrates
- does not absorb unnecessary raw data
- decides what to delegate
- correlates evidence
- maintains final findings

### Explorer/recon agent

- broad inventory / attack-surface identification
- cheap triage first
- points the primary toward expensive deep dives

### Deep-review agent

Tool-specific:

- firmware: native/Ghidra reverse engineering
- API: authz/input testing
- APK: Java/Kotlin/Smali or native/JNI analysis

### Research agent

- public information only
- precise questions after local identification
- never substitutes public claims for local evidence
- must not leak sensitive/private target data into queries

### Validator agent

- assumes the candidate may be wrong
- tries to falsify it
- independently checks reachability, prerequisites and impact

## Shared filesystem concepts

Recommended common names:

```text
original/ or target/     immutable target input/config
work/tmp/                local temporary files
work/cache/              optional tool caches
extracted/               derived artifacts where applicable
reports/tool-output/     raw tool output
reports/subagents/       delegated detailed analysis
findings/                concise durable results
```

## Shared config controls

Common OpenCode behaviors worth preserving:

- `default_agent`
- `subagent_depth: 1`
- `compaction.auto: true`
- `compaction.prune: true`
- `external_directory: deny`
- deny editing original input / target scope configuration
- deny broad web access except on researcher agents
- deny nested `task` use on subagents

## Tool-specific safety/control layers

### Firmware

Static analysis by default. User-mode emulation only when needed. Full-system emulation is not assumed to be available in an LXC.

### API

Active network requests must obey explicit authorization, URL-prefix scope, method scope and rate constraints. Prefer a scope-enforcing wrapper instead of unrestricted shell HTTP calls.

### APK

Static analysis by default. Dynamic ADB/Frida behavior is separately gated per action. External app network activity requires explicit authorization and host allowlisting.
