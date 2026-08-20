# Suggested Next Steps for Codex

The goal is to evolve the three prototypes into a generic Git repository that can be checked out on a worker and used without returning to the original ChatGPT conversation.

## Phase 1 — Inventory before refactor

Inspect all three current distributions/setup generators and create a comparison table of:

- directory layouts
- OpenCode config settings
- agent prompt conventions
- subagent permissions
- start scripts/environment variables
- target/config file formats
- report/findings formats
- installer/bootstrap behavior
- safety/scope controls

Do not refactor until the common and tool-specific behavior is explicit.

## Phase 2 — Define a generic repository layout

A plausible direction:

```text
repo/
├── AGENTS.md
├── README.md
├── bin/
│   └── toolbox
├── lib/
│   ├── shell/
│   ├── templates/
│   └── validation/
├── modules/
│   ├── firmware/
│   ├── api/
│   └── apk/
├── tests/
└── dist/
```

This is a suggestion, not a requirement. Preserve easy standalone distributions.

## Phase 3 — Extract only genuine common pieces

Candidates:

- project-local temp/cache setup
- common workspace directories
- shared OpenCode primary orchestration text
- research-agent base rules
- validator-agent base rules
- reporting schema
- config syntax validation
- bootstrap utility
- artifact/ZIP build utility

Avoid forcing firmware/API/APK into the same detailed target schema.

## Phase 4 — Add a worker-facing CLI

Target experience:

```bash
./toolbox list
./toolbox init firmware ./jobs/router-123
./toolbox init api ./jobs/customer-api
./toolbox init apk ./jobs/android-app
```

Possible conveniences:

- validate prerequisites
- copy module template into a job directory
- create project-local `work/tmp`
- validate target configuration
- optionally install module dependencies
- start OpenCode with the correct agent
- build/update standalone ZIP + setup scripts

## Phase 5 — Tests and CI

High-value tests:

### Common

- JSON/TOML syntax
- shellcheck / bash syntax
- Python syntax/unit tests
- no generated references to `/tmp` except documentation/tests explicitly checking prohibition
- target/original edit permissions remain denied
- subagents cannot spawn subagents

### API

- in-scope request accepted
- out-of-scope host denied
- out-of-scope path denied
- disallowed method denied
- redirects not followed
- credential headers redacted
- 429/repeated-5xx pause behavior

### APK

- TARGET authorization gate
- preparation refuses external artifact path
- output stays project-local
- dynamic flags default false
- researcher cannot access target secrets through designed workflow

### Firmware

- original artifact not modified
- extraction/report paths project-local
- Ghidra path conventions
- user-mode QEMU workflow does not require binfmt

## Phase 6 — Documentation

The final README should let a fresh operator:

1. clone the repo
2. install common prerequisites
3. create a job from a module
4. configure/insert the target
5. validate the job configuration
6. launch OpenCode
7. find reports and findings

No knowledge from the original ChatGPT conversation should be required.

## Compatibility goal

Keep generating the existing standalone forms during migration:

- per-tool ZIP
- per-tool self-contained setup `.sh`

The current originals are retained under `artifacts/` so Codex can compare behavior while refactoring.
