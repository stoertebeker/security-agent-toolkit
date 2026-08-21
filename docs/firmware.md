# Firmware analysis

The `firmware` module performs deterministic static firmware extraction, filesystem inventory, component/secret triage and focused reverse engineering through OpenCode. It is currently static-only and never executes target firmware binaries on the analysis host.

## Create a workspace

After installing the module from the repository README:

```bash
mkdir -p ~/security-work
./toolkit init firmware ~/security-work/router-review
cd ~/security-work/router-review
```

Copy the firmware image into `input/` without changing its format merely to satisfy the toolkit. For example:

```bash
cp /path/to/firmware.chk input/
```

Configure `target/TARGET.toml`:

```toml
[engagement]
name = "Firmware review"
authorized = true

[orchestration]
max_parallel_agents = 2
research_max_questions = 5
research_max_sources_per_question = 5
research_max_report_words = 900

[firmware]
path = "input/firmware.chk"
extract_processes = 4
extract_depth = 10
extract_timeout_seconds = 3600
max_rootfs_candidates = 20

[analysis]
max_binary_deep_reviews = 8
max_service_deep_reviews = 8
max_update_deep_reviews = 4
max_ghidra_slices_per_hypothesis = 3

[secrets]
store_plaintext = false
ai_plausibility_triage = true
ai_triage_batch_size = 20
ai_representative_locations = 3
```

`max_ghidra_slices_per_hypothesis` bounds iterative native reverse engineering for one binary/security hypothesis. Reaching the budget preserves unresolved evidence as `NEEDS VALIDATION` rather than turning one firmware image into an open-ended reverse-engineering project.

## Normal automated analysis

The normal workflow is intentionally hands-off after workspace configuration:

```bash
./start.sh
```

Then run in OpenCode:

```text
/analyze
```

`/analyze` owns the complete static workflow. It refreshes stale deterministic artifacts, delegates attack-surface and secret review, selects bounded service/update/native hypotheses, invokes Ghidra automatically when lightweight architecture tooling is insufficient, validates important candidates, performs bounded last-mile research, and produces the final report.

A normal assessment should not require the operator to copy/paste Ghidra, grep, awk, objdump or deterministic preparation commands. Manual execution of those tools is intended for toolkit development/debugging or for inspecting a particular artifact after the automated run.

The high-level flow is:

```text
firmware image
    -> deterministic extraction / rootfs discovery / safety audit
    -> baseline + component + grouped-secret preprocessing
    -> firmware-explorer + firmware-secret-hunter
    -> selected service/web/auth, update and native-binary hypotheses
    -> bounded Ghidra slices where native call flow is materially required
    -> independent validation of important candidates
    -> bounded last-mile public research
    -> durable findings + STATIC_SECURITY_REPORT.md
```

The explorer reconstructs a focused native boot chain when shell/init evidence is insufficient, rather than treating missing regex startup hits as absence of services. Native analysis is hypothesis-driven and architecture/vendor agnostic; target-specific function addresses, vendor names and one-off regexes must not be added to toolkit code merely to complete one assessment.

## Deterministic preparation and diagnostics

The deterministic stages are run/reused automatically by `/analyze`. They can also be invoked manually when debugging the toolkit or inspecting preprocessing:

```bash
python3 tools/firmware_prepare.py
python3 tools/firmware_baseline.py
python3 tools/firmware_component_fingerprint.py
python3 tools/firmware_secret_scan.py
python3 tools/firmware_secret_group.py
```

The stages have separate responsibilities:

```text
firmware image
    -> recursive extraction / rootfs discovery / extraction audit
    -> filesystem, account, service lifecycle, update and ELF baseline
    -> conservative component version fingerprints
    -> redacted secret candidate scan
    -> semantic secret grouping
```

`firmware_prepare.py` uses Binwalk for structural hints and unblob for recursive extraction. Exact extractor availability is recorded through unblob's external-dependency report; unsupported/missing format helpers become explicit coverage limitations rather than permission to assume complete extraction.

The extracted filesystem is treated as untrusted input. The deterministic tools do not follow extracted firmware symlinks into host paths, and nested unblob `*_extract` analysis artifacts inside an established rootfs are pruned from subsequent target inventory to avoid duplicate binaries/files.

## Baseline semantics

The baseline outputs leads, not findings. In particular:

- dangerous imports and weak hardening are binary-review prioritization signals, not vulnerabilities;
- a component version is a research anchor, not proof that a public CVE applies;
- `kind=stop` service records prove lifecycle knowledge only and do not establish startup/listening state;
- zero deterministic startup/config leads does not mean no services start; native `init`/`rc` dispatchers may own startup;
- `firmware-update-leads.*` contains update mechanism/security leads;
- `firmware-update-ui-paths.*` contains UI/navigation/entry-point anchors only.

The component fingerprint output groups repeated locations by component/version. Secret scanning is group-first: specific key/token formats remain visible, while generic password-like UI/localization noise is suppressed before AI triage. Exact material is retained only under `reports/sensitive/` when explicitly enabled.

## Focused commands

For targeted follow-up inside an existing workspace, the module also exposes:

```text
/prepare
/secrets
/services
/binaries
/update
/research
/summary
```

These are useful for focused re-analysis, but `/analyze` is the normal end-to-end command.

Ghidra is used only for selected custom/security-sensitive binaries tied to concrete hypotheses. The binary reverser invokes `tools/firmware_ghidra_slice.py` itself, uses a small sequence of xref-driven slices, and stops at the configured convergence budget when remaining evidence requires runtime/topology/hardware/backend facts or broad vendor-specific archaeology.

## Workspace updates

Workspaces are snapshots of the module template. Refresh toolkit-managed code/agents without overwriting project evidence using:

```bash
./toolkit sync firmware ~/security-work/router-review
```

Sync preserves the active `target/TARGET.toml`, `input/`, `work/`, `reports/` and existing findings.

## Important artifacts

Preparation/baseline artifacts include:

```text
reports/tool-output/firmware-preparation.{json,txt}
reports/tool-output/unblob-dependencies.txt
reports/tool-output/firmware-baseline.{json,txt}
reports/tool-output/firmware-services.{json,txt}
reports/tool-output/firmware-update-leads.{json,txt}
reports/tool-output/firmware-update-ui-paths.{json,txt}
reports/tool-output/firmware-component-fingerprints.{json,txt}
reports/tool-output/firmware-secret-groups.{json,txt}
reports/tool-output/firmware-binaries.json
reports/tool-output/ghidra-*.log
work/ghidra/slices/
```

Durable state is maintained under:

```text
findings/inventory.md
findings/attack-surface.md
findings/secrets.md
findings/update-security.md
findings/findings.md
findings/coverage.md
findings/research.md
findings/analysis-log.md
```

The final static report is:

```text
reports/STATIC_SECURITY_REPORT.md
```

## Detailed documentation

- [Firmware analysis pipeline](FIRMWARE_ANALYSIS_PIPELINE.md)
