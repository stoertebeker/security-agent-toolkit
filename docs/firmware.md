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
cp /path/to/R7000-V1.0.9.42_10.2.44.chk input/
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
path = "input/R7000-V1.0.9.42_10.2.44.chk"
extract_processes = 4
extract_depth = 10
extract_timeout_seconds = 3600
max_rootfs_candidates = 20

[analysis]
max_binary_deep_reviews = 8
max_service_deep_reviews = 8
max_update_deep_reviews = 4

[secrets]
store_plaintext = false
ai_plausibility_triage = true
ai_triage_batch_size = 20
ai_representative_locations = 3
```

## Deterministic preparation

Before broad AI analysis run:

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

## OpenCode analysis

Start the orchestrator with:

```bash
./start.sh
```

The full run starts from the deterministic summaries instead of recursively feeding the entire rootfs to the primary model. Typical focused commands are:

```text
/prepare
/secrets
/services
/binaries
/update
/research
/summary
```

The main analysis flow is:

```text
firmware-explorer + firmware-secret-hunter
    -> integrate durable attack-surface/secret state
    -> selected service/web/auth, update and native-binary deep dives
    -> independent validator for important High/Critical candidates
    -> bounded last-mile public research
    -> STATIC_SECURITY_REPORT.md
```

The explorer reconstructs a focused native boot chain when shell/init evidence is insufficient, rather than treating missing regex startup hits as absence of services.

Ghidra is reserved for selected custom/security-sensitive binaries tied to concrete hypotheses. The module does not execute target binaries.

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
