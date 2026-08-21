# Firmware analysis pipeline

The firmware module is a static-first, evidence-first workflow for authorized firmware images. Target images and extracted data live only in generated workspaces outside the toolkit repository.

## Pipeline overview

```text
firmware image
    |
    v
firmware_prepare.py
  - SHA-256 / file identity
  - Binwalk structure lead
  - recursive unblob extraction
  - rootfs candidate scoring
  - absolute/escaping symlink audit
  - resumable preparation state
    |
    v
firmware_baseline.py
  - accounts / shadow state
  - permissions / SUID / SGID / world writable
  - init / service / web / IPC leads
  - update/security leads
  - ELF architecture / hardening / imports
  - package database inventory
    |
    +--> firmware_component_fingerprint.py
    |      - known static version strings
    |      - kernel module directory anchors
    |
    +--> firmware_secret_scan.py
           - broad local redacted matching
           - optional exact local evidence only in reports/sensitive/
                 |
                 v
         firmware_secret_group.py
           - deduplication by redacted fingerprint/rule
           - bounded representative locations
                 |
                 v
         firmware-secret-hunter -> bounded review workers

Deterministic baselines -> focused firmware-explorer -> selected service/update/binary reviewers -> validator -> bounded local-facts research -> final report
```

## Preparation

Run:

```bash
python3 tools/firmware_prepare.py
```

The tool writes:

```text
reports/tool-output/firmware.sha256
reports/tool-output/firmware-file.txt
reports/tool-output/firmware-binwalk.txt
reports/tool-output/unblob.txt
reports/tool-output/unblob-report.json
reports/tool-output/unblob-dependencies.txt
reports/tool-output/firmware-preparation.json
reports/tool-output/firmware-preparation.txt
work/extracted/
```

The input SHA-256 is used for resumability. `--force` discards/rebuilds the extraction tree.

Unblob is the recursive extractor. Binwalk is used as a structural lead rather than a second automatic extraction engine. Preparation records missing unblob external extractors and non-zero extraction status as degraded coverage when usable output remains.

### Rootfs discovery

Firmware containers frequently contain bootloader/kernel/recovery/one-or-more filesystems. The preparation tool scores directories using rootfs markers such as `etc/passwd`, `sbin/init`, `bin/busybox`, `etc/init.d`, libraries and web roots.

The highest candidate becomes `primary_rootfs`, while alternatives remain in the preparation inventory. A missing conventional rootfs is `degraded`, not a reason to pretend the full extraction tree is one filesystem.

### Symlink safety

Extracted firmware commonly contains absolute target-root symlinks (`/lib/...`) and relative links. Analysis tools must never follow such links onto the analysis host. Preparation records absolute links and relative links that would escape the extraction root. This is coverage/safety metadata, not a target vulnerability by itself.

## Deterministic baseline

Run:

```bash
python3 tools/firmware_baseline.py
python3 tools/firmware_component_fingerprint.py
```

Key outputs:

```text
reports/tool-output/firmware-baseline.{json,txt}
reports/tool-output/firmware-binaries.json
reports/tool-output/firmware-services.{json,txt}
reports/tool-output/firmware-update-leads.{json,txt}
reports/tool-output/firmware-components.{json,txt}
reports/tool-output/firmware-component-fingerprints.{json,txt}
reports/tool-output/firmware-scripts.json
reports/tool-output/firmware-web-files.json
```

### Binary baseline

ELFs are inspected statically using binutils. The baseline records architecture/endianness/type/interpreter, PIE, RELRO, GNU stack/NX clue, canary reference, fortify imports, stripping, RPATH/RUNPATH, SUID/SGID and selected dangerous/network imports.

These are triage leads. Missing hardening and imports such as `system`/`strcpy` are not findings without a relevant input/call path/reachability/impact chain.

`binary_priority_leads` rank potential deep-review candidates using service/update correlation, privilege and import/hardening clues. The score is ordering only.

### Services and reachability

Init scripts, inittab/systemd/inetd/xinetd/UCI/cron-like locations are parsed for startup/service leads. A configured or startup-enabled daemon does not prove actual LAN/WAN reachability. Durable records distinguish configuration/startup evidence from runtime/topology exposure.

### Component/version fingerprints

Package databases (opkg/dpkg/apk where present) are primary local version anchors. Many embedded systems have no package DB, so a second deterministic step extracts known version strings for common components such as BusyBox, Dropbear, OpenSSL, dnsmasq, lighttpd/nginx, hostapd and similar named files.

A version fingerprint is a research anchor, not a vulnerability. CVE applicability still requires affected version/configuration/use and local reachability.

## Credential/material pipeline

Run:

```bash
python3 tools/firmware_secret_scan.py
python3 tools/firmware_secret_group.py
```

The scanner covers text configuration plus special account/private-key paths. Ordinary outputs are redacted: rule, path, line, short value fingerprint, length and redacted context. When `[secrets].store_plaintext=true`, exact matched values may be kept only in `reports/sensitive/firmware-secrets.json` with restrictive permissions. Private-key bodies are not duplicated merely for reporting.

LLM triage is strictly group-first:

```text
firmware-secret-candidates.json   # raw deterministic array; not LLM input
             |
             v
firmware_secret_group.py
             |
             v
firmware-secret-groups.json       # only scanner-derived LLM input
             |
             v
firmware-secret-hunter
             |
             +--> bounded firmware-secret-review-worker batches
```

Important distinctions include reusable confidential credentials, local account credentials, password hashes, operational private keys, embedded service/cloud credentials, public trust material, samples/placeholders and false positives.

## Focused review

### `/services`

Reviews selected startup/network/web/auth/IPC paths. It should trace concrete handlers and preserve unknown firewall/interface/topology conditions.

### `/binaries`

Reviews only prioritized custom/security-sensitive ELFs. Cheap static tooling comes before Ghidra. Target binaries are never executed.

### `/update`

Reviews update flows as:

```text
source/download -> parsing/version -> integrity/authenticity -> staging -> privileged flash/write -> recovery/rollback
```

Checksum/integrity is not authenticity; signature strings or public keys are not proof of enforced signature verification.

### `/secrets`

Refreshes scanner/grouping and bounded semantic-group AI triage without repeating broad analysis.

## Public research

`/research` is local-first and last-mile. Every question carries:

```text
RQ-ID / narrow question
Why it matters
Local facts: 2-5 concrete non-sensitive target facts
External fact needed
Source/report budgets
```

Local facts should include exact component/version/startup/use when relevant and useful negative evidence. The web worker searches once, fetches/reads the strongest primary source before broadening, and treats search-only evidence as `SOURCE_LEAD_ONLY`.

Firmware research commonly targets vendor advisories, upstream source/fixes, GPL source releases, exact version semantics and proprietary update-format documentation. Public research never proves local exploitability by itself.

## Durable records

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

The final human-readable report is `reports/STATIC_SECURITY_REPORT.md` and is derived from these records.

The report begins with a short analyst summary: confirmed Critical/High status, highest supported severity, up to three top risks, unusual behavior (or none), concealment/hidden-behavior state and the largest remaining coverage/runtime/topology/vendor limitation.

## Targeted regression commands

```text
/prepare
/secrets
/services
/binaries
/update
/research
/summary
```

A full fresh assessment starts from `START_PROMPT.txt`.

## Static v1 boundary

Firmware v1 does not require QEMU/system emulation or live hardware. Runtime service reachability, network topology, bootloader/secure-boot state, hardware-specific code paths and cloud/backend behavior remain explicit limitations unless separately established.
