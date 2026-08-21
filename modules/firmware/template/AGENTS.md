# Firmware Analysis Workspace

## Scope and workspace rules

- Analyze only the authorized firmware configured in `target/TARGET.toml` and only when `engagement.authorized=true`.
- Keep all target/extraction/report artifacts inside this workspace. Do not use `/tmp`, `/var/tmp` or `/dev/shm` for analysis artifacts.
- Do not execute target firmware binaries on the analysis host.
- Static analysis is the v1 scope. No QEMU/emulator/live-device requirement.
- Read `[orchestration].max_parallel_agents` and never exceed that many concurrently executing delegated tasks; default to 2.
- Important High/Critical candidate findings require independent validation.
- Public web access belongs only to bounded firmware web-research workers.

## Deterministic preparation contract

Before broad AI review, run or reuse fresh artifacts from:

```text
python3 tools/firmware_prepare.py
python3 tools/firmware_baseline.py
python3 tools/firmware_component_fingerprint.py
python3 tools/firmware_secret_scan.py
python3 tools/firmware_secret_group.py
```

- `firmware_prepare.py` owns input hashing, unblob extraction, Binwalk structure output, rootfs candidate selection, resumability and symlink safety audit.
- `firmware_baseline.py` owns filesystem/accounts/permissions/service/update/package-DB/ELF inventory and priority leads.
- `firmware_component_fingerprint.py` adds conservative static component/version anchors when package databases are missing or incomplete. Fingerprints are research anchors, not findings.
- Do not recursively feed the extracted rootfs to an LLM merely to inventory it.
- Rootfs ambiguity, extraction errors, missing extractor dependencies, opaque/encrypted regions and unsafe target-root symlinks are coverage limitations and must be retained.
- Absolute firmware symlinks such as `/lib/...` are target-root semantics. Never follow them onto the host filesystem.

## Evidence rules

A service name, config line, SUID bit, dangerous import, package/version fingerprint, update keyword, YARA/string hit, hash, private-key filename, old library or public CVE is a lead, not a finding.

Where applicable establish:

```text
relevant/attacker input -> processing/validation -> security-sensitive sink -> startup/reachability/privilege -> realistic impact
```

Static startup/config evidence does not prove actual LAN/WAN exposure. Distinguish configuration, startup enablement and externally reachable runtime behavior.

## Secret/material contract

- LLM triage is strictly group-first.
- The raw `reports/tool-output/firmware-secret-candidates.json` array MUST NOT be loaded/iterated by agents.
- Run/refresh `firmware_secret_group.py`; AI reads `firmware-secret-groups.json` only.
- Distinguish reusable secrets, local login credentials, password hashes, host/service private keys, embedded upstream/service credentials, public trust material, tests/placeholders and false positives.
- `/etc/shadow` is not itself a finding; account state, hash type and login/reachability matter.
- A private key is not automatically a shared vendor secret; establish uniqueness/use/trust consequences.
- When `secrets.store_plaintext=true`, exact material belongs only under `reports/sensitive/`. Never copy it into normal reports, public research or agent summaries.
- No automatic password/hash cracking.

## Service/web/IPC contract

- Start from deterministic startup/service leads and focused init/config files.
- Trace concrete web/API handlers and backing processes; webroot presence alone is not reachability.
- Review authentication/authorization/session/CSRF/command/file/config/upload/diagnostic paths where applicable.
- Distinguish registered local IPC/RPC methods from remotely reachable interfaces.
- Preserve unknown firewall/interface/topology conditions instead of inventing exposure.

## Native binary contract

- `firmware-binaries.json` provides deterministic ELF architecture/hardening/import metadata and `binary_priority_leads` only for review ordering.
- Missing PIE/RELRO/canary/NX or dangerous imports are not vulnerabilities by themselves.
- Use `binary-reverser` only for custom/security-sensitive binaries tied to a concrete service/update/privilege/parser hypothesis.
- Start with `file`/`readelf`/`objdump`/`nm`/`strings`; use Ghidra only when justified.
- Never execute target binaries.

## Update-security contract

Trace update flows as:

```text
source/download -> parsing/version -> integrity/authenticity -> staging -> privileged flash/write -> recovery/rollback
```

- Checksum/integrity is not authenticity.
- Signature-related strings/public keys are not proof that verification is enforced.
- Record alternate recovery/debug/unsigned paths and trust-key writability where established.
- Bootloader/secure-boot behavior unavailable from the rootfs is an explicit limitation.

## Behavior and concealment contract

Record unusual/high-impact firmware behavior and hidden/analysis-resistance evidence in `findings/attack-surface.md`.

Allowed state:
- `NONE_ESTABLISHED`
- `ORDINARY_PACKING_OR_STRIPPING_ONLY`
- `SUSPICIOUS_CONCEALMENT_INDICATORS`
- `CONFIRMED_ANTI_ANALYSIS_OR_HIDDEN_BEHAVIOR`

Normal compression, BusyBox symlinks, stripped vendor binaries, UPX/packing alone, minified web assets and expected maintenance interfaces do not establish malicious intent.

## Research contract

- Research is local-first and last-mile.
- Every delegated RQ needs why it matters, 2-5 concrete non-sensitive local facts and the exact external fact still needed.
- Include locally established version/startup/use and useful negative evidence when applicable.
- If local facts are incomplete, return `NEEDS_LOCAL_CONTEXT` and do not browse.
- Web workers discover once, fetch/read strongest primary source before broadening search, and keep search snippets as `SOURCE_LEAD_ONLY` when the decisive source is unread.
- A CVE/component match does not confirm target exploitability without local affected conditions.

## Durable reporting contract

The primary MUST maintain:
- `findings/inventory.md`
- `findings/attack-surface.md`
- `findings/secrets.md`
- `findings/update-security.md`
- `findings/findings.md`
- `findings/coverage.md`
- `findings/research.md`
- `findings/analysis-log.md`

Detailed subagent notes belong under `reports/subagents/`; deterministic output under `reports/tool-output/`; one canonical report per research question under `reports/research/`; exact sensitive values only under `reports/sensitive/` when enabled.

At completion create `reports/STATIC_SECURITY_REPORT.md` from durable records. Near the top include a compact `## Analyst summary`: Critical/High status and highest severity, top three risks, unusual behavior or `None established`, concealment state/evidence, and the largest remaining coverage/runtime/topology/vendor limitation. Repeat it in the final OpenCode response.
