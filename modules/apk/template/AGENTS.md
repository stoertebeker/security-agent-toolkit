# APK Analysis Workspace

## Scope and workspace rules

- Analyze only the APK configured in `target/TARGET.toml` and only when `engagement.authorized=true`.
- Keep all analysis artifacts inside this workspace. Do not use `/tmp`, `/var/tmp` or `/dev/shm` for analysis artifacts.
- Static analysis is primary. ADB/Frida testing may target an external authorized device only when explicitly enabled in `TARGET.toml`.
- The primary agent runs at most TWO subagents concurrently.
- Important High/Critical candidate findings require independent validation.

## Evidence rules

A suspicious string, dangerous API, exported component, scanner hit or decompiler artifact is only a lead.
Where applicable establish attacker-controlled source -> processing/validation -> security-sensitive sink -> reachability -> impact.
Distinguish CONFIRMED, LIKELY, NEEDS VALIDATION and FALSE POSITIVE.
If JADX output is incomplete or suspicious, verify the relevant path against Apktool/Smali before relying on it.

## Durable reporting contract

The primary agent MUST maintain these files throughout the analysis:

- `findings/inventory.md` - package/version/signing metadata, SDK levels, component/library/native inventory.
- `findings/attack-surface.md` - exported components, deep links, providers, WebViews, IPC and prioritized entry points.
- `findings/secrets.md` - credentials/keys/tokens/certificates and their validation status. Do not duplicate real secrets unnecessarily.
- `findings/findings.md` - concise evidence-backed security findings and candidate findings.
- `findings/coverage.md` - what was reviewed, what was skipped/degraded, including JADX/decompiler limitations.
- `findings/analysis-log.md` - major decisions, delegated investigations, unresolved questions and recommended follow-up.

Detailed subagent work and bulky evidence belong under `reports/subagents/`.
Raw tool logs belong under `reports/tool-output/`.

At the end, produce a human-readable consolidated report at:

- `reports/STATIC_SECURITY_REPORT.md`

The consolidated report is derived from the structured `findings/` files. It does NOT replace them.
