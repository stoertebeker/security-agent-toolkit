# APK Analysis Workspace

## Scope and workspace rules

- Analyze only the APK configured in `target/TARGET.toml` and only when `engagement.authorized=true`.
- Keep all analysis artifacts inside this workspace. Do not use `/tmp`, `/var/tmp` or `/dev/shm` for analysis artifacts.
- Static analysis is primary. ADB/Frida testing may target an external authorized device only when explicitly enabled in `TARGET.toml`.
- Read `[orchestration].max_parallel_agents` from TARGET.toml and never exceed that many concurrently executing delegated tasks; default to 2 when absent.
- Important High/Critical candidate findings require independent validation.
- Public web access is reserved for the bounded APK research worker path; normal analysis agents must not browse directly.

## Evidence rules

A suspicious string, dangerous API, exported component, scanner hit, secret-pattern hit, or decompiler artifact is only a lead.
Where applicable establish attacker-controlled source -> processing/validation -> security-sensitive sink -> reachability -> impact.
Distinguish CONFIRMED, LIKELY, NEEDS VALIDATION and FALSE POSITIVE.
If JADX output is incomplete or suspicious, verify the relevant path against Apktool/Smali before relying on it.

Secret/credential candidates require classification. Distinguish reusable credential/private material from public client configuration, identifiers, certificates/trust anchors, test data and false positives. Never duplicate a full real credential in reports when source location plus fingerprint is sufficient.

Public research may support or challenge a local hypothesis but cannot confirm an APK vulnerability by itself. Never place credentials, tokens, private target data, proprietary code blocks, local signing allowlist values, or sensitive TARGET.toml contents into web queries.

## Research efficiency contract

- Local first: use existing Java/Smali/XML/resources, metadata, hashes and local parsing before asking the web.
- Public research is only for facts that remain external after that local check.
- Each research question has exactly one canonical detail artifact under `reports/research/RQ-XX-....md`.
- `findings/research.md` is only a compact index; do not duplicate source tables or long analysis there.
- Do not create a second coordinator/batch research report.
- A decisive external fact should be supported by an actually fetched/read primary source when reasonably available. Search snippets alone remain `SOURCE_LEAD_ONLY`.
- Perform cheap deterministic local correlation enabled by research before leaving a question unresolved.
- Prefer one consolidated validator pass for material research-driven finding changes when appropriate.

## Durable reporting contract

The primary agent MUST maintain these files throughout the analysis:

- `findings/inventory.md` - package/version/signing metadata, SDK levels, component/library/native inventory.
- `findings/attack-surface.md` - exported components, deep links, providers, WebViews, IPC and prioritized entry points.
- `findings/secrets.md` - triaged credentials/keys/tokens/certificates without unnecessarily copying raw values.
- `findings/findings.md` - concise evidence-backed security findings and candidate findings.
- `findings/coverage.md` - what was reviewed, which installed tools were used or intentionally skipped, why they were skipped, secret-scan coverage, and degraded coverage such as JADX errors.
- `findings/research.md` - compact index of narrow public-research questions, local-first status, research status, effect and canonical report path.
- `findings/analysis-log.md` - major decisions and concise delegation provenance, including layer, result path and observed peak concurrency; do not duplicate full finding prose.

Detailed non-research subagent work belongs under `reports/subagents/`.
Each public-research question gets one detail file under `reports/research/`.
Raw tool logs and deterministic secret candidates belong under `reports/tool-output/`.

At the end, produce a human-readable consolidated report at:

- `reports/STATIC_SECURITY_REPORT.md`

The consolidated report is derived from the structured `findings/` files. It does NOT replace them. It should include analysis limitations, validation status, material research-backed changes, hard-coded-secret coverage, and a short Tools/Coverage summary.
