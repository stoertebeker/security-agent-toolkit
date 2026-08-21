# Android Application Analysis Workspace

## Scope and workspace rules

- Analyze only the authorized Android package configured in `target/TARGET.toml` and only when `engagement.authorized=true`.
- Keep all analysis artifacts inside this workspace. Do not use `/tmp`, `/var/tmp` or `/dev/shm` for analysis artifacts.
- Static analysis is primary. ADB/Frida testing may target an external authorized device only when explicitly enabled in `TARGET.toml`.
- Read `[orchestration].max_parallel_agents` from TARGET.toml and never exceed that many concurrently executing delegated tasks; default to 2 when absent.
- Important High/Critical candidate findings require independent validation.
- Public web access is reserved for bounded research workers; normal analysis agents must not browse directly.

## Input handling

- `tools/apk_prepare.py` accepts a normal `.apk` or supported package container such as `.xapk`.
- When preparation produces a base APK plus splits, treat them together as one application. The base manifest is the primary component/permission surface; splits may contribute DEX code, resources and native libraries.
- XAPK containers are safely extracted by preparation; never pass an untrusted container directly to JADX. Read `reports/tool-output/xapk-inventory.json` when present and record split/OBB coverage honestly.
- ZIP-compatible OBB data may be safely expanded for static inspection; opaque/non-ZIP OBB files remain inventory-only unless separately reviewed.

## Evidence rules

A suspicious string, dangerous API, exported component, scanner hit, secret-pattern hit, native hardening indicator, hash-format guess, obfuscated name, or decompiler artifact is only a lead.
Where applicable establish attacker-controlled source -> processing/validation -> security-sensitive sink -> reachability -> impact.
Distinguish CONFIRMED, LIKELY, NEEDS VALIDATION and FALSE POSITIVE.
If JADX output is incomplete or suspicious, verify the relevant path against Apktool/Smali before relying on it.

## Behavior and concealment contract

- Record evidence-backed unusual or high-impact application capabilities in `findings/attack-surface.md`, even when they are not vulnerabilities by themselves.
- Record any concrete concealment or analysis-resistance indicators separately from ordinary build obfuscation/minification.
- Ordinary R8/ProGuard/minification, generated identifiers, compressed assets, stripped vendor libraries and normal framework reflection do not establish malicious intent.
- Use the attack-surface state `NONE_ESTABLISHED`, `ORDINARY_BUILD_OBFUSCATION_ONLY`, `SUSPICIOUS_CONCEALMENT_INDICATORS`, or `CONFIRMED_ANTI_ANALYSIS_BEHAVIOR` and support the latter two with concrete app-specific evidence.
- The final analyst summary must say whether unusual behavior or meaningful concealment/analysis-resistance was established.

## Secret/material contract

- Deterministic scanning may produce `secret-candidates.*`, but language-model triage is strictly GROUP-FIRST.
- ALWAYS run/refresh `tools/apk_secret_group.py` before AI triage.
- The LLM workflow must use `reports/tool-output/secret-groups.json`; do not load or iterate the raw candidate array.
- Repeated values, invalid crypt-prefix noise, dependency-only hits and localized Android resources are reduced deterministically before AI plausibility review.
- Distinguish actual confidential/privileged credentials from `EXPOSED_CLIENT_SIGNING_MATERIAL`, `CLIENT_SDK_AUTH_MATERIAL`, public client configuration, runtime credentials, reversible encodings, hashes/KDFs, identifiers/checksums, certificates/trust anchors, tests and false positives.
- A symbol named `secret`, `APPSECRET`, `clientSecret`, `key` or `token` does not by itself establish confidentiality or backend/provider privilege.
- When `secrets.store_plaintext=true`, exact matched/decoded values may be retained only under `reports/sensitive/`. Keep them out of ordinary findings, consolidated reports and public research.
- Encoding is not hashing. Bare digest length alone does not identify a unique algorithm. Hashcat mode hints are operator aids only; the APK workflow does not crack hashes.

## Native baseline contract

- Refresh `tools/apk_native_baseline.py` when native baseline artifacts are missing or stale.
- The baseline recursively covers `.so` files under `extracted/apktool/`, including split/ABI trees, and records ELF/hardening/JNI/import plus redacted native secret-string leads.
- Baseline indicators are triage leads, not vulnerabilities.
- Use `apk-native-reverser` and Ghidra only for app-relevant/JNI/reachable or otherwise plausible security-sensitive native paths. Do not reverse every dependency merely for coverage.
- `findings/coverage.md` must distinguish deterministic native-baseline coverage from deeper native reverse engineering.

## Research efficiency contract

- Local first: use existing Java/Smali/XML/resources, metadata, hashes, deterministic secret/native outputs and local parsing before asking the web.
- Every delegated research question MUST include 2-5 concrete non-sensitive `Local facts`, why the question matters, and the exact `External fact needed`.
- If the local-facts packet is incomplete, do not browse; return it for local clarification.
- Web workers should do one focused discovery search, then fetch/read the strongest primary source before broadening search. If that fetch fails, try at most one alternate primary page before another search.
- Each research question has exactly one canonical detail artifact under `reports/research/RQ-XX-....md`.
- `findings/research.md` is only a compact index; do not duplicate source tables or long analysis there.
- A decisive external fact should be supported by an actually fetched/read primary source when reasonably available. Search snippets alone remain `SOURCE_LEAD_ONLY` and cannot change findings.
- Perform cheap deterministic local correlation enabled by research before leaving a question unresolved.
- Prefer one consolidated validator pass for material research-driven finding changes when appropriate.

## Durable reporting contract

The primary agent MUST maintain:
- `findings/inventory.md` - package/version/signing/SDK/component/library/native and split/OBB inventory where applicable.
- `findings/attack-surface.md` - exported components, deep links, providers, WebViews, IPC, prioritized entry points, unusual behavior and concealment/analysis-resistance state.
- `findings/secrets.md` - grouped credential/material classification without raw sensitive values.
- `findings/findings.md` - concise evidence-backed security findings/candidates.
- `findings/coverage.md` - actual/skipped tooling, grouped secret coverage, native baseline vs deep review, split/container coverage and degraded coverage.
- `findings/research.md` - compact index of research questions/status/effect/canonical report path.
- `findings/analysis-log.md` - major decisions and concise delegation provenance including result path and observed peak concurrency.

Detailed non-research work belongs under `reports/subagents/`. Each RQ gets one detail file under `reports/research/`. Raw logs/redacted deterministic outputs belong under `reports/tool-output/`. Raw retained credentials/decoded/hash operator material belongs only under `reports/sensitive/` when explicitly enabled.

At the end produce `reports/STATIC_SECURITY_REPORT.md`, derived from the structured findings. Near the top it must contain a compact `## Analyst summary` that states: whether any Critical/High finding was independently confirmed, the highest supported severity, up to three most important risks, unusual behavior found or none, concealment/analysis-resistance state with evidence, and the single most important remaining limitation. Keep it short and do not duplicate the full findings section.

The final OpenCode response to the operator must repeat the same compact analyst summary.
