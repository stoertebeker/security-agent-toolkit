# Android Application Analysis Workspace

## Scope and workspace rules

- Analyze only the authorized Android package configured in `target/TARGET.toml` and only when `engagement.authorized=true`.
- Keep all analysis artifacts inside this workspace. Do not use `/tmp`, `/var/tmp` or `/dev/shm` for analysis artifacts.
- Static analysis is always available. Dynamic analysis, when enabled, uses only the toolkit-managed Android Emulator; no external Android device is required or assumed.
- Read `[orchestration].max_parallel_agents` from TARGET.toml and never exceed that many concurrently executing delegated tasks; default to 2 when absent.
- Important High/Critical candidate findings require independent validation.
- Public web access is reserved for bounded research workers; normal analysis agents must not browse directly.

## Input handling

- `tools/apk_prepare.py` accepts a normal `.apk` or supported package container such as `.xapk`.
- When preparation produces a base APK plus splits, treat them together as one application. The base manifest is the primary component/permission surface; splits may contribute DEX code, resources and native libraries.
- XAPK containers are safely extracted by preparation; never pass an untrusted container directly to JADX. Read `reports/tool-output/xapk-inventory.json` when present and record split/OBB coverage honestly.
- ZIP-compatible OBB data may be safely expanded for static inspection; opaque/non-ZIP OBB files remain inventory-only unless separately reviewed.

## Evidence rules

A suspicious string, dangerous API, exported component, scanner hit, secret-pattern hit, native hardening indicator, runtime hook event, hash-format guess, obfuscated name, or decompiler artifact is only a lead.
Where applicable establish attacker-controlled source -> processing/validation -> security-sensitive sink -> reachability -> impact.
Distinguish CONFIRMED, LIKELY, NEEDS VALIDATION and FALSE POSITIVE.
If JADX output is incomplete or suspicious, verify the relevant path against Apktool/Smali before relying on it.

## Behavior and concealment contract

- Record evidence-backed unusual or high-impact application capabilities in `findings/attack-surface.md`, even when they are not vulnerabilities by themselves.
- Record concrete concealment or analysis-resistance indicators separately from ordinary build obfuscation/minification.
- Ordinary R8/ProGuard/minification, generated identifiers, compressed assets, stripped vendor libraries and normal framework reflection do not establish malicious intent.
- Use `NONE_ESTABLISHED`, `ORDINARY_BUILD_OBFUSCATION_ONLY`, `SUSPICIOUS_CONCEALMENT_INDICATORS`, or `CONFIRMED_ANTI_ANALYSIS_BEHAVIOR` and support the latter two with concrete app-specific evidence.

## Secret/material contract

- Deterministic scanning may produce `secret-candidates.*`, but language-model triage is strictly GROUP-FIRST.
- ALWAYS run/refresh `tools/apk_secret_group.py` before AI triage.
- The LLM workflow must use `reports/tool-output/secret-groups.json`; do not load or iterate the raw candidate array.
- Distinguish actual confidential/privileged credentials from `EXPOSED_CLIENT_SIGNING_MATERIAL`, `CLIENT_SDK_AUTH_MATERIAL`, public client configuration, runtime credentials, reversible encodings, hashes/KDFs, identifiers/checksums, certificates/trust anchors, tests and false positives.
- A symbol named `secret`, `APPSECRET`, `clientSecret`, `key` or `token` does not by itself establish confidentiality or backend/provider privilege.
- When `secrets.store_plaintext=true`, exact matched/decoded values may be retained only under `reports/sensitive/`. Keep them out of ordinary findings, dynamic instrumentation output, consolidated reports and public research.
- Encoding is not hashing. Bare digest length alone does not identify a unique algorithm. Hashcat mode hints are operator aids only; the APK workflow does not crack hashes.

## Native baseline contract

- Refresh `tools/apk_native_baseline.py` when native baseline artifacts are missing or stale.
- The baseline recursively covers `.so` files under `extracted/apktool/`, including split/ABI trees, and records ELF/hardening/JNI/import plus redacted native secret-string leads.
- Baseline indicators are triage leads, not vulnerabilities.
- Use `apk-native-reverser` and Ghidra only for app-relevant/JNI/reachable or otherwise plausible security-sensitive native paths. Do not reverse every dependency merely for coverage.

## Dynamic-analysis contract

- Dynamic analysis is controlled by `[dynamic]` in TARGET.toml and is toolkit-contained. Do not require an external device.
- `tools/apk_dynamic.py probe` is the mandatory first step. It detects host architecture, bare-metal/VM/container/LXC environment, CPU virtualization flags, `/dev/kvm` presence/access and `emulator -accel-check`.
- CPU `vmx`/`svm` flags alone do not prove KVM is usable. Only the emulator's own acceleration check may establish KVM mode.
- For LXC/container without `/dev/kvm`, record that the host must pass the device through for acceleration. Do not alter the host from the workspace.
- For a VM without `/dev/kvm`, record likely missing nested virtualization. Do not alter the hypervisor from the workspace.
- Software emulation is allowed only when `dynamic.allow_software_emulation=true`; state its performance limitation explicitly.
- Select an Android system-image ABI compatible with the prepared package/native splits. ARM64-only app native code on an x86_64 host normally requires software CPU emulation.
- Managed Android SDK/emulator/system images live under `$SAT_HOME/android-sdk`; AVD/user/runtime state lives under project-local `work/android/`.
- Prefer rootable AOSP/default images. Verify root after boot with `adb root`; never assume it from image naming.
- PCAP, logcat, UI dumps, screenshots, app/process state and Frida output belong under `reports/dynamic/`.
- Run `tools/apk_dynamic_evidence.py` before agent interpretation.
- Use `apk-dynamic-analyst` for runtime correlation with existing static hypotheses.
- Runtime absence is not proof of absence unless the relevant feature was actually exercised.
- Emulator incompatibility, missing Google services, software-emulation slowness, missing root/Frida and unexercised login/features are coverage limitations rather than target findings.

### Frida

- Frida injected mode is allowed only when `dynamic.allow_frida=true` and the managed emulator actually provides root.
- Use a matching managed `frida-server`; do not repackage the target with Frida Gadget in this v1 workflow.
- Keep Frida evidence redacted: URL without query, key names/value lengths, bridge/library names. Never log passwords, tokens, request bodies or raw sensitive values into ordinary dynamic artifacts.

### Active runtime validation

- Only when `dynamic.allow_active_validation=true` may the workflow invoke exported components/deep links or perform bounded emulator-local UI actions derived from existing static hypotheses.
- Do not broad-fuzz components.
- Do not craft, replay, mutate or automate backend/provider API requests under this gate. Backend/API testing remains a separate scope/module concern.

## Research efficiency contract

- Local first: use existing Java/Smali/XML/resources, metadata, hashes, deterministic secret/native outputs, dynamic evidence when available and local parsing before asking the web.
- Every delegated research question MUST include 2-5 concrete non-sensitive `Local facts`, why the question matters, and the exact `External fact needed`.
- Web workers should do one focused discovery search, then fetch/read the strongest primary source before broadening search.
- Search snippets alone remain `SOURCE_LEAD_ONLY` and cannot change findings.

## Durable reporting contract

The primary agent MUST maintain:
- `findings/inventory.md`
- `findings/attack-surface.md`
- `findings/secrets.md`
- `findings/findings.md`
- `findings/dynamic.md`
- `findings/coverage.md`
- `findings/research.md`
- `findings/analysis-log.md`

Detailed non-research work belongs under `reports/subagents/`. Runtime evidence belongs under `reports/dynamic/`. Each RQ gets one detail file under `reports/research/`. Raw retained credentials/decoded/hash operator material belongs only under `reports/sensitive/` when explicitly enabled.

At the end produce `reports/STATIC_SECURITY_REPORT.md`, derived from the structured findings. Near the top it must contain a compact `## Analyst summary` stating whether any Critical/High finding was independently confirmed, highest supported severity, up to three most important risks, unusual behavior found or none, concealment/analysis-resistance state, and the most important remaining limitation.

When dynamic analysis ran, also create `reports/DYNAMIC_SECURITY_REPORT.md` and incorporate validated runtime changes into the analyst summary without treating unobserved behavior as proof of absence.

The final OpenCode response must repeat the same compact analyst summary.
