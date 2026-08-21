# Android Application Analysis Workspace

## Scope and workspace rules

- Analyze only the authorized Android package configured in `target/TARGET.toml` and only when `engagement.authorized=true`.
- Keep all analysis artifacts inside this workspace. Do not use `/tmp`, `/var/tmp` or `/dev/shm` for analysis artifacts.
- Static analysis is always available. Dynamic analysis, when enabled, uses only the toolkit-managed Android Emulator; no external Android device is required or assumed.
- Read `[orchestration].max_parallel_agents` from TARGET.toml and never exceed that many concurrently executing delegated tasks; default to 2.
- Important High/Critical candidate findings require independent validation.
- Public web access is reserved for bounded research workers; normal analysis agents must not browse directly.

## Input handling

- `tools/apk_prepare.py` accepts normal `.apk` or supported package containers such as `.xapk`.
- Base + splits are one application. The base manifest is the primary component/permission surface; splits may contribute DEX/resources/native libraries.
- Never pass an untrusted XAPK directly to JADX. Use the preparation output and record split/OBB limitations honestly.

## Evidence and behavior rules

A suspicious string/API/exported component/scanner hit/native indicator/runtime event/hash guess/obfuscated name/decompiler artifact is only a lead. Where applicable establish source -> processing/validation -> security-sensitive sink -> reachability -> impact. Cross-check important incomplete JADX paths against Apktool/Smali.

Record evidence-backed unusual/high-impact capabilities in `findings/attack-surface.md`. Separate ordinary R8/ProGuard/minification, compressed assets, stripped vendor libraries and normal reflection from concrete concealment/anti-analysis behavior. Use `NONE_ESTABLISHED`, `ORDINARY_BUILD_OBFUSCATION_ONLY`, `SUSPICIOUS_CONCEALMENT_INDICATORS`, or `CONFIRMED_ANTI_ANALYSIS_BEHAVIOR` with evidence.

## Secret/material contract

- AI triage is strictly GROUP-FIRST: refresh `tools/apk_secret_group.py`, then use `reports/tool-output/secret-groups.json`; do not feed the raw candidate array into LLM context.
- Distinguish confidential credentials from `EXPOSED_CLIENT_SIGNING_MATERIAL`, `CLIENT_SDK_AUTH_MATERIAL`, public configuration, runtime credentials, encodings, hashes/KDFs, identifiers, certificates, tests and false positives.
- Names like `secret`, `APPSECRET`, `clientSecret`, `key` or `token` are not confidentiality proofs.
- Opted-in exact values stay under `reports/sensitive/` and out of ordinary findings, dynamic instrumentation and public research.
- No automatic cracking.

## Native baseline contract

- Refresh `tools/apk_native_baseline.py` when stale.
- It recursively covers base/split `.so` files and records ELF/hardening/JNI/import/redacted string leads.
- Baseline indicators are not vulnerabilities. Reserve deeper reversing/Ghidra for app-relevant/reachable paths.

## Dynamic-analysis contract

- Dynamic analysis is toolkit-contained and controlled by `[dynamic]`. Do not require an external device.
- `tools/apk_dynamic.py probe` is mandatory first. It detects host architecture, bare-metal/VM/container/LXC, CPU virtualization flags, `/dev/kvm` presence/access, `emulator -accel-check`, package native ABIs and runtime ABI strategy.
- CPU `vmx`/`svm` flags alone do not establish KVM. Only the emulator self-check may select KVM.
- LXC/container without `/dev/kvm`: record that host-side passthrough is needed for acceleration; do not alter the host.
- VM without `/dev/kvm`: record likely missing nested virtualization; do not alter the hypervisor.
- Same-architecture x86_64 `-accel off` is allowed only when `dynamic.allow_software_emulation=true` and must be reported as slow.
- On x86_64, use native x86_64 runtime when possible. If native code exists but no x86_64 library is supplied and `minSdk <= 30`, `allow_android11_multiabi_fallback=true` may select an Android 11/API 30 x86_64 image whose runtime supports ARMv7/ARM64 app binaries. Mark this as API-30 compatibility coverage, not target-OS coverage.
- If no documented compatible ABI path exists, report `UNAVAILABLE`; do not attempt unverified cross-architecture emulation.
- `/dynamic-setup` must include a real boot smoke test through `sys.boot_completed=1`, ABI validation and root verification.
- Managed SDK/system images live under `$SAT_HOME/android-sdk`; project AVD/user/runtime state lives under `work/android/`.
- PCAP/logcat/UI/screenshot/app/process/action/Frida evidence belongs under `reports/dynamic/`.
- Run `tools/apk_dynamic_evidence.py` before agent interpretation.
- Use `apk-dynamic-analyst` for runtime correlation with existing static hypotheses.
- Runtime absence is not proof of absence unless the relevant feature was actually exercised.
- Missing Google services, API-30 compatibility fallback, slow software emulation, missing root/Frida and unexercised login/features are coverage limitations, not target findings.

### Frida

- Frida injected mode requires `dynamic.allow_frida=true` plus actual emulator root.
- Use matching managed `frida-server`; do not repackage with Frida Gadget in dynamic v1.
- Keep hooks redacted: endpoints without query/fragment, bridge/library/crypto names, storage key/table names and value lengths. Never log passwords, tokens, request bodies or raw sensitive values.

### Active runtime validation

- Only when `dynamic.allow_active_validation=true` may bounded emulator-local actions derived from existing static hypotheses be performed.
- Use `tools/apk_dynamic_action.py` exclusively for active actions so custom schemes/components are constrained and every action is logged to `reports/dynamic/actions.jsonl`.
- Do not broad-fuzz and do not bypass the wrapper with ad-hoc active ADB commands.
- Do not craft/replay/mutate backend/provider API requests. Backend/API testing is a separate scope/module concern.

## Research efficiency contract

Use local static/dynamic evidence first. Every delegated RQ must include why it matters, 2-5 concrete non-sensitive local facts and the exact external fact needed. Workers fetch/read a strong primary source before broadening search. Search snippets alone remain `SOURCE_LEAD_ONLY`.

## Durable reporting contract

Maintain:
- `findings/inventory.md`
- `findings/attack-surface.md`
- `findings/secrets.md`
- `findings/findings.md`
- `findings/dynamic.md`
- `findings/coverage.md`
- `findings/research.md`
- `findings/analysis-log.md`

Runtime evidence belongs under `reports/dynamic/`; detailed delegated notes under `reports/subagents/`; raw sensitive values only under `reports/sensitive/` when explicitly enabled.

At completion produce `reports/STATIC_SECURITY_REPORT.md` with a compact `## Analyst summary` stating confirmed Critical/High status, highest supported severity, top risks, unusual behavior, concealment/analysis-resistance state and main limitation. When dynamic analysis runs, also create `reports/DYNAMIC_SECURITY_REPORT.md` and incorporate validated runtime changes without treating unobserved behavior as absence.

Repeat the analyst summary in the final OpenCode response.
