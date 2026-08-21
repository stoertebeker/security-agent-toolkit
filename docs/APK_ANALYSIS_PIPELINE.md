# APK analysis pipeline

The APK module supports normal APK inputs and supported package containers prepared into one logical Android application.

## Secret/material pipeline

Raw scanner candidates are not LLM input:

```text
secret-candidates.json -> apk_secret_group.py -> secret-groups.json
                       -> apk-secret-hunter -> bounded review workers
```

Every semantic group receives plausibility, classification and confidence. Client-shipped values are not automatically confidential credentials because a field is named `secret`, `APPSECRET` or `clientSecret`.

## Native pipeline

`python3 tools/apk_native_baseline.py` recursively covers `.so` files under `extracted/apktool/`, including decoded split/ABI trees. Deeper `apk-native-reverser`/Ghidra work is reserved for app-relevant, reachable or otherwise security-interesting libraries. `/native` refreshes this path without repeating the whole assessment.

## Dynamic pipeline

Dynamic analysis uses only the toolkit-managed Android Emulator. There is no external-device path in dynamic v1.

Install optional runtime extras once:

```bash
./toolkit install apk --with-optional
```

The managed Android SDK/emulator lives under `$SAT_HOME/android-sdk`; system images are downloaded on demand. Project AVD/user/runtime state remains under `work/android/`.

### Capability and ABI gate

Every dynamic run starts with:

```text
python3 tools/apk_dynamic.py probe
```

The probe records host architecture, bare-metal/VM/container type, CPU virtualization flags, `/dev/kvm` access, `emulator -accel-check`, package native ABIs, selected runtime ABI strategy and KVM/software/unavailable mode.

CPU virtualization flags alone are not enough. KVM is selected only when the emulator itself reports it usable.

LXC/container without `/dev/kvm` is reported as needing host-side KVM device passthrough for acceleration. A VM without `/dev/kvm` is reported as likely lacking nested virtualization. The toolkit does not modify either host configuration.

On x86_64:
- package with x86_64 native code: use an x86_64 system image;
- package without native code: use an x86_64 system image;
- native package without x86_64 code and `minSdk <= 30`: when `allow_android11_multiabi_fallback=true`, use an Android 11/API 30 x86_64 image whose documented runtime supports x86/x86_64/ARMv7/ARM64 app binaries;
- otherwise report dynamic runtime `UNAVAILABLE` rather than attempt an unverified cross-architecture setup.

If KVM is unavailable, same-architecture x86_64 `-accel off` is permitted only with `allow_software_emulation=true` and is reported as potentially very slow. The API-30 multi-ABI fallback is compatibility coverage, not target-OS coverage.

### Real setup test

`/dynamic-setup` performs the static capability probe, creates/downloads the AVD and then runs:

```text
python3 tools/apk_dynamic_smoke.py
```

The smoke test actually boots through `sys.boot_completed=1`, verifies device ABI compatibility/root state, and shuts down again. This catches LXC/seccomp/device/runtime constraints that CPU/KVM inspection cannot predict.

### Full dynamic collection

`/dynamic` runs:

```text
probe -> setup -> boot -> verify device ABI -> install APK/base+splits
      -> launch/observe -> optional Frida
      -> PCAP/logcat/UI/state collection
      -> deterministic evidence summary
      -> dynamic analyst -> validator if needed
```

Key artifacts:

```text
reports/tool-output/dynamic-capabilities.{json,txt}
reports/dynamic/setup.json
reports/dynamic/setup-smoke.json
reports/dynamic/device-info.json
reports/dynamic/root-status.json
reports/dynamic/abi-compatibility.json
reports/dynamic/network.pcap
reports/dynamic/*logcat*.txt
reports/dynamic/ui.xml
reports/dynamic/screenshot.png
reports/dynamic/states/
reports/dynamic/frida-events.txt
reports/dynamic/actions.jsonl
reports/dynamic/evidence-summary.{json,txt}
reports/subagents/dynamic-review.md
findings/dynamic.md
reports/DYNAMIC_SECURITY_REPORT.md
```

The emulator's `-tcpdump` capture records virtual Ethernet traffic. `apk_dynamic_evidence.py` parses it locally with `tcpdump` and also summarizes Frida event types, loaded libraries/process maps, app-data file deltas and selected logcat indicators before LLM interpretation.

### Frida

When `dynamic.allow_frida=true`, injected instrumentation requires actual root on the managed emulator. A `frida-server` matching the installed Frida client and emulator ABI is downloaded and deployed; the target APK is not repackaged.

Default redacted hooks may record:
- WebView/navigation URL without query/fragment and JavaScript-interface names;
- Java URLConnection/OkHttp method+endpoint metadata without headers/bodies;
- native library and Dex/in-memory-Dex loading;
- SharedPreferences keys/value lengths and SQLite table/key names;
- crypto algorithm/key-length metadata without key bytes;
- intent action/component/redacted URI;
- subprocess executable metadata;
- debugger-check execution.

Passwords, tokens, request bodies and raw stored values are intentionally excluded.

### Active validation boundary

`dynamic.allow_active_validation=true` permits bounded emulator-local checks derived from static hypotheses. All active actions go through `tools/apk_dynamic_action.py`, which validates declared custom schemes/components where applicable and writes redacted `reports/dynamic/actions.jsonl` provenance.

Supported actions are custom deep links, declared activity/service/receiver invocation, tap, keyevent and text input. Text input records only length.

Do not broad-fuzz and do not craft/replay/mutate backend/provider API requests under this gate. Backend/API testing is separately scoped.

Runtime absence is not proof of absence unless the relevant feature was actually exercised. Missing Google services, API-30 compatibility mode, software-emulation slowness, missing root/Frida and inaccessible login-gated features are coverage limitations.

## Behavior and concealment review

Recon, code review and dynamic evidence record unusual/high-impact behavior and concrete concealment/analysis-resistance indicators in durable state. Generated names, compressed resources, stripped vendor libraries, or ordinary framework reflection are not evidence of malicious intent by themselves.

## Public research pipeline

Research remains local-first. Every externally delegated RQ must include why it matters, 2-5 concrete non-sensitive local facts and the exact external fact still needed. Workers fetch/read a primary source before broadening search. Search snippets remain `SOURCE_LEAD_ONLY`.

## Analyst summary

Every completed assessment includes a compact `## Analyst summary` near the top of `reports/STATIC_SECURITY_REPORT.md` and repeats it in the final OpenCode response. When dynamic analysis runs, validated runtime changes are incorporated and a separate `reports/DYNAMIC_SECURITY_REPORT.md` is produced.

## Targeted commands

```text
/secrets
/native
/research
/dynamic-setup
/dynamic
/summary
```

A full new assessment starts from `START_PROMPT.txt`; when `[dynamic].enabled=true`, its validated static phase is followed by the managed dynamic phase.
