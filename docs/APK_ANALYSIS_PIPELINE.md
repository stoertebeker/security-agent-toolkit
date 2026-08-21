# APK analysis pipeline

The APK module supports normal APK inputs and supported package containers prepared into one logical Android application.

## Secret/material pipeline

Raw scanner candidates are not LLM input:

```text
secret-candidates.json
        -> apk_secret_group.py
        -> secret-groups.json
        -> apk-secret-hunter
        -> bounded apk-secret-review-worker batches
```

Every semantic group receives plausibility, classification and confidence. Client-shipped values are not automatically confidential credentials because a field is named `secret`, `APPSECRET` or `clientSecret`.

## Native pipeline

`python3 tools/apk_native_baseline.py` recursively covers `.so` files under `extracted/apktool/`, including decoded split/ABI trees. Deeper `apk-native-reverser`/Ghidra work is reserved for app-relevant, reachable or otherwise security-interesting libraries. `/native` refreshes this path without repeating the whole assessment.

## Dynamic pipeline

Dynamic analysis uses only the toolkit-managed Android Emulator. There is no external-device path in the v1 workflow.

Install the optional runtime once:

```bash
./toolkit install apk --with-optional
```

The managed Android SDK/emulator lives under `$SAT_HOME/android-sdk`. Android system images are downloaded on demand. Project AVD state remains under `work/android/`.

### Capability gate

Every dynamic run starts with:

```text
python3 tools/apk_dynamic.py probe
```

The probe records:
- Linux host architecture;
- bare-metal, VM, LXC/container virtualization type;
- CPU `vmx`/`svm` flags;
- `/dev/kvm` presence and read/write access;
- `emulator -accel-check` result;
- prepared APK/XAPK native ABIs;
- selected emulator image ABI;
- selected `kvm`, `software`, or unavailable mode.

CPU virtualization flags alone are not enough. KVM mode is selected only when the Android Emulator itself reports acceleration usable.

For an LXC/container without `/dev/kvm`, the toolkit reports that the host must pass the KVM device through. It does not modify the host. For a VM without `/dev/kvm`, it reports likely missing nested virtualization. If `allow_software_emulation=true`, software CPU emulation remains a fallback, including cross-architecture ARM64 app images on an x86_64 host, but can be dramatically slower.

### Emulator setup and collection

`/dynamic-setup` performs the probe and creates a compatible AVD. Rootable AOSP/default images are preferred; root is verified after boot rather than assumed.

`/dynamic` runs:

```text
probe -> setup -> boot -> install APK/splits -> launch/observe
      -> optional Frida -> collect PCAP/logcat/UI/state
      -> deterministic evidence summary -> dynamic analyst -> validator if needed
```

Key artifacts:

```text
reports/tool-output/dynamic-capabilities.{json,txt}
reports/dynamic/setup.json
reports/dynamic/device-info.json
reports/dynamic/root-status.json
reports/dynamic/network.pcap
reports/dynamic/*logcat*.txt
reports/dynamic/ui.xml
reports/dynamic/states/
reports/dynamic/frida-events.txt          # only when enabled/available
reports/dynamic/evidence-summary.{json,txt}
reports/subagents/dynamic-review.md
findings/dynamic.md
reports/DYNAMIC_SECURITY_REPORT.md
```

The emulator's `-tcpdump` capture records runtime Ethernet traffic. `apk_dynamic_evidence.py` parses the capture locally with `tcpdump`, summarizes Frida event types, process mappings, app-data file deltas and selected logcat indicators before agent interpretation.

### Frida

When `dynamic.allow_frida=true`, the workflow requires a root-capable managed emulator. It downloads a `frida-server` version matching the installed Frida client and emulator ABI, deploys it to `/data/local/tmp`, and runs redacted observation hooks.

The default hooks record only metadata such as:
- WebView URL with query/fragment redacted;
- JavaScript-interface name;
- native library name;
- DexClassLoader path;
- SharedPreferences key plus value length;
- SQLite table/key names;
- intent action/component/redacted URI;
- debugger-check execution.

They intentionally do not record passwords, tokens, request bodies or raw stored values.

### Active validation boundary

`dynamic.allow_active_validation=true` allows bounded emulator-local validation of existing static hypotheses, such as invoking an exported component/deep link or navigating to an app feature. It does not authorize broad fuzzing or crafted/replayed/mutated backend/provider API requests. Those belong to a separately scoped API assessment.

Runtime absence is not proof of absence unless the relevant feature was actually exercised. Missing Google services, incompatible images, software-emulation slowness, lack of root/Frida and unexercised credential-gated features are recorded as coverage limitations.

## Behavior and concealment review

Recon, code review and dynamic evidence record unusual/high-impact behavior and concrete concealment or analysis-resistance indicators in durable state. Generated names, compressed resources, stripped vendor libraries, or ordinary framework reflection are not evidence of malicious intent by themselves.

## Public research pipeline

Research remains local-first. Every externally delegated RQ must include why it matters, 2-5 concrete non-sensitive local facts and the exact external fact still needed. Workers fetch/read a primary source before broadening search. Search snippets remain `SOURCE_LEAD_ONLY`.

## Analyst summary

Every completed assessment includes a compact `## Analyst summary` near the top of `reports/STATIC_SECURITY_REPORT.md` and repeats it in the final OpenCode response. When dynamic analysis ran, validated runtime changes are incorporated and a separate `reports/DYNAMIC_SECURITY_REPORT.md` is produced.

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
