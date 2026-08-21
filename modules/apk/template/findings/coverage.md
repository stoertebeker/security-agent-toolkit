# APK Analysis Coverage

Record what was actually reviewed, what was intentionally skipped, and where coverage is degraded. Do not list tools as used merely because they are installed.

## Preparation and static artifacts

| Tool/artifact | Status | Security use / limitation |
|---|---|---|
| AAPT/AAPT2 | | |
| apksigner | | |
| JADX | | |
| Apktool/Smali | | |
| deterministic secret candidate scan | | `reports/tool-output/secret-candidates.*` |
| strict secret grouping/filter | | `reports/tool-output/secret-groups.*` |
| deterministic native baseline | | `reports/tool-output/native-baseline.*`; base + split `.so` coverage |

## Secret/material coverage

- Raw candidate scan completed:
- Files scanned / skipped:
- Candidate cap reached:
- Post-format-filter count:
- Semantic groups:
- AI plausibility groups reviewed:
- `apk-secret-hunter` triage completed:
- Confirmed confidential/privileged material:
- Client signing / client SDK auth material requiring semantics validation:
- Public client configuration intentionally not promoted:
- Encoding/hash/KDF conclusions:
- Secret-review limitations:

## Native coverage

- Native baseline completed:
- Base `.so` count:
- Split/ABI `.so` count:
- JNI-export libraries:
- Native secret-string leads:
- Libraries selected for deeper `apk-native-reverser` review:
- Libraries baseline-only and why:
- Ghidra used/skipped and why:
- Native-review limitations:

## Dynamic runtime coverage

- Dynamic enabled:
- Capability probe result: KVM / software / unavailable
- Host environment: bare metal / VM / container and detected type
- `/dev/kvm` / emulator acceleration result:
- Emulator system image: API / tag / ABI
- App package ABI compatibility:
- Root requested / actually available:
- APK/XAPK installation result:
- Launch/UI path exercised:
- Network PCAP captured / parsed:
- Logcat captured:
- App-data/process-state comparison available:
- Frida allowed / actually used:
- Active validation allowed / actions actually performed:
- Static hypotheses exercised at runtime:
- Credential/login/features not exercised:
- Emulator-specific limitations (software speed, missing Google services, image mismatch, root/Frida):

Do not record runtime behavior as absent merely because it was not observed. State whether the relevant feature was actually exercised.

## Security-area coverage

| Area | Reviewed | Result / limitation |
|---|---|---|
| Manifest/exported components | | |
| Deep links/intents | | |
| Authentication/authorization | | |
| Providers/IPC/PendingIntent | | |
| TLS/network security | | |
| WebView | | |
| Storage/FileProvider | | |
| Hard-coded secrets/credentials/material | | |
| Native/JNI/dynamic loading | | Distinguish baseline, deep review and runtime load observation. |
| Third-party SDK/dependencies | | |

## Public research coverage

- Local-first questions resolved without web:
- Questions sent to public research:
- Local-facts packets supplied:
- Canonical RQ report paths:
- Primary sources actually fetched/read:
- Source-lead-only conclusions:
- Research-driven finding changes:

## Explicit exclusions / follow-up

List server-side/partner/runtime/UI questions this run did not establish, including dynamic features that could not be exercised.
