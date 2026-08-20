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
| Native/JNI/dynamic loading | | Distinguish baseline from deep review. |
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

List dynamic/server-side/partner/runtime questions that this run did not establish.
