# APK Analysis Coverage

Record what was actually reviewed, what was intentionally skipped, and where coverage is degraded. Do not list tools as used merely because they are installed.

## Preparation and static artifacts

| Tool/artifact | Status | Security use / limitation |
|---|---|---|
| AAPT | | |
| apksigner | | |
| JADX | | |
| Apktool/Smali | | |
| deterministic secret candidate scan | | `reports/tool-output/secret-candidates.*` |

## Secret/credential coverage

- Candidate scan completed:
- Files scanned:
- Candidate cap reached:
- Native `.so` string scan available/used:
- `apk-secret-hunter` triage completed:
- High-confidence/private material findings:
- Public client configuration intentionally not promoted:
- Secret-review limitations:

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
| Hard-coded secrets/credentials | | |
| Native/JNI/dynamic loading | | |
| Third-party SDK/dependencies | | |

## Public research coverage

- Local-first questions resolved without web:
- Questions sent to public research:
- Canonical RQ report paths:
- Source-lead-only conclusions:
- Research-driven finding changes:

## Explicit exclusions / follow-up

List dynamic/server-side/partner/runtime questions that this run did not establish.
