# XAPK analysis

The APK module accepts both normal `.apk` files and `.xapk` containers through the same `target/TARGET.toml` setting:

```toml
[apk]
path = "input/app.xapk"
```

## What XAPK is

XAPK is a third-party distribution container rather than an Android platform package format. It is normally a ZIP archive containing some combination of:

- one base APK;
- split APKs for ABI, language, display density, or dynamic features;
- optional OBB expansion data;
- `manifest.json` describing the package and its split APKs.

Android split APKs collectively form one installed application. The base APK normally contains the complete application component/permission manifest, while feature/config splits may add code, resources, or native libraries.

## Security handling

Do not pass the original XAPK directly to JADX. `tools/apk_prepare.py` performs its own bounded extraction first and rejects:

- absolute archive paths;
- `..` path traversal;
- symlink archive members;
- excessive entry counts;
- excessive total uncompressed size.

The preparation step then:

1. reads `manifest.json` when present;
2. identifies the base APK (`split_apks[].id == "base"` when available, with conservative fallbacks);
3. inventories all split APKs and OBB files;
4. hashes the XAPK, base APK, splits, and OBB files;
5. verifies base/split APK signatures and records metadata;
6. passes the extracted APK files, not the XAPK container, to JADX;
7. decodes the base and split APKs with Apktool;
8. safely expands ZIP-compatible OBB files for static inspection;
9. runs deterministic secret/material scanning across the prepared output.

Relevant outputs include:

```text
reports/tool-output/xapk.sha256
reports/tool-output/xapk-inventory.json
reports/tool-output/xapk-inventory.txt
reports/tool-output/xapk-split-*-apksigner.txt
reports/tool-output/xapk-split-*-aapt.txt
reports/tool-output/xapk-split-*-apktool.txt
extracted/xapk/
extracted/apktool/splits/
extracted/apktool/xapk-obb/
```

## Native split coverage

ABI/configuration splits often contain the native `.so` libraries even when the base APK does not. The normal analysis flow therefore refreshes:

```text
reports/tool-output/native-baseline.json
reports/tool-output/native-baseline.txt
```

via `tools/apk_native_baseline.py`. The tool recursively scans `extracted/apktool/`, so decoded ABI/split libraries are included automatically. It records architecture, selected ELF hardening properties, JNI exports, dangerous-import leads and redacted native secret-string leads.

This is baseline coverage, not full native reverse engineering. `apk-native-reverser`/Ghidra should be used only for app-relevant, reachable or otherwise security-interesting libraries. Reports must distinguish baseline-only libraries from those that received deeper review.

## OBB limitation

OBB expansion files are not guaranteed to be ZIP archives. ZIP-compatible OBBs are safely unpacked under `extracted/apktool/xapk-obb/` so normal local searches can inspect them. Opaque/non-ZIP OBB files are hashed and inventoried but are not automatically decoded. The final coverage/report must state this limitation rather than claiming full OBB coverage.

## Reporting expectations

When `xapk-inventory.json` exists, the primary agent should record:

- base APK and split inventory;
- signing consistency or mismatch observations;
- which splits were decoded successfully;
- native baseline counts including ABI/split placement;
- which native libraries, if any, received deeper reversing;
- OBB inventory and decode limitations;
- any degraded JADX/Apktool coverage.

Security findings still require evidence from the combined application, not merely the presence of a split or XAPK metadata.
