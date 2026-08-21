# XAPK analysis

The APK module accepts normal `.apk` files and `.xapk` containers through the same target setting:

```toml
[apk]
path = "input/app.xapk"
```

## What XAPK is

XAPK is a third-party distribution container, normally a ZIP archive containing one base APK, configuration/feature split APKs, optional OBB data and `manifest.json`. Android installs the base/splits as one application; splits can add code, resources and native libraries.

## Safe static handling

Do not pass the original XAPK directly to JADX. `tools/apk_prepare.py` performs bounded extraction and rejects absolute/traversal/symlink members and excessive archive sizes/counts.

Preparation then:

1. parses `manifest.json` when present;
2. identifies the base APK conservatively;
3. inventories/hashes base, splits and OBBs;
4. checks signatures/metadata;
5. passes only extracted APK files to JADX;
6. decodes base and splits with Apktool;
7. safely expands ZIP-compatible OBBs;
8. runs deterministic secret/material scanning.

Key outputs:

```text
reports/tool-output/xapk-inventory.{json,txt}
reports/tool-output/xapk-split-*-apksigner.txt
reports/tool-output/xapk-split-*-aapt.txt
reports/tool-output/xapk-split-*-apktool.txt
extracted/xapk/
extracted/apktool/splits/
extracted/apktool/xapk-obb/
```

## Native split coverage

ABI splits often contain all native `.so` libraries while the base APK contains none. `tools/apk_native_baseline.py` recursively scans the full decoded tree, including split libraries, and records ABI/ELF/JNI/import/redacted string leads. This is baseline coverage; deeper reversing/Ghidra remains selective.

## Dynamic installation

The toolkit-managed dynamic runtime never installs the original XAPK container directly. `tools/apk_dynamic.py install` reads the prepared `xapk-inventory.json` and installs the extracted base APK plus every recorded split APK together with:

```text
adb install-multiple
```

Before installation, dynamic setup selects and boots a compatible emulator runtime and compares the device's actual ABI list against prepared package native ABIs. For ARM-only native splits on an x86_64 host, the documented Android-11/API-30 x86_64 multi-ABI fallback may be used when `minSdk <= 30`; otherwise dynamic v1 reports the package/runtime combination unavailable.

The base/split hashes and prepared inventory therefore remain the common identity boundary between static and dynamic phases.

## OBB limitation

ZIP-compatible OBBs are safely unpacked for static inspection. Opaque/non-ZIP OBB files remain hashed/inventoried. Dynamic v1 does not automatically place arbitrary OBB expansion content into emulator storage; this must be recorded as a runtime coverage limitation if the app depends on OBB data.

## Reporting expectations

When `xapk-inventory.json` exists, record base/split inventory, signing consistency, decode status, native split placement, deeper native review, dynamic base+split installation result, emulator ABI compatibility, OBB limitations and any degraded JADX/Apktool/runtime coverage.

Findings require evidence from the combined application, not merely the presence of a split or XAPK metadata.
