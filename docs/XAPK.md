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
5. verifies base/split APK signatures and records AAPT metadata;
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

## OBB limitation

OBB expansion files are not guaranteed to be ZIP archives. ZIP-compatible OBBs are safely unpacked under `extracted/apktool/xapk-obb/` so normal local searches and secret/material scans can inspect them. Opaque/non-ZIP OBB files are hashed and inventoried but are not automatically decoded. The final coverage/report must state this limitation rather than claiming full OBB coverage.

## Reporting expectations

When `xapk-inventory.json` exists, the primary agent should record:

- base APK and split inventory;
- signing consistency or mismatch observations;
- which splits were decoded successfully;
- OBB inventory and decode limitations;
- any degraded JADX/Apktool coverage.

Security findings still require evidence from the combined application, not merely the presence of a split or XAPK metadata.
