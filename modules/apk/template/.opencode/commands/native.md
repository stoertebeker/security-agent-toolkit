---
description: Refresh deterministic native-library baseline and focused JNI review
agent: apk-security
---
Review native/JNI coverage for the authorized Android application without repeating broad static analysis, secret triage, public research, or dynamic testing.

1. Run `python3 tools/apk_native_baseline.py` to refresh `reports/tool-output/native-baseline.{json,txt}`. The tool recursively covers `.so` files under `extracted/apktool/`, including decoded split/ABI trees.
2. Read the baseline summary and correlate native libraries with `System.loadLibrary`, native method declarations, JNI registration/exports, and app/framework usage already present in local artifacts.
3. Treat executable-stack, TEXTREL, dangerous imports, JNI exports and native secret-string leads as triage leads only.
4. Delegate `apk-native-reverser` only for libraries that are app-relevant, reachable through meaningful JNI/native input, or otherwise have a plausible security-sensitive lead. Do not run Ghidra over every dependency merely for coverage.
5. Update `findings/inventory.md` with native counts/base-vs-split placement where useful.
6. Update `findings/coverage.md` to distinguish deterministic native baseline coverage from libraries that received deeper native reverse engineering.
7. Promote a native issue into `findings/findings.md` only when evidence establishes reachable unsafe behavior and realistic impact.
8. Update `reports/STATIC_SECURITY_REPORT.md` only if native conclusions or material coverage changed.
9. Record concise provenance and any delegated native-review result path in `findings/analysis-log.md`.

Do not browse the web, run dynamic tests, fuzz targets, or perform broad unrelated analysis.
