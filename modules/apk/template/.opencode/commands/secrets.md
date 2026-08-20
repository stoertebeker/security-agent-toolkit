---
description: Run or refresh deterministic hard-coded secret and credential triage
agent: apk-security
---
Review hard-coded secret/credential coverage for the authorized APK without repeating broad static analysis or public research.

1. If `reports/tool-output/secret-candidates.json` is missing or older than the current extracted JADX/Apktool artifacts, run:
   `python3 tools/apk_secret_scan.py`
2. Delegate candidate triage to `apk-secret-hunter`.
3. Inspect only the local source/resource locations needed to validate material candidates and their usage.
4. Update `findings/secrets.md` with classification counts and security-relevant candidates without copying full credentials.
5. Update `findings/coverage.md` with deterministic scan/triage coverage and degradation.
6. Promote something into `findings/findings.md` only when local evidence establishes that hard-coded material is genuinely secret/credential/private material with a realistic security impact. Public client configuration, identifiers, certificates/trust anchors and test data are not findings merely because they matched a pattern.
7. Update `reports/STATIC_SECURITY_REPORT.md` only if the secret review changes a material security conclusion or the coverage summary.
8. Record one concise `primary->apk-secret-hunter` provenance entry in `findings/analysis-log.md`.

Do not browse the web, perform dynamic testing, or repeat APK preparation/decompilation unless the extracted artifacts required by the scanner are absent.
