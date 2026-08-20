---
description: Run or refresh deterministic hard-coded secret, encoding and hash/KDF triage
agent: apk-security
---
Review hard-coded credential/secret/material coverage for the authorized APK without repeating broad static analysis or public research.

1. Read `[secrets]` from `target/TARGET.toml`.
2. If `reports/tool-output/secret-candidates.json` is missing or older than the current extracted JADX/Apktool artifacts, run:
   `python3 tools/apk_secret_scan.py`
3. If `secrets.store_plaintext=true`, confirm the sensitive outputs exist under `reports/sensitive/` and keep exact values confined there.
4. Delegate candidate triage to `apk-secret-hunter`.
5. Inspect only the local source/resource locations needed to validate material candidates and their usage.
6. Distinguish plaintext/direct values, reversible encodings, structured hash/KDF formats, ambiguous bare digests, public client configuration, certificates/fingerprints/checksums, test data and false positives.
7. Update `findings/secrets.md` with classification counts and security-relevant candidates without copying full credentials. Reference sensitive local artifacts by path when plaintext retention is enabled.
8. Update `findings/coverage.md` with deterministic scan, encoding/hash analysis and triage coverage/degradation.
9. Promote something into `findings/findings.md` only when local evidence establishes that hard-coded material is genuinely secret/credential/private material with realistic security impact. A hash/digest/encoding is not a vulnerability by itself.
10. Update `reports/STATIC_SECURITY_REPORT.md` only if the review changes a material security conclusion or coverage summary.
11. Record one concise `primary->apk-secret-hunter` provenance entry in `findings/analysis-log.md`.

Hashcat mode suggestions are operator hints only. Do not run password/hash cracking in this workflow. Bare 32/40/64/128-hex values must remain ambiguous unless code/context identifies the algorithm.

Do not browse the web, perform dynamic testing, or repeat APK preparation/decompilation unless the extracted artifacts required by the scanner are absent.
