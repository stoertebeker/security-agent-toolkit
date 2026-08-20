---
description: Run or refresh deterministic hard-coded secret, encoding, hash/KDF and AI plausibility triage
agent: apk-security
---
Review hard-coded credential/secret/material coverage for the authorized APK without repeating broad static analysis or public research.

1. Read `[secrets]` and `[orchestration]` from `target/TARGET.toml`.
2. If `reports/tool-output/secret-candidates.json` is missing or older than the current extracted JADX/Apktool artifacts, run:
   `python3 tools/apk_secret_scan.py`
3. Build/refresh grouped unique values with:
   `python3 tools/apk_secret_group.py`
   Grouping prevents repeated occurrences of the same value from consuming separate AI reviews.
4. If `secrets.store_plaintext=true`, confirm sensitive outputs exist under `reports/sensitive/` and keep exact values confined there.
5. Delegate grouped plausibility triage to `apk-secret-hunter`. If `secrets.ai_plausibility_triage=true`, it must review every unique group in bounded `apk-secret-review-worker` batches, honoring `ai_triage_batch_size`, `ai_representative_locations`, and `orchestration.max_parallel_agents`.
6. Require AI plausibility HIGH/MEDIUM/LOW, final classification, confidence, concise local evidence and follow-up for every unique group. LOW groups may be summarized by category after classification but must not be silently dropped.
7. Distinguish plaintext/direct values, reversible encodings, structured hash/KDF formats, ambiguous bare digests, public client configuration, certificates/fingerprints/checksums, test data and false positives.
8. Update `findings/secrets.md` with raw-hit count, unique-group count, plausibility/classification counts, and security-relevant candidates without copying full credentials. Reference sensitive local artifacts by path when plaintext retention is enabled.
9. Update `findings/coverage.md` with deterministic scan, grouping, AI plausibility coverage, encoding/hash analysis and any degradation/unreviewed groups.
10. Promote something into `findings/findings.md` only when local evidence establishes that hard-coded material is genuinely secret/credential/private material with realistic security impact. A hash/digest/encoding is not a vulnerability by itself.
11. Update `reports/STATIC_SECURITY_REPORT.md` only if the review changes a material security conclusion or coverage summary.
12. Record concise provenance including `primary->apk-secret-hunter`, number of nested plausibility batches, and observed peak concurrency in `findings/analysis-log.md`.

Hashcat mode suggestions are operator hints only. Do not run password/hash cracking in this workflow. Bare 32/40/64/128-hex values must remain ambiguous unless code/context identifies the algorithm.

Do not browse the web, perform dynamic testing, or repeat APK preparation/decompilation unless the extracted artifacts required by the scanner are absent.
