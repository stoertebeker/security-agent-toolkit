---
description: Run or refresh deterministic hard-coded secret, encoding, hash/KDF and AI plausibility triage
agent: apk-security
---
Review hard-coded credential/secret/material coverage for the authorized Android application without repeating broad static analysis or public research.

1. Read `[secrets]` and `[orchestration]` from `target/TARGET.toml`.
2. If `reports/tool-output/secret-candidates.json` is missing or older than current extracted artifacts, run `python3 tools/apk_secret_scan.py`.
3. ALWAYS build/refresh semantic groups with `python3 tools/apk_secret_group.py` before AI triage.
4. From this point onward, the LLM workflow must use `reports/tool-output/secret-groups.json` as the scanner-derived input. Do not load or iterate the raw `secret-candidates.json` candidate array. Raw candidates exist only for deterministic preprocessing and protected operator evidence.
5. If `secrets.store_plaintext=true`, keep exact values confined to `reports/sensitive/`; inspect a raw value only for a specific group when classification genuinely requires it.
6. Delegate grouped plausibility triage to `apk-secret-hunter`. If `secrets.ai_plausibility_triage=true`, it must review every semantic group in bounded `apk-secret-review-worker` batches, honoring `ai_triage_batch_size`, `ai_representative_locations`, and `orchestration.max_parallel_agents`.
7. Require AI plausibility HIGH/MEDIUM/LOW, final classification, confidence, concise local evidence and follow-up for every semantic group. LOW groups may be summarized by category after classification but must not be silently dropped.
8. Distinguish confirmed confidential/privileged credentials from `EXPOSED_CLIENT_SIGNING_MATERIAL`, `CLIENT_SDK_AUTH_MATERIAL`, public client configuration, plaintext/runtime credentials, reversible encodings, structured hash/KDF formats, ambiguous bare digests, certificates/fingerprints/checksums, test data and false positives. A field named `secret` is not automatically a confirmed secret.
9. Update `findings/secrets.md` with raw-hit count, post-format-filter count, semantic-group count, plausibility/classification counts, and security-relevant groups without copying full credentials.
10. Update `findings/coverage.md` with deterministic scan, strict filtering/grouping, AI plausibility coverage, encoding/hash analysis and any degradation/unreviewed groups.
11. Promote something into `findings/findings.md` only when evidence establishes realistic security impact. Client-shipped signing/SDK-auth material may still warrant a finding, but do not describe it as a confidential backend credential unless confidentiality/privilege semantics are established.
12. Update `reports/STATIC_SECURITY_REPORT.md` only if the review changes a material security conclusion or coverage summary.
13. Record concise provenance including `primary->apk-secret-hunter`, number of nested plausibility batches, and observed peak concurrency in `findings/analysis-log.md`.

Hashcat mode suggestions are operator hints only. Do not run password/hash cracking. Bare digest lengths remain ambiguous unless implementation context identifies the algorithm.

Do not browse the web, perform dynamic testing, or repeat decompilation unless required prepared artifacts are absent.
