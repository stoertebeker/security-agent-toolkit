---
description: Research unresolved public questions from the APK review
agent: apk-security
---
Review the current structured findings and `reports/STATIC_SECURITY_REPORT.md` if it exists. Do not repeat APK preparation, broad scanning, or the full static analysis.

Read `[orchestration]` from `target/TARGET.toml`. Defaults when absent:
- `max_parallel_agents = 2`
- `research_max_questions = 3`
- `research_max_sources_per_question = 5`
- `research_max_report_words = 900`

## 1. Local-first gate

Identify candidate uncertainties that could materially change severity, applicability, confidence, or the next validation step. Before creating a public-research question, ask whether the uncertainty can be answered cheaply from existing local artifacts.

Prefer local deterministic checks first, for example:
- exact Java/Smali/XML tracing;
- local manifest/resource/config searches;
- comparing already-known local hashes with a published digest after that digest is obtained;
- OpenSSL/certificate parsing of local public material;
- version/package/signer metadata already produced by preparation;
- narrow archive/file-name/string searches;
- a focused `apk-code-reviewer`, `apk-secret-hunter`, or `apk-validator` task when interpretation rather than public facts is missing.

Do not send a question to the web merely because the first report called it unresolved. If local evidence answers it, update the finding and stop there.

## 2. Build only externally answerable questions

Select at most `research_max_questions` questions that still require a PUBLIC fact after the local-first gate. Good examples are platform API semantics, exact upstream versions/advisories, public source/fixes, package ownership/signing history, or vendor documentation.

Record each selected question in `findings/research.md` as one compact index row before delegation. Do not write a prose mini-report there.

## 3. Bounded web research

Delegate one bounded batch to `apk-researcher`. It may use `apk-web-worker` within `max_parallel_agents`. Each RQ gets exactly one canonical detail artifact under `reports/research/RQ-XX-....md`; no coordinator/batch report is required.

Never send secrets, tokens, private target data, proprietary code, confidential certificate/allowlist values, or sensitive TARGET.toml content to public research.

## 4. Deterministic local correlation after research

For every external answer, immediately perform any cheap deterministic local correlation that the answer makes possible before marking a question unresolved. Examples: compare hashes, verify a local signer/certificate property, grep the exact local implementation, or check a local manifest setting. Public research supplies outside facts; existing local artifacts decide applicability.

If a decisive external claim is supported only by search snippets or an unfetched primary source, keep it `SOURCE_LEAD_ONLY`; do not use it to change a finding.

## 5. Validate only material changes

After correlation, use one focused `apk-validator` task for the set of material changes to important findings rather than one validator task per research question when a consolidated review is sufficient.

Update:
- the relevant `findings/*.md` records;
- the compact row in `findings/research.md`;
- `findings/analysis-log.md` with delegation layer, task/report path, and observed peak concurrency;
- `reports/STATIC_SECURITY_REPORT.md` only where conclusions actually changed.

Do not copy worker reports into other files. Link to them and summarize only the changed conclusion.

Public research never confirms a vulnerability without local evidence.
