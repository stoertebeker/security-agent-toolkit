---
description: Research unresolved public questions from the APK review
agent: apk-security
---
Review current structured findings and `reports/STATIC_SECURITY_REPORT.md` if it exists. Do not repeat preparation, broad scanning, or the full static analysis.

Read `[orchestration]` from `target/TARGET.toml`. Defaults when absent:
- `max_parallel_agents = 2`
- `research_max_questions = 3`
- `research_max_sources_per_question = 5`
- `research_max_report_words = 900`

## 1. Local-first gate

Identify uncertainties that could materially change severity, applicability, classification, confidence, or the next validation step. Before creating public research, determine whether existing local artifacts can answer them cheaply.

Prefer exact Java/Smali/XML tracing, manifest/resource/config searches, local hash/certificate/package/version checks, narrow archive/file/string searches, deterministic native/secret outputs, or a focused local subagent. Do not send a question to the web merely because an earlier report called it unresolved.

## 2. Build only externally answerable research packets

Select at most `research_max_questions` questions that still require a PUBLIC fact. For EACH selected RQ, construct this packet before delegation:

- `RQ-ID` and narrow external question;
- `Why it matters` — one sentence naming the finding/status/classification decision it could affect;
- `Local facts` — 2 to 5 concrete, non-sensitive locally established facts, including relevant usage/flow and useful negative evidence;
- `External fact needed` — the exact remaining fact that cannot be learned from local artifacts;
- `Max sources` and `Max report words`.

The `Local facts` block is mandatory. For example, do not ask "what is Getui APPSECRET?" without also supplying locally established facts such as "APPSECRET is read from manifest metadata by client SDK initialization" and "no MasterSecret/server-API signing flow was found locally". Do not ask about a client signing value without stating the locally traced signing/header/request use.

Record each selected question in `findings/research.md` as one compact index row before delegation. Do not write a prose mini-report there.

## 3. Bounded web research

Delegate the complete packets to `apk-researcher`. It may use `apk-web-worker` within `max_parallel_agents`. Each RQ gets exactly one canonical detail artifact under `reports/research/RQ-XX-....md`; no coordinator/batch report is required.

Never send secrets, tokens, private target data, proprietary code, confidential certificate/allowlist values, or sensitive TARGET.toml content to public research.

Workers must prefer fetch-before-more-search: discover a likely primary source, fetch/read it, try at most one alternate primary page if fetch fails, and only then broaden discovery. Search snippets alone remain leads.

## 4. Deterministic local correlation after research

For every external answer, immediately perform any cheap deterministic local correlation enabled by the answer before marking a question unresolved. Compare hashes, confirm exact local usage, verify signer/certificate properties, or check manifest/configuration as appropriate.

If a decisive external claim is supported only by search snippets or an unfetched primary source, keep it `SOURCE_LEAD_ONLY`; do not use it to change a finding.

## 5. Validate only material changes

After correlation, use one focused `apk-validator` task for the set of material changes to important findings rather than one validator task per RQ when a consolidated review is sufficient.

Update the relevant `findings/*.md`, the compact `findings/research.md` row, `findings/analysis-log.md` with delegation/provenance/concurrency, and `reports/STATIC_SECURITY_REPORT.md` only where conclusions actually changed.

Do not copy worker reports into other files. Link them and summarize only the changed conclusion.

Public research never confirms a vulnerability without local evidence.
