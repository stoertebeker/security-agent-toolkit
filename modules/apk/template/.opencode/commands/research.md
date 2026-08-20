---
description: Research unresolved public questions from the APK review
agent: apk-security
---
Review the current structured findings and `reports/STATIC_SECURITY_REPORT.md` if it exists.

Do not repeat broad APK preparation or the full static analysis.

Read `[orchestration]` from `target/TARGET.toml`. Defaults when absent:
- `max_parallel_agents = 2`
- `research_max_questions = 3`
- `research_max_sources_per_question = 5`

Identify at most `research_max_questions` unresolved questions where public information could materially change a finding's severity, applicability, confidence, validation plan, or save unnecessary reverse engineering. Good examples include Android API behavior, SDK/library versions and advisories, upstream fixes/source, package ownership/signing history, partner applications, or published research relevant to a locally observed implementation.

For each worthwhile question:
1. record the narrow question, why it matters and the local evidence in `findings/research.md`;
2. delegate the bounded research batch to `apk-researcher`;
3. require detailed source notes under `reports/research/`;
4. correlate the external answer with local APK evidence;
5. use `apk-validator` when the research materially changes an important security conclusion;
6. update the relevant structured findings and `reports/STATIC_SECURITY_REPORT.md`.

Never exceed `max_parallel_agents` concurrently executing delegated tasks. Do not send secrets, tokens, private target data, proprietary code blocks or sensitive TARGET.toml content to public research. Public research never confirms a vulnerability without local evidence.
