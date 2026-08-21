---
description: Generate or refresh the compact analyst outcome summary from existing APK analysis records
agent: apk-security
---
Generate or refresh only the analyst-facing outcome summary for the current authorized Android application review. Do not repeat preparation, broad static analysis, secret scanning, native scanning, public research, or dynamic testing.

Read the current durable evidence:
- `findings/findings.md`
- `findings/attack-surface.md`
- `findings/secrets.md`
- `findings/coverage.md`
- `findings/research.md`
- `findings/analysis-log.md`
- `reports/STATIC_SECURITY_REPORT.md` when present
- relevant validator/subagent reports only when the durable records do not contain enough context for one summary statement.

Create or replace a compact `## Analyst summary` near the top of `reports/STATIC_SECURITY_REPORT.md`. Keep it normally to 6-12 lines and do not duplicate the full findings section.

The summary must state:
1. `Overall result` - whether any Critical or High finding was independently confirmed and the highest supported severity. Distinguish confirmed findings from candidates/conditional severity.
2. `Most important risks` - at most three concise evidence-backed findings/design risks with current status.
3. `Unusual behavior` - at most three surprising/high-impact application behaviors supported by local evidence, or `None established`.
4. `Concealment / analysis resistance` - use the durable state from `findings/attack-surface.md`: none established, ordinary build obfuscation only, suspicious indicators, or confirmed deliberate analysis-resistance behavior. Give one short evidence statement. Never infer malicious intent from minification, generated names, compressed assets, stripped vendor libraries, or ordinary framework behavior alone.
5. `Main limitation` - the single most important remaining runtime/backend/decompiler/native uncertainty.

Use validated conclusions over earlier lead severity. Do not expose raw sensitive values. If the durable records do not support a claim, say so rather than inferring it.

Return the same compact analyst summary to the operator after updating the report.
