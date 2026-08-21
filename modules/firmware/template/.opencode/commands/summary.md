---
description: Refresh the compact firmware analyst outcome summary from durable records
agent: firmware-security
---
Generate or refresh only the compact analyst-facing outcome summary. Do not repeat extraction, scanning, reversing, validation or web research.

Read:
- `findings/findings.md`
- `findings/attack-surface.md`
- `findings/secrets.md`
- `findings/update-security.md`
- `findings/coverage.md`
- validation artifacts referenced by findings

Update the `## Analyst summary` near the top of `reports/STATIC_SECURITY_REPORT.md` and print the same summary to the operator.

Keep it normally 6-12 lines and state:
- whether any Critical/High finding was independently confirmed and the highest supported severity;
- at most three most important risks;
- evidence-backed unusual/high-impact firmware behavior or `None established`;
- concealment/hidden-behavior state plus one short evidence statement;
- the single most important remaining extraction/runtime/topology/bootloader/vendor limitation.

Expected normal service startup, standard management protocols, BusyBox symlinks, ordinary packing/stripping, or a configured deep/service route are not `unusual behavior` merely because analysis confirmed them.

If the final report does not yet exist, create a minimal `reports/STATIC_SECURITY_REPORT.md` with this summary and links/sections pointing to durable findings rather than inventing missing analysis content.
