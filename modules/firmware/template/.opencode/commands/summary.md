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
- whether any Critical/High finding was independently confirmed and the **highest confirmed finding severity**;
- the **highest unresolved candidate severity/status separately** when candidates remain; never call an unresolved candidate the "highest supported severity";
- at most three most important risks, labeling unresolved candidates explicitly;
- evidence-backed unusual behavior or `None established`, with ordinary but security-relevant mechanisms reported separately as notable attack-surface behavior;
- concealment/hidden-behavior state plus one short evidence statement;
- the single most important remaining extraction/runtime/topology/bootloader/vendor limitation.

Expected service startup, standard management/recovery/debug functionality, password-recovery pages, hidden/debug filenames or strings, proprietary component names, BusyBox symlinks, ordinary packing/stripping, or a configured deep/service route are not unusual/concealed merely because analysis confirmed them. `SUSPICIOUS_CONCEALMENT_INDICATORS` requires behavioral evidence such as intentionally undisclosed reachable management functionality, hidden startup/listener behavior, covert/opaque privileged control, deliberate log suppression/self-deletion, anti-analysis, or intentional security-control bypass. Names/strings alone require `NONE_ESTABLISHED` (or `ORDINARY_PACKING_OR_STRIPPING_ONLY` when applicable).

If the final report does not yet exist, create a minimal `reports/STATIC_SECURITY_REPORT.md` with this summary and links/sections pointing to durable findings rather than inventing missing analysis content.
