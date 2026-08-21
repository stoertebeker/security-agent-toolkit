---
description: Reverse prioritized firmware binaries without broad re-analysis
agent: firmware-security
---
Perform focused native-binary review only.

1. Require fresh `reports/tool-output/firmware-binaries.json` and `firmware-baseline.json`; refresh `firmware_baseline.py` only when stale/missing.
2. Read `analysis.max_binary_deep_reviews` as a ceiling.
3. Use `binary_priority_leads` only for ordering. Correlate candidates with startup/service/update/web/config evidence before delegation.
4. Prefer custom/vendor binaries that are root/SUID, startup-enabled, network-facing, update-related, parser-heavy, or connected to a concrete security hypothesis. Do not reverse every library.
5. Delegate bounded `binary-reverser` tasks, one narrow binary/hypothesis per task where practical. Start with lightweight evidence; Ghidra only when justified.
6. Missing hardening or dangerous imports alone are not findings.
7. Update affected `findings/attack-surface.md`, `findings/update-security.md`, `findings/findings.md`, `findings/coverage.md`, and `findings/analysis-log.md`.
8. Independently validate important High/Critical candidates before promotion. No public research in this command.
