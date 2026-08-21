---
description: Reverse prioritized firmware binaries without broad re-analysis
agent: firmware-security
---
Perform focused native-binary review only.

1. Require fresh `reports/tool-output/firmware-binaries.json` and `firmware-baseline.json`; refresh `firmware_baseline.py` only when stale/missing.
2. Read `analysis.max_binary_deep_reviews` as a ceiling.
3. Use `binary_priority_leads` only for ordering. Correlate candidates with startup/service/update/web/config evidence before delegation.
4. Prefer custom/vendor binaries that are root/SUID, startup-enabled, network-facing, update-related, parser-heavy, or connected to a concrete security hypothesis. Do not reverse every library.
5. Delegate bounded `binary-reverser` tasks. Use **one binary and one narrow hypothesis per task** unless two binaries form a directly coupled caller/callee path that cannot be reviewed separately.
6. Start with lightweight evidence. If host disassembly does not support the target architecture, the binary is stripped and call-flow ordering matters, or a High/Critical-impact candidate remains unresolved primarily because native control flow is missing, the delegated task must attempt toolkit-managed Ghidra headless analysis before declaring a static tooling limitation.
7. A final `NEEDS VALIDATION` result may remain because runtime startup/listener/topology, bootloader/hardware, cloud-peer behavior, or genuinely unresolved indirect control flow is missing. It must not remain solely because host `objdump` lacked target-architecture support when `analyzeHeadless` was available but untried.
8. Missing hardening or dangerous imports alone are not findings.
9. Update affected `findings/attack-surface.md`, `findings/update-security.md`, `findings/findings.md`, `findings/coverage.md`, and `findings/analysis-log.md`. Record whether Ghidra was attempted, its artifact/log path, and the exact reason if it could not resolve the hypothesis.
10. Independently validate important High/Critical candidates before promotion. No public research in this command.
