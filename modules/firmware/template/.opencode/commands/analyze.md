---
description: Run the complete evidence-first firmware security assessment
agent: firmware-security
---
Run the complete authorized firmware security assessment for the target configured in `target/TARGET.toml`.

1. Read `[engagement]`, `[orchestration]`, `[firmware]`, `[analysis]`, and `[secrets]` first. Refuse if `engagement.authorized` is not true. Respect `orchestration.max_parallel_agents`; never exceed it.
2. Reuse fresh deterministic artifacts for the current firmware hash. Refresh only stale/missing stages in this order:
   - `python3 tools/firmware_prepare.py`
   - `python3 tools/firmware_baseline.py`
   - `python3 tools/firmware_component_fingerprint.py`
   - `python3 tools/firmware_secret_scan.py`
   - `python3 tools/firmware_secret_group.py`
3. Treat deterministic outputs as prioritization and coverage evidence, not findings. In particular:
   - service `kind=stop` is lifecycle evidence only and is not startup proof;
   - zero deterministic startup/config leads does not prove that no services start; reconstruct the native/vendor boot chain when needed;
   - `firmware-update-ui-paths.*` contains navigation/UI anchors only and must not be treated as update mechanism or verification evidence;
   - `firmware-update-leads.*` is the mechanism/security lead set;
   - component versions, imports, hardening gaps, private-key presence, hashes, or filenames alone are not vulnerabilities.
4. Delegate `firmware-explorer` and `firmware-secret-hunter` concurrently when the task ceiling permits. Integrate their results into durable records before choosing deeper work.
5. From locally evidenced attack paths select only the highest-value unresolved service/web/auth/IPC, update, and native-binary hypotheses. Delegate `firmware-service-reviewer`, `firmware-update-reviewer`, and `binary-reverser` within the configured review ceilings. Do not broadly reverse every high-scoring ELF. Give each binary-reverser one binary and one narrow hypothesis where practical.
6. If deterministic service discovery found no start/config evidence, the explorer must trace the actual boot/service orchestration from init, `rc`, vendor service managers, config/NVRAM dispatch, and concrete daemon invocations before reachability claims are made.
7. For update analysis, begin with mechanism leads such as `upgrade.sh`, then trace source/input -> parsing/version -> integrity/authenticity -> staging -> privileged write -> recovery/rollback. Use UI anchors only to locate entry points.
8. Native-analysis escalation is mandatory for material unresolved candidates. If host `objdump` or another lightweight disassembler lacks the target architecture, or a High/Critical-impact candidate remains unresolved primarily because stripped native call-flow ordering is missing, delegate a Ghidra-backed `binary-reverser` retry before finalizing the assessment. `Host disassembler lacks ARM support` is not an acceptable final tooling limitation while toolkit-managed `analyzeHeadless` is available but untried. If Ghidra fails, record the exact command/artifact path and concrete failure reason.
9. Keep native deep dives convergent. For one binary/hypothesis, normally allow no more than three focused Ghidra slice iterations after lightweight triage. A fourth is justified only by one concrete new function/address likely to close the exact missing source/gate/sink link. Stop and preserve `NEEDS VALIDATION` when additional work would mostly be vendor-specific archaeology, require broad whole-program reversing, or depend on runtime/topology/hardware/backend/cross-device evidence. Do not add target-specific toolkit logic merely to finish one firmware image.
10. Important High/Critical candidate findings require independent `security-validator` review before promotion. If the validator identifies missing native call flow as a decisive gap and Ghidra has not been attempted for that hypothesis, perform the Ghidra-backed retry and revalidate any materially changed conclusion.
11. Perform bounded public research only after local evidence is complete and only for external facts that could materially change a specific local conclusion. Correlate research back to local version/use/reachability evidence.
12. Maintain `findings/inventory.md`, `findings/attack-surface.md`, `findings/secrets.md`, `findings/update-security.md`, `findings/findings.md`, `findings/coverage.md`, `findings/research.md`, and `findings/analysis-log.md` throughout the run.
13. At completion create `reports/STATIC_SECURITY_REPORT.md` from the durable records. Include a compact `## Analyst summary` near the top and repeat the same summary in the final response. In that summary, report the highest confirmed finding severity separately from the highest unresolved candidate severity/status. Never call an unresolved conditional candidate the "highest supported severity". Keep `Unusual behavior` separate from ordinary but notable attack-surface behavior. Native coverage must say whether Ghidra was attempted for each material native hypothesis and distinguish `not attempted`, `attempted but failed`, and `attempted but control flow still unresolved`.

Do not execute target firmware binaries on the analysis host. Do not infer WAN exposure from static configuration alone. Keep the primary context small and put detailed delegated evidence under `reports/subagents/`.
