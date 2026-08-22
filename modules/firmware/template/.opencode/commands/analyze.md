---
description: Run the complete evidence-first firmware security assessment
agent: firmware-security
---
Run the complete authorized firmware security assessment for `target/TARGET.toml`.

1. Read `[engagement]`, `[orchestration]`, `[firmware]`, `[analysis]`, and `[secrets]`. Refuse unless authorized. Respect `max_parallel_agents`. `analysis.max_ghidra_slices_per_hypothesis` remains the per-hypothesis ceiling; helper-enforced per-binary/per-assessment ceilings also apply.
2. Refresh stale deterministic stages for the current firmware/tool hashes:
   - `python3 tools/firmware_prepare.py`
   - `python3 tools/firmware_baseline.py` (this also creates `firmware-web-surface.*`)
   - `python3 tools/firmware_component_fingerprint.py`
   - `python3 tools/firmware_secret_scan.py`
   - `python3 tools/firmware_secret_group.py`
3. Delegate `firmware-explorer` and `firmware-secret-hunter` within the concurrency ceiling. A delegated artifact is complete only with `Completion: COMPLETE`; allow at most one bounded retry after a step limit/incomplete artifact.
4. Before deep-review selection, require explicit `INVESTIGATE`/`DEPRIORITIZE` dispositions for the top `analysis.max_web_hypotheses` ranked entries in `reports/tool-output/firmware-web-surface.json`. Preserve their `WS-...` IDs in the explorer/service evidence. Client-side validation and risky parameter names are leads, not findings.
5. If `orchestration.advisory_scout=true` and local evidence establishes vendor/product/hardware revision/firmware version or build, spend at most one research question on `RQ-ADVISORY-SCOUT`. Ask authoritative vendor/CVE sources for applicable High/Critical advisories and any disclosed vulnerable feature/parameter. Treat every match only as a `HYPOTHESIS_SEED`; locally investigate or explicitly reject/defer each applicable seed. This scout is the sole exception to normal last-mile research.
6. Select only the highest-value unresolved service/web/auth/IPC, update and native hypotheses. Use deterministic mechanism evidence rather than UI names alone. Do not let the first interesting path crowd out higher-ranked web-surface/advisory seeds.
7. For missing startup evidence, reconstruct the focused init/rc/vendor dispatch chain. `kind=stop` never proves startup. Do not infer WAN exposure from static configuration alone.
8. Native escalation is mandatory when decisive static control flow is missing and could materially change a candidate. A host `objdump` architecture limitation is not an endpoint while toolkit-managed `analyzeHeadless` is available. Use a Ghidra-backed `binary-reverser`, stable hypothesis IDs, cross-library symbol-owner resolution when needed, and hard budgets. If Ghidra fails, record the exact artifact/log reason.
9. Important High/Critical candidates and applicable High/Critical advisory seeds require independent `security-validator` challenge before final disposition.
10. All non-scout public research is local-first and last-mile. Public claims never replace local applicability.
11. Maintain durable records under `findings/` and detailed evidence under `reports/subagents/`/`reports/research/`.
12. Create `reports/STATIC_SECURITY_REPORT.md`. Separate highest confirmed severity from unresolved candidate impact/status; do not assign severity solely from hypothetical impact.
13. Run `python3 tools/firmware_postrun_check.py`. Make at most one bounded repair pass. Do not publish complete coverage while the checker fails.

Do not ask the operator to run local analysis commands during a normal `/analyze` assessment. The agents invoke deterministic tools, Ghidra helpers and searches themselves. Never execute target firmware binaries on the host.
