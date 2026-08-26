---
description: Run the complete evidence-first firmware security assessment
agent: firmware-security
---
Run the complete authorized firmware security assessment for the target configured in `target/TARGET.toml`.

1. Read `[engagement]`, `[orchestration]`, `[firmware]`, `[identity]`, `[analysis]`, and `[secrets]`. Refuse unless authorized. Respect `max_parallel_agents`. `analysis.max_ghidra_slices_per_hypothesis` remains the per-question ceiling and all Ghidra budgets are mechanically enforced; never rename the same unresolved question to reset them.
2. Refresh/reuse deterministic stages for the current image in this order:
   - `python3 tools/firmware_prepare.py`
   - `python3 tools/firmware_baseline.py` (also creates `firmware-identity.*` and `firmware-web-surface.*`)
   - `python3 tools/firmware_component_fingerprint.py`
   - `python3 tools/firmware_secret_scan.py`
   - `python3 tools/firmware_secret_group.py`
   Treat the baseline stage as stale when `firmware-identity.json` or `firmware-web-surface.json` is missing, even when the firmware SHA has not changed.
3. Treat deterministic outputs as leads/coverage, not findings. `kind=stop` is not startup proof; UI pages are not update-mechanism proof; versions/imports/strings/keys are not vulnerabilities.
4. If `orchestration.advisory_scout=true`, run exactly one early `RQ-ADVISORY-SCOUT` through `firmware-researcher`. Supply `reports/tool-output/firmware-identity.json` as the identity contract. If `advisory_ready=true`, do not describe model/build as unavailable. If identity is partial, preserve the exact missing/conflicting field.
5. Every advisory seed with a disclosed feature/endpoint/parameter/function must receive a **local behavior disposition independently of CVE applicability**. If that feature/parameter exists locally, create a stable local hypothesis and investigate it even when the CVE label is `DEFERRED_CVE_IDENTITY`. Record:
   `Seed disposition: CVE-YYYY-NNNN -> INVESTIGATED|REJECTED|DEFERRED_CVE_IDENTITY; local-hypothesis=<id-or-none>; reason=<brief evidence>`.
6. Delegate `firmware-explorer` and `firmware-secret-hunter` early. A delegated artifact is complete only with `Completion: COMPLETE`; one bounded resume/retry is allowed. Secret coverage may be called complete only if every deterministic group ID is present in `firmware-secrets-review.md`.
7. Before expensive deep-review selection, explicitly disposition the top `analysis.max_web_hypotheses` entries from `firmware-web-surface.json`. Do not let the first interesting route crowd out similarly risky web surfaces.
8. Select only the highest-value unresolved service/web/auth/IPC, update and native hypotheses. Establish source -> processing/validation -> sensitive sink -> auth/reachability/privilege -> realistic impact. Give native reviewers one stable hypothesis ID and use Ghidra only where control flow can change the conclusion.
9. Native escalation is **Ghidra-backed** through toolkit-managed `analyzeHeadless`; a host `objdump` architecture limitation is not an analysis endpoint. If a decisive symbol remains external/thunk-only, use `tools/firmware_symbol_owner.py`; cross-library work keeps the same hypothesis budget. Stop with `NEEDS VALIDATION` when the remaining gap is runtime/topology/hardware/backend evidence or broad vendor archaeology.
10. Important High/Critical candidates require `security-validator`. Keep CVE-label uncertainty separate from locally established vulnerability behavior.
11. All non-scout research remains last-mile and bounded. Never send private target data, target hashes, credentials, keys or source blocks to public research.
12. Maintain all durable `findings/` records and create `reports/STATIC_SECURITY_REPORT.md`. Separate confirmed severity from unresolved potential impact/status; do not call an unproven primitive a severity finding.
13. Run both `python3 tools/firmware_postrun_check.py` and `python3 tools/firmware_hypothesis_check.py`. A PASS requires deterministic identity/web-surface artifacts, explicit top-web dispositions, and explicit advisory-seed dispositions. If either checker fails, make at most one bounded repair pass; otherwise report partial coverage rather than claiming completion.

Do not ask the operator to run routine analysis commands during `/analyze`. Never execute target firmware binaries on the analysis host and never infer WAN exposure from static configuration alone.
