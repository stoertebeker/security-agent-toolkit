---
description: Run the complete evidence-first firmware security assessment
agent: firmware-security
---
Run the complete authorized firmware security assessment for the target configured in `target/TARGET.toml`.

1. Read `[engagement]`, `[orchestration]`, `[firmware]`, `[identity]`, `[analysis]`, and `[secrets]`. Refuse unless authorized. Respect `max_parallel_agents`. `analysis.max_ghidra_slices_per_hypothesis` remains the per-question ceiling and all Ghidra budgets are mechanically enforced; never rename the same unresolved question to reset them.
2. Refresh/reuse deterministic stages for the current image in this order:
   - `python3 tools/firmware_prepare.py`
   - `python3 tools/firmware_baseline.py` (also creates `firmware-identity.*`, `firmware-web-surface.*`, and `firmware-web-native-bridge.*`)
   - `python3 tools/firmware_component_fingerprint.py`
   - `python3 tools/firmware_secret_scan.py`
   - `python3 tools/firmware_secret_group.py`
   Treat the baseline stage as stale when identity, web-surface, or web/native-bridge output is missing for the current firmware/tool code.
3. Treat deterministic outputs as leads/coverage, not findings. `kind=stop` is not startup proof; UI pages are not update-mechanism proof; versions/imports/strings/keys are not vulnerabilities; a web/native bridge is string-correlation evidence, not control-flow proof.
4. If `orchestration.advisory_scout=true`, run exactly one early `RQ-ADVISORY-SCOUT` through `firmware-researcher`. Supply `firmware-identity.json` as the identity contract. Every disclosed feature/endpoint/parameter/function seed must receive a local behavior disposition independently of CVE applicability. When `advisory_scout=false`, do not perform product/build CVE discovery.
5. Delegate `firmware-explorer` and `firmware-secret-hunter` early. A delegated artifact is complete only with `Completion: COMPLETE`; one bounded resume/retry is allowed. Secret coverage may be called complete only if every deterministic group ID is present in `firmware-secrets-review.md`.
6. Before expensive deep-review selection, explicitly disposition the top `analysis.max_web_hypotheses` entries from `firmware-web-surface.json`. For each `INVESTIGATE` web lead, inspect its candidates in `firmware-web-native-bridge.json`. A high-scoring bridge with an exact risky request field must receive an explicit bridge disposition and, when materially security-relevant, a stable local hypothesis.
7. For a native web hypothesis, preserve the attacker-controlled field name. The first Ghidra-backed trace should use the strongest exact request-field token plus a route/page/form-action token from the deterministic bridge when available. Do not replace a concrete input token with a broad hypothesis such as “HTTPD management routes.” Follow later slices through recovered functions, IPC helpers, validation and sinks using the same hypothesis ID.
8. Select only the highest-value unresolved service/web/auth/IPC, update and native hypotheses. Establish source -> processing/validation -> sensitive sink -> auth/reachability/privilege -> realistic impact. If HTTP parsing hands data to another daemon/library through IPC, treat HTTP-input -> IPC serialization/dispatch -> privileged consumer as one coupled security hypothesis rather than stopping at the process boundary.
9. Native escalation is **Ghidra-backed** through toolkit-managed `analyzeHeadless`; a host `objdump` architecture limitation is not an analysis endpoint. If a decisive symbol remains external/thunk-only, use `tools/firmware_symbol_owner.py`; cross-library work keeps the same hypothesis budget. Stop with `NEEDS VALIDATION` when the remaining gap is genuinely runtime/topology/hardware/backend evidence or broad vendor archaeology, not merely because the source and sink sit in different firmware processes.
10. Important High/Critical candidates require `security-validator`. Keep CVE-label uncertainty separate from locally established vulnerability behavior.
11. All non-scout research remains last-mile and bounded. Never send private target data, target hashes, credentials, keys or source blocks to public research.
12. Maintain all durable `findings/` records and create `reports/STATIC_SECURITY_REPORT.md`. Separate confirmed severity from unresolved potential impact/status; do not call an unproven primitive a severity finding.
13. Run both `python3 tools/firmware_postrun_check.py` and `python3 tools/firmware_hypothesis_check.py`. A PASS requires deterministic identity/web-surface/web-native-bridge artifacts plus explicit required web/bridge/advisory dispositions. If either checker fails, make at most one bounded repair pass; otherwise report partial coverage rather than claiming completion.

Do not ask the operator to run routine analysis commands during `/analyze`. Never execute target firmware binaries on the analysis host and never infer WAN exposure from static configuration alone.
