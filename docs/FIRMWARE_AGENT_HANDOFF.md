# Firmware module agent handoff

Date: 2026-08-22  
Branch: `refactor/modular-toolkit-v1`  
Repository: `stoertebeker/security-agent-toolkit`

## Primary goal

The firmware module is being developed as a **vendor-agnostic, mostly hands-off AI security test suite**, not as a bespoke reverse-engineering project for one firmware image.

The desired operator workflow is:

```text
firmware image + target/TARGET.toml
    -> ./start.sh
    -> /analyze
    -> autonomous deterministic preparation
    -> autonomous focused AI review
    -> bounded native/Ghidra escalation when justified
    -> independent validation
    -> bounded public research
    -> reports/STATIC_SECURITY_REPORT.md
```

Manual shell/Ghidra commands are acceptable while debugging the toolkit itself, but they must not become part of the normal assessment workflow. In normal `/analyze` runs the agents must execute available local tools themselves and stop cleanly when the configured evidence budget is exhausted.

## Non-negotiable design constraints

- OpenCode is the orchestrator.
- Keep customer/target/project artifacts out of the toolkit repository.
- Workspace temp/output stays local to the assessment workspace; do not use `/tmp` for toolkit-controlled state.
- Never execute target firmware binaries on the analysis host.
- Start from deterministic baselines instead of recursively feeding the extracted rootfs to an LLM.
- Evidence first: strings, imports, filenames, hardening gaps, versions and CVEs are leads, not findings.
- Important High/Critical candidates require independent validation.
- Default delegated concurrency remains bounded by `orchestration.max_parallel_agents`, normally 2.
- Research is local-first, last-mile and budgeted.
- Do not add target-specific regexes, vendor names, hard-coded function addresses or one-off logic merely to finish one image.
- Improvements should be architecture-/vendor-agnostic, hypothesis-driven, budgeted and reproducible.

## Current firmware static pipeline

Deterministic stages:

```text
python3 tools/firmware_prepare.py
python3 tools/firmware_baseline.py
python3 tools/firmware_component_fingerprint.py
python3 tools/firmware_secret_scan.py
python3 tools/firmware_secret_group.py
```

Primary orchestration then uses:

```text
firmware-explorer
firmware-secret-hunter
firmware-service-reviewer
firmware-update-reviewer
binary-reverser
security-validator
firmware-researcher
```

Durable records live under `findings/`; final output is `reports/STATIC_SECURITY_REPORT.md`.

## Netgear R7000 test vector

The main development/regression image so far has been:

```text
R7000-V1.0.9.42_10.2.44.chk
SHA-256 ec1eba7b465e3997927fa6d884c475d16f2caa60b3143b25c0a647034c7ab9ef
```

Known structure:

```text
Netgear CHK
  -> TRX
  -> LZMA + SquashFS
  -> conventional Linux rootfs
```

Extraction/rootfs discovery is working reliably on this image. The first full assessment exposed several orchestration/reporting defects; those defects, rather than the target-specific vulnerability details, are the important outcome of the R7000 work.

Do not keep optimizing the module around this router. The R7000 should now be treated primarily as a regression vector.

## R7000 assessment state

The autonomous regression run completed without operator-driven analysis commands. Its final summary reported:

- no confirmed Critical/High vulnerability;
- highest unresolved candidate: High, conditional, for the HTTP firmware-update path;
- other unresolved candidates around ReadyCloud CGI handling, embedded RSA material and aMule external control;
- the native F-01 review autonomously used the configured hard budget of 3 Ghidra slices, all succeeded, and the agent stopped with unresolved control flow instead of continuing indefinitely;
- artifact consistency passed.

That hands-off behavior is considered a successful automation regression.

### Important caveat from the final regression run

The run classified concealment as `SUSPICIOUS_CONCEALMENT_INDICATORS` because hidden/debug CGI and password-recovery strings existed, while simultaneously stating that no malicious or anti-analysis behavior was established.

That classification is considered a **generic reporting bug**, not a meaningful R7000 conclusion. With the available evidence, the appropriate concealment state remains `NONE_ESTABLISHED` unless concrete hidden/reachable behavior or anti-analysis evidence is established.

The concealment evidence contract was hardened after that run. The regression has not been rerun solely for that wording/classification fix.

## Generic lessons learned from the R7000 work

### 1. Missing host disassembler support is not an analysis endpoint

The original assessment stopped native ARM call-flow analysis because host `objdump` lacked ARM support even though Ghidra was installed.

The toolkit now requires escalation to toolkit-managed Ghidra when:

- host disassembly cannot handle the target architecture;
- a stripped binary blocks a concrete source/gate/sink hypothesis;
- a material High/Critical-impact candidate remains unresolved mainly because call-flow ordering is missing.

Do not report `host objdump lacks ARM support` as the final limitation while `analyzeHeadless` is available and untried.

### 2. Ghidra analysis must be focused, not whole-binary dumping

New helper:

```text
tools/firmware_ghidra_slice.py
tools/ghidra/SatDecompileRefs.java
```

Behavior:

- imports one selected ELF;
- uses target-rootfs library search paths where available;
- keeps Ghidra config/cache/temp/workspace state project-local;
- searches hypothesis-specific strings/symbols;
- follows direct xrefs plus a bounded caller layer;
- records small instruction contexts around direct xrefs;
- decompiles a bounded function set;
- supports direct selection of recovered/generated function names such as `FUN_0001c108`;
- prioritizes real internal functions over imported/external stubs;
- gives distinct queries distinct slice artifacts instead of overwriting previous work.

Raw slices live under `work/ghidra/slices/`; invocation logs live under `reports/tool-output/`.

### 3. Native reversing must converge

`[analysis]` now includes:

```toml
max_ghidra_slices_per_hypothesis = 3
```

This is a real validated configuration value, not merely advisory prompt text.

For one binary/hypothesis the reverser should normally perform no more than the configured number of focused slices. Stop with `NEEDS VALIDATION` when additional work would mainly be:

- vendor archaeology;
- broad whole-program reversing;
- runtime/listener/firewall/topology work;
- bootloader/hardware work;
- cloud/backend acceptance;
- cross-device secret/key reuse analysis.

A fourth slice should only occur when one newly discovered concrete function/address is likely to close the exact missing link and materially change the candidate disposition.

### 4. The normal operator workflow must be hands-off

`/analyze` and `binary-reverser` now explicitly require the agents to execute Ghidra/helper/tool commands themselves.

The normal assessment must not ask the operator to copy/paste `python3`, `grep`, `awk`, Ghidra or similar analysis commands. Manual commands are for toolkit debugging only.

### 5. Function/import names can create false correlations

Generic key names such as `server.key` and `client.key` matched unrelated OpenVPN/provisioning logic while investigating embedded Foxconn RSA material.

For material/secret correlation, prefer full paths or distinctive directory tokens such as `foxconn_ca`, not generic basenames. Do not promote a consumer relationship without path/use correlation.

### 6. PLT/external stubs must not consume scarce reverse-engineering budget

An early focused slice selected `mtd_write` PLT/external functions and pushed the real internal caller out of a small `max-functions` set.

The selector now prioritizes internal functions and does not waste deep-dive slots on imported/external stubs when a real caller is available.

### 7. Service lifecycle semantics must stay strict

`kind=stop` remains lifecycle evidence only. It does not prove startup, listening or reachability.

Zero deterministic startup/config leads also does not prove that no services start. Native/vendor `init`/`rc` dispatchers must be investigated as focused boot-chain leads when applicable.

### 8. Update UI and update mechanism evidence remain separate

`firmware-update-ui-paths.*` is navigation/entry-point evidence only.

`firmware-update-leads.*` is mechanism/security evidence.

A firmware page, DOM id or `upgrade.cgi` string does not by itself prove privileged flashing, missing verification or remote reachability.

### 9. Candidate severity must remain separate from confirmed severity

Final summaries must state separately:

```text
Highest confirmed finding severity: ...
Highest unresolved candidate: ... (conditional / needs runtime / needs vendor evidence)
```

Do not use wording such as `highest supported severity is conditional High`.

### 10. Concealment requires behavioral evidence

The following alone must not establish `SUSPICIOUS_CONCEALMENT_INDICATORS`:

- filenames containing `hidden`, `debug`, `recovery`, `password`, etc.;
- UI pages or debug strings;
- proprietary/opaque binaries;
- ordinary packing/stripping;
- remote-management functionality.

Suspicious/confirmed concealment requires concrete target-specific behavior such as an actually hidden reachable administration path, covert listener, deliberately concealed startup/persistence, security-check bypass, deliberate log suppression or anti-analysis behavior.

This rule is now present in the primary, explorer, validator and summary contracts and is checked by `lib/validate.py`.

## R7000-specific technical observations that should NOT become toolkit special cases

These are useful only as regression context:

- Native `/sbin/rc` is the relevant boot/control dispatcher and is heavily NVRAM-driven.
- Native `httpd` contains real listener setup and TLS initialization.
- Update CGI paths and MTD-writing code both exist and are reachable in native control flow, but the complete request/auth/XSRF/authenticity-to-flash chain was not established within the bounded static budget.
- The flash-writing path performs real image/header/size/model-style checks before `mtd_write`; do not describe it as an unchecked direct upload-to-flash path.
- `FUN_00018ddc` behaves like a request verifier/token comparison for some URI classes, but its full security role and relationship to higher-level authentication were not established.
- Three RSA private-key groups remain material leads. Generic `server.key`/`client.key` matches were shown to collide with unrelated OpenVPN/provisioning logic; cross-device reuse/trust remains unproven.
- aMule external-control material remains a conditional Medium candidate because startup/bind/reachability were not established.

Do not hard-code any of the above function addresses/names or vendor-specific path logic into reusable toolkit code.

## Important recent commits

The following commits capture the main native-analysis/automation lessons:

```text
e81f57ad  Require Ghidra fallback for unsupported firmware architectures
c18072db  Escalate unresolved firmware native hypotheses to Ghidra
b9209c54  Require Ghidra-backed retry before final firmware conclusions
3144a907  Validate firmware Ghidra escalation contract

dff2d7fb  Add focused Ghidra reference decompiler for firmware
cf745617  Add focused firmware Ghidra slice wrapper
1e1a785f  Use focused Ghidra slice helper in firmware reverser

e0030bdd  Improve focused firmware Ghidra analysis quality
1df32a91  Prioritize multi-needle firmware Ghidra references
97bd1a70  Keep firmware Ghidra state workspace-local
85810179  Validate firmware Ghidra slice helper
8f2df91d  Add instruction context for firmware Ghidra xrefs
7fd15e23  Allow direct firmware function selection in Ghidra slices
8159180d  Preserve separate firmware Ghidra query slices
0e793574  Make firmware Ghidra reversing iterative and xref-driven
b447d32b  Prioritize internal firmware Ghidra functions over stubs
3987db16  Use distinctive paths for firmware Ghidra secret references

70c325fe  Bound firmware reverse-engineering convergence
35f7c93c  Bound firmware native-analysis convergence
4d23cad9  Make firmware Ghidra convergence budget configurable
0b673ad4  Validate autonomous firmware Ghidra budgets
190baad1  Make firmware reversing autonomous and budget-driven
6bd6a1c3  Make firmware analyze hands-off and budgeted
7127e58d  Document autonomous firmware analysis workflow

501a203d  Require behavioral evidence for firmware concealment
d144fd2e  Challenge firmware concealment classifications
27904a61  Align firmware summary severity and concealment semantics
8bcf061d  Prevent string-only firmware concealment escalation
e2acae82  Validate firmware concealment evidence contract
```

Also preserve earlier preprocessing lessons: service lifecycle vs startup evidence, update UI vs mechanism evidence, group-first secret triage, pruning nested extraction artifacts and avoiding naive version/CVE promotion.

## Current confidence level

Firmware Static v1 has now been exercised end-to-end on one real Netgear R7000 image, including a fresh hands-off regression where Ghidra escalation and convergence happened autonomously.

This is enough to call the R7000 path a useful field/regression validation, but **not enough to claim broad firmware-family generalization**.

The next milestone should therefore be diversity of targets, not deeper R7000 archaeology.

## Recommended next work

### First priority: second firmware family

Use a deliberately different target, ideally changing several dimensions at once:

- different vendor;
- different packaging/extraction path;
- preferably MIPS or another architecture instead of ARM;
- more shell/rc.d/UCI-style startup if possible;
- different web-management implementation;
- different update mechanism.

Run it hands-off with `/analyze`. Do not manually help the agent unless debugging a reusable toolkit defect.

Evaluate whether the suite can independently:

1. extract and establish a rootfs;
2. identify the actual startup model without Netgear-specific assumptions;
3. rank useful service/web/update/native hypotheses;
4. keep secret triage precise;
5. escalate to Ghidra on another architecture when needed;
6. obey the Ghidra convergence budget;
7. stop with truthful `NEEDS VALIDATION` when evidence runs out;
8. avoid false WAN exposure, false CVE applicability and false concealment claims;
9. independently validate important findings;
10. generate a coherent report without operator intervention.

### Second priority: post-run invariant checker

A valuable next reusable component is an automatic post-run checker that validates the **behavior of the AI testsuite**, not the truth of individual vulnerabilities.

Possible invariants:

- all required durable records exist;
- final report exists;
- configured concurrency/budgets are recorded and not exceeded;
- material native hypotheses record whether Ghidra was not attempted / attempted and failed / attempted and exhausted;
- High/Critical promotions have validator artifacts;
- raw secret candidates were not used as LLM input;
- exact secret values are absent from normal reports;
- candidate vs confirmed severity semantics are consistent;
- concealment state has sufficient evidence role;
- research budgets are respected;
- preparation hash matches the target image;
- no operator-manual-analysis dependency is recorded during a normal `/analyze` run.

This would move the project further from "a collection of capable agents" toward a reproducible AI security testing framework.

## Regression matrix to start maintaining

Track future target coverage explicitly rather than relying on narrative confidence:

```text
                         R7000   Target B   Target C
Extraction                PASS      ?          ?
Rootfs discovery          PASS      ?          ?
Deterministic baseline    PASS      ?          ?
Boot/service discovery    PASS      ?          ?
Secret triage             PASS      ?          ?
Update analysis           PASS      ?          ?
Native/Ghidra             PASS      ?          ?
Validation                PASS      ?          ?
Convergence/budgets       PASS      ?          ?
Hands-off operation       PASS      ?          ?
Reporting semantics       PASS*     ?          ?

* A concealment-classification bug was found in the hands-off R7000 run and fixed after the run.
```

## What the next agent should not do

- Do not spend many more rounds manually reversing the R7000 merely to close F-01.
- Do not encode R7000/Netgear-specific addresses, names or patterns in toolkit code.
- Do not treat old component versions as vulnerabilities without local applicability.
- Do not infer service startup from stop scripts or strings.
- Do not infer WAN exposure from webroots/listener code/config alone.
- Do not classify hidden/debug/recovery names as concealment without behavior evidence.
- Do not ask the operator to run analysis commands during a normal `/analyze` flow.
- Do not let one difficult binary consume unbounded analysis budget.

## Useful entry points for the next agent

Read these first:

```text
docs/firmware.md
docs/FIRMWARE_ANALYSIS_PIPELINE.md
modules/firmware/template/.opencode/agents/firmware-security.md
modules/firmware/template/.opencode/agents/binary-reverser.md
modules/firmware/template/.opencode/commands/analyze.md
modules/firmware/template/tools/firmware_ghidra_slice.py
modules/firmware/template/tools/ghidra/SatDecompileRefs.java
lib/validate.py
```

The immediate objective is no longer "finish the R7000". It is:

> Prove that the autonomous, evidence-first, bounded analysis strategy generalizes to a meaningfully different firmware family, and turn any failures into reusable toolkit improvements rather than target-specific patches.
