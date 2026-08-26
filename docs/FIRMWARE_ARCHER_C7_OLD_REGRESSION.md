# Archer C7 V2 old-firmware regression lesson

Date: 2026-08-22 to 2026-08-26
Target: TP-Link Archer C7(EU) V2, firmware 3.15.3 Build 180305

## First old-firmware run: hypothesis starvation

The first old-firmware regression completed hands-off and passed extraction, webroot/service discovery, secret-group coverage, Ghidra budgeting and post-run invariants, but it missed known ground truth: CVE-2025-9377, an authenticated OS-command-injection vulnerability in the Parental Control page affecting Archer C7(EU) V2 before build 241108.

The miss was not caused by failed extraction or native tooling. Local artifacts already exposed `web/userRpm/ParentCtrlRpm.htm` and `httpParentCtrlInit`, but hypothesis selection favored a diagnostic command-dispatch path and never opened a Parental-Control hypothesis. The failure mode was **hypothesis starvation / first-interesting-path bias**.

Corrections:

1. `firmware_web_surface.py` deterministically ranks management pages and risky/free-form request fields and assigns stable `WS-...` lead IDs.
2. The explorer must explicitly disposition the top configured web leads before expensive review selection.
3. `firmware_hypothesis_check.py` rejects silent top-web omissions.
4. The primary prompt was shortened so deterministic coverage mechanisms carry more policy.

## Second old-firmware run: assisted correlation and identity provenance

The second run selected a Parental-Control/rule path and traced it toward privileged shell/iptables behavior, but an experimentally enabled advisory scout allowed known CVEs to seed hypotheses. That was unsuitable for a blind-discovery benchmark. The scout then deferred CVE applicability because model/region/build identity was considered unavailable, even though both invariant checks passed.

This exposed two separate issues:

1. Blind discovery and assisted known-vulnerability correlation must be distinct modes. `advisory_scout=false` is now the default and product/build CVE discovery is prohibited in blind mode.
2. Product identity was an LLM conclusion assembled from incidental strings rather than a deterministic, auditable artifact.

Corrections:

- `firmware_identity.py` emits bounded, auditable identity/provenance without using identity to seed blind attack paths.
- Vendor filenames are preserved when practical; the parser uses structured filename/metadata evidence and prevents repeated weak strings from overwhelming strong evidence.
- Optional `[identity]` overrides exist for unusual images but are not normal required input.
- Assisted mode, when explicitly enabled, keeps CVE applicability separate from local behavior validation.

## Third old-firmware run: web parameter to native sink gap

The third run was a clean blind-discovery assessment. Identity was correct, advisory scouting was disabled, the top six deterministic web leads were all considered, secret triage and Ghidra budgets passed, and independent validation ran. The scanner still did not establish the known command-injection ground truth. Its largest static uncertainty was whether attacker-controlled HTTP input reached privileged IPC/native sinks.

This narrowed the remaining failure to **input provenance across native/IPC boundaries**. `firmware_web_surface.py` could identify a risky management page/request field, but after that the AI had to infer which ELF consumed those exact tokens. Deep review therefore drifted into broad labels such as HTTPD management routes and UCLITED IPC instead of preserving a concrete request field from web source to privileged sink.

Corrections:

1. `firmware_web_native_bridge.py` now correlates ranked `WS-...` leads and exact request fields/form/route tokens against the deterministic ELF inventory and assigns stable `WB-...` bridge IDs.
2. Exact risky fields that co-occur with a route in an HTTP-facing binary, or with sensitive operations in a downstream consumer, become trace-ready bridge candidates.
3. Web/native hypotheses must preserve the exact attacker-controlled field through HTTP parsing, IPC serialization/dispatch, receiving daemon/library, validation and sink analysis.
4. The first Ghidra slice for a bridged web hypothesis should use the concrete risky field plus route/form token when available; later slices follow recovered functions while retaining the same hypothesis ID across binaries/processes.
5. Explorer output now uses structured `Web disposition:` and `Bridge disposition:` records.
6. `firmware_hypothesis_check.py` verifies bridge provenance, requires disposition of the strongest trace-ready bridge for investigated top web leads, and verifies that a `TRACE` bridge is propagated beyond the explorer into downstream analysis.

## General lesson

A post-run PASS must not merely prove that tools ran, budgets were obeyed and artifacts exist. For autonomous vulnerability discovery it must also make the **hypothesis-selection and source-provenance chain measurable**:

```text
web input -> candidate native consumer -> focused control-flow trace -> cross-process/library handoff -> privileged sink -> validation outcome
```

Deterministic tooling should preserve those anchors; the AI should decide what they mean rather than having to rediscover them from scratch.
