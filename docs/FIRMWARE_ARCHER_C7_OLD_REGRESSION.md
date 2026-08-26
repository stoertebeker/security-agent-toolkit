# Archer C7 V2 old-firmware regression lesson

Date: 2026-08-22 to 2026-08-26
Target: TP-Link Archer C7(EU) V2, firmware 3.15.3 Build 180305

## First old-firmware run: hypothesis starvation

The first old-firmware regression completed hands-off and passed extraction, webroot/service discovery, secret-group coverage, Ghidra budgeting and post-run invariants, but it missed known ground truth: CVE-2025-9377, an authenticated OS-command-injection vulnerability in the Parental Control page affecting Archer C7(EU) V2 before build 241108.

The miss was not caused by failed extraction or native tooling. Local artifacts already exposed `web/userRpm/ParentCtrlRpm.htm` and `httpParentCtrlInit`, but hypothesis selection favored a diagnostic command-dispatch path and never opened a Parental-Control hypothesis. The failure mode was **hypothesis starvation / first-interesting-path bias**.

Corrections:

1. `firmware_web_surface.py` deterministically ranks management pages and risky/free-form request fields and assigns stable `WS-...` lead IDs.
2. The explorer must explicitly disposition the top configured web leads before expensive review selection.
3. One early bounded `RQ-ADVISORY-SCOUT` may seed known High/Critical feature/parameter hypotheses.
4. `firmware_hypothesis_check.py` rejects silent top-web/advisory-seed omissions.
5. The primary prompt was shortened so deterministic coverage mechanisms carry more policy.

## Second old-firmware run: identity provenance gap

After the web-hypothesis fix, the scanner did select a Parental-Control/rule path and traced it toward privileged shell/iptables behavior. However, the advisory seeds for CVE-2025-9377 and CVE-2023-39224 were deferred because the agent considered exact model/region/build identity unavailable. Both invariant checks still passed.

This exposed a second architectural gap: product identity was an LLM conclusion assembled from incidental strings rather than a deterministic, auditable artifact. Renaming a vendor firmware file to `input/firmware.bin` also discarded useful filename evidence.

Corrections:

1. `firmware_identity.py` now gathers bounded evidence from the configured/source filename, raw image printable metadata and the extracted rootfs.
2. It emits `firmware-identity.{json,txt}` with canonical vendor/product/hardware revision/region/version/build/release values, confidence, alternatives and source context.
3. Optional `[identity]` values in `TARGET.toml` are evidence overrides for unusual images, not normal required operator input.
4. The advisory scout must consume `firmware-identity.json`; when `advisory_ready=true` it may not claim model/build identity is unavailable.
5. CVE-label applicability is separated from the local behavior hypothesis. Partial region/build identity may defer a CVE mapping, but a disclosed local feature/parameter must still be investigated.
6. Advisory scout artifacts use structured `Seed-ID` blocks, and durable analysis records use structured `Seed disposition:` lines. The hypothesis checker validates these relationships.

The broader lesson is that a post-run checker can verify execution invariants while still missing discovery blind spots. Hypothesis coverage and target identity both need deterministic provenance, while the AI should decide how to interpret and validate those evidenced leads.
