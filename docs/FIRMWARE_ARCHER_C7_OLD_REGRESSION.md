# Archer C7 V2 old-firmware regression lesson

Date: 2026-08-22
Target: TP-Link Archer C7(EU) V2, firmware 3.15.3 Build 180305

The old-firmware regression completed hands-off and passed extraction, webroot/service discovery, secret-group coverage, Ghidra budgeting and post-run invariants, but it missed known ground truth: CVE-2025-9377, an authenticated OS-command-injection vulnerability in the Parental Control page affecting Archer C7(EU) V2 before build 241108.

The miss was not caused by failed extraction or native tooling. Local artifacts already exposed `web/userRpm/ParentCtrlRpm.htm` and `httpParentCtrlInit`, but hypothesis selection favored a diagnostic command-dispatch path and never opened a Parental-Control hypothesis. The failure mode is therefore best described as **hypothesis starvation / first-interesting-path bias**.

Generic corrections:

1. `firmware_web_surface.py` deterministically ranks management pages and free-form/risky request fields and assigns stable `WS-...` lead IDs.
2. The explorer must explicitly disposition the top configured web leads before expensive review selection.
3. One early, bounded `RQ-ADVISORY-SCOUT` is allowed for exact product/revision/version identity. Authoritative advisory matches are hypothesis seeds only and still require local validation.
4. `firmware_hypothesis_check.py` fails the run if top web leads were silently ignored or advisory CVE seeds lack a local disposition.
5. The primary prompt was shortened so deterministic coverage mechanisms carry more policy instead of adding another large instruction block.

This regression is a reminder that a post-run checker can verify orchestration invariants and still miss a security-coverage blind spot unless the hypothesis-selection layer itself has measurable coverage.
