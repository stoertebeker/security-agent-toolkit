---
description: Review firmware update authenticity integrity rollback and flash paths
agent: firmware-security
---
Perform focused update-security review only.

1. Require fresh deterministic preparation/baseline/update artifacts.
2. Read `analysis.max_update_deep_reviews` as a ceiling.
3. Start from `firmware-update-leads.json` as the mechanism/security lead set, `firmware-update-ui-paths.json` only as a navigation/entry-point anchor set, `findings/update-security.md`, and locally identified web/API/update binaries/scripts/trust material.
4. Never promote a UI page name, DOM id, CSS class, help string, or vendor prefix such as `FW_` into update-mechanism evidence by itself. Confirm the backend handler or control flow first.
5. Build the update chain before deciding what needs deep review: source/download -> parsing/version -> integrity/authenticity -> staging -> privileged write -> recovery/rollback.
6. Delegate bounded `firmware-update-reviewer` tasks for the highest-value unresolved mechanism paths. Delegate `binary-reverser` only when the verification/write control flow resides in selected native code.
7. Distinguish checksum from authenticity and signature code from enforced signature failure behavior.
8. Update `findings/update-security.md`, affected `findings/findings.md`, `findings/coverage.md`, and `findings/analysis-log.md`.
9. Important High/Critical candidates require independent `security-validator` review.
10. Do not browse in this command. Queue narrow vendor-format/signature/GPL-source questions for `/research` only after local facts are complete.
