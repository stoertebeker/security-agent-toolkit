---
description: Review firmware update authenticity integrity rollback and flash paths
agent: firmware-security
---
Perform focused update-security review only.

1. Require fresh deterministic preparation/baseline/update-lead artifacts.
2. Read `analysis.max_update_deep_reviews` as a ceiling.
3. Start from `firmware-update-leads.json`, `findings/update-security.md`, and locally identified web/API/update binaries/scripts/trust material.
4. Build the update chain before deciding what needs deep review: source/download -> parsing/version -> integrity/authenticity -> staging -> privileged write -> recovery/rollback.
5. Delegate bounded `firmware-update-reviewer` tasks for the highest-value unresolved paths. Delegate `binary-reverser` only when the verification/write control flow resides in selected native code.
6. Distinguish checksum from authenticity and signature code from enforced signature failure behavior.
7. Update `findings/update-security.md`, affected `findings/findings.md`, `findings/coverage.md`, and `findings/analysis-log.md`.
8. Important High/Critical candidates require independent `security-validator` review.
9. Do not browse in this command. Queue narrow vendor-format/signature/GPL-source questions for `/research` only after local facts are complete.
