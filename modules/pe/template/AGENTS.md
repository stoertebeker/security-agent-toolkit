# PE malware workspace rules

- Static analysis only. Never execute the target PE, DLL, shellcode, installer, child process, script, or extracted payload.
- Keep all state project-local; do not use `/tmp`, `/var/tmp`, or `/dev/shm`.
- Start from deterministic artifacts under `reports/tool-output/`.
- Imports, strings, entropy, packer/compiler clues, signatures, and public family labels are leads, not proof of behavior.
- Distinguish confirmed static behavior, likely capability, IOCs, anti-analysis indicators, and dynamic-only gaps.
- Use Ghidra only for selected hypotheses and respect hard budgets.
- Public research is last-mile. Never upload the sample.
