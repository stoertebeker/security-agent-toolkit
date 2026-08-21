---
description: Prepare and inventory firmware without broad AI analysis
agent: firmware-security
---
Prepare the authorized firmware deterministically. Do not perform broad vulnerability analysis or public research.

1. Read `target/TARGET.toml`; require `engagement.authorized=true`.
2. Run in order:

```text
python3 tools/firmware_prepare.py
python3 tools/firmware_baseline.py
python3 tools/firmware_secret_scan.py
python3 tools/firmware_secret_group.py
```

3. Read only the compact deterministic summaries first:
- `reports/tool-output/firmware-preparation.txt`
- `reports/tool-output/firmware-baseline.txt`
- `reports/tool-output/firmware-services.txt`
- `reports/tool-output/firmware-update-leads.txt`
- `reports/tool-output/firmware-secret-groups.txt`

4. Update `findings/inventory.md` and the preparation/baseline/secret coverage portions of `findings/coverage.md`. Do not invent service reachability or vulnerabilities.
5. Record any degraded extraction, rootfs ambiguity, absolute/escaping symlinks, opaque regions, missing extractor dependencies, or baseline parse failures.
6. Give the operator a compact preparation summary: input/hash, extraction status, primary rootfs, file/ELF/service/update/group counts, and the highest-value next review areas.
