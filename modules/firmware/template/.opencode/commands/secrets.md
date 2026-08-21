---
description: Refresh group-first firmware credential and secret/material triage
agent: firmware-security
---
Perform only firmware credential/material triage; do not repeat broad exploration, binary reversing or research.

1. Require authorized target and existing preparation/rootfs artifacts.
2. Run:

```text
python3 tools/firmware_secret_scan.py
python3 tools/firmware_secret_group.py
```

3. Never load or iterate `firmware-secret-candidates.json` in LLM context.
4. Delegate one `firmware-secret-hunter` task. It must use only semantic groups and bounded review workers.
5. Integrate its redacted conclusions into `findings/secrets.md` and only create/update a finding when local usage/trust consequences justify it.
6. Preserve distinctions between plaintext/reusable credentials, password hashes, locked/empty accounts, host/service private keys, public trust material, service integration material, tests/placeholders and false positives.
7. Update `findings/coverage.md` and `findings/analysis-log.md` with group counts, batches, worker outcomes and limitations.
8. Do not crack hashes/passwords and do not perform web research.
