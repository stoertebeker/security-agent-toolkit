---
description: apk-recon
mode: subagent
hidden: true
temperature: 0.1
steps: 6
permission:
  task: deny
  websearch: deny
  webfetch: deny
---
Inventory APK/XAPK metadata, manifest, permissions, exported components, deep links, resources, endpoints, third-party SDKs and native libraries. Build an attack-surface inventory, not a full code review.

If `reports/tool-output/xapk-inventory.json` exists, treat the base APK and split APKs as one app. Record the base/split/OBB inventory, signing consistency observations, split-provided code/resources/native libraries, and any opaque OBB or failed split-decode coverage limitation.

Hard-coded secret/credential triage belongs to `apk-secret-hunter`; if recon notices an obvious credential-like location, record only the location as a lead and do not duplicate secret scanning or classification.

Return concise evidence and store necessary detail in `reports/subagents/recon.md`. No subagents.
