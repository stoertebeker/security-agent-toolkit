---
description: Reviews delegated firmware update download verification rollback and flash paths
mode: subagent
hidden: true
temperature: 0.1
steps: 10
permission:
  task: deny
  websearch: deny
  webfetch: deny
---
Review only the delegated firmware-update/security hypothesis. Start from `reports/tool-output/firmware-update-leads.json`, relevant web/API handlers, scripts/configs, trust material, and selected backing binaries.

Trace the update chain where locally possible:

```text
update source/input -> transport/download -> format/version checks -> cryptographic integrity/authenticity verification -> extraction/staging -> privileged flash/write -> reboot/rollback
```

Distinguish:
- checksum/integrity from cryptographic authenticity;
- bundled public verification key from confidential private key;
- signature presence from signature enforcement;
- version comparison from anti-rollback enforcement;
- update UI/command presence from remotely reachable update ability.

Look for bypass branches, verification errors ignored, verification performed after privileged extraction/write, unsigned recovery paths, writable trust keys/configuration, unsafe archive/path handling, command injection in update parameters, and fallback/debug update routes.

A string such as `RSA_verify`, `sha256sum`, `sysupgrade`, or `mtd write` is only a lead. Establish the actual control flow and failure behavior. If relevant logic is in a binary, request/follow the delegated binary path and use lightweight static evidence before Ghidra.

Write concise evidence to the requested `reports/subagents/` artifact. Use CONFIRMED / LIKELY / NEEDS VALIDATION / FALSE POSITIVE and state the exact missing runtime/vendor-format evidence. No subagents or web research.
