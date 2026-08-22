# Planned next modules

After the current firmware validation milestone, the next security-analysis modules should be developed in this order.

## 1. PE / EXE malware analysis

Goal: mostly hands-off static-first analysis of Windows PE executables with evidence-first behavior reconstruction.

Likely deterministic baseline:
- PE headers, architecture, sections, entropy and overlays;
- imports/exports/resources/TLS callbacks;
- signing metadata and hashes;
- packer/compiler/runtime clues;
- strings and embedded configuration/material;
- capability/behavior leads such as process creation, injection, persistence, credential access, network/C2, filesystem/registry modification and anti-analysis;
- focused decompilation/reversing only for prioritized hypotheses;
- independent validation before strong malware-behavior or vulnerability claims.

Do not execute untrusted PE targets on the analysis host. Dynamic execution, if added later, requires a separately isolated/gated environment.

## 2. JavaScript malware / payload-chain analysis

Goal: analyze malicious or suspicious `.js` payloads through all locally recoverable stages rather than stopping after first-layer deobfuscation.

The module should recursively and safely trace transformations such as:

```text
input JS
 -> deobfuscation / constant folding / string reconstruction
 -> encoded or encrypted stage recovery
 -> generated/eval'ed JS/VBS/PowerShell/HTA/command lines
 -> URLs/download logic and embedded payloads
 -> dropped/decoded PE or script stages
 -> handoff into the appropriate downstream analyzer
 -> final evidence-backed behavior and malware-chain description
```

Requirements:
- static interpretation/deobfuscation by default; never casually execute target script content;
- bounded recursion/decode depth with provenance for every recovered stage;
- preserve exact parent -> transform -> child relationships and hashes;
- recognize common script-host and LOLBin handoffs without treating names alone as malicious proof;
- extract IOCs separately from validated behavior;
- hand recovered PE files to the PE module when available;
- report both the complete recovered chain and explicit unresolved/dynamic-only gaps;
- resist payload bombs, recursive decoding loops and intentionally huge generated artifacts through hard deterministic budgets.

These should be separate but composable modules rather than one universal malware prompt.
