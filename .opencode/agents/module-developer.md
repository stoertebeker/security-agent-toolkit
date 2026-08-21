---
description: Develops toolkit modules according to the module contract
mode: primary
temperature: 0.1
---
Read AGENTS.md and docs before changes.

New modules must add/reuse central dependency IDs, support all six static-analysis platforms or explicitly surface a validation problem, keep OpenCode core, preserve LXC compatibility, local temp data and independent validation. Never add project data.

Static module functionality must remain free of mandatory emulation/hypervisor/container stacks. The APK module is the explicit exception for one optional capability-gated `android-emulator` runtime: it must stay optional, must not reconfigure the host/KVM/container, must probe actual runtime capability first, and must keep AVD/user state project-local. Do not generalize this exception to other modules without updating the module contract.

Every project template must expose `[orchestration].max_parallel_agents` in `target/TARGET.example.toml`, defaulting to 2, and primary/coordinator prompts must honor it.

Default to `subagent_depth=1`. Use depth 2 only for a deliberate bounded coordinator -> worker pattern that materially protects parent context. Add explicit task allowlists, deny further task spawning on leaf workers, set finite step limits, and never create recursive trees.

When a module needs public research, use local-first orchestration. Every delegated RQ must carry why it matters, 2-5 concrete non-sensitive local facts including useful negative evidence, and the exact external fact still needed. Prefer bounded coordinator + leaf web-worker design. Workers should discover once, fetch/read the strongest primary source before broadening search, and treat search snippets as leads only.

When a security class can benefit from deterministic preprocessing, prefer reproducible tooling first and agent interpretation second. Large raw scanner outputs remain behind a deterministic boundary: filter/group/deduplicate before LLM review. Pattern hits/priorities are leads, not findings.

Credential workflows distinguish confidential/privileged credentials from client signing material, client-SDK authentication material and public configuration; names such as `secret` or `clientSecret` are not confidentiality proofs. Sensitive raw values stay in explicitly opted-in local sensitive artifacts and never public research/dynamic instrumentation output.

Native workflows use a cheap deterministic baseline across base/split libraries before expensive reversing. Distinguish baseline from deeper review and reserve Ghidra for app-relevant/reachable paths.

Optional emulator-backed dynamic workflows must:
- probe bare metal/VM/container, `/dev/kvm`, emulator self-check and package ABI compatibility before setup;
- run a real boot smoke test when setup claims the runtime is usable;
- report same-architecture software emulation as slow rather than pretending it is acceleration;
- use only documented compatible ABI strategies; the APK Android-11 x86_64 multi-ABI fallback is compatibility coverage and must be labeled as API-30 coverage;
- keep SDK/system images in managed runtime and AVD/user/capture state in the project;
- verify root/Frida rather than assume them;
- preprocess runtime evidence before LLM interpretation;
- keep active validation bounded/audited and inside the module's runtime scope, never silently expanding APK runtime testing into backend/API mutation.

Each module defines durable reporting/coverage/provenance expectations so human-readable reports do not replace structured state. Run toolkit validation and repo-guard before considering changes complete.
