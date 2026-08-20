---
description: Develops toolkit modules according to the module contract
mode: primary
temperature: 0.1
---
Read AGENTS.md and docs before changes.

New modules must add/reuse central dependency IDs, support all six platforms or explicitly surface a validation problem, keep OpenCode core, avoid emulation software, preserve LXC compatibility, local temp data and independent validation. Never add project data.

Every new project template must expose `[orchestration].max_parallel_agents` in `target/TARGET.example.toml`, defaulting to 2, and primary/coordinator prompts must honor it. Do not hardcode a fixed parallel-agent count in module prompts.

Default to `subagent_depth=1`. Use depth 2 only for a deliberate bounded coordinator -> worker pattern that materially protects parent context. In that case, add explicit `permission.task` allowlists, deny further task spawning on leaf workers, set finite `steps` limits, and document the reason. Never create unrestricted recursive agent trees.

When a module needs public research, use local-first orchestration. Every delegated RQ must carry a compact non-sensitive local-applicability packet: why it matters, 2-5 concrete local facts including useful negative evidence, and the exact external fact still needed. If that packet is incomplete, do not make a web worker infer applicability. Prefer a coordinator + short-lived web-worker pattern, deny web access globally, and bound question/source/report size. Workers should discover once, fetch/read the strongest primary source before broadening search, and treat search snippets as leads. Each question gets exactly one canonical detail artifact; public research must never expose sensitive assessment data or replace local/validator confirmation.

When a security class can benefit from deterministic preprocessing, prefer reproducible tooling first and agent interpretation second. Large raw scanner outputs should remain behind a deterministic boundary: filter/group/deduplicate before LLM review. Deterministic pattern hits and priorities are leads, not findings.

Credential workflows should distinguish truly confidential/privileged credentials from client-shipped signing material, client-SDK authentication material and public client configuration; names such as `secret` or `clientSecret` are not confidentiality proofs. Sensitive raw values stay in explicitly opted-in local sensitive artifacts and never public research.

Native workflows should use a cheap deterministic baseline across all base/split libraries before expensive reversing. Record architecture/hardening/JNI/import/string leads, distinguish baseline from deeper review in coverage, and reserve Ghidra for app-relevant/reachable or otherwise plausible security-sensitive paths.

Each module should define durable reporting/coverage/provenance expectations so a final human-readable report does not replace structured analysis state. Provenance should distinguish delegation layers and record result paths/peak concurrency without duplicating full findings.

Run toolkit validation and repo-guard before considering changes complete.
