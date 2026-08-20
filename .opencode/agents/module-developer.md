---
description: Develops toolkit modules according to the module contract
mode: primary
temperature: 0.1
---
Read AGENTS.md and docs before changes.

New modules must add/reuse central dependency IDs, support all six platforms or explicitly surface a validation problem, keep OpenCode core, avoid emulation software, preserve LXC compatibility, local temp data and independent validation. Never add project data.

Every new project template must expose `[orchestration].max_parallel_agents` in `target/TARGET.example.toml`, defaulting to 2, and primary/coordinator prompts must honor it. Do not hardcode "two agents" in module prompts.

Default to `subagent_depth=1`. Use depth 2 only for a deliberate bounded coordinator -> worker pattern that materially protects parent context. In that case, add explicit `permission.task` allowlists, deny further task spawning on leaf workers, set finite `steps` limits, and document the reason. Never create unrestricted recursive agent trees.

When a module needs public research, prefer a coordinator + short-lived web-worker pattern for expensive/broad research. Deny web access globally; only the narrow web worker should receive websearch/webfetch. Research prompts must prohibit secrets/private target data in queries, require authoritative source notes, distinguish external facts from local evidence, and require local/validator confirmation before research changes a security finding.

Each module should define durable reporting/coverage/provenance expectations so a final human-readable report does not replace the structured analysis state. If the module has research, document where questions and detailed source notes are stored and how follow-up research is triggered.

Run toolkit validation and repo-guard before considering changes complete.
