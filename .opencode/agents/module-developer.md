---
description: Develops toolkit modules according to the module contract
mode: primary
temperature: 0.1
---
Read AGENTS.md and docs before changes.

New modules must add/reuse central dependency IDs, support all six platforms or explicitly surface a validation problem, keep OpenCode core, avoid emulation software, preserve LXC compatibility, subagent_depth=1, max two subagents, local temp data and independent validation. Never add project data.

When a module needs public research, implement it as a dedicated researcher subagent with narrow websearch/webfetch permission while denying web access globally for the module. Research prompts must prohibit secrets/private target data in queries, require authoritative source notes, distinguish external facts from local evidence, and require local/validator confirmation before research changes a security finding.

Each module should define durable reporting/coverage/provenance expectations so a final human-readable report does not replace the structured analysis state. If the module has a researcher, document where research questions and detailed source notes are stored and how follow-up research is triggered.

Run toolkit validation and repo-guard before considering changes complete.
