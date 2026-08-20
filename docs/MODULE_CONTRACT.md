# Module Contract

Each `modules/<id>` needs `module.toml` plus template `AGENTS.md`, `opencode.json`, `start.sh`, and `target/TARGET.example.toml`. All dependencies must exist centrally. Preserve all six supported platforms, LXC compatibility, no emulation requirement, `external_directory=deny`, project-local temporary files, and evidence-first validation.

Every generated project must expose `[orchestration].max_parallel_agents` in `target/TARGET.toml`; default is 2. Primary/coordinator prompts must read and honor it. This setting is agent-enforced because OpenCode currently has no native max-concurrency scheduler option.

Default `subagent_depth` is 1. Depth 2 is permitted only for a bounded coordinator -> worker architecture where:
- task routing explicitly prevents arbitrary nesting;
- leaf workers have `permission.task: deny`;
- coordinator and worker agents have finite `steps` budgets;
- the nested level materially reduces parent-context growth;
- no third nested level is possible.

When a module supports public research:
- perform cheap local artifact checks before creating a web question;
- isolate websearch/webfetch to narrow worker agents;
- bound question count, useful-source count, and worker-report size;
- use one canonical detail artifact per question and link to it from compact durable indexes/logs rather than duplicating source tables and caveats;
- treat search snippets as discovery leads rather than verified material facts when the decisive source was not actually fetched/read;
- correlate public facts with local evidence before changing a finding;
- prefer a consolidated validator pass for a set of material research-driven changes when appropriate.

When a security class can be supported by deterministic preprocessing, use reproducible tooling before agent interpretation. Pattern/scanner hits are leads, not findings. Prefer semantic grouping/deduplication before AI review so repeated/decompiler/localization copies are not independently re-analyzed. Deterministic priority is ordering only; final plausibility/classification belongs to evidence-aware local review.

For credential/secret workflows:
- keep normal reports redacted by default;
- if exact values are operationally required, expose an explicit per-project opt-in rather than silently copying them into findings or chat summaries;
- confine opted-in plaintext/decoded values to a dedicated local sensitive-artifact path with restrictive permissions where possible;
- never send sensitive values into public research merely because plaintext retention is enabled;
- distinguish reversible encodings from hashes/KDFs and distinguish both from public client configuration, certificates/fingerprints, checksums, identifiers, test data, and false positives;
- bare digest lengths are ambiguous unless local implementation context establishes the algorithm;
- automatic cracking/password recovery is outside the normal analysis workflow.

APK public research and deterministic secret/material preprocessing -> semantic grouping -> bounded AI plausibility triage are reference implementations of these patterns.
