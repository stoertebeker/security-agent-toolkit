# Module Contract

Each `modules/<id>` needs `module.toml` plus template `AGENTS.md`, `opencode.json`, `start.sh`, and `target/TARGET.example.toml`. All dependencies must exist centrally. Preserve all six supported platforms, LXC compatibility, no emulation requirement, `external_directory=deny`, project-local temporary files, and evidence-first validation.

Every generated project must expose `[orchestration].max_parallel_agents` in `target/TARGET.toml`; default is 2. Primary/coordinator prompts must read and honor it. This setting is agent-enforced because OpenCode currently has no native max-concurrency scheduler option.

Default `subagent_depth` is 1. Depth 2 is permitted only for a bounded coordinator -> worker architecture where:
- task routing explicitly prevents arbitrary nesting;
- leaf workers have `permission.task: deny`;
- coordinator and worker agents have finite `steps` budgets;
- the nested level materially reduces parent-context growth;
- no third nested level is possible.

APK public research is the reference implementation for this exception.
