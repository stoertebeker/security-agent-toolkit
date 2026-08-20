# Module Contract

Each `modules/<id>` needs `module.toml` plus template `AGENTS.md`, `opencode.json`, `start.sh`. All dependencies must exist centrally. Preserve six platforms, LXC compatibility, no emulation, `subagent_depth=1`, `external_directory=deny`, max two subagents and evidence-first validation.
