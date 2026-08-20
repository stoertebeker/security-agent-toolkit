# Adding a Module

Create `modules/<id>/module.toml` and a project template. Reuse/add dependency IDs in `dependencies/catalog.toml`; special installers go once into `lib/dependencies.sh`. There is no central module registry.

A new module must also:

1. add `target/TARGET.example.toml` with `[engagement]` and `[orchestration]`;
2. set `orchestration.max_parallel_agents = 2` as the default and make its primary/coordinator prompts honor the value;
3. add the primary OpenCode agent and focused subagents;
4. default to `subagent_depth = 1`;
5. use depth 2 only for a bounded coordinator -> worker pattern with explicit task allowlists and `steps` limits;
6. keep web access restricted to dedicated research workers when public research is needed;
7. define local reporting/findings/provenance paths;
8. keep all target/project data outside the toolkit repository and all temporary analysis artifacts project-local;
9. document module usage in README/docs when operator behavior changes;
10. run `./toolkit validate-module <id>`, `./toolkit validate`, and `./toolkit repo-guard`.
