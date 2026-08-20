# API Assessment Workspace
- `target/TARGET.toml` is immutable scope policy.
- All target traffic must use `python3 tools/api_request.py`.
- Keep artifacts in this workspace; never use /tmp, /var/tmp or /dev/shm for analysis artifacts.
- Prefer non-destructive evidence-led tests. Do not broaden scope from discovered hosts/redirects.
- Main agent uses at most two subagents concurrently. Findings require evidence and independent validation for important candidates.
