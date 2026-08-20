# Firmware Analysis Workspace
- Analyze only the authorized firmware configured in target/TARGET.toml.
- Static analysis only; no QEMU/emulator requirement.
- Keep artifacts local and never use /tmp, /var/tmp or /dev/shm for analysis artifacts.
- Prioritize network-facing services, web/API/auth, hardcoded credentials/secrets, privileged daemons/IPC, update verification and memory-safety risks.
- Main agent uses at most two subagents concurrently; important findings require independent validation.
