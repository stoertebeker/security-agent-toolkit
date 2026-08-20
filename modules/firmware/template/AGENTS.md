# Firmware Analysis Workspace
- Analyze only the authorized firmware configured in target/TARGET.toml.
- Static analysis only; no QEMU/emulator requirement.
- Keep artifacts local and never use /tmp, /var/tmp or /dev/shm for analysis artifacts.
- Prioritize network-facing services, web/API/auth, hardcoded credentials/secrets, privileged daemons/IPC, update verification and memory-safety risks.
- Read `[orchestration].max_parallel_agents` from TARGET.toml and never exceed that many concurrently executing delegated tasks; default to 2 when absent.
- Important findings require independent validation.
