# APK Analysis Workspace
- Analyze only the APK configured in target/TARGET.toml and only when authorized=true.
- Keep all artifacts local; no /tmp, /var/tmp or /dev/shm for analysis artifacts.
- Static analysis is primary. No local emulator is required. Optional ADB/Frida testing may target an external authorized device only when explicitly enabled.
- Main agent uses at most two subagents concurrently. Important findings get independent validation.
