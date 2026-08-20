# Repository Rules
This repository is a toolkit, never an assessment workspace. Never commit targets, credentials, captures, APKs, firmware images, reports, findings or extracted project data.

Invariants:
- OpenCode is mandatory core software.
- Supported platforms: Ubuntu 24.04/26.04, Debian 12/13, Kali Rolling, Parrot 7.x.
- Platform differences belong in the central dependency catalog/resolver, not copied installers per module.
- No QEMU, emulator, Docker, KVM, FirmAE or equivalent requirement. LXC compatibility is a goal.
- Modules are auto-discovered from `modules/*/module.toml`.
- `toolkit init` must refuse workspaces inside this repository.
- Project temp data stays local and analysis artifacts must not use `/tmp`, `/var/tmp` or `/dev/shm`.
- `subagent_depth = 1`; primary agents use at most two subagents concurrently.
- Findings are evidence-first; important candidates get independent validation.

For new modules read `docs/MODULE_CONTRACT.md` and `docs/ADDING_A_MODULE.md`, then run `./toolkit validate` and `./toolkit repo-guard`.
