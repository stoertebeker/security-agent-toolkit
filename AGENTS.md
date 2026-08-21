# Repository Rules
This repository is a toolkit, never an assessment workspace. Never commit targets, credentials, captures, APKs, firmware images, reports, findings or extracted project data.

Invariants:
- OpenCode is mandatory core software.
- Supported platforms for static analysis: Ubuntu 24.04/26.04, Debian 12/13, Kali Rolling, Parrot 7.x.
- Platform differences belong in the central dependency catalog/resolver, not copied installers per module.
- Static modules must not require QEMU, Docker, KVM, FirmAE or equivalent emulation stacks. LXC compatibility remains a goal.
- APK dynamic analysis may expose exactly one optional managed `android-emulator` dependency. It must be capability-gated, must not install/reconfigure a host hypervisor, and must keep AVD state project-local. KVM is a detected host capability, not a toolkit-managed requirement. Other modules remain emulator-free unless the module contract is explicitly revised.
- Modules are auto-discovered from `modules/*/module.toml`.
- `toolkit init` must refuse workspaces inside this repository.
- Project temp data stays local and analysis artifacts must not use `/tmp`, `/var/tmp` or `/dev/shm`.
- Every project template should expose `[orchestration].max_parallel_agents` in TARGET.toml, defaulting to 2. Agent prompts must honor it.
- Default subagent depth is 1. A module may use depth 2 only for a deliberately bounded coordinator -> worker pattern with explicit task routing, step limits, and no further nesting.
- Findings are evidence-first; important candidates get independent validation.
- Large deterministic scanner outputs should stay behind a preprocessing boundary. Filter/group/deduplicate before LLM review when practical.
- Credential/material workflows must distinguish actually confidential/privileged secrets from client-shipped signing material, client-SDK authentication material, public client configuration and mere secret-like names.
- Native-code workflows should use a deterministic low-cost baseline before expensive reversing and distinguish baseline coverage from deeper review.
- Dynamic evidence must distinguish observed runtime behavior from unexercised behavior; emulator/container limitations are coverage issues, not target findings.
- APK active dynamic validation is emulator-local. It must not silently expand into backend/API request mutation or replay.
- When a module supports public research, web access belongs only to narrowly scoped workers. Every delegated RQ should carry concrete non-sensitive local applicability facts and the exact external fact still needed. Search snippets alone must not change findings.
- Public research must not expose sensitive assessment data and never replaces local validation.
- Human-readable reports should be derived from durable structured findings/coverage/provenance records rather than replacing them.

For new modules read `docs/MODULE_CONTRACT.md` and `docs/ADDING_A_MODULE.md`, then run `./toolkit validate` and `./toolkit repo-guard`.
