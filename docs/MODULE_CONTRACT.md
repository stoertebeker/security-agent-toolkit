# Module Contract

Each `modules/<id>` needs `module.toml` plus template `AGENTS.md`, `opencode.json`, `start.sh`, and `target/TARGET.example.toml`. All dependencies must exist centrally. Preserve all six supported static-analysis platforms, LXC compatibility, `external_directory=deny`, project-local temporary files, and evidence-first validation.

Static functionality must not require QEMU/libvirt/Docker/KVM/FirmAE or another emulation stack. Optional dynamic capabilities may add a tightly scoped managed runtime only when the module contract explicitly allows it. The APK module may use the optional central dependency `android-emulator`; it must remain optional, capability-gated, and must never reconfigure the host hypervisor or assume `/dev/kvm` is available. KVM is detected host capability, not a toolkit-managed dependency. Other modules remain emulator-free unless this contract is deliberately revised.

Every generated project must expose `[orchestration].max_parallel_agents` in `target/TARGET.toml`; default is 2. Primary/coordinator prompts must read and honor it.

Default `subagent_depth` is 1. Depth 2 is permitted only for a bounded coordinator -> worker architecture where task routing prevents arbitrary nesting, leaf workers deny further tasks, finite step budgets exist, and no third nested level is possible.

When a module supports public research:
- perform cheap local artifact checks before a web question;
- every RQ must include why it matters, 2-5 concrete non-sensitive local facts and the exact external fact needed;
- isolate web access to narrow workers;
- discover once, fetch/read the strongest primary source before broadening search;
- bound question/source/report size;
- use one canonical detail artifact per question;
- treat unfetched search snippets as leads only;
- correlate public facts with local evidence and validate material changes.

When deterministic preprocessing can reduce a security class, use it before agent interpretation. Pattern/scanner hits are leads, not findings. Large raw outputs stay behind filter/group/dedup boundaries rather than entering LLM context directly.

Credential workflows must keep normal output redacted and distinguish truly confidential/privileged credentials from client signing material, client-SDK authentication material, public client configuration, certificates/fingerprints, checksums, identifiers, tests and false positives. Secret-like names are not confidentiality proofs. Automatic cracking is outside normal workflow.

Native workflows use a cheap deterministic baseline across all base/split libraries before deeper reversing. Record architecture/hardening/JNI/import/string leads, distinguish baseline from deeper review, and reserve Ghidra for app-relevant/reachable paths.

For optional emulator-backed dynamic workflows:
- capability probe precedes setup and records bare metal/VM/container, CPU virtualization flags, `/dev/kvm` access, emulator hypervisor self-check, package ABI requirements and selected runtime strategy;
- KVM usability must not be inferred from `vmx`/`svm` alone;
- LXC without `/dev/kvm` and VM without nested virtualization are environment limitations, not invitations to alter the host;
- same-architecture software emulation is explicit and reported as slow;
- ABI compatibility must use documented runtime paths only. For APK on x86_64, Android-11/API-30 x86_64 multi-ABI compatibility may be used for ARMv7/ARM64 package code only when `minSdk <= 30` and the project permits it; label it API-30 compatibility coverage rather than target-OS coverage;
- if no documented compatible runtime exists, report `UNAVAILABLE` instead of attempting speculative cross-architecture emulation;
- setup must include a real boot smoke test, not only static host capability checks;
- managed SDK/system images may live in toolkit runtime, but AVD/user/runtime state and captures remain project-local;
- prefer rootable analysis images where possible and verify root after boot;
- runtime evidence should have deterministic preprocessing before LLM interpretation;
- lack of observation is not proof of absence unless the relevant behavior was exercised;
- active actions must be bounded and auditable. APK active validation uses its toolkit wrapper for declared components/custom schemes/UI actions and does not silently expand into backend/API mutation or replay.

APK public research, group-first secret/material triage, deterministic native baseline -> focused native review, and capability-gated emulator runtime analysis are reference implementations of these patterns.
