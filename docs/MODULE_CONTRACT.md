# Module Contract

Each `modules/<id>` needs `module.toml` plus template `AGENTS.md`, `opencode.json`, `start.sh`, and `target/TARGET.example.toml`. All dependencies must exist centrally. Preserve all six supported static-analysis platforms, LXC compatibility, `external_directory=deny`, project-local temporary files, and evidence-first validation.

Static functionality must not require QEMU/libvirt/Docker/KVM/FirmAE or another emulation stack. Optional dynamic capabilities may add a tightly scoped managed runtime only when the module contract explicitly allows it. The APK module may use the optional central dependency `android-emulator`; it must remain optional, capability-gated, and must never reconfigure the host hypervisor or assume `/dev/kvm` is available. KVM is detected host capability, not a toolkit-managed dependency. Other modules remain emulator-free unless this contract is deliberately revised.

Every generated project must expose `[orchestration].max_parallel_agents` in `target/TARGET.toml`; default is 2. Primary/coordinator prompts must read and honor it.

Default `subagent_depth` is 1. Depth 2 is permitted only for a bounded coordinator -> worker architecture where:
- task routing explicitly prevents arbitrary nesting;
- leaf workers have `permission.task: deny`;
- coordinator and worker agents have finite `steps` budgets;
- the nested level materially reduces parent-context growth;
- no third nested level is possible.

When a module supports public research:
- perform cheap local artifact checks before creating a web question;
- every delegated RQ must include why it matters, 2-5 concrete non-sensitive local facts including useful negative evidence, and the exact external fact still needed;
- isolate websearch/webfetch to narrow worker agents;
- workers should discover once, fetch/read the strongest primary source before broadening search;
- bound question count, useful-source count, and report size;
- use one canonical detail artifact per question;
- treat search snippets as discovery leads rather than verified material facts when the decisive source was not actually fetched/read;
- correlate public facts with local evidence before changing a finding;
- prefer a consolidated validator pass for material research-driven changes.

When a security class can be supported by deterministic preprocessing, use reproducible tooling before agent interpretation. Pattern/scanner hits are leads, not findings. Prefer semantic grouping/deduplication before AI review. Where raw scanner output is large, keep it behind a deterministic preprocessing boundary instead of feeding it into LLM context.

For credential/secret workflows:
- keep normal reports redacted by default;
- exact values require explicit per-project opt-in and must remain in a dedicated sensitive-artifact path;
- never send sensitive values into public research or ordinary dynamic instrumentation output;
- distinguish truly confidential/privileged credentials from client-shipped signing material, client-SDK authentication material, public client configuration, certificates/fingerprints, checksums, identifiers, test data and false positives;
- names such as `secret`, `clientSecret` or `APPSECRET` are not confidentiality proofs;
- distinguish reversible encodings from hashes/KDFs; bare digest lengths remain ambiguous without local implementation context;
- automatic cracking/password recovery is outside the normal workflow.

For native-code workflows:
- use a cheap deterministic baseline before expensive reverse engineering;
- enumerate all package/split native libraries and record architecture, hardening/JNI/import/string leads without treating them as findings;
- distinguish baseline coverage from deeper reverse engineering;
- reserve Ghidra/deeper analysis for app-relevant, reachable or otherwise plausible security-sensitive paths.

For optional emulator-backed dynamic workflows:
- capability probe must precede setup and record bare metal/VM/container, CPU virtualization flags, `/dev/kvm` presence/access, emulator hypervisor self-check, package ABI requirements and selected acceleration mode;
- do not infer KVM usability from `vmx`/`svm` alone;
- LXC/container without `/dev/kvm` and VM without nested virtualization must be surfaced as environment limitations, not silently worked around by changing the host;
- software CPU emulation is allowed only by explicit project configuration and must be reported as potentially very slow;
- managed SDK/system images may live in toolkit runtime, but AVD/user/runtime state and captures must remain project-local;
- prefer rootable analysis images where possible and verify root after boot;
- runtime evidence should have deterministic preprocessing before LLM interpretation where practical;
- lack of observation is not proof of absence unless the relevant behavior was actually exercised;
- active validation must remain within the module's defined local/runtime scope. APK emulator-local component/deep-link actions do not authorize backend/API mutation or replay.

APK public research, group-first secret/material triage, deterministic native baseline -> focused native review, and capability-gated emulator runtime analysis are reference implementations of these patterns.
