---
description: Probe and prepare the toolkit-managed Android Emulator for this APK workspace
agent: apk-security
---
Prepare dynamic analysis only; do not repeat static analysis and do not run the application yet.

1. Read `[dynamic]` from `target/TARGET.toml`. If `dynamic.enabled=false`, stop and state that dynamic analysis is intentionally disabled.
2. Run `python3 tools/apk_dynamic.py probe`.
3. Read `reports/tool-output/dynamic-capabilities.txt` and explain the selected mode:
   - KVM accelerated;
   - software emulation;
   - unavailable.
4. If Android Emulator tooling is missing, stop with the exact operator action `./toolkit install apk --with-optional` in the toolkit repository. Do not try to modify the host hypervisor or escape the workspace.
5. If the capability probe is unavailable because LXC/container lacks `/dev/kvm`, a VM lacks nested virtualization, or host architecture is unsupported, preserve that reason. Software emulation may still proceed only when `allow_software_emulation=true` and the probe selected it.
6. Run `python3 tools/apk_dynamic.py setup`.
7. Read `reports/dynamic/setup.json` and report selected Android API, system-image tag, ABI, acceleration mode, and whether root is expected. Do not claim root until boot verifies it.

The setup may download a managed Android system image into `$SAT_HOME/android-sdk`; all AVD state remains project-local under `work/android/`.
