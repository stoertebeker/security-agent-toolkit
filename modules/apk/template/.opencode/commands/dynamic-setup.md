---
description: Probe and prepare the toolkit-managed Android Emulator for this APK workspace
agent: apk-security
---
Prepare dynamic analysis only; do not repeat static analysis or perform target interactions.

1. Read `[dynamic]` from `target/TARGET.toml`. If `dynamic.enabled=false`, stop and state that dynamic analysis is intentionally disabled.
2. Run `python3 tools/apk_dynamic.py probe`.
3. Read `reports/tool-output/dynamic-capabilities.txt` and explain:
   - host environment (bare metal / VM / container);
   - `/dev/kvm` and emulator acceleration status;
   - package native ABIs;
   - runtime ABI mode (`native-x86_64`, no-native, Android-11 multi-ABI compatibility, or unavailable);
   - selected KVM/software/unavailable mode.
4. The Android Emulator is a toolkit-managed binary under `$SAT_HOME/bin` (default `~/.local/share/security-agent-toolkit/bin`). It is intentionally not required to be on the operator's interactive shell `PATH`. Therefore `emulator: command not found` in a normal shell does NOT mean the toolkit runtime is missing when the capability probe says `tooling ready: yes` / `emulator_installed: true`.

   To invoke the managed binary manually, use:

   ```text
   SAT_HOME=${SAT_HOME:-$HOME/.local/share/security-agent-toolkit}
   "$SAT_HOME/bin/emulator" -accel-check
   ```

   Do not install a second distro-provided Android Emulator merely because the shell suggests a package such as `google-android-emulator-installer`; that would create a second unmanaged runtime beside the toolkit copy.
5. If Android Emulator tooling is genuinely missing according to the capability probe, stop with the exact operator action `./toolkit install apk --with-optional` in the toolkit repository. Do not modify the host hypervisor/container from the workspace.
6. If an LXC/container has no `/dev/kvm`, explicitly recommend host-side KVM-device passthrough before accepting slow software emulation when the operator controls the host. Do not perform the change from the workspace.

   For Proxmox VE, provide this bounded host-side example and label placeholders clearly:

   ```text
   # On the Proxmox host
   test -c /dev/kvm && ls -l /dev/kvm
   pct config <CTID> | grep -E '^(unprivileged|dev[0-9]+):'

   # Use the next free devN slot. Prefer mode 0660 and the container's kvm GID.
   pct set <CTID> --dev0 path=/dev/kvm,mode=0660,gid=<CONTAINER_KVM_GID>
   pct reboot <CTID>
   ```

   Determine `<CONTAINER_KVM_GID>` inside the container with `getent group kvm`; ensure the analysis user belongs to that group (`sudo usermod -aG kvm <user>` followed by a new login/session). If `dev0` is already used, select the next free `devN` slot.

   After the host-side change, verify inside the container:

   ```text
   ls -l /dev/kvm
   test -r /dev/kvm && test -w /dev/kvm
   SAT_HOME=${SAT_HOME:-$HOME/.local/share/security-agent-toolkit}
   "$SAT_HOME/bin/emulator" -accel-check
   python3 tools/apk_dynamic.py probe
   ```

   The expected improvement is `/dev/kvm: rw`, `KVM usable by emulator: yes`, and `selected acceleration: kvm`. If modern `pct ... --devN` is unavailable on an older Proxmox release, do not invent syntax; refer the operator to the documented cgroup-v2 device-passthrough method for that release.
7. If the capability probe is unavailable because host architecture/ABI compatibility cannot be supported, preserve the exact reason. LXC/VM without KVM may use same-architecture x86_64 software emulation only when `allow_software_emulation=true`.
8. Run `python3 tools/apk_dynamic.py setup`.
9. Run the real boot capability test:

```text
python3 tools/apk_dynamic_smoke.py
```

This must boot the generated AVD through `sys.boot_completed=1`, inspect native CPU ABIs, Android native-bridge translation properties, and actual root-shell state, then shut it down. It catches runtime/container restrictions that a CPU/KVM probe alone cannot detect.

For `android11-x86_64-multiabi-translation`, do NOT require `ro.product.cpu.abilist` itself to contain `arm64-v8a`. That property may describe only the device's native x86/x86_64 ABIs while ARM compatibility is supplied through Android's native bridge. The smoke test must instead verify the native-bridge/ISA-translation properties. The later `adb install` / `adb install-multiple` step in `/dynamic` is the final package-level compatibility test.

Root handling is similarly evidence-based: if `adb shell id` already reports `uid=0`, treat root as available and do not require a successful extra `adb root` restart. If root cannot be established, continue non-root dynamic coverage and record Frida/root-only evidence as unavailable rather than failing the entire runtime.
10. Read `reports/dynamic/setup.json`, `reports/dynamic/setup-smoke.json`, `reports/dynamic/device-info.json`, `reports/dynamic/abi-compatibility.json` when present, and `reports/dynamic/root-status.json`. Report selected Android API/tag/ABI, compatibility basis (`direct-device-abilist` or `android-native-bridge`), acceleration, boot success and actual root availability.

The setup may download a managed Android system image into `$SAT_HOME/android-sdk`; all AVD/user/runtime state remains project-local under `work/android/`.
