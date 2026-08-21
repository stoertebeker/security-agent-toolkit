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
4. If Android Emulator tooling is missing, stop with the exact operator action `./toolkit install apk --with-optional` in the toolkit repository. Do not modify the host hypervisor/container from the workspace.
5. If an LXC/container has no `/dev/kvm`, explicitly recommend host-side KVM-device passthrough before accepting slow software emulation when the operator controls the host. Do not perform the change from the workspace.

   For Proxmox VE, provide this bounded host-side example and label placeholders clearly:

   ```text
   # On the Proxmox host
   test -c /dev/kvm && ls -l /dev/kvm
   pct config <CTID> | grep -E '^(unprivileged|dev[0-9]+):'

   # Use the next free devN slot. Prefer mode 0660 and the container's kvm GID.
   pct set <CTID> --dev0 path=/dev/kvm,mode=0660,gid=<CONTAINER_KVM_GID>
   pct reboot <CTID>
   ```

   Determine `<CONTAINER_KVM_GID>` inside the container with `getent group kvm`; ensure the analysis user belongs to that group (`sudo usermod -aG kvm <user>` followed by a new login/session). If `dev0` is already used, select the next free `devN` slot. Recent Proxmox VE exposes `dev[n]` specifically for passing a host device into a container.

   After the host-side change, verify inside the container:

   ```text
   ls -l /dev/kvm
   test -r /dev/kvm && test -w /dev/kvm
   emulator -accel-check
   python3 tools/apk_dynamic.py probe
   ```

   The expected improvement is `/dev/kvm: rw`, `KVM usable by emulator: yes`, and `selected acceleration: kvm`. If modern `pct ... --devN` is unavailable on an older Proxmox release, do not invent syntax; refer the operator to the documented cgroup-v2 device-passthrough method (`lxc.cgroup2.devices.allow` plus a bind-mounted `/dev/kvm`) for that release.
6. If the capability probe is unavailable because host architecture/ABI compatibility cannot be supported, preserve the exact reason. LXC/VM without KVM may use same-architecture x86_64 software emulation only when `allow_software_emulation=true`.
7. Run `python3 tools/apk_dynamic.py setup`.
8. Run the real boot capability test:

```text
python3 tools/apk_dynamic_smoke.py
```

This must boot the generated AVD through `sys.boot_completed=1`, verify the device ABI list/root state, then shut it down. It catches runtime/container restrictions that a CPU/KVM probe alone cannot detect.
9. Read `reports/dynamic/setup.json`, `reports/dynamic/setup-smoke.json`, `reports/dynamic/device-info.json`, `reports/dynamic/abi-compatibility.json` when present, and `reports/dynamic/root-status.json`. Report selected Android API/tag/ABI, compatibility mode, acceleration, boot success and actual root availability.

The setup may download a managed Android system image into `$SAT_HOME/android-sdk`; all AVD/user/runtime state remains project-local under `work/android/`.
