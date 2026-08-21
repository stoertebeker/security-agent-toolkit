# APK dynamic analysis

The APK module's dynamic v1 workflow is deliberately self-contained: it uses a toolkit-managed Android Emulator and does not require an external Android device.

## Install

Static-only installation remains unchanged:

```bash
./toolkit install apk
```

Dynamic extras are explicit:

```bash
./toolkit install apk --with-optional
./toolkit doctor apk
```

This installs the managed Android command-line tools/emulator/platform-tools under `$SAT_HOME/android-sdk` plus local PCAP parsing support. System images are installed on demand.

The toolkit does not install libvirt, modify KVM permissions, enable nested virtualization, change LXC configuration, or pass `/dev/kvm` into a container.

### Managed tools and the interactive shell PATH

The Android runtime belongs to the toolkit, not to the distribution. The installer creates managed entry points under:

```text
$SAT_HOME/bin
```

with the default:

```text
~/.local/share/security-agent-toolkit/bin
```

`apk_dynamic.py`, `./toolkit doctor`, and the OpenCode workflow prepend this directory internally. The operator's normal interactive shell does not have to contain it. Therefore this can be normal:

```text
$ emulator
Command 'emulator' not found
```

while the capability probe simultaneously reports:

```text
tooling ready: yes
emulator_installed: true
```

To call the managed emulator manually, use:

```bash
SAT_HOME=${SAT_HOME:-$HOME/.local/share/security-agent-toolkit}
"$SAT_HOME/bin/emulator" -accel-check
```

Do **not** install a second distro-provided emulator merely because the shell suggests a package such as `google-android-emulator-installer`. That would create a second unmanaged Android runtime beside the toolkit copy and make diagnostics/version selection ambiguous.

Some Android command-line-tools releases may also print a migration/deprecation warning for `sdkmanager`. Treat the warning itself as non-fatal when the toolkit install check completes successfully; the managed runtime remains the source of truth for the workflow rather than a second system installation.

## Configure

Enable dynamic analysis in the project `target/TARGET.toml`:

```toml
[dynamic]
enabled=true
backend="auto"
api_level=36
image_tag="auto"
allow_software_emulation=true
allow_android11_multiabi_fallback=true
headless=true
wipe_data_on_start=true
grant_runtime_permissions=false
request_root=true
allow_frida=true
allow_active_validation=false
memory_mb=4096
cores=4
boot_timeout_seconds=600
observation_seconds=15
emulator_port=5554
```

Start conservatively with `allow_active_validation=false`. Frida is also optional; if the chosen image does not provide root, the workflow records Frida as unavailable rather than repackaging the target.

## Environment probe

Run:

```bash
python3 tools/apk_dynamic.py probe
```

Outputs:

```text
reports/tool-output/dynamic-capabilities.txt
reports/tool-output/dynamic-capabilities.json
```

The probe distinguishes:

| Environment | KVM result | Toolkit behavior |
|---|---|---|
| bare metal + usable `/dev/kvm` | accelerated | KVM |
| VM + nested virtualization exposed as `/dev/kvm` | accelerated | KVM |
| VM without `/dev/kvm` | not accelerated | software x86_64 if allowed; otherwise unavailable |
| LXC/container + `/dev/kvm` passed through and usable | accelerated | KVM |
| LXC/container without `/dev/kvm` | not accelerated | software x86_64 if allowed; otherwise unavailable |
| non-x86_64 host | dynamic v1 unsupported | unavailable; static analysis remains supported |

`vmx`/`svm` CPU flags are diagnostic only. KVM mode is selected only when the Android Emulator itself reports acceleration usable.

## Proxmox VE LXC: pass `/dev/kvm` through when possible

When the probe reports `container/lxc`, CPU virtualization flags are visible, but `/dev/kvm` is absent, a Proxmox operator can normally improve the runtime substantially by passing the host KVM character device into the analysis CT.

First verify on the **Proxmox host**:

```bash
test -c /dev/kvm && ls -l /dev/kvm
pct config <CTID> | grep -E '^(unprivileged|dev[0-9]+):'
```

Inside the **container**, determine the intended KVM group ID and add the analysis user to the group when needed:

```bash
getent group kvm
sudo usermod -aG kvm <analysis-user>
```

Then, on recent Proxmox VE releases, use a free `devN` slot:

```bash
pct set <CTID> --dev0 path=/dev/kvm,mode=0660,gid=<CONTAINER_KVM_GID>
pct reboot <CTID>
```

If `dev0` is already present, use the next free `devN`. The `gid` is the `kvm` group ID as seen inside the container. Start a new login/session after changing group membership. Current Proxmox `pct` documents `dev[n]` as a device passed through to the container, with configurable path, GID and mode.

Verify inside the container using the managed emulator path:

```bash
ls -l /dev/kvm
test -r /dev/kvm && test -w /dev/kvm && echo kvm-device-rw
SAT_HOME=${SAT_HOME:-$HOME/.local/share/security-agent-toolkit}
"$SAT_HOME/bin/emulator" -accel-check
python3 tools/apk_dynamic.py probe
```

The desired result is:

```text
/dev/kvm: rw
KVM usable by emulator: yes
selected acceleration: kvm
```

A successfully verified Proxmox/LXC setup may look like:

```text
host architecture: x86_64
virtualization: container/lxc
/dev/kvm: rw
tooling ready: yes
KVM usable by emulator: yes
target ABIs: arm64-v8a
runtime ABI mode: android11-x86_64-multiabi-translation
selected image ABI: x86_64
selected API override: 30
selected acceleration: kvm
dynamic available: yes
```

Older Proxmox VE releases that do not support `pct ... --devN` use the cgroup-v2 device-passthrough mechanism instead. Proxmox documents `lxc.cgroup2.devices.allow` for cgroup-v2 hardware passthrough; `/dev/kvm` is normally character device major/minor `10:232`, but verify the actual host device before using legacy configuration. A typical legacy configuration is conceptually:

```text
lxc.cgroup2.devices.allow: c 10:232 rwm
lxc.mount.entry: /dev/kvm dev/kvm none bind,optional,create=file
```

Prefer the native `devN` device-passthrough option when available because it handles the container device entry explicitly.

Passing `/dev/kvm` increases the container's access to the host kernel's KVM interface. Use it for a dedicated trusted analysis container rather than treating it as a zero-cost isolation feature. The toolkit never makes this host-side change itself.

## ABI compatibility

The package's prepared native ABIs are part of the runtime decision.

On x86_64:

1. x86_64 native library present: use x86_64 system image at the requested/target API where available.
2. no native libraries: use x86_64 normally.
3. native code exists but no x86_64 library, and `minSdk <= 30`: when enabled, use Android 11/API 30 x86_64 multi-ABI compatibility. Android 11 x86_64 emulator images support ARM binaries through Android's native-bridge translation mechanism.
4. no compatible documented path: report `UNAVAILABLE`.

For the Android-11 multi-ABI path, `ro.product.cpu.abilist` is **not** by itself the compatibility verdict. A booted x86_64 image may report only native `x86,x86_64` ABIs there while ARM compatibility is supplied through the native bridge. The smoke test therefore records and checks properties such as:

```text
ro.dalvik.vm.native.bridge
ro.enable.native.bridge.exec
ro.dalvik.vm.isa.arm64
ro.dalvik.vm.isa.arm
ro.ndk_translation.version / ro.berberis.version
```

`reports/dynamic/abi-compatibility.json` distinguishes direct native compatibility from `android-native-bridge` compatibility. The later successful `adb install` / `adb install-multiple` step is the final package-level compatibility proof and is added to that artifact.

The Android-11 fallback validates runtime behavior on API 30 only. Do not generalize the result to Android 16/17 platform-specific behavior.

## Setup smoke test

Inside OpenCode:

```text
/dynamic-setup
```

or manually:

```bash
python3 tools/apk_dynamic.py setup
python3 tools/apk_dynamic_smoke.py
```

The smoke test performs a real boot, waits for `sys.boot_completed=1`, records native ABI and native-bridge properties, verifies the selected compatibility path, measures actual root-shell state, then shuts down. This is the decisive test for LXC/VM restrictions that are not visible from CPU flags or `/dev/kvm` alone.

Root is also evidence-based. If `adb shell id` already reports `uid=0`, the runtime records root as available without requiring an extra `adb root` restart. If root cannot be established, non-root ADB analysis continues; Frida injected mode and root-only data collection become coverage limitations rather than a global dynamic failure.

Review:

```text
reports/dynamic/setup.json
reports/dynamic/setup-smoke.json
reports/dynamic/device-info.json
reports/dynamic/root-status.json
reports/dynamic/abi-compatibility.json
reports/dynamic/emulator.log
```

## Full run

Inside OpenCode:

```text
/dynamic
```

The normal flow is:

```text
probe -> setup -> boot -> runtime/native-bridge ABI verify -> install -> launch
      -> optional Frida -> collect -> deterministic evidence summary
      -> dynamic analyst -> validator for material changes
```

The XAPK path installs the prepared base plus all split APKs with `adb install-multiple`. A successful installation upgrades the ABI evidence from a boot-time compatibility indication to an actual package-level compatibility result.

## Runtime evidence

Collected data includes:

- emulator PCAP (`-tcpdump`);
- logcat;
- current UI hierarchy and screenshot;
- package/app-op/activity/process state;
- root-only app-data file inventory and process maps when root is actually available;
- installed package paths;
- redacted Frida events when enabled;
- audit trail of active local actions.

`tools/apk_dynamic_evidence.py` reduces these artifacts into a bounded deterministic summary before the dynamic agent reads them.

Encrypted PCAP traffic remains encrypted. Endpoint/API metadata may also come from redacted Frida hooks, but this workflow does not automatically install a MITM CA or disable TLS validation.

## Frida

When `allow_frida=true` and root is available, the toolkit downloads a `frida-server` matching the installed Frida client and emulator ABI, deploys it to `/data/local/tmp`, and starts redacted observation.

No Frida Gadget APK repackaging is used.

Hooks deliberately record metadata rather than secrets: URL without query/fragment, method, bridge/library names, storage key/table names and value lengths, crypto algorithm/key length, Dex/class loading, subprocess executable, and debugger-check execution.

## Active validation

When `allow_active_validation=true`, use the audited wrapper only:

```bash
python3 tools/apk_dynamic_action.py deep-link 'myapp://path'
python3 tools/apk_dynamic_action.py component activity com.example.SomeActivity
python3 tools/apk_dynamic_action.py component service com.example.SomeService
python3 tools/apk_dynamic_action.py component receiver com.example.SomeReceiver
python3 tools/apk_dynamic_action.py tap 500 900
python3 tools/apk_dynamic_action.py keyevent KEYCODE_BACK
python3 tools/apk_dynamic_action.py text 'non-sensitive-test-input'
```

Custom deep links must use a scheme declared in the decoded manifest and are package-restricted. Components must be declared in the manifest. UI text is not copied into the action log; only its length is recorded.

This is deliberately not an API pentest gate. Do not use it for request replay/mutation, IDOR testing or provider/backend attacks.

## Cleanup

```bash
python3 tools/apk_dynamic.py frida-stop
python3 tools/apk_dynamic.py stop
```

AVD state remains under `work/android/` and can be removed with the project when no longer needed.

## Common outcomes

### LXC without `/dev/kvm`

Expected probe note: container has no `/dev/kvm`. If the Proxmox host is under operator control, prefer KVM-device passthrough as described above before accepting software emulation. Otherwise, if software emulation is enabled, the x86_64 AVD may still be tried and `/dynamic-setup` performs the real boot test.

### VM without nested virtualization

Usually `/dev/kvm` is absent and `emulator -accel-check` fails. Same-architecture software mode remains possible when enabled, but may be very slow.

### ARM64-only XAPK on x86_64

If `minSdk <= 30`, expect `android11-x86_64-multiabi-translation` and API 30. Do not expect `ro.product.cpu.abilist` necessarily to contain `arm64-v8a`; inspect the native-bridge evidence and then require successful package installation during `/dynamic`. If `minSdk > 30`, dynamic v1 reports no documented compatible runtime.

### App requires Google Play services

`image_tag="auto"` prefers AOSP/default for analysis/root and can fall back to `google_apis`. If functionality depends on Google services, set `image_tag="google_apis"` and let the boot/root probe record the resulting capability. Play Store images are intentionally outside this flow.

### Root unavailable

Continue ADB-based runtime observation. Frida injected mode and root-only app-data/process-map collection are recorded as unavailable.
