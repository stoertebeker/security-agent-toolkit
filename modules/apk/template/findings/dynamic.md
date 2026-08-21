# APK Dynamic Analysis

Maintained by the `apk-security` primary agent after toolkit-managed runtime analysis.

## Runtime environment

- Capability result:
- Virtualization/container:
- `/dev/kvm` / emulator acceleration check:
- Emulator image/API/ABI:
- Runtime ABI mode: native / no-native / Android-11 multi-ABI compatibility / unavailable
- Boot smoke test:
- Acceleration: KVM / software / unavailable
- Root requested / actually available:
- Frida allowed / actually used:
- Google services available/required:

When Android-11/API-30 multi-ABI compatibility is used, state explicitly that runtime evidence covers API 30 and does not validate newer target-OS-specific behavior.

## Runtime observations

Record only evidence-backed observations from `reports/dynamic/`, for example:
- actually loaded native libraries / process mappings;
- WebView URLs and bridge registrations;
- runtime Dex/class loading;
- permission/app-op behavior;
- local storage files/keys without copying sensitive values;
- actual process/activity/IPC behavior;
- network endpoints/protocol observations from capture/Frida metadata;
- crypto algorithms/key lengths without key bytes;
- anti-analysis/debugger checks that actually executed.

## Static hypotheses exercised

| Static finding / hypothesis | Feature/action actually exercised | Dynamic evidence | Result | Effect |
|---|---|---|---|---|

Use `CONFIRMED_RUNTIME`, `NOT_OBSERVED`, `NARROWED`, `NEEDS_MORE_INTERACTION`, or `UNAVAILABLE`. `NOT_OBSERVED` is not proof of absence unless the triggering feature/action was actually exercised.

## Active validation

Only populate when `dynamic.allow_active_validation=true`. Actions must come from `tools/apk_dynamic_action.py` and be traceable in `reports/dynamic/actions.jsonl`. Keep them emulator-local and derived from existing static hypotheses. Do not treat this gate as authorization for backend/API request mutation or replay.

## Limitations

State missing KVM, software-emulation slowness, API-30 compatibility mode, incompatible ABI/image, failed boot smoke, missing root/Frida, unavailable Google services, UI flows requiring credentials/user input, unexercised features, and backend behavior outside app-runtime evidence.
