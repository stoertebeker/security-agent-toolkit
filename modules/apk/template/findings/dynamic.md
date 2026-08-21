# APK Dynamic Analysis

Maintained by the `apk-security` primary agent after toolkit-managed runtime analysis.

## Runtime environment

- Capability mode:
- Virtualization/container:
- Emulator image/API/ABI:
- Acceleration: KVM / software / unavailable
- Root available:
- Frida available/used:

## Runtime observations

Record only evidence-backed observations from `reports/dynamic/`, for example:
- actually loaded native libraries / process mappings;
- WebView URLs and bridge registrations;
- runtime Dex/class loading;
- permission/app-op behavior;
- local storage files/keys without copying sensitive values;
- actual process/activity/IPC behavior;
- network endpoints/protocol observations from capture metadata;
- anti-analysis/debugger checks that were actually executed.

## Static hypotheses exercised

| Static finding / hypothesis | Dynamic evidence | Result | Effect |
|---|---|---|---|

Use `CONFIRMED_RUNTIME`, `NOT_OBSERVED`, `NARROWED`, `NEEDS_MORE_INTERACTION`, or `UNAVAILABLE` rather than treating lack of observation as proof of absence.

## Active validation

Only populate when `dynamic.allow_active_validation=true`. Keep validation emulator-local (for example exported component/deep-link invocation). Do not treat this gate as authorization for crafted backend/API requests.

## Limitations

State missing KVM, software-emulation slowness, incompatible ABI/image, missing root/Frida, unavailable Google services, UI flows that require credentials/user input, unexercised features, and backend behavior that remains outside app-runtime evidence.
