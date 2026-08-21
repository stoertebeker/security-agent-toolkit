# APK Attack Surface

Maintained by the `apk-security` primary agent.

## Entry points and IPC

Record exported components, intent/deep-link surfaces, providers, services, receivers, PendingIntent/IPC paths and externally reachable app-specific actions.

## Web, navigation and network surfaces

Record WebViews, URL/deep-link routing, bridges, network-security configuration, cleartext/mixed-content behavior and externally/server-controlled navigation.

## Unusual or high-power behavior

Record only evidence-backed application behavior that deserves analyst attention even when it is not itself a vulnerability. Examples include accessibility/device-admin/VPN/overlay use, boot/background persistence, notification interception, broad device or file access, shell/process execution, self-update/downloaded payload handling, extensive reflection, or other surprising capabilities. Distinguish app-owned behavior from ordinary framework/SDK behavior.

If nothing material is established, write `None established from reviewed static artifacts.`

## Obfuscation, concealment and anti-analysis indicators

Record evidence for runtime code loading, encrypted/encoded code or configuration unpacked at runtime, reflection used to obscure security-sensitive calls, hidden/disabled components or launcher-icon manipulation, debugger/root/emulator/instrumentation/Frida/Xposed checks, signature/self-integrity checks, anti-tamper logic, unusual native loaders, or comparable anti-analysis/evasion mechanisms.

Normal R8/ProGuard/minification, generated names, compressed resources, stripped third-party native libraries, and ordinary SDK reflection are not evidence of malicious concealment by themselves. Do not infer intent from obfuscation alone. Classify the observed state as one of:
- `NONE_ESTABLISHED`
- `ORDINARY_BUILD_OBFUSCATION_ONLY`
- `SUSPICIOUS_CONCEALMENT_INDICATORS`
- `CONFIRMED_ANTI_ANALYSIS_BEHAVIOR`

For the latter two, include the concrete app-specific evidence and security relevance.

## Prioritized attack surface

List the highest-value entry points and behaviors for deeper review. Keep this concise and evidence-backed.
