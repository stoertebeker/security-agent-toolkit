# Firmware Attack Surface

Maintained by the `firmware-security` primary agent.

## Prioritized entry points

| Entry point | Startup/config evidence | Auth/trust boundary | Privilege | Reachability confidence | Review status |
|---|---|---|---|---|---|

Do not label a daemon `internet-exposed` from a config/startup file alone. Preserve unknown topology/firewall/runtime state.

## Web/API management surface

Record concrete handlers/routes/configuration and backing processes. Separate public/static assets from state-changing management handlers.

## Local IPC / privileged dispatch

Record ubus/rpc/dbus/socket/command-dispatch mechanisms and the caller privilege boundary when established.

## Debug / maintenance surface

Record telnet/SSH debug modes, maintenance accounts, diagnostic commands, factory/recovery interfaces and hidden/admin paths. Presence is not automatically a vulnerability.

## Unusual behavior and concealment

Concealment/hidden-behavior state: `NONE_ESTABLISHED`

Allowed states:
- `NONE_ESTABLISHED`
- `ORDINARY_PACKING_OR_STRIPPING_ONLY`
- `SUSPICIOUS_CONCEALMENT_INDICATORS`
- `CONFIRMED_ANTI_ANALYSIS_OR_HIDDEN_BEHAVIOR`

Evidence-backed unusual/high-impact behavior:
- None established.

Do not classify normal compression, stripped vendor binaries, BusyBox symlinks, minified web assets, UPX/packing alone, or ordinary maintenance functionality as malicious concealment.

## Highest-value unresolved reachability questions

Record runtime/network/vendor facts that static analysis cannot establish and which could materially change severity.
