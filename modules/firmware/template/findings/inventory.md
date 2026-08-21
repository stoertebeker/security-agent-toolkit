# Firmware Inventory

Maintained by the `firmware-security` primary agent from deterministic preparation/baseline artifacts and focused local verification.

## Input and extraction

- Firmware path:
- SHA-256:
- `file` description:
- Extraction status: complete / degraded / unavailable
- Primary rootfs:
- Additional rootfs/filesystem candidates:
- Absolute/escaping symlink observations:
- Extraction limitations:

## Platform and filesystem

- CPU architecture / endianness evidence:
- Rootfs/filesystem family evidence:
- Init/service manager:
- Kernel/version evidence:
- BusyBox/base system evidence:
- Package database(s):

## Accounts and privilege surface

| Account | UID/GID | Shell/home | Credential state | Security relevance |
|---|---|---|---|---|

- SUID/SGID summary:
- World-writable security-sensitive paths:
- Privileged custom daemons/binaries:

## Service and management inventory

| Service/component | Startup/config evidence | Interface/port clue | Privilege | Reachability status |
|---|---|---|---|---|

Reachability status should be `CONFIGURED`, `STARTUP_ENABLED`, `LOCAL_ONLY_BY_EVIDENCE`, `EXTERNAL_REACHABILITY_UNKNOWN`, or stronger only when local evidence supports it.

## Web/API/IPC inventory

- Web roots/frameworks:
- CGI/Lua/PHP/native handlers:
- RPC/IPC mechanisms:
- Management/debug endpoints:

## Update subsystem

- Update entry points:
- Download/source mechanism:
- Verification/trust material:
- Flash/write tooling:
- Rollback/version mechanism:

## Third-party/component anchors

Record only locally evidenced names/versions/build identifiers. Public CVE applicability belongs in research/findings, not this inventory.
