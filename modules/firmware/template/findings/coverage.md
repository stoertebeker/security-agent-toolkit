# Firmware Analysis Coverage

Record what was actually analyzed, what was intentionally skipped, and where extraction/static evidence is degraded. Do not list a tool as used merely because it is installed.

## Preparation and extraction

| Tool/artifact | Status | Security use / limitation |
|---|---|---|
| `file` | | input identification |
| Binwalk structure scan | | structure lead only; not proof of complete extraction |
| unblob recursive extraction | | status/depth/external dependency limitations |
| rootfs discovery | | primary/additional candidates |
| symlink safety audit | | absolute/escaping target-root links |
| deterministic firmware baseline | | filesystem/accounts/services/update/ELF/components |

- Input hash matched preparation state:
- Preparation status: complete / degraded / unavailable
- Primary rootfs established:
- Additional filesystem/rootfs candidates reviewed:
- Opaque/encrypted/unparsed regions:

## Filesystem / privilege coverage

- Files/directories/symlinks inventoried:
- Users/passwd/shadow reviewed:
- SUID/SGID reviewed:
- World-writable security-sensitive paths reviewed:
- Init/startup systems reviewed:
- Cron/factory/recovery startup paths reviewed:

## Service / web / IPC coverage

- Deterministic startup/service leads:
- Services selected for deeper review:
- Web roots/handlers selected for deeper review:
- Authentication/authorization paths reviewed:
- IPC/RPC mechanisms reviewed:
- Reachability limitation: static configuration/startup does not prove actual LAN/WAN exposure.

## Secret/material coverage

- Text files scanned / large-binary skipped:
- Raw candidates:
- Semantic groups:
- AI groups reviewed:
- Exact plaintext retention enabled:
- Security-relevant credentials/keys/hashes integrated:
- Secret-review limitations:

## Native binary coverage

- ELF count:
- Architecture(s):
- Hardening baseline coverage:
- SUID/root-startup binaries:
- Network/dangerous-import leads:
- Binaries selected for deeper reverse engineering:
- Ghidra used/skipped and why:
- Stripped/decompiler limitations:

## Update-security coverage

- Update entry points identified:
- Download/source path reviewed:
- Integrity/authenticity enforcement reviewed:
- Flash/write sink reviewed:
- Rollback/recovery path reviewed:
- Bootloader/secure-boot/proprietary-format limitations:

## Third-party/research coverage

- Locally established component/version anchors:
- Questions resolved locally without web:
- Questions sent to public research:
- Complete local-facts packets supplied:
- Primary sources fetched/read:
- SOURCE_LEAD_ONLY results:
- Research-driven finding changes:

## Explicit exclusions / follow-up

List runtime/network-topology/hardware/bootloader/vendor/cloud questions not established by this static run. Runtime non-coverage must not be rewritten as proof that a service/path is unreachable.
