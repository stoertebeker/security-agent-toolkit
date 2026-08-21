# Firmware Update Security

Maintained by the `firmware-security` primary agent from deterministic update leads and focused review.

## Update chain

| Stage | Local evidence | Security property | Status / limitation |
|---|---|---|---|
| Source/download | | transport/origin | |
| Input/format | | parser/bounds/path handling | |
| Version/policy | | downgrade/rollback | |
| Integrity | | checksum/hash | |
| Authenticity | | signature/MAC/trust key | |
| Staging/extraction | | path/permissions | |
| Flash/write | | privileged sink | |
| Recovery/rollback | | alternate trust path | |

## Verification semantics

State explicitly whether the firmware establishes:
- no verification found;
- checksum/integrity only;
- cryptographic authenticity logic present but enforcement unresolved;
- authenticity verification enforced on the reviewed path;
- alternate unsigned/recovery path requiring validation.

Do not equate SHA-256 with authenticity. Do not equate a public key or `RSA_verify` string with enforced signature verification.

## Trust material

Record public verification keys/certificates, writable key/config paths, trust-anchor selection and key-rotation clues without copying sensitive material.

## Update-related findings / candidates

| ID | Path | Evidence chain | Status | Severity |
|---|---|---|---|---|

## Limitations

Record proprietary container/signature formats, bootloader enforcement, secure-boot state, recovery behavior and runtime/vendor facts unavailable to static rootfs analysis.
