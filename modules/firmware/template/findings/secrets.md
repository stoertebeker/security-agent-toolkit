# Firmware Secrets and Credential Material

This is the durable redacted record for credentials, account material, private keys, tokens and secret-like configuration.

Raw scanner candidates stay under `reports/tool-output/firmware-secret-candidates.json`. AI triage uses only `firmware-secret-groups.json`. Exact retained values belong only under `reports/sensitive/` when explicitly enabled.

## Classification summary

| Classification | Count | Notes |
|---|---:|---|
| CONFIRMED_SECRET_OR_CREDENTIAL | 0 | |
| LOCAL_LOGIN_CREDENTIAL | 0 | |
| PASSWORD_HASH_OR_CREDENTIAL_FIELD | 0 | |
| PRIVATE_KEY_MATERIAL | 0 | |
| EMBEDDED_SERVICE_CREDENTIAL | 0 | |
| TOKEN_LIKE_MATERIAL | 0 | |
| PUBLIC_KEY_OR_CERTIFICATE | 0 | |
| TEST_SAMPLE_DATA | 0 | |
| PLACEHOLDER | 0 | |
| FALSE_POSITIVE | 0 | |
| NEEDS_VALIDATION | 0 | |

## Deterministic/grouped coverage

- Text files scanned / skipped:
- Raw candidate count:
- Semantic group count:
- AI groups reviewed:
- Worker batches / peak concurrency:
- Plaintext retention enabled:

## Security-relevant material

| ID | Classification | Redacted source | Local consumer/trust role | Status / impact |
|---|---|---|---|---|

Never paste full credentials, hashes or private keys here. Use source location, rule, short fingerprint if useful, and redacted role/evidence.

## Account credential notes

Distinguish an embedded/empty local password, a password hash, a locked service account, and a remotely reachable login. `/etc/shadow` presence alone is not a vulnerability.

## Private-key notes

Distinguish per-device host keys, shared vendor keys, update-signing verification/public keys, TLS server private keys, test keys and unused artifacts. A private-key file becomes a security finding only when its operational trust/reuse consequences are established.

## Remaining validation

Record reachability, uniqueness/reuse, provider/server authority, or runtime checks still required.
