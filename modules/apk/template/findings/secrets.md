# APK Secrets and Credentials

This is the durable triage record for hard-coded credentials, signing/SDK-auth material, keys, tokens, private material, hashes/encodings, and credential-like client configuration.

Deterministic scanning feeds `tools/apk_secret_group.py`; the LLM triage source is `reports/tool-output/secret-groups.json`. Detailed AI triage belongs in `reports/subagents/secrets-review.md`. Do not iterate raw `secret-candidates.json` in the language-model workflow.

Never copy a full real credential into this file. Use semantic group ID, source path/resource key, fingerprint where available, type, usage and status.

## Classification summary

| Classification | Count | Notes |
|---|---:|---|
| CONFIRMED_SECRET_OR_CREDENTIAL | 0 | Actually confidential/privileged reusable credential/private material. |
| EXPOSED_CLIENT_SIGNING_MATERIAL | 0 | Client-shipped signing/attestation-like material; server trust/confidentiality semantics conditional. |
| CLIENT_SDK_AUTH_MATERIAL | 0 | Client/mobile-SDK integration authentication material; provider-side privilege/reusability conditional. |
| SENSITIVE_TOKEN_OR_PASSWORD_EQUIVALENT | 0 | |
| PUBLIC_CLIENT_CONFIGURATION | 0 | |
| CERTIFICATE_OR_TRUST_MATERIAL | 0 | |
| HASH_OR_KDF_HIGH_CONFIDENCE | 0 | |
| HASH_OR_DIGEST_AMBIGUOUS | 0 | |
| TEST_OR_SAMPLE_DATA | 0 | |
| FALSE_POSITIVE | 0 | |
| NEEDS_VALIDATION | 0 | May overlap a material classification where impact semantics remain unresolved. |

Do not classify a client-shipped value as `CONFIRMED_SECRET_OR_CREDENTIAL` solely because a symbol/provider calls it `secret`, `APPSECRET`, `clientSecret`, `key` or `token`.

## Security-relevant groups

| ID | Classification | Source/resource key | Fingerprint | Local usage/evidence | Status / impact |
|---|---|---|---|---|---|

## Intentionally not promoted

Record public SDK/client identifiers, client-visible expected configuration, certificates/trust anchors, non-secret digests/identifiers, UI/test data and false positives only when useful to prevent later re-triage. Keep this section concise.

## Coverage and remaining validation

- Deterministic raw scan status:
- Post-format-filter / semantic-group count:
- AI plausibility groups reviewed:
- Candidate cap reached: no
- Native secret-string lead coverage: see `reports/tool-output/native-baseline.json` when present
- Decompiler limitations affecting secret review:
- Remaining manual/runtime/server-side validation:
