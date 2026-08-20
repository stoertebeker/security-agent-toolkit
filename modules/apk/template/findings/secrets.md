# APK Secrets and Credentials

This is the durable triage record for hard-coded credentials, keys, tokens, private material, and credential-like client configuration.

The deterministic candidate source is `reports/tool-output/secret-candidates.json`; detailed triage belongs in `reports/subagents/secrets-review.md`.

Never copy a full real credential into this file. Use source path/line, candidate rule, short SHA-256 fingerprint from the candidate scan, type, usage, and status.

## Classification summary

| Classification | Count | Notes |
|---|---:|---|
| CONFIRMED_SECRET_OR_CREDENTIAL | 0 | |
| SENSITIVE_TOKEN_OR_PASSWORD_EQUIVALENT | 0 | |
| PUBLIC_CLIENT_CONFIGURATION | 0 | |
| CERTIFICATE_OR_TRUST_MATERIAL | 0 | |
| TEST_OR_SAMPLE_DATA | 0 | |
| FALSE_POSITIVE | 0 | |
| NEEDS_VALIDATION | 0 | |

## Security-relevant candidates

| ID | Classification | Source | Candidate fingerprint | Local usage/evidence | Status / impact |
|---|---|---|---|---|---|

## Intentionally not promoted

Record public SDK/client identifiers, certificates/trust anchors, test data, and other reviewed candidates here only when their classification is useful to prevent later re-triage. Keep this section concise.

## Coverage and remaining validation

- Deterministic scan status:
- Candidate cap reached: no
- Native-string coverage:
- Decompiler limitations affecting secret review:
- Remaining manual/runtime/server-side validation:
