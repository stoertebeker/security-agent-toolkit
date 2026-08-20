# APK analysis pipeline

The APK module supports normal APK inputs and supported package containers prepared into one logical Android application.

## Secret/material pipeline

The deterministic scanner may produce many raw hits. Raw candidates are not LLM input.

```text
secret-candidates.json
        |
        v
apk_secret_group.py
  - strict format filtering
  - value deduplication
  - Android resource-key grouping
  - dependency/localization hints
        |
        v
secret-groups.json
        |
        v
apk-secret-hunter
        |
        +--> bounded apk-secret-review-worker batches
```

Every semantic group receives plausibility, classification and confidence. Client-shipped values are not automatically confidential credentials just because a field is named `secret`, `APPSECRET` or `clientSecret`.

Use these distinctions where applicable:
- `CONFIRMED_SECRET_OR_CREDENTIAL` for actually confidential/privileged reusable material;
- `EXPOSED_CLIENT_SIGNING_MATERIAL` for client-side signing material whose server trust/confidentiality semantics remain conditional;
- `CLIENT_SDK_AUTH_MATERIAL` for mobile-SDK integration authentication material whose provider-side privilege/reusability is unresolved or client-scoped;
- `PUBLIC_CLIENT_CONFIGURATION` for expected public client identifiers/configuration.

Opted-in raw values remain under `reports/sensitive/` only.

## Native pipeline

Run:

```text
python3 tools/apk_native_baseline.py
```

The baseline recursively covers `.so` files under `extracted/apktool/`, including decoded split/ABI trees. It records architecture, selected hardening properties, JNI exports, dangerous-import leads and redacted native secret-string leads.

Baseline indicators are not vulnerabilities. Deeper `apk-native-reverser`/Ghidra work is reserved for app-relevant, reachable or otherwise security-interesting libraries. Durable coverage must distinguish baseline-only libraries from deeply reviewed libraries.

Inside OpenCode, `/native` refreshes the baseline and performs focused follow-up without repeating the whole assessment.

## Public research pipeline

Research is local-first. Every externally delegated research question must carry:
- RQ ID and narrow question;
- why it matters;
- 2-5 concrete non-sensitive local facts, including useful negative evidence;
- the exact external fact still needed;
- source/report budgets.

The web worker performs one focused discovery search, then fetches/reads the strongest primary source before broadening search. If the primary fetch fails, it tries at most one alternate primary page before another search. Search snippets remain `SOURCE_LEAD_ONLY` and cannot change findings.

Each RQ has exactly one canonical report under `reports/research/RQ-XX-....md`. The primary correlates verified external facts back to local evidence and uses validation only for material finding changes.

## Targeted regression commands

After changing the module, an existing prepared workspace can exercise the changed paths without repeating decompilation:

```text
/secrets
/native
/research
```

A full new assessment should still start from `START_PROMPT.txt`.
