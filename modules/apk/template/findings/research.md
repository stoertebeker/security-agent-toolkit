# Public research index

This file is an index, not a second research report. Detailed source notes live only in `reports/research/RQ-XX-....md`.

| ID | Narrow question | Local-first status | Research status | Effect on finding | Canonical detail |
|---|---|---|---|---|---|

Use short cells. `Local-first status` should summarize the concrete local facts supplied to research, including useful negative evidence where relevant (for example `manifest value used by client SDK init; no server API credential flow found locally`). Do not paste the full research packet here.

Every delegated RQ must have 2-5 non-sensitive local facts and an exact external fact needed before web research starts. If that context is missing, use `NEEDS_LOCAL_CONTEXT` and do not browse.

`Effect on finding` should be one sentence such as `F-03 narrowed; High unsupported` or `no change`.

Allowed research states: `OPEN`, `ANSWERED`, `PARTIAL`, `NOT_FOUND`, `SOURCE_LEAD_ONLY`, `NEEDS_LOCAL_CONTEXT`, `NEEDS_LOCAL_VALIDATION`.

Do not duplicate source tables, long caveats, raw credentials, tokens, private target data, proprietary code, local signing allowlist values, or certificate fingerprints here.
