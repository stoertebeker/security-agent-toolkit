# APK Analysis Log

Keep this as concise orchestration provenance, not a duplicate findings report.

## Run configuration

- `max_parallel_agents`:
- `research_max_questions`:
- `research_max_sources_per_question`:
- `research_max_report_words`:
- Observed peak delegated tasks:

## Delegation log

| Sequence | Layer | Agent/task | Purpose | Result path | Outcome |
|---:|---|---|---|---|---|

`Layer` should distinguish at least `primary->subagent` from `researcher->web-worker` when observable. Do not paste worker conclusions here; link the result path and record only the outcome/decision.

## Major decisions

Record only decisions that changed scope, severity/status, validation strategy, or coverage. One or two sentences each.

## Unresolved follow-up

Keep a short list of remaining questions that require dynamic/server-side/partner/runtime evidence.
