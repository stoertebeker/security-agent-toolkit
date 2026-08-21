# Firmware Analysis Log

Keep this as concise orchestration provenance, not a duplicate findings report.

## Run configuration

- `max_parallel_agents`:
- `research_max_questions`:
- `research_max_sources_per_question`:
- `research_max_report_words`:
- `max_binary_deep_reviews`:
- `max_service_deep_reviews`:
- `max_update_deep_reviews`:
- Observed peak delegated tasks:

## Delegation log

| Sequence | Layer | Agent/task | Purpose | Result path | Outcome |
|---:|---|---|---|---|---|

Distinguish `primary->subagent` from `researcher->web-worker` and `secret-hunter->review-worker` when observable. Record step-limit/failure/retry outcomes honestly.

## Major decisions

Record only decisions that changed scope, priority, severity/status, extraction/coverage strategy, or research/validation strategy.

## Unresolved follow-up

Keep a short list of questions requiring runtime/network-topology/hardware/bootloader/vendor/cloud evidence or deeper reversing.
