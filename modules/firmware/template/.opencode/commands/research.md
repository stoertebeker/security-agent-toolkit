---
description: Perform bounded local-facts-grounded firmware public research
agent: firmware-security
---
Perform public research only for unresolved external facts that can materially change an already locally grounded firmware conclusion.

1. Read research budgets from TARGET.toml.
2. Review unresolved items in `findings/findings.md`, `findings/update-security.md`, `findings/attack-surface.md`, `findings/research.md`, and focused subagent notes.
3. Before creating any RQ, do the cheapest local check necessary using package DBs, configs/init scripts, deterministic binary metadata/strings, relevant source/scripts, update logic and current durable findings.
4. Retain at most `research_max_questions`. Every RQ packet MUST include:
   - RQ-ID / narrow question;
   - why it matters;
   - 2-5 concrete non-sensitive local facts including component/version/startup/use or useful negative evidence;
   - exact external fact needed;
   - source/report budgets.
5. If local facts are incomplete, do not browse. Mark/return `NEEDS_LOCAL_CONTEXT` and perform/queue the local check.
6. Update `findings/research.md` with compact index rows, then delegate one `firmware-researcher` batch respecting concurrency.
7. Workers must fetch/read primary sources before broadening search. `SOURCE_LEAD_ONLY` must not change findings.
8. Correlate verified external facts back to local target evidence. A CVE/version match without affected configuration/reachability is not a confirmed target vulnerability.
9. Use one consolidated `security-validator` task for material research-driven finding changes when appropriate.
10. Update durable findings/coverage/analysis-log without duplicating research source tables outside canonical RQ files.
