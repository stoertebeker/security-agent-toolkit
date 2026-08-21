---
description: Review prioritized firmware service web auth and IPC paths
agent: firmware-security
---
Perform focused service/web/auth/IPC review without repeating the whole assessment.

1. Require fresh `firmware-preparation.*`, `firmware-baseline.*` and `firmware-services.*`; refresh `firmware_baseline.py` only when missing/stale.
2. Read `analysis.max_service_deep_reviews` from TARGET.toml as a ceiling.
3. Start from configured/startup service leads and `findings/attack-surface.md`. Select only the highest-value unresolved paths based on startup evidence, privilege, management exposure, web/API role and dangerous command/file/IPC sinks.
4. Delegate bounded `firmware-service-reviewer` tasks, respecting global concurrency. Each task must name the specific service/config/handler hypothesis and relevant paths.
5. Do not claim WAN/LAN exposure solely from startup/configuration. Preserve `EXTERNAL_REACHABILITY_UNKNOWN` where topology/firewall/runtime evidence is unavailable.
6. Update `findings/attack-surface.md`, affected `findings/findings.md`, `findings/coverage.md`, and `findings/analysis-log.md`.
7. Important High/Critical candidates require `security-validator` before promotion.
8. Do not perform public research in this command; create narrow RQ candidates for `/research` only when an external component/vendor fact would materially change a locally evidenced path.
