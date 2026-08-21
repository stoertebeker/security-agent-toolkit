---
description: Run toolkit-contained Android emulator dynamic analysis and correlate runtime evidence with static findings
agent: apk-security
---
Run dynamic analysis for the authorized Android package using only the toolkit-managed emulator. Do not require an external Android device and do not repeat broad static analysis.

## 1. Preconditions and capability gate

- Read `[dynamic]`, `[orchestration]`, and `[apk]` from `target/TARGET.toml`.
- Require `dynamic.enabled=true`.
- Require preparation artifacts for the current APK/XAPK. Reuse them when present.
- Run `python3 tools/apk_dynamic.py probe` and read `reports/tool-output/dynamic-capabilities.*`.
- If emulator tooling is missing, stop with `./toolkit install apk --with-optional` in the toolkit repository.
- If `dynamic_available=false`, update `findings/dynamic.md` and `findings/coverage.md` with the exact limitation and stop. Do not pretend runtime coverage occurred.
- Record the runtime ABI mode. Android-11 x86_64 multi-ABI fallback is API-30 compatibility coverage, not target-OS coverage.

## 2. Reuse or prepare isolated emulator

If `reports/dynamic/setup-smoke.json` exists, reports `success=true`, and the referenced `reports/dynamic/setup.json` AVD still exists under project-local `work/android/avd/`, reuse that already boot-tested AVD. Do not recreate it merely because `/dynamic` follows `/dynamic-setup`.

Otherwise run:

```text
python3 tools/apk_dynamic.py setup
python3 tools/apk_dynamic_smoke.py
```

The smoke test must pass before continuing. Then run:

```text
python3 tools/apk_dynamic.py start
python3 tools/apk_dynamic.py install
```

All AVD/user state stays under `work/android/`; runtime evidence belongs under `reports/dynamic/`. KVM is used only when the capability probe confirms it; otherwise same-architecture x86_64 software emulation is allowed only when configured. The booted runtime compatibility state and actual package installation are used to establish package/runtime ABI compatibility.

## 3. Runtime observation

If `dynamic.allow_frida=true`, inspect `reports/dynamic/root-status.json` after emulator start. Attempt `python3 tools/apk_dynamic.py frida-start` only when root is actually available. If root is unavailable, Frida download/deployment/smoke fails, or the target process cannot be instrumented, record the exact Frida limitation in `findings/dynamic.md`/`findings/coverage.md` and **continue the non-Frida dynamic workflow**. Frida is optional enrichment, not a prerequisite for ADB/PCAP/logcat/UI/state collection. Do not repackage the APK with Frida Gadget.

Then run:

```text
python3 tools/apk_dynamic.py launch
python3 tools/apk_dynamic.py collect
python3 tools/apk_dynamic_evidence.py
```

Use PCAP, logcat, UI dump/screenshot, package/app-op/process state, root-only app-data inventory/process maps when available, and redacted Frida events when available as runtime evidence.

## 4. Targeted active validation

Only when `dynamic.allow_active_validation=true`, perform a small number of emulator-local actions derived from already documented static hypotheses. Use only:

```text
python3 tools/apk_dynamic_action.py deep-link <declared-custom-uri>
python3 tools/apk_dynamic_action.py component <activity|service|receiver> <declared-component>
python3 tools/apk_dynamic_action.py tap <x> <y>
python3 tools/apk_dynamic_action.py keyevent <KEYCODE>
python3 tools/apk_dynamic_action.py text <value>
```

The wrapper validates custom schemes/components where applicable and appends a redacted audit record to `reports/dynamic/actions.jsonl`. Do not bypass it with arbitrary ADB active-validation commands. Text input logs only its length.

Do not broad-fuzz. Do not craft/replay/mutate backend/provider API requests. This gate is not backend/API pentest authorization.

After meaningful actions, run `python3 tools/apk_dynamic.py collect` and `python3 tools/apk_dynamic_evidence.py` again.

## 5. Dynamic review and validation

Delegate one `apk-dynamic-analyst` task with the narrow static hypotheses and runtime artifact paths. It writes `reports/subagents/dynamic-review.md`.

For each static hypothesis use:
- `CONFIRMED_RUNTIME`
- `NARROWED`
- `NOT_OBSERVED`
- `NEEDS_MORE_INTERACTION`
- `UNAVAILABLE`

`NOT_OBSERVED` is not evidence of absence unless the triggering feature was actually exercised.

If runtime evidence materially changes a Medium/High/Critical finding, use one consolidated `apk-validator` task before editing final severity/status.

## 6. Durable outputs and scope reconciliation

Update:
- `findings/dynamic.md`;
- affected `findings/findings.md` / `findings/attack-surface.md` only where runtime evidence changes/confirms a conclusion;
- `findings/coverage.md` with environment/API/ABI/runtime mode/acceleration/root/Frida and unexercised features;
- `findings/analysis-log.md` with dynamic provenance;
- the analyst summary when the overall conclusion changes.

Before finalizing, **reconcile stale scope/limitation statements left by the earlier static phase across all durable records and reports**. In particular:
- no file may still say dynamic analysis/checks were `disabled`, `not run`, or unavailable when a dynamic run actually completed;
- replace such statements with the precise remaining limitation, for example `dynamic startup observation completed; active validation/login/backend/provider flow not exercised`;
- distinguish `dynamic analysis ran` from `dynamic.allow_active_validation=false` and from `backend/API testing out of scope`;
- do not erase historical provenance in `findings/analysis-log.md`; when an older entry describes the state at that earlier point, keep it clearly historical rather than presenting it as current scope;
- perform a final consistency read of `findings/findings.md`, `findings/dynamic.md`, `findings/coverage.md`, `reports/STATIC_SECURITY_REPORT.md`, and `reports/DYNAMIC_SECURITY_REPORT.md` so their current-scope statements agree.

Create `reports/DYNAMIC_SECURITY_REPORT.md` with:
1. Runtime environment/capability mode
2. Runtime observations
3. Static hypotheses exercised and result
4. Dynamic finding changes
5. Unusual/concealment behavior actually observed
6. Network/storage/WebView/native observations
7. Limitations and unexercised flows

Keep sensitive values redacted.

## 7. Cleanup

Run:

```text
python3 tools/apk_dynamic.py frida-stop
python3 tools/apk_dynamic.py stop
```

Do not leave emulator/Frida/logcat processes running unintentionally.
