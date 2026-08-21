---
description: Run toolkit-contained Android emulator dynamic analysis and correlate runtime evidence with static findings
agent: apk-security
---
Run dynamic analysis for the authorized Android package using only the toolkit-managed emulator. Do not require an external Android device and do not repeat broad static analysis.

## 1. Preconditions and capability gate

- Read `[dynamic]`, `[orchestration]`, and `[apk]` from `target/TARGET.toml`.
- Require `dynamic.enabled=true`.
- Require existing preparation artifacts for the current APK/XAPK. If they are absent, run `tools/apk_prepare.py` once; otherwise reuse them.
- Run `python3 tools/apk_dynamic.py probe` and read `reports/tool-output/dynamic-capabilities.*`.
- If emulator tooling is missing, stop with the operator instruction `./toolkit install apk --with-optional` in the toolkit repository.
- If the probe says `dynamic_available=false`, update `findings/dynamic.md` and `findings/coverage.md` with the exact environment limitation and stop. Do not pretend dynamic coverage occurred.

## 2. Build/start isolated emulator

Run, in order:

```text
python3 tools/apk_dynamic.py setup
python3 tools/apk_dynamic.py start
python3 tools/apk_dynamic.py install
```

All AVD state must remain under `work/android/`. Runtime evidence belongs under `reports/dynamic/`.

The setup chooses an image ABI compatible with prepared native code. KVM is used only when the capability probe confirms it is usable; otherwise software emulation is allowed only when configured. LXC/VM host limitations are evidence/coverage, not app findings.

## 3. Runtime observation

If `dynamic.allow_frida=true`, run:

```text
python3 tools/apk_dynamic.py frida-start
```

Frida injected mode is permitted only when the managed emulator actually provides root. The toolkit downloads a matching `frida-server` version when needed. Do not repackage the APK with Frida Gadget in this workflow.

Then run:

```text
python3 tools/apk_dynamic.py launch
python3 tools/apk_dynamic.py collect
python3 tools/apk_dynamic_evidence.py
```

Use the resulting PCAP, logcat, UI dump, package/app-op/process state, root-only file inventory/process maps, and redacted Frida events as runtime evidence.

## 4. Targeted active validation

Only when `dynamic.allow_active_validation=true`, perform a small number of emulator-local actions derived from already documented static hypotheses, for example:
- invoke an exported activity/service with a benign intent;
- invoke a documented custom deep link with non-sensitive local test data;
- navigate locally to a feature needed to exercise a static WebView/storage hypothesis.

Do not broad-fuzz components. Do not craft/replay/mutate backend or provider API requests. This setting is not backend/API pentest authorization.

After each action, recollect relevant logcat/UI/state evidence and record the exact action in `findings/dynamic.md`.

## 5. Dynamic review and validation

Delegate one `apk-dynamic-analyst` task with the narrow static hypotheses that matter and the runtime artifact paths. It must write `reports/subagents/dynamic-review.md`.

For each static hypothesis use one of:
- `CONFIRMED_RUNTIME`
- `NARROWED`
- `NOT_OBSERVED`
- `NEEDS_MORE_INTERACTION`
- `UNAVAILABLE`

Absence of observation is never proof of absence unless the triggering feature was actually exercised.

If runtime evidence materially changes a Medium/High/Critical finding, use one consolidated `apk-validator` task to challenge those changes before editing final severity/status.

## 6. Durable outputs

Update:
- `findings/dynamic.md`;
- affected `findings/findings.md` / `findings/attack-surface.md` only where runtime evidence changes or confirms a conclusion;
- `findings/coverage.md` with emulator/API/ABI/acceleration/root/Frida and unexercised features;
- `findings/analysis-log.md` with dynamic task provenance;
- the `Analyst summary` in `reports/STATIC_SECURITY_REPORT.md` when the overall conclusion changes.

Create `reports/DYNAMIC_SECURITY_REPORT.md` containing:
1. Runtime environment/capability mode
2. Runtime observations
3. Static hypotheses exercised and result
4. Dynamic finding changes
5. Unusual/concealment behavior actually observed
6. Network/storage/WebView/native observations
7. Limitations and unexercised flows

Keep sensitive values redacted. Dynamic instrumentation must not create a second plaintext credential report.

## 7. Cleanup

When collection/review is complete, run:

```text
python3 tools/apk_dynamic.py frida-stop
python3 tools/apk_dynamic.py stop
```

Do not leave emulator/frida/logcat processes running unintentionally.
