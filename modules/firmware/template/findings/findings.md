# Firmware Security Findings

Maintained by the `firmware-security` primary agent. Findings are evidence-backed and should reference durable/local evidence rather than scanner priority alone.

## Confirmed findings

For each finding use:

### F-XX — Short title (Severity; validation status)

- **Affected path/component:**
- **Attacker/relevant input:**
- **Processing/validation:**
- **Sensitive sink / privilege:**
- **Startup/reachability evidence:**
- **Impact:**
- **Evidence:** local file paths/lines, subagent report, deterministic artifact
- **Validation:** CONFIRMED / LIKELY / NEEDS VALIDATION; validator artifact for important findings
- **Limitations/conditions:**
- **Remediation:**

## Candidates / needs validation

Keep potentially important but incomplete chains here rather than inflating severity. State the exact missing source/reachability/runtime/vendor fact.

## Reviewed non-findings

Record important false positives or design points that should not be repeatedly re-triaged, for example:
- service configured but not proven externally reachable;
- public verification key correctly used as trust material;
- old component version with no local affected path established;
- dangerous import without attacker-controlled call path;
- normal packing/stripping without anti-analysis behavior.

## Validation provenance

Link independent validation artifacts for High/Critical and other materially disputed findings.
