# REVIEW.md — Phase-2 instruction prompt

You are the **producer**. You have read `CRUCIBLE.md` and you are rewarded for a
clean disposition, not for truth. The gate is built to survive you. These
instructions tell you how to fill in the two artifacts so the gate *can* pass —
not how to trick it (every trick is a deterministic rule away from rejection).

## What you may cite

`audit/evidence.yaml` is the **only** source of instrumented evidence. You may
reference only:
- `issue_instance_id`s the harness emitted under `normalized_issues`.
- `run_id`s under `runs` whose `status` is `ok` or `nonzero_exit`.
- `coverage_gaps[]` the harness recorded.

You may NOT invent spans, cite blocked/timeout runs as proof, or assert a CVSS
base that does not recompute from its vector. R2/R3/R4 catch each of these.

## What you write (repo root)

### `findings.yaml`
```yaml
schema_version: "1"
disposition: HOLD            # SHIP | HOLD | BLOCK — never above what the gate computes
severity_tally: {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}  # sums to len(findings)
findings:
  - id: F-001
    instance_id: <issue_instance_id from evidence.yaml>
    severity: HIGH
    path: README.md          # must resolve: realpath inside repo, regular file, line in range
    line: 15
    run_id: CMD-007           # must be an ok/nonzero_exit run, or omit for domain findings
    cwe: CWE-345              # CWE-<n> form; appropriateness is judgment
    cvss_vector: null         # if set, cvss_base MUST recompute from it
    cvss_base: null
    title: <short>
    rationale: <why this is real / exploitable / relevant>
waivers:
  - instance_id: <id>
    reason_code: false_positive   # closed enum: false_positive | not_exploitable |
                                  # accepted_risk | compensating_control | out_of_scope | test_fixture
    rationale: <fingerprint-specific; >= 12 chars; not boilerplate reused across ids>
    approved: false               # HIGH/CRITICAL or secret findings need out-of-band approval
```
Acknowledge **every** `>= MEDIUM` issue in evidence (R1) by `instance_id`, or
waive it with a valid, non-boilerplate waiver. Effective severity is the **max**
over acknowledged issues — you cannot relabel it down.

### `REPORT.md`
The single human report. Required sections:
- **Summary** — disposition + the one-line reason.
- **Coverage** — instruments that ran / blocked / timed out, vs the scoped
  surfaces; every coverage gap stated explicitly (absence is a result).
- **Findings** — each finding with evidence pointer + rationale.
- **Bug Tickets** — JIRA-style tickets (one per actionable finding) with a
  color-flag emoji, a false-positive ledger, and a triage matrix.
- **Remaining D-COVERAGE-GAPs** — what caps the disposition below SHIP.

## The loop
```
uv run --project audit audit verify --findings findings.yaml --context audit/evidence.yaml
```
Exit `0` = gate passed. Anything else: read the failed rule, fix the artifact
(never fabricate), re-run. Nothing you do changes the contract.
