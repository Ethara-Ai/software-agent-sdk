---
description: >-
  Phase 1 (run the gate) + Phase 3 (verify). Drives the CRUCIBLE adversarial
  audit gate end-to-end. Defers to CRUCIBLE.md for the contract; never restates
  it.
agent: build
---

# /audit — run the CRUCIBLE gate

The full contract lives in `@CRUCIBLE.md`. This command never restates the axes,
severity scale, or disposition vocabulary — that would be a drift bug. It only
sequences the run.

## Phase 1 — generate evidence (UNGATED)

!`uv run --project audit audit all -t 900`

This writes `audit/evidence.yaml` (the only citable evidence source) and the
per-command transcripts under `audit/results/` (gitignored). Evidence is
**UNGATED until `audit verify` exits 0**.

## Phase 2 — review (you write the two artifacts)

Read `@REVIEW.md` as your instructions and `@audit/evidence.yaml` as the ONLY
source of instrumented evidence. Then write, at the repo root:

- `findings.yaml` — machine findings (strip any `_template`/`_example` keys).
- `REPORT.md` — the single human report; its **Bug Tickets** section carries the
  JIRA-style tickets, false-positive ledger, and triage matrix.

You may cite ONLY ids the harness emitted in `evidence.yaml`. Every `path:line`
must resolve; every cited run must have completed; every `cvss_base` must
recompute from its vector.

## Phase 3 — verify (the gate)

```
uv run --project audit audit verify --findings findings.yaml --context audit/evidence.yaml
```

Loop Phase 2 → Phase 3 until `verify` exits `0`. That exit code is the only
signal that means the gate passed.
