---
name: audit-gate
description: >-
  Use when running, reviewing, or passing the CRUCIBLE adversarial audit gate on
  this repo — producing findings.yaml + REPORT.md grounded in audit/evidence.yaml
  and looping `audit verify` until it exits 0.
---

# audit-gate

This skill defers entirely to the contract in `CRUCIBLE.md` at the repo root and
never restates it (the axes, severity scale, and SHIP/HOLD/BLOCK vocabulary live
there once).

Two artifacts you produce, at the repo root:
- `findings.yaml` — machine findings + waivers + disposition.
- `REPORT.md` — the single human report (Bug Tickets section = JIRA-style
  tickets + false-positive ledger + triage matrix).

One evidence source you may cite: `audit/evidence.yaml`. Nothing else.

The loop:
1. `uv run --project audit audit all -t 900` → regenerates `audit/evidence.yaml`.
2. Read `REVIEW.md` + `audit/evidence.yaml`; write `findings.yaml` + `REPORT.md`.
3. `uv run --project audit audit verify --findings findings.yaml --context audit/evidence.yaml`.
4. Repeat 2–3 until verify exits `0`.

Run playbook + rationale: `audit/README.md`.
