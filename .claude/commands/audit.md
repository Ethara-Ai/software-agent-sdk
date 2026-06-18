# /audit (Claude Code wrapper)

One-screen wrapper. The contract is in `CRUCIBLE.md` at the repo root — this
file defers to it and never restates the axes, severity scale, or disposition
vocabulary.

1. Run the gate (writes `audit/evidence.yaml`, UNGATED):
   `uv run --project audit audit all -t 900`
2. Read `REVIEW.md` + `audit/evidence.yaml`; write `findings.yaml` + `REPORT.md`
   at the repo root. Cite only ids the harness emitted.
3. Verify (the gate; exit 0 = pass):
   `uv run --project audit audit verify --findings findings.yaml --context audit/evidence.yaml`

Loop 2–3 until verify exits 0.
