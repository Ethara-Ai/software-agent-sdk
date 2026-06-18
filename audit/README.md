# audit/ — CRUCIBLE audit gate (run playbook + rationale)

This directory is a self-contained `uv` project (Python 3.12+) that instruments
the parent repo. The **contract** lives once in `../CRUCIBLE.md`; this README is
the **run playbook + rationale** and never restates the contract.

## Layout

```
audit/
  scope.yaml          # Phase-0 machine scope (the single scope artifact)
  scope.approved      # Phase-0.5 sign-off: sha256(scope.yaml), one hex line
  pyproject.toml      # uv project; [scanners] + [dev] extras
  conftest.py         # puts flat modules on sys.path for pytest
  audit.py            # Typer orchestrator: provision / run / verify / all
  models.py           # enums, Tool contract, NormalizedIssue, identity hashing
  policy.py           # scope sentinel, total severity map, CRITICAL floor
  recon.py            # git/env/LOC/surface map + scanner DB pins
  tools.py            # instrument registry + runner (real exit codes, artifacts)
  normalize.py        # per-tool parsers -> NormalizedIssue (fails closed)
  domain.py           # bespoke domain-integrity checks (the core)
  cvss.py             # offline CVSS v3.1 base recompute (R4)
  recall.py           # R1 recall + waiver discipline
  verifier.py         # the six rules + fail-closed disposition
  evidence.yaml       # COMMITTED evidence bundle (only citable source)
  results/            # GITIGNORED per-command stdout transcripts
  tests/              # negative-control tests + Hypothesis self-fuzz
  drift_ledger.md     # executable drift ledger (Bucket-D conformance)
```

## Commands

```bash
# one-shot: provision scanners, run, print Phase-2 hand-off
uv run --project audit audit all -t 900

# just (re)generate evidence (UNGATED)
uv run --project audit audit run

# the gate — exits 0 ONLY when all six rules hold
uv run --project audit audit verify --findings findings.yaml --context audit/evidence.yaml
```

Native scanners (`gitleaks`, `trivy`, `hadolint`, `osv-scanner`) install
out-of-band (e.g. `brew install gitleaks trivy hadolint osv-scanner`); the pip
extras (`bandit`, `semgrep`, `pip-audit`) come from `uv sync --extra scanners`.
A genuinely-missing required scanner is recorded as `tool_blocked` and becomes a
coverage gap that **caps the disposition** — it is never a silent pass.

## Why it is built this way (rationale)

- **Provenance ≠ validity ≠ relevance.** The harness owns provenance (a run
  happened, this is its real exit code and output digest), co-owns validity, and
  is mostly blind to relevance. A tool exiting `0` is a measurement under a
  configuration, not truth.
- **Bucket D vs Bucket N.** Anything specifiable as a total bounded recomputable
  relation is harness code (D): a hash, a parse, a CVSS recompute, a multiset
  membership test. The irreducibly semantic residual (exploitability, severity
  honesty, CWE appropriateness) is the model's job (N) — and only *on top of* a
  verified substrate. A decidable-but-unimplemented atom is a `D-COVERAGE-GAP`
  that caps the disposition; it is never laundered into judgment.
- **Fail closed.** Unknown severity → MEDIUM, never INFO. Parse failure on a
  required tool → coverage gap → HOLD. Missing provenance → HOLD (Trusted-
  Evidence Axiom: a signature proves key possession, not honest collection).
- **The producer is the adversary.** Identity (`cluster_fingerprint`,
  `issue_instance_id`) is computed by the verifier from raw output; the producer
  may only reference verifier-emitted ids. Recall is per-instance; effective
  severity is the max over acknowledged issues, not the producer's label.

## Drift ledger

Every Bucket-D guarantee has an executable conformance test in `tests/`. A row
in `drift_ledger.md` is marked `Implemented` only with a passing negative-control
test; otherwise it is `Not implemented` / `D-COVERAGE-GAP` and caps the
disposition. Editing `../CRUCIBLE.md` and re-running reconciles the harness
through the ledger — never silently.
