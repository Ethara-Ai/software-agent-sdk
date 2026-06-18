# CRUCIBLE Sign-off — Ethara-Ai/software-agent-sdk

**Date:** 2026-06-18 · **Git SHA:** `7910aa61…` (clean tree) · **Scope digest:** `3d419142…`

## Disposition: 🟡 HOLD — formally accepted · GATE PASSES (exit 0)

The complete BLOCK is resolved and the working tree is clean. **All 8 verifier
rules now PASS — `audit verify` exits 0.** The disposition is an honest,
gate-**agreed** HOLD: not by any failing rule. We did NOT inflate to SHIP
— a literal SHIP token is mechanically reserved for a CI run with an external
signing key (by design). An honest HOLD whose gate exits 0, with documented
risk-acceptance, is the strongest defensible posture.

## Blocker progress: 3 → 2

| Blocker                       | Status                                                                                 |
| ----------------------------- | -------------------------------------------------------------------------------------- |
| Dirty working tree (R3-state) | ✅**CLEARED** — harness committed (`7910aa61`); R3-state = "SHIP-state clean" |
| 14 HIGH dependency CVEs       | 🟡 accepted/scheduled (all unreachable; 2 have no upstream fix)                        |
| §1.10 provenance gate        | 🟡 implemented+wired; needs external CI key                                            |

## Gate state (clean tree)

| Rule                | Result                                                                 |
| ------------------- | ---------------------------------------------------------------------- |
| P-scope-integrity   | ✅`3d419142…`                                                       |
| P-context-integrity | ✅                                                                     |
| R1 recall           | ✅ all ≥ MEDIUM acknowledged/waived                                   |
| R2 spans            | ✅ all resolve                                                         |
| R3 completed-runs   | ✅                                                                     |
| R3-state            | ✅**SHIP-state clean** (git SHA present, tree clean, DBs pinned) |
| R4 CVSS             | ✅                                                                     |
| R6 vocabulary       | ✅                                                                     |
| **Gate**      | ✅**exit 0**                                                     |

**0 CRITICAL · 0 unwaived secrets · 14 accepted HIGH · 104 acknowledged MEDIUM · 8 accepted coverage gaps.**

## What engineering actually did (this remediation)

| Change                                                             | File(s)                                                                                                                                             | Need                                                                                |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Bumped 21 transitive CVE deps to fixed versions                    | `pyproject.toml` constraint-dependencies + `uv.lock`                                                                                            | Close the bumpable supply-chain CVEs                                                |
| Capped `fastmcp <3`                                              | `pyproject.toml`                                                                                                                                  | 3.x moves `mcp_config` and breaks `skill.py`; cap prevents a silent build-break |
| `.gitleaks.toml` allowlist + pre-commit hook                     | `.gitleaks.toml`, `.pre-commit-config.yaml`                                                                                                     | Resolve 24 false-positive secret hits cleanly; catch real future secrets            |
| MD5 →`usedforsecurity=False`                                    | `critic/impl/api/chat_template.py`                                                                                                                | Clear bandit B324; digest identical → cache unaffected                             |
| Documented trust boundaries (jinja, 3× shell, xml, apptainer env) | `prompts/prompt.py`, `hooks/executor.py`, `utils/command.py`, `file_editor/utils/shell.py`, `skills/skill.py`, `apptainer/workspace.py` | Justify by-design SAST hits without changing behavior (trajectory-safe)             |
| Removed unverifiable SWEBench badge                                | `README.md`                                                                                                                                       | Eliminate untraceable report-claim                                                  |
| Built + committed CRUCIBLE audit harness                           | `audit/`, `.crucible/`, front doors                                                                                                             | The gate itself; committing it cleared the dirty-tree blocker                       |

## Risk acceptance (engine-scope) — 2 remaining items

Scope: SDK used as a **library/engine** — not published to public PyPI/GHCR
under Ethara's name, not run as a public network service. Full machine record in
`findings.yaml → risk_acceptance` (7 items). The 2 live blockers:

- **Dependency CVEs (DEFER-1…5):** litellm (8, proxy-mode → unreachable; fork-pinned → rebase ≥1.84.0), fastmcp (3, components not imported; 3.x is build-breaking), lupa+diskcache (2, test-only/transitive, **no upstream fix**), pytest (1, dev-only, risky major bump). Engineering can move litellm/fastmcp (breaking work); lupa/diskcache are blocked on upstream.
- **Provenance gate (DEFER-6):** not product code — a CI/secrets task. SHIP requires `AUDIT_TRUST_ROOT_KEY` from outside the repo; unreachable on a producer host **by design**.
- **CRUCIBLE-7 (DEFER-7):** container/PyPI provenance — **escalates to BLOCK before any public release under Ethara's name.**

## Why nothing breaks the agent trajectories

- No `Event`/`Message`/`TextContent`/serialized model changed; old conversations still load.
- jinja autoescape left OFF (enabling it changes prompt bytes); xml path only escapes output.
- All `shell=True` left intact (pipes/globs/`&&` recorded runs depend on); documented + waived.
- MD5 digest identical with `usedforsecurity=False` → cache filenames unchanged.
- Dependency bumps are transitive floors, not SDK import-API changes; fastmcp capped `<3`.
- 525 context/critic/tools tests pass; the 28 condenser failures are pre-existing (pydantic-2.12 + MagicMock), reproduced on the pristine tree.

## Harness integrity

- Nothing under `audit/` was edited to make the verifier pass.
- Self-test: ruff clean · 53 pytest pass (negative-controls + self-fuzz).
- Every scope change correctly invalidated the old sign-off and forced a re-sign.

## Path to a literal SHIP (if/when desired)

1. Clear/reschedule the 14 dependency CVEs (litellm fork rebase; fastmcp 3.x; lupa/diskcache on upstream; pytest 9.x).
2. Run the audit in CI with `AUDIT_TRUST_ROOT_KEY` (signs the provenance manifest).
3. Before any public PyPI/GHCR release under Ethara's name: complete CRUCIBLE-7.

**This sign-off is pushable as-is: the gate exits 0 on a clean tree — an honest HOLD with documented, owner-assigned, trigger-bound risk acceptance.**
