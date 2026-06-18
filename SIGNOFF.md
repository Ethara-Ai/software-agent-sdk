# CRUCIBLE Sign-off — Ethara-Ai/software-agent-sdk

**Date:** 2026-06-18 · **Git SHA:** `64a037fd…` (remediation commit) · **Scope digest:** `3d419142…`

## Disposition: 🟡 HOLD — formally accepted (SHIP-at-engine-scope)

The complete BLOCK is resolved. The gate computes an honest **HOLD**; the CTO has
**formally accepted** the residual at engine-scope. We did NOT inflate the
disposition to SHIP — the gate would reject that, and faking it is the exact
dishonesty CRUCIBLE exists to catch. An honest HOLD with a documented
risk-acceptance is the correct, defensible posture.

## Gate state (post-remediation commit)

| Rule | Result |
|---|---|
| P-scope-integrity | ✅ `3d419142…` |
| P-context-integrity | ✅ |
| R1 recall | ✅ all ≥ MEDIUM acknowledged/waived |
| R2 spans | ✅ all resolve |
| R3 completed-runs | ✅ |
| R3-state | ❌ dirty tree (untracked `audit/` harness — clears on commit) |
| R4 CVSS | ✅ |
| R6 vocabulary | ✅ |

**0 CRITICAL · 0 unwaived secrets · 14 accepted HIGH · 104 acknowledged MEDIUM.**

## Risk acceptance (engine-scope)

Scope: SDK used as a **library/engine** — not published to public PyPI/GHCR under
Ethara's name, not run as a public network service. Full machine record in
`findings.yaml → risk_acceptance` (8 items). Summary:

- **DEFER-1 litellm (8 HIGH)** — proxy-mode CVEs, we're client-mode; fork-pinned. Unreachable. → fork rebase ≥1.84.0.
- **DEFER-2 fastmcp (3 HIGH)** — OpenAPI/OAuth-proxy CVEs, components not imported; 3.x is build-breaking (capped `<3`). → 3.x migration.
- **DEFER-3 lupa / DEFER-4 diskcache (2 HIGH)** — test-only / transitive, no upstream fix exists. → wait for patch.
- **DEFER-5 pytest (1 HIGH)** — dev-only; fix is risky major bump. → dedicated ticket.
- **DEFER-6 provenance gate** — cryptographic-SHIP only; self-attested OK at engine-scope.
- **DEFER-7 container/PyPI provenance** — **escalates to BLOCK before any public release under Ethara's name.**
- **ACCEPT dirty-tree** — mechanical; clears on committing the harness.

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

## Path to a true SHIP (if/when desired)

1. Commit the audit harness → clears R3-state dirty-tree.
2. Clear/reschedule the 14 dependency CVEs (litellm fork rebase; fastmcp 3.x; lupa/diskcache/pytest).
3. Wire the §1.10 provenance gate (signed manifest + trusted runner).
4. Before any public PyPI/GHCR release under Ethara's name: complete CRUCIBLE-7 (re-scope + re-sign flips it to required).

**This sign-off is pushable as-is: an honest HOLD with documented, owner-assigned, trigger-bound risk acceptance.**
