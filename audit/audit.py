"""CRUCIBLE audit gate — orchestrator (Typer app).

Commands:
  provision : install scanners (uv sync --extra scanners + native binaries).
  run       : recon + scanners + normalization + domain checks -> writes the
              committed evidence bundle audit/evidence.yaml and the gitignored
              per-command stdout artifacts under audit/results/. Bucket-D
              evidence generation, NOT a gate.
  verify    : the six rules against findings.yaml; exits 0 ONLY when all hold —
              the ONLY command whose success means the gate passed.
  all       : provision (unless --no-install) -> run -> optional --verify ->
              prints the Phase-2 hand-off. Never writes findings. States that
              findings are UNGATED until `audit verify` exits 0.

Bootstrapped via: uv run --project audit audit all
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import typer
import yaml

from domain import run_all_domain_checks
from models import CoverageGap, RunStatus
from normalize import finalize_issues, normalize_run
from policy import (
    AUDIT_DIR,
    REPO_ROOT,
    ScopeError,
    assert_scope_approved,
    load_scope,
    required_instrument_ids,
    severity_map_digest,
)
from recon import collect_recon
from tools import RESULTS_DIR, applicable_tools, build_registry, run_tool
from verifier import verify

app = typer.Typer(
    add_completion=False,
    help="CRUCIBLE adversarial audit gate for OpenHands/software-agent-sdk.",
)

EVIDENCE_PATH = REPO_ROOT / "audit" / "evidence.yaml"
_GLOBAL_BUDGET_SEC = 1800


def _echo(msg: str) -> None:
    typer.echo(msg)


@app.command()
def provision(no_install: bool = typer.Option(False, "--no-install")) -> None:
    """Install scanners. Hard-fail on the pip extras; native tools best-effort."""
    if no_install:
        _echo("provision: --no-install set, skipping.")
        return
    _echo("provision: uv sync --extra scanners (audit project)…")
    rc = subprocess.run(
        ["uv", "sync", "--extra", "scanners", "--extra", "dev"],
        cwd=AUDIT_DIR,
        check=False,
    ).returncode
    if rc != 0:
        _echo("provision: uv sync FAILED (hard-fail).")
        raise typer.Exit(code=rc)
    _echo(
        "provision: native scanners (osv-scanner/gitleaks/hadolint/trivy) "
        "are installed out-of-band (e.g. brew); recorded as tool_blocked if "
        "absent."
    )


def _present_surface_ids(scope: dict) -> set[str]:
    present = set()
    for s in scope.get("surfaces", []):
        if s.get("status", "").startswith(("PRESENT", "CAPABILITY")):
            present.add(s["id"])
    return present


@app.command()
def run() -> None:
    """Recon + scanners + normalization + domain checks -> evidence.yaml."""
    try:
        scope_digest = assert_scope_approved()
    except ScopeError as exc:
        _echo(f"run: REFUSED — {exc}")
        raise typer.Exit(code=2) from exc

    scope = load_scope()
    smap = severity_map_digest()
    _echo("run: collecting recon…")
    recon = collect_recon(scope_digest, smap)

    registry = build_registry()
    present = _present_surface_ids(scope)
    tools = applicable_tools(registry, present)

    runs = []
    normalized_issues = []
    coverage_gaps: list[CoverageGap] = []
    required = set(required_instrument_ids(scope))

    start = time.monotonic()
    for i, tool in enumerate(tools, start=1):
        if time.monotonic() - start > _GLOBAL_BUDGET_SEC:
            coverage_gaps.append(
                CoverageGap(
                    gap_id=f"global_budget_exceeded_{tool.name}",
                    detail=f"global wall-clock budget hit before {tool.name}",
                    cap=tool.disposition_cap_on_absent,
                    instrument=tool.name,
                )
            )
            continue
        run_id = f"CMD-{i:03d}"
        _echo(f"run: [{run_id}] {tool.name} …")
        tr = run_tool(tool, run_id)

        # Normalize completed runs; record coverage gap on block/timeout/parse-fail.
        if tr.completed:
            raw = ""
            if tr.stdout_path and Path(tr.stdout_path).exists():
                raw = Path(tr.stdout_path).read_text(errors="replace")
            issues, parsed_ok, parse_err = normalize_run(tr, raw, scope_digest or "")
            tr.parsed_ok = parsed_ok
            tr.parse_error = parse_err
            if parsed_ok:
                normalized_issues.extend(issues)
            elif tool.name in required and tool.parser_required:
                coverage_gaps.append(
                    CoverageGap(
                        gap_id=f"parse_failed_{tool.name}",
                        detail=(
                            f"required tool {tool.name} output unparsable: {parse_err}"
                        ),
                        cap=tool.disposition_cap_on_absent,
                        instrument=tool.name,
                        run_id=run_id,
                    )
                )
        else:
            if tool.name in required:
                coverage_gaps.append(
                    CoverageGap(
                        gap_id=f"{tr.status.value}_{tool.name}",
                        detail=f"required tool {tool.name} {tr.status.value}: "
                        f"{tr.blocked_reason}",
                        cap=tool.disposition_cap_on_absent,
                        instrument=tool.name,
                        run_id=run_id,
                    )
                )
        runs.append(tr)

    # Required instruments that never produced a run at all (e.g. no binary
    # mapping) -> coverage gap. Fail closed.
    ran_tool_names = {r.tool_name for r in runs}
    registry_names = {t.name for t in registry}
    for inst in required:
        if inst not in registry_names and inst not in ran_tool_names:
            coverage_gaps.append(
                CoverageGap(
                    gap_id=f"no_instrument_{inst}",
                    detail=f"required instrument {inst} has no wired tool runner",
                    cap="HOLD",
                    instrument=inst,
                )
            )

    # Domain-integrity checks (the core).
    domain_results = run_all_domain_checks()
    domain_blocks = []
    for dr in domain_results:
        # Give domain findings the same verifier-owned identity as scanner
        # findings (cluster_fingerprint + issue_instance_id), so R1 can match
        # them by instance id. Domain findings have no run_id (R3 exempt).
        finalize_issues(dr.issues, run_id="", source_manifest_digest=scope_digest or "")
        normalized_issues.extend(dr.issues)
        coverage_gaps.extend(dr.gaps)
        domain_blocks.append(
            {
                "name": dr.name,
                "coverage": dr.coverage,
                "issues": len(dr.issues),
                "gaps": len(dr.gaps),
            }
        )

    # Declared scope coverage gaps (provenance gate unwired, etc.).
    for g in scope.get("coverage_gaps", []) or []:
        if g.get("cap") in ("HOLD", "BLOCK"):
            coverage_gaps.append(
                CoverageGap(
                    gap_id=g["id"],
                    detail=g.get("detail", ""),
                    cap=g["cap"],
                )
            )

    evidence = {
        "schema_version": "2",
        "generated_by": "crucible-audit run",
        "scope_digest": scope_digest,
        "severity_map_digest": smap,
        "recon": recon.model_dump(),
        "runs": [r.model_dump(mode="json") for r in runs],
        "normalized_issues": [i.model_dump(mode="json") for i in normalized_issues],
        "coverage_gaps": [g.model_dump() for g in _dedup_gaps(coverage_gaps)],
        "domain_checks": domain_blocks,
        "not_run_or_blocked": [
            {"tool": r.tool_name, "status": r.status.value, "reason": r.blocked_reason}
            for r in runs
            if not r.completed
        ],
    }
    EVIDENCE_PATH.write_text(
        yaml.safe_dump(evidence, sort_keys=False, default_flow_style=False, width=100)
    )
    _echo(
        f"run: wrote {EVIDENCE_PATH} "
        f"({len(normalized_issues)} issues, {len(evidence['coverage_gaps'])} gaps)."
    )
    _echo("run: evidence is UNGATED until `audit verify` exits 0.")


def _dedup_gaps(gaps: list[CoverageGap]) -> list[CoverageGap]:
    seen: dict[str, CoverageGap] = {}
    for g in gaps:
        seen.setdefault(g.gap_id, g)
    return list(seen.values())


@app.command(name="verify")
def verify_cmd(
    findings: Path = typer.Option(..., "--findings"),
    context: Path = typer.Option(EVIDENCE_PATH, "--context"),
) -> None:
    """Run the six rules. Exits 0 ONLY when the gate passes."""
    if not findings.exists():
        _echo(f"verify: findings file not found: {findings}")
        raise typer.Exit(code=2)
    outcome = verify(findings, context)
    _echo("=" * 64)
    _echo("CRUCIBLE verify")
    _echo("=" * 64)
    for r in outcome.rules:
        mark = "PASS" if r.ok else "FAIL"
        _echo(f"  [{mark}] {r.rule}: {r.detail}")
        for item in r.items[:8]:
            _echo(f"          - {item}")
    _echo("-" * 64)
    _echo(f"  disposition: {outcome.disposition.value}")
    _echo(f"  reason:      {outcome.capped_reason}")
    _echo(f"  gate:        {'PASS (exit 0)' if outcome.ok else 'FAIL (exit 1)'}")
    _echo("=" * 64)
    raise typer.Exit(code=outcome.exit_code())


@app.command()
def all(
    no_install: bool = typer.Option(False, "--no-install"),
    verify_after: bool = typer.Option(False, "--verify"),
    timeout: int = typer.Option(900, "-t", "--timeout"),
) -> None:
    """provision -> run -> optional verify -> Phase-2 hand-off."""
    global _GLOBAL_BUDGET_SEC
    _GLOBAL_BUDGET_SEC = timeout
    if not no_install:
        provision(no_install=False)
    run()
    if verify_after:
        findings = REPO_ROOT / "findings.yaml"
        if findings.exists():
            verify_cmd(findings=findings, context=EVIDENCE_PATH)
        else:
            _echo("all: no findings.yaml yet — skipping verify.")
    _echo("")
    _echo("─" * 64)
    _echo("PHASE 2 HAND-OFF")
    _echo("─" * 64)
    _echo("Evidence written to audit/evidence.yaml (the ONLY citable source).")
    _echo("Findings are UNGATED until `audit verify` exits 0.")
    _echo("Next: read REVIEW.md + audit/evidence.yaml, write findings.yaml +")
    _echo("REPORT.md at the repo root, then loop:")
    _echo(
        "  uv run --project audit audit verify --findings findings.yaml "
        "--context audit/evidence.yaml"
    )


def main() -> None:
    try:
        app()
    except ScopeError as exc:
        _echo(f"REFUSED: {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()


# Keep RESULTS_DIR / RunStatus referenced for module import side-effect clarity.
_ = (RESULTS_DIR, RunStatus)
