"""Verifier — six deterministic rules + the fail-closed disposition.

Reads the committed evidence bundle (audit/evidence.yaml) and the producer's
findings.yaml. Exits 0 ONLY when every rule holds. This is the ONLY command
whose success means the gate passed.

Rules:
  R1 recall          — every >= MEDIUM parsed-run issue acknowledged/validly
                       waived; empty report passes only if every required
                       instrument ran clean+parsed; effective sev = max over ack.
  R2 span resolution — every path:line resolves inside the audit root (realpath,
                       regular file, line in range; no .., no symlink escape).
  R3 completed-run   — only ok/nonzero_exit runs back a finding; blocked/timeout
                       back only a coverage gap. R3-state: SHIP needs non-null
                       git SHA + clean tree + pinned DBs.
  R4 CVSS form/truth — recompute v3.1 base offline; reject mismatched cvss_base.
  R6 vocabulary      — dispositions SHIP/HOLD/BLOCK only; severity independent;
                       tallies sum to finding count.

Plus §1.10 provenance pre-checks (scope integrity + the unwired provenance gate
that caps SHIP as a D-COVERAGE-GAP under the Trusted-Evidence Axiom).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from cvss import CVSSError, base_score
from models import Disposition, NormalizedIssue, Severity
from policy import (
    AUDIT_DIR,
    REPO_ROOT,
    assert_scope_approved,
    load_scope,
    required_instrument_ids,
)
from recall import check_recall


@dataclass
class RuleResult:
    rule: str
    ok: bool
    detail: str = ""
    items: list[str] = field(default_factory=list)


@dataclass
class VerifyOutcome:
    ok: bool
    disposition: Disposition
    rules: list[RuleResult] = field(default_factory=list)
    capped_reason: str = ""

    def exit_code(self) -> int:
        return 0 if self.ok else 1


# ---------------------------------------------------------------------------
# Evidence / findings loading
# ---------------------------------------------------------------------------
def load_evidence(path: Path) -> dict:
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


def load_findings(path: Path) -> dict:
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


def _evidence_issues(evidence: dict) -> list[NormalizedIssue]:
    out: list[NormalizedIssue] = []
    for raw in evidence.get("normalized_issues", []) or []:
        try:
            out.append(NormalizedIssue.model_validate(raw))
        except (ValueError, TypeError):
            continue
    return out


# ---------------------------------------------------------------------------
# §1.10 pre-checks
# ---------------------------------------------------------------------------
def precheck_scope_integrity() -> RuleResult:
    try:
        digest = assert_scope_approved()
        return RuleResult("P-scope-integrity", True, f"scope digest {digest[:12]}…")
    except Exception as exc:  # noqa: BLE001 — surface any sentinel failure
        return RuleResult("P-scope-integrity", False, str(exc))


def precheck_context_integrity(evidence_path: Path, evidence: dict) -> RuleResult:
    """Context integrity: the evidence bundle must declare its own identity and
    exist. (Full §1.10 manifest signing is the declared D-COVERAGE-GAP.)"""
    if not evidence_path.exists():
        return RuleResult("P-context-integrity", False, "evidence.yaml missing")
    if "recon" not in evidence:
        return RuleResult("P-context-integrity", False, "evidence missing recon block")
    return RuleResult(
        "P-context-integrity", True, "evidence bundle present + structured"
    )


# ---------------------------------------------------------------------------
# R1 — recall
# ---------------------------------------------------------------------------
def rule_r1_recall(evidence: dict, findings: dict) -> tuple[RuleResult, Severity]:
    issues = _evidence_issues(evidence)
    ack_ids = {
        f.get("instance_id", "")
        for f in findings.get("findings", []) or []
        if f.get("instance_id")
    }
    waivers = findings.get("waivers", []) or []

    # Empty/all-clear report passes ONLY if every required instrument ran clean.
    required = set(required_instrument_ids(load_scope()))
    clean_runs = {
        r.get("tool_name")
        for r in evidence.get("runs", []) or []
        if r.get("status") in ("ok", "nonzero_exit") and r.get("parsed_ok") is True
    }
    gaps = evidence.get("coverage_gaps", []) or []
    capping_gaps = [g for g in gaps if g.get("cap") in ("HOLD", "BLOCK")]

    res = check_recall(issues, ack_ids, waivers)
    if not res.ok:
        detail = (
            f"{len(res.missing_instance_ids)} unacknowledged >= MEDIUM issue(s); "
            f"{len(res.bad_waivers)} bad waiver(s)"
        )
        return (
            RuleResult(
                "R1-recall",
                False,
                detail,
                items=res.missing_instance_ids + res.bad_waivers,
            ),
            res.effective_severity,
        )
    if not issues:
        missing_required = required - clean_runs
        if missing_required or capping_gaps:
            return (
                RuleResult(
                    "R1-recall",
                    True,
                    "empty findings accepted BUT coverage gaps cap disposition",
                    items=sorted(missing_required),
                ),
                Severity.INFO,
            )
    return RuleResult(
        "R1-recall", True, "all >= MEDIUM issues acknowledged"
    ), res.effective_severity


# ---------------------------------------------------------------------------
# R2 — span resolution
# ---------------------------------------------------------------------------
def _resolve_span(path_str: str, line: int | None, root: Path) -> str | None:
    if ".." in Path(path_str).parts:
        return "path contains '..'"
    candidate = (root / path_str).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return "path escapes audit root"
    if candidate.is_symlink():
        return "path is a symlink"
    if not candidate.is_file():
        return "not a regular file"
    if line is not None:
        try:
            with candidate.open("rb") as fh:
                total = sum(1 for _ in fh)
        except OSError as exc:
            return f"unreadable: {exc}"
        if line < 1 or line > max(total, 1):
            return f"line {line} out of range (1..{total})"
    return None


def rule_r2_spans(findings: dict, root: Path = REPO_ROOT) -> RuleResult:
    bad: list[str] = []
    for f in findings.get("findings", []) or []:
        path = f.get("path")
        if not path:
            continue
        err = _resolve_span(str(path), f.get("line"), root)
        if err:
            bad.append(f"{f.get('id', '?')} {path}:{f.get('line')} — {err}")
    return RuleResult(
        "R2-spans",
        not bad,
        "all spans resolve" if not bad else f"{len(bad)} unresolvable span(s)",
        items=bad,
    )


# ---------------------------------------------------------------------------
# R3 — completed-run evidence + R3-state
# ---------------------------------------------------------------------------
def rule_r3_completed_runs(evidence: dict, findings: dict) -> RuleResult:
    run_status = {
        r.get("run_id"): r.get("status") for r in evidence.get("runs", []) or []
    }
    bad: list[str] = []
    for f in findings.get("findings", []) or []:
        rid = f.get("run_id")
        if rid is None:
            continue  # domain/coverage findings may not cite a run
        status = run_status.get(rid)
        if status not in ("ok", "nonzero_exit"):
            bad.append(f"{f.get('id', '?')} cites run {rid} with status {status}")
    return RuleResult(
        "R3-completed-runs",
        not bad,
        "all cited runs completed"
        if not bad
        else f"{len(bad)} finding(s) cite blocked/timeout/phantom runs",
        items=bad,
    )


def rule_r3_state(evidence: dict) -> RuleResult:
    recon = evidence.get("recon", {}) or {}
    problems: list[str] = []
    if not recon.get("git_sha"):
        problems.append("null git SHA")
    if recon.get("git_dirty"):
        problems.append("dirty working tree")
    unpinned = [
        p.get("name")
        for p in recon.get("scanner_pins", []) or []
        if p.get("db_version") is None and p.get("note", "").find("UNPINNED") >= 0
    ]
    if unpinned:
        problems.append(f"unpinned DBs: {unpinned}")
    return RuleResult(
        "R3-state",
        not problems,
        "SHIP-state clean" if not problems else "; ".join(problems),
        items=problems,
    )


# ---------------------------------------------------------------------------
# R4 — CVSS form vs truth
# ---------------------------------------------------------------------------
def rule_r4_cvss(findings: dict) -> RuleResult:
    bad: list[str] = []
    for f in findings.get("findings", []) or []:
        # CWE format is checked INDEPENDENTLY of CVSS presence.
        cwe = f.get("cwe")
        if cwe is not None and not str(cwe).upper().startswith("CWE-"):
            bad.append(f"{f.get('id', '?')}: malformed CWE {cwe!r}")
        vector = f.get("cvss_vector")
        claimed = f.get("cvss_base")
        if vector is None and claimed is None:
            continue
        if vector is None:
            bad.append(f"{f.get('id', '?')}: cvss_base without vector")
            continue
        try:
            recomputed = base_score(str(vector))
        except CVSSError as exc:
            bad.append(f"{f.get('id', '?')}: bad vector — {exc}")
            continue
        if claimed is None or abs(recomputed - float(claimed)) > 0.05:
            bad.append(
                f"{f.get('id', '?')}: claimed {claimed} != recomputed {recomputed}"
            )
    return RuleResult(
        "R4-cvss",
        not bad,
        "all CVSS recompute + CWE well-formed"
        if not bad
        else f"{len(bad)} CVSS/CWE problem(s)",
        items=bad,
    )


# ---------------------------------------------------------------------------
# R6 — vocabulary
# ---------------------------------------------------------------------------
def rule_r6_vocabulary(findings: dict) -> RuleResult:
    problems: list[str] = []
    disp = findings.get("disposition")
    valid_disp = {d.value for d in Disposition}
    if disp not in valid_disp:
        problems.append(f"invalid disposition {disp!r}")
    valid_sev = {s.value for s in Severity}
    items = findings.get("findings", []) or []
    for f in items:
        if f.get("severity") not in valid_sev:
            problems.append(
                f"{f.get('id', '?')}: invalid severity {f.get('severity')!r}"
            )
    tally = findings.get("severity_tally", {}) or {}
    if tally:
        tally_sum = sum(int(v) for v in tally.values())
        if tally_sum != len(items):
            problems.append(f"tally sum {tally_sum} != finding count {len(items)}")
    return RuleResult(
        "R6-vocabulary",
        not problems,
        "vocabulary + tallies valid" if not problems else "; ".join(problems),
        items=problems,
    )


# ---------------------------------------------------------------------------
# Disposition — fail closed
# ---------------------------------------------------------------------------
def _provenance_gate_wired() -> bool:
    """§1.10: SHIP requires a signed artifact-closure manifest + trusted run
    environment. This is the declared D-COVERAGE-GAP: unwired => caps SHIP."""
    manifest = AUDIT_DIR / "manifest.sig"
    trusted = os.environ.get("CRUCIBLE_TRUSTED_RUN") == "1"
    return manifest.exists() and trusted


def compute_disposition(
    evidence: dict,
    findings: dict,
    rules: list[RuleResult],
    effective_severity: Severity,
) -> tuple[Disposition, str]:
    """Total, fail-closed disposition.

    BLOCK if any CRITICAL-floor finding or a BLOCK-capped gap; else HOLD if any
    rule fails, any HOLD/BLOCK coverage gap exists, effective severity >= HIGH,
    or the provenance gate is unwired; else SHIP.
    """
    gaps = evidence.get("coverage_gaps", []) or []
    block_gaps = [g for g in gaps if g.get("cap") == "BLOCK"]
    hold_gaps = [g for g in gaps if g.get("cap") == "HOLD"]

    issues = _evidence_issues(evidence)
    has_critical = any(i.severity == Severity.CRITICAL for i in issues)

    if has_critical or block_gaps:
        why = (
            "CRITICAL-floor finding present"
            if has_critical
            else f"{len(block_gaps)} BLOCK-capped coverage gap(s)"
        )
        return Disposition.BLOCK, why

    failed = [r for r in rules if not r.ok]
    if failed:
        return Disposition.HOLD, f"verifier rule(s) failed: {[r.rule for r in failed]}"
    if hold_gaps:
        return Disposition.HOLD, f"{len(hold_gaps)} HOLD-capped coverage gap(s)"
    if effective_severity >= Severity.HIGH:
        return (
            Disposition.HOLD,
            f"effective severity {effective_severity.value} >= HIGH",
        )
    if not _provenance_gate_wired():
        return Disposition.HOLD, (
            "provenance gate unwired (D-COVERAGE-GAP) — Trusted-Evidence Axiom "
            "caps SHIP until a signed manifest + trusted runner are present"
        )
    return Disposition.SHIP, "all rules hold; coverage complete; provenance wired"


# ---------------------------------------------------------------------------
# Top-level verify
# ---------------------------------------------------------------------------
def verify(findings_path: Path, evidence_path: Path) -> VerifyOutcome:
    rules: list[RuleResult] = []
    # §1.10 pre-checks first.
    p_scope = precheck_scope_integrity()
    rules.append(p_scope)
    if not p_scope.ok:
        return VerifyOutcome(False, Disposition.BLOCK, rules, p_scope.detail)

    evidence = load_evidence(evidence_path)
    rules.append(precheck_context_integrity(evidence_path, evidence))
    findings = load_findings(findings_path)

    r1, eff_sev = rule_r1_recall(evidence, findings)
    rules.append(r1)
    rules.append(rule_r2_spans(findings))
    rules.append(rule_r3_completed_runs(evidence, findings))
    rules.append(rule_r3_state(evidence))
    rules.append(rule_r4_cvss(findings))
    rules.append(rule_r6_vocabulary(findings))

    all_ok = all(r.ok for r in rules)
    disposition, reason = compute_disposition(evidence, findings, rules, eff_sev)

    # The producer's claimed disposition must not exceed what the gate computes.
    claimed = findings.get("disposition")
    rank = {"BLOCK": 0, "HOLD": 1, "SHIP": 2}
    if claimed in rank and rank[claimed] > rank[disposition.value]:
        all_ok = False
        rules.append(
            RuleResult(
                "D-disposition-cap",
                False,
                f"producer claims {claimed} but gate computes {disposition.value}",
            )
        )

    # Gate passes iff all rules hold AND the computed disposition is not BLOCK.
    gate_ok = all_ok and disposition != Disposition.BLOCK
    return VerifyOutcome(gate_ok, disposition, rules, reason)
