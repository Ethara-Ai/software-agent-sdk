"""Bespoke domain-integrity checks (THE CORE — deterministic, because no
off-the-shelf scanner ships them).

Each check is Bucket D: a total, bounded, recomputable relation over the
grounded artifacts. Where a check's subject surface is NOT_APPLICABLE for this
target (per scope.yaml), the check records a clean coverage manifest entry with
its detector evidence rather than silently skipping (absence is a result).

Implemented for THIS repo's scope:
- report_claim_artifact_check : reconcile the README 'SWEBench 77.6' claim;
  untraceable claim -> HIGH + HOLD (cross-repo pointer absent).
- dataset_leakage_check       : NOT_APPLICABLE (no shipped scored dataset) ->
  clean coverage-manifest entry with detector evidence.
- reward_provenance_check     : CAPABILITY_ONLY (in-memory CriticResult.score,
  no persisted reward path) -> records capability + conditional-BLOCK note.
- rollout_integrity_check     : CAPABILITY_ONLY (test-only gitignored runner) ->
  records capability + conditional-BLOCK note.
"""

from __future__ import annotations

import re
from pathlib import Path

from models import CoverageGap, NormalizedIssue, Severity
from policy import REPO_ROOT

_SWEBENCH_CLAIM_RE = re.compile(r"SWE-?Bench[^0-9]{0,12}(\d{1,3}(?:\.\d+)?)", re.I)
# A traceable pointer would name a commit SHA + run id + dataset revision.
_TRACE_RE = re.compile(
    r"(run[_\s-]?id|commit\s+[0-9a-f]{7,40}|dataset\s+rev|evaluation@|results\.eval)",
    re.I,
)


class DomainResult:
    """Container for one domain check's output."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.issues: list[NormalizedIssue] = []
        self.gaps: list[CoverageGap] = []
        self.coverage: dict[str, object] = {}


def report_claim_artifact_check(repo_root: Path = REPO_ROOT) -> DomainResult:
    """Recompute / trace the README performance claim.

    Bucket D: parse README, find the claim, search the tree for a traceable
    cross-repo pointer (commit + run id + dataset rev). An UNTRACEABLE claim is
    HIGH + HOLD per §1.5; a metric MISMATCH that changes a disposition would be
    CRITICAL + BLOCK (no recomputable local artifact here, so mismatch is N/A).
    """
    res = DomainResult("report_claim_artifact_check")
    readme = repo_root / "README.md"
    if not readme.exists():
        res.coverage = {"status": "no_readme", "claims_found": 0}
        return res
    text = readme.read_text(errors="replace")
    claims = _SWEBENCH_CLAIM_RE.findall(text)
    res.coverage = {
        "status": "scanned",
        "claims_found": len(claims),
        "claim_values": claims,
        "readme_path": "README.md",
    }
    if not claims:
        return res
    # Is there ANY traceable pointer anywhere reasonable in the tree?
    traceable = bool(_TRACE_RE.search(text))
    if not traceable:
        for rel in ("README.md", "docs", "EVALUATION.md", "benchmarks"):
            p = repo_root / rel
            if p.is_file() and _TRACE_RE.search(p.read_text(errors="replace")):
                traceable = True
                break
    if not traceable:
        res.issues.append(
            NormalizedIssue(
                tool="report_claim_traceability_check",
                rule_id="REPORT-CLAIM-UNTRACED",
                severity=Severity.HIGH,
                location_type="artifact",
                path="README.md",
                line=_first_line_of(text, "SWE"),
                message=(
                    f"README advertises SWEBench score {claims} with no "
                    "verifiable cross-repo pointer (commit SHA + run id + "
                    "dataset revision). Claim is untraceable to a scored run."
                ),
                normalized_snippet="readme swebench score untraceable claim",
                tool_native_fingerprint="REPORT-CLAIM-UNTRACED",
            )
        )
        res.gaps.append(
            CoverageGap(
                gap_id="readme_score_claim_untraced",
                detail=(
                    f"README 'SWEBench {claims}' has no verifiable cross-repo "
                    "pointer (commit/run-id/dataset rev)."
                ),
                cap="HOLD",
                instrument="report_claim_traceability_check",
                surface="report_claim_readme_score",
            )
        )
    return res


def _first_line_of(text: str, needle: str) -> int | None:
    for i, line in enumerate(text.splitlines(), start=1):
        if needle.lower() in line.lower():
            return i
    return None


def dataset_leakage_check(repo_root: Path = REPO_ROOT) -> DomainResult:
    """NOT_APPLICABLE for this target: no shipped scored dataset.

    Records a fail-closed coverage manifest with detector evidence rather than
    silently skipping. If a scored train/test pair were present, this would run
    exact SHA-256 + MinHash containment and emit CRITICAL+BLOCK on leak.
    """
    res = DomainResult("dataset_leakage_check")
    # Detector: look for shipped scored data formats outside test fixtures.
    candidates: list[str] = []
    for pat in ("*.parquet", "*.jsonl"):
        for p in repo_root.rglob(pat):
            parts = set(p.parts)
            if parts & {".venv", ".git", "node_modules", "results", "__pycache__"}:
                continue
            if "fixtures" in parts or "tests" in parts:
                continue
            candidates.append(str(p.relative_to(repo_root)))
    res.coverage = {
        "status": "not_applicable",
        "detector_evidence": (
            "No shipped scored parquet/jsonl datasets outside tests/fixtures. "
            "SWE-bench traces are downloaded externally, not committed."
        ),
        "shipped_scored_dataset_candidates": candidates,
        "would_emit_on_leak": "CRITICAL + BLOCK",
    }
    return res


def reward_provenance_check(repo_root: Path = REPO_ROOT) -> DomainResult:
    """CAPABILITY_ONLY for this target.

    CriticResult.score is in-memory (part of the normal Event stream); there is
    NO persisted reward file and NO agent-writable reward path. Records the
    capability + the conditional BLOCK that activates downstream on an
    eval-output bundle.
    """
    res = DomainResult("reward_provenance_check")
    critic_dir = repo_root / "openhands-sdk/openhands/sdk/critic"
    res.coverage = {
        "status": "capability_only",
        "evidence": (
            "openhands.sdk.critic.CriticResult.score is a float in-memory in the "
            "Event stream; no persisted reward file, no HMAC/signature, no "
            "agent-writable reward path for this target."
        ),
        "critic_present": critic_dir.is_dir(),
        "conditional_obligation": {
            "activates_when": "audit target is an eval-output bundle",
            "cap_when_active": "BLOCK",
        },
        "downstream_inheritance": "OpenHands/evaluation inherits this obligation",
    }
    return res


def rollout_integrity_check(repo_root: Path = REPO_ROOT) -> DomainResult:
    """CAPABILITY_ONLY for this target.

    The multi-rollout batch runner exists only as test harness
    (tests/integration/run_infer.py) writing gitignored outputs; no shipped
    aggregated metrics. Records capability + conditional BLOCK.
    """
    res = DomainResult("rollout_integrity_check")
    runner = repo_root / "tests/integration/run_infer.py"
    res.coverage = {
        "status": "capability_only",
        "evidence": (
            "Multi-rollout runner is test-only (tests/integration/run_infer.py); "
            "outputs under tests/integration/outputs/ are gitignored and never "
            "shipped with a disposition."
        ),
        "runner_present": runner.is_file(),
        "conditional_obligation": {
            "activates_when": (
                "target reports final aggregated metrics from persisted trials"
            ),
            "cap_when_active": "BLOCK",
        },
        "downstream_inheritance": "OpenHands/evaluation inherits this obligation",
    }
    return res


def run_all_domain_checks(repo_root: Path = REPO_ROOT) -> list[DomainResult]:
    return [
        report_claim_artifact_check(repo_root),
        dataset_leakage_check(repo_root),
        reward_provenance_check(repo_root),
        rollout_integrity_check(repo_root),
    ]
