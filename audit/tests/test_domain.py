"""Conformance: bespoke domain-integrity checks (ledger rows 16-19)."""

from __future__ import annotations

from pathlib import Path

from domain import (
    dataset_leakage_check,
    report_claim_artifact_check,
    reward_provenance_check,
    rollout_integrity_check,
)


def test_untraced_claim(tmp_path: Path):
    # A README with a SWE-bench score and NO traceable pointer -> HIGH + HOLD.
    (tmp_path / "README.md").write_text(
        "We score SWEBench 77.6 on the verified split.\n"
    )
    res = report_claim_artifact_check(tmp_path)
    assert res.issues, "expected an untraceable-claim finding"
    assert res.issues[0].severity.value == "HIGH"
    assert any(g.gap_id == "readme_score_claim_untraced" for g in res.gaps)


def test_traced_claim_clean(tmp_path: Path):
    # A README with a traceable pointer -> no finding.
    (tmp_path / "README.md").write_text(
        "SWEBench 77.6 — reproduced at evaluation@commit a1b2c3d run_id=42 "
        "dataset rev 2024-09.\n"
    )
    res = report_claim_artifact_check(tmp_path)
    assert not res.issues


def test_dataset_na_manifest(tmp_path: Path):
    # No shipped scored dataset -> not_applicable coverage manifest, no crash.
    res = dataset_leakage_check(tmp_path)
    assert res.coverage["status"] == "not_applicable"
    assert "would_emit_on_leak" in res.coverage


def test_reward_capability_only(tmp_path: Path):
    res = reward_provenance_check(tmp_path)
    assert res.coverage["status"] == "capability_only"
    assert res.coverage["conditional_obligation"]["cap_when_active"] == "BLOCK"


def test_rollout_capability_only(tmp_path: Path):
    res = rollout_integrity_check(tmp_path)
    assert res.coverage["status"] == "capability_only"
    assert res.coverage["conditional_obligation"]["cap_when_active"] == "BLOCK"
