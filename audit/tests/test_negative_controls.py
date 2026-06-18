"""Negative-control tests: prove each producer bypass is CAUGHT (ledger 7-14).

These write a (broken) findings.yaml + (real) evidence.yaml to a tmp dir and run
the verifier, asserting the gate FAILS. The matching positive case asserts a
correct findings.yaml passes the relevant rule. The scope-integrity pre-check is
neutralised in these tests by pointing the verifier at the real repo scope (which
is signed off); we exercise R1-R6 + disposition.
"""

from __future__ import annotations

import yaml

from models import Disposition
from verifier import (
    rule_r1_recall,
    rule_r2_spans,
    rule_r3_completed_runs,
    rule_r3_state,
    rule_r4_cvss,
    rule_r6_vocabulary,
    verify,
)


def _write(tmp_path, evidence, findings):
    ev = tmp_path / "evidence.yaml"
    fi = tmp_path / "findings.yaml"
    ev.write_text(yaml.safe_dump(evidence))
    fi.write_text(yaml.safe_dump(findings))
    return fi, ev


# --- (a) omitted issue / R1 ---
def test_a_omitted_issue(base_evidence):
    evidence, _issue = base_evidence
    empty = {"disposition": "SHIP", "findings": [], "waivers": [], "severity_tally": {}}
    r1, _eff = rule_r1_recall(evidence, empty)
    # There IS a HIGH issue in evidence; an empty findings list fails recall.
    assert not r1.ok


def test_a_acknowledged_passes(base_evidence, clean_findings):
    evidence, _issue = base_evidence
    r1, eff = rule_r1_recall(evidence, clean_findings)
    assert r1.ok
    assert eff.value == "HIGH"


# --- (b) fabricated span / R2 (4 sub-cases) ---
def test_b_fabricated_span_nonexistent():
    findings = {"findings": [{"id": "F", "path": "nope/does_not_exist.py", "line": 1}]}
    assert not rule_r2_spans(findings).ok


def test_b_fabricated_span_traversal():
    findings = {"findings": [{"id": "F", "path": "../../etc/passwd", "line": 1}]}
    assert not rule_r2_spans(findings).ok


def test_b_fabricated_span_line_out_of_range():
    findings = {"findings": [{"id": "F", "path": "README.md", "line": 10_000_000}]}
    assert not rule_r2_spans(findings).ok


def test_b_fabricated_span_directory():
    findings = {"findings": [{"id": "F", "path": "openhands-sdk", "line": 1}]}
    assert not rule_r2_spans(findings).ok


def test_b_valid_span_passes():
    findings = {"findings": [{"id": "F", "path": "README.md", "line": 1}]}
    assert rule_r2_spans(findings).ok


# --- (c) blocked/timeout run cited / R3 ---
def test_c_blocked_run_cited():
    evidence = {
        "runs": [
            {"run_id": "CMD-001", "tool_name": "trivy_fs", "status": "tool_blocked"}
        ]
    }
    findings = {"findings": [{"id": "F", "run_id": "CMD-001"}]}
    assert not rule_r3_completed_runs(evidence, findings).ok


def test_c_timeout_run_cited():
    evidence = {"runs": [{"run_id": "CMD-001", "status": "timeout"}]}
    findings = {"findings": [{"id": "F", "run_id": "CMD-001"}]}
    assert not rule_r3_completed_runs(evidence, findings).ok


def test_c_completed_run_passes():
    evidence = {"runs": [{"run_id": "CMD-001", "status": "nonzero_exit"}]}
    findings = {"findings": [{"id": "F", "run_id": "CMD-001"}]}
    assert rule_r3_completed_runs(evidence, findings).ok


# --- (d) empty all-SHIP with coverage gaps / R1 + disposition ---
def test_d_empty_all_ship(tmp_path):
    evidence = {
        "recon": {"git_sha": "abc", "git_dirty": False, "scanner_pins": []},
        "runs": [],
        "normalized_issues": [],
        "coverage_gaps": [
            {"gap_id": "python_sast_absent", "detail": "x", "cap": "HOLD"}
        ],
    }
    findings = {
        "disposition": "SHIP",
        "findings": [],
        "waivers": [],
        "severity_tally": {},
    }
    fi, ev = _write(tmp_path, evidence, findings)
    outcome = verify(fi, ev)
    # A HOLD-capped gap must prevent SHIP; producer's SHIP claim is rejected.
    assert outcome.disposition != Disposition.SHIP
    assert not outcome.ok


# --- (e) wrong cvss_base + malformed CWE / R4 ---
def test_e_wrong_cvss():
    findings = {
        "findings": [
            {
                "id": "F",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_base": 5.0,  # real is 9.8
            }
        ]
    }
    assert not rule_r4_cvss(findings).ok


def test_e_malformed_cwe():
    findings = {"findings": [{"id": "F", "cwe": "732"}]}  # missing CWE- prefix
    assert not rule_r4_cvss(findings).ok


def test_e_correct_cvss_passes():
    findings = {
        "findings": [
            {
                "id": "F",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_base": 9.8,
                "cwe": "CWE-78",
            }
        ]
    }
    assert rule_r4_cvss(findings).ok


# --- (f) dirty tree + unpinned DB / R3-state ---
def test_f_dirty_tree():
    evidence = {"recon": {"git_sha": "abc", "git_dirty": True, "scanner_pins": []}}
    assert not rule_r3_state(evidence).ok


def test_f_null_sha():
    evidence = {"recon": {"git_sha": None, "git_dirty": False, "scanner_pins": []}}
    assert not rule_r3_state(evidence).ok


def test_f_unpinned_db():
    evidence = {
        "recon": {
            "git_sha": "abc",
            "git_dirty": False,
            "scanner_pins": [
                {
                    "name": "semgrep",
                    "db_version": None,
                    "note": "db UNPINNED — caps HOLD",
                },
            ],
        }
    }
    assert not rule_r3_state(evidence).ok


def test_f_clean_state_passes():
    evidence = {
        "recon": {
            "git_sha": "abc",
            "git_dirty": False,
            "scanner_pins": [
                {"name": "semgrep", "db_version": "1.0", "note": "pinned"},
            ],
        }
    }
    assert rule_r3_state(evidence).ok


# --- R6 vocabulary ---
def test_r6_bad_disposition():
    assert not rule_r6_vocabulary({"disposition": "MAYBE", "findings": []}).ok


def test_r6_tally_mismatch():
    findings = {
        "disposition": "HOLD",
        "findings": [{"id": "F", "severity": "HIGH"}],
        "severity_tally": {"HIGH": 5},
    }
    assert not rule_r6_vocabulary(findings).ok


def test_r6_valid():
    findings = {
        "disposition": "HOLD",
        "findings": [{"id": "F", "severity": "HIGH"}],
        "severity_tally": {"HIGH": 1},
    }
    assert rule_r6_vocabulary(findings).ok


# --- disposition cap: producer can't claim above what the gate computes ---
def test_disposition_cap(tmp_path, base_evidence):
    evidence, issue = base_evidence
    # Acknowledge the issue correctly, but claim SHIP with a HIGH effective sev.
    findings = {
        "disposition": "SHIP",
        "severity_tally": {"HIGH": 1},
        "findings": [
            {
                "id": "F-001",
                "instance_id": issue.issue_instance_id,
                "severity": "HIGH",
                "path": "README.md",
                "line": 1,
                "run_id": "CMD-001",
                "title": "x",
                "rationale": "real",
            }
        ],
        "waivers": [],
    }
    fi, ev = _write(tmp_path, evidence, findings)
    outcome = verify(fi, ev)
    assert outcome.disposition == Disposition.HOLD
    assert not outcome.ok  # claimed SHIP > computed HOLD
