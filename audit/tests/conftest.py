"""Shared fixtures for the audit harness conformance tests."""

from __future__ import annotations

import pytest

from models import (
    NormalizedIssue,
    RunStatus,
    Severity,
    ToolRun,
    cluster_fingerprint,
    issue_instance_id,
)


@pytest.fixture
def make_issue():
    def _make(
        tool="bandit",
        rule_id="B602",
        severity=Severity.HIGH,
        path="README.md",
        line=1,
        message="subprocess call with shell=True",
        cvss_vector=None,
        cvss_base=None,
        ordinal=0,
    ) -> NormalizedIssue:
        fp = cluster_fingerprint(tool, rule_id, path, path, "msgclass", message.lower())
        iid = issue_instance_id(fp, ordinal, "manifestdigest", tool, rule_id)
        return NormalizedIssue(
            tool=tool,
            rule_id=rule_id,
            severity=severity,
            location_type="source",
            path=path,
            line=line,
            message=message,
            normalized_snippet=message.lower(),
            cvss_vector=cvss_vector,
            cvss_base=cvss_base,
            cluster_fingerprint=fp,
            issue_instance_id=iid,
            occurrence_ordinal=ordinal,
            run_id="CMD-001",
        )

    return _make


@pytest.fixture
def base_evidence(make_issue):
    """A minimal evidence bundle with one HIGH issue from a completed run."""
    issue = make_issue()
    return {
        "schema_version": "2",
        "scope_digest": "deadbeef",
        "recon": {
            "git_sha": "c1cdb16a",
            "git_dirty": False,
            "scanner_pins": [
                {"name": "semgrep", "db_version": "1.0", "note": "pinned"},
            ],
        },
        "runs": [
            {
                "run_id": "CMD-001",
                "tool_name": "bandit",
                "status": "nonzero_exit",
                "parsed_ok": True,
            },
        ],
        "normalized_issues": [issue.model_dump(mode="json")],
        "coverage_gaps": [],
    }, issue


@pytest.fixture
def clean_findings(base_evidence):
    """A findings.yaml that correctly acknowledges the one HIGH issue."""
    _evidence, issue = base_evidence
    return {
        "schema_version": "1",
        "disposition": "HOLD",
        "severity_tally": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "findings": [
            {
                "id": "F-001",
                "instance_id": issue.issue_instance_id,
                "severity": "HIGH",
                "path": "README.md",
                "line": 1,
                "run_id": "CMD-001",
                "title": "shell=True",
                "rationale": "real",
            },
        ],
        "waivers": [],
    }


@pytest.fixture
def completed_run():
    return ToolRun(
        run_id="CMD-001",
        tool_name="bandit",
        category="sast",
        argv=["bandit"],
        cwd=".",
        status=RunStatus.NONZERO_EXIT,
        exit_code=1,
        parsed_ok=True,
    )
