"""Hypothesis self-fuzz: the verifier never returns OK on an invariant
violation and never crashes (ledger row 15)."""

from __future__ import annotations

import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from models import Disposition
from verifier import verify

# Strategies for arbitrary-ish findings / evidence dicts.
_severities = st.sampled_from(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "BOGUS"])
_dispositions = st.sampled_from(["SHIP", "HOLD", "BLOCK", "MAYBE", ""])
_finding = st.fixed_dictionaries(
    {
        "id": st.text(min_size=0, max_size=8),
        "severity": _severities,
        "path": st.sampled_from(["README.md", "../x", "nope.py", "openhands-sdk"]),
        "line": st.integers(min_value=-5, max_value=10_000_000),
        "run_id": st.sampled_from(["CMD-001", "CMD-999", None]),
        "cvss_vector": st.sampled_from([None, "bad", "CVSS:3.1/AV:N"]),
        "cvss_base": st.sampled_from([None, 0.0, 5.0, 9.8]),
    }
)


@settings(max_examples=120, deadline=None)
@given(
    disposition=_dispositions,
    findings=st.lists(_finding, max_size=4),
)
def test_fuzz_never_false_ok(tmp_path_factory, disposition, findings):
    tmp = tmp_path_factory.mktemp("fuzz")
    evidence = {
        "recon": {"git_sha": "abc", "git_dirty": False, "scanner_pins": []},
        "runs": [{"run_id": "CMD-001", "status": "nonzero_exit", "parsed_ok": True}],
        "normalized_issues": [],
        "coverage_gaps": [{"gap_id": "g", "detail": "d", "cap": "HOLD"}],
    }
    fdoc = {
        "disposition": disposition,
        "findings": findings,
        "waivers": [],
        "severity_tally": {},
    }
    ev = tmp / "evidence.yaml"
    fi = tmp / "findings.yaml"
    ev.write_text(yaml.safe_dump(evidence))
    fi.write_text(yaml.safe_dump(fdoc))

    # Must never crash.
    outcome = verify(fi, ev)

    # Invariant: a HOLD-capped coverage gap is present, so SHIP is impossible.
    assert outcome.disposition != Disposition.SHIP
    # Invariant: if the gate says ok, the disposition is not BLOCK and every
    # rule passed.
    if outcome.ok:
        assert outcome.disposition != Disposition.BLOCK
        assert all(r.ok for r in outcome.rules)
