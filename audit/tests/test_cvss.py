"""Conformance: offline CVSS v3.1 base recompute (ledger row 6)."""

from __future__ import annotations

import pytest

from cvss import CVSSError, base_score, matches


@pytest.mark.parametrize(
    "vector,expected",
    [
        # CVE-2021-44228 Log4Shell (scope changed)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # A medium: AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N = 3.7
        ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N", 3.7),
        # None impact -> 0.0
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_known_vectors(vector, expected):
    assert base_score(vector) == pytest.approx(expected, abs=0.05)


def test_matches():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert matches(v, 9.8)
    assert not matches(v, 7.5)


def test_malformed_fails_closed():
    with pytest.raises(CVSSError):
        base_score("not-a-vector")
    with pytest.raises(CVSSError):
        base_score("CVSS:3.1/AV:N/AC:L")  # missing metrics
    with pytest.raises(CVSSError):
        base_score("")
