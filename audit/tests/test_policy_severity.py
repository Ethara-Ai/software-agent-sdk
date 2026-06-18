"""Conformance: severity map is total + fails closed (ledger rows 2, 3)."""

from __future__ import annotations

from models import Severity
from policy import map_severity, severity_map_digest


def test_unknown_fails_closed():
    # An unrecognised native severity must never become INFO/LOW.
    assert map_severity("not-a-real-severity") == Severity.MEDIUM
    assert map_severity(None) == Severity.MEDIUM
    assert map_severity("") == Severity.MEDIUM


def test_known_tokens_map():
    assert map_severity("critical") == Severity.CRITICAL
    assert map_severity("HIGH") == Severity.HIGH
    assert map_severity("warning") == Severity.MEDIUM
    assert map_severity("info") == Severity.INFO
    assert map_severity("low") == Severity.LOW


def test_required_floor():
    # A required-instrument finding is never mapped below MEDIUM.
    assert map_severity("info", from_required_instrument=True) == Severity.MEDIUM
    assert map_severity("low", from_required_instrument=True) == Severity.MEDIUM
    # but a genuine HIGH stays HIGH
    assert map_severity("high", from_required_instrument=True) == Severity.HIGH


def test_severity_map_digest_stable():
    assert severity_map_digest() == severity_map_digest()
    assert len(severity_map_digest()) == 64


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
    assert Severity.MEDIUM >= Severity.MEDIUM
