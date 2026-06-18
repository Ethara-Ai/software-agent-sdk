"""Conformance: a fatally-crashed scanner fails closed (tool_blocked), never
masquerades as a clean parse. This is the gitleaks /dev/stdout starvation bypass
caught during the first real run."""

from __future__ import annotations

from tools import _looks_fatal


def test_clean_run_not_fatal():
    assert _looks_fatal('{"results": []}', "", 0) is None
    # nonzero with real output (findings present) is NOT fatal.
    assert _looks_fatal('[{"RuleID": "x"}]', "warn", 1) is None


def test_permission_denied_is_fatal():
    reason = _looks_fatal("", "FTL Report path is not writable: permission denied", 1)
    assert reason is not None
    assert "permission denied" in reason


def test_panic_is_fatal():
    assert _looks_fatal("", "panic: runtime error", 2) is not None


def test_traceback_is_fatal():
    assert _looks_fatal("", "Traceback (most recent call last):", 1) is not None


def test_empty_clean_exit_not_fatal():
    # exit 0 with empty stdout is a legitimately clean scan, not a crash.
    assert _looks_fatal("", "", 0) is None
