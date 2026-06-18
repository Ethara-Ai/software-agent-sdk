"""Conformance: scope sentinel refuses on missing/mismatched approval (row 1)."""

from __future__ import annotations

import pytest

from policy import ScopeError, assert_scope_approved


def test_mismatch_refuses(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text("required_instruments: []\n")
    approved = tmp_path / "scope.approved"
    approved.write_text(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    with pytest.raises(ScopeError, match="digest mismatch"):
        assert_scope_approved(scope, approved)


def test_missing_approval_refuses(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text("x: 1\n")
    approved = tmp_path / "scope.approved"  # not created
    with pytest.raises(ScopeError, match="sign-off not performed"):
        assert_scope_approved(scope, approved)


def test_missing_scope_refuses(tmp_path):
    scope = tmp_path / "scope.yaml"  # not created
    approved = tmp_path / "scope.approved"
    approved.write_text("abc")
    with pytest.raises(ScopeError, match="scope.yaml missing"):
        assert_scope_approved(scope, approved)


def test_match_returns_digest(tmp_path):
    import hashlib

    scope = tmp_path / "scope.yaml"
    scope.write_text("required_instruments: []\n")
    digest = hashlib.sha256(scope.read_bytes()).hexdigest()
    approved = tmp_path / "scope.approved"
    approved.write_text(digest + "\n")
    assert assert_scope_approved(scope, approved) == digest


def test_real_repo_scope_approved():
    # The actual repo scope must be signed off (we self-approved it).
    assert len(assert_scope_approved()) == 64
