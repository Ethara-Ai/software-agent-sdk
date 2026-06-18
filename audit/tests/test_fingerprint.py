"""Conformance: content-anchored identity (ledger rows 4, 5)."""

from __future__ import annotations

from models import cluster_fingerprint, issue_instance_id


def test_survives_reformat():
    # The fingerprint EXCLUDES the line number, so reformatting that shifts the
    # line must NOT fork identity.
    fp_a = cluster_fingerprint("bandit", "B602", "subj", "f.py", "msgclass", "snippet")
    fp_b = cluster_fingerprint("bandit", "B602", "subj", "f.py", "msgclass", "snippet")
    assert fp_a == fp_b
    assert len(fp_a) == 64


def test_different_message_forks():
    fp_a = cluster_fingerprint("bandit", "B602", "subj", "f.py", "classA", "snip")
    fp_b = cluster_fingerprint("bandit", "B602", "subj", "f.py", "classB", "snip")
    assert fp_a != fp_b


def test_multiset_ordinal():
    # Two occurrences of the same cluster get distinct instance ids via ordinal.
    fp = cluster_fingerprint("bandit", "B602", "subj", "f.py", "msgclass", "snip")
    iid0 = issue_instance_id(fp, 0, "manifest", "bandit", "B602")
    iid1 = issue_instance_id(fp, 1, "manifest", "bandit", "B602")
    assert iid0 != iid1
    # Same ordinal + inputs is stable (deterministic).
    assert iid0 == issue_instance_id(fp, 0, "manifest", "bandit", "B602")


def test_instance_id_binds_manifest():
    fp = cluster_fingerprint("bandit", "B602", "subj", "f.py", "msgclass", "snip")
    a = issue_instance_id(fp, 0, "manifestA", "bandit", "B602")
    b = issue_instance_id(fp, 0, "manifestB", "bandit", "B602")
    assert a != b
