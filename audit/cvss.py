"""Offline CVSS v3.1 base-score recomputation (verifier rule R4).

Pure arithmetic over the parsed vector — no network, no library. The producer's
`cvss_base` is recomputed here and rejected on mismatch. This is Bucket D: a
total bounded recomputable relation.

Reference: FIRST CVSS v3.1 specification, section 7.1 (Base score).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
# PR depends on Scope (changed/unchanged)
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


class CVSSError(ValueError):
    """Raised on a malformed or incomplete CVSS v3.1 vector."""


@dataclass(frozen=True)
class CVSSVector:
    av: str
    ac: str
    pr: str
    ui: str
    s: str
    c: str
    i: str
    a: str


def parse_vector(vector: str) -> CVSSVector:
    """Parse a full CVSS:3.1 base vector. Fails closed on missing metrics."""
    if not vector:
        raise CVSSError("empty CVSS vector")
    parts = vector.strip().split("/")
    if not parts or not parts[0].upper().startswith("CVSS:3"):
        raise CVSSError(f"not a CVSS:3.x vector: {vector!r}")
    metrics: dict[str, str] = {}
    for token in parts[1:]:
        if ":" not in token:
            raise CVSSError(f"malformed metric token: {token!r}")
        key, _, val = token.partition(":")
        metrics[key.upper()] = val.upper()
    missing = [m for m in _METRIC_ORDER if m not in metrics]
    if missing:
        raise CVSSError(f"missing base metrics {missing} in vector {vector!r}")
    return CVSSVector(
        av=metrics["AV"],
        ac=metrics["AC"],
        pr=metrics["PR"],
        ui=metrics["UI"],
        s=metrics["S"],
        c=metrics["C"],
        i=metrics["I"],
        a=metrics["A"],
    )


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A roundup: ceil to one decimal on a 100k-int grid."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Recompute the CVSS v3.1 base score from the vector. Total + offline."""
    v = parse_vector(vector)
    try:
        av = _AV[v.av]
        ac = _AC[v.ac]
        ui = _UI[v.ui]
        conf = _CIA[v.c]
        integ = _CIA[v.i]
        avail = _CIA[v.a]
    except KeyError as exc:
        raise CVSSError(f"invalid metric value: {exc}") from exc
    if v.s not in ("U", "C"):
        raise CVSSError(f"invalid Scope: {v.s!r}")
    scope_changed = v.s == "C"
    pr = (_PR_C if scope_changed else _PR_U).get(v.pr)
    if pr is None:
        raise CVSSError(f"invalid PR: {v.pr!r}")

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def matches(vector: str, claimed_base: float, tol: float = 0.05) -> bool:
    """True iff the recomputed base score matches the producer's claim."""
    return abs(base_score(vector) - claimed_base) <= tol
