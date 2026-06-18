"""R1 recall logic — isolated for testability.

Per-instance, verifier-owned ids. Every >= MEDIUM issue from a parsed run must
be acknowledged by the producer (by issue_instance_id). An empty/all-clear
report passes R1 ONLY if every required instrument ran clean and parsed.
Effective severity = MAX over acknowledged issues (never the producer's label).

Waiver discipline: reason-code enum + fingerprint-bound rationale; HIGH/CRITICAL
and any security finding need an out-of-band approved waiver; boilerplate
rationale reused across unrelated fingerprints is rejected.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from models import NormalizedIssue, Severity, WaiverReason


@dataclass
class RecallResult:
    ok: bool
    missing_instance_ids: list[str] = field(default_factory=list)
    effective_severity: Severity = Severity.INFO
    bad_waivers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _valid_reason(code: str | None) -> bool:
    if not code:
        return False
    try:
        WaiverReason(code)
        return True
    except ValueError:
        return False


def check_recall(
    evidence_issues: list[NormalizedIssue],
    acknowledged_ids: set[str],
    waivers: list[dict],
    *,
    min_ack_severity: Severity = Severity.MEDIUM,
) -> RecallResult:
    """Core R1: are all >= MEDIUM evidence issues acknowledged or validly waived?

    `waivers` is a list of {instance_id, reason_code, rationale, approved}.
    """
    waiver_by_id: dict[str, dict] = {
        w.get("instance_id", ""): w for w in waivers if w.get("instance_id")
    }
    # Detect boilerplate rationale reused across unrelated fingerprints.
    rationale_counts: Counter[str] = Counter(
        (w.get("rationale", "").strip().lower()) for w in waivers if w.get("rationale")
    )
    missing: list[str] = []
    bad_waivers: list[str] = []
    acknowledged_severities: list[Severity] = []

    for iss in evidence_issues:
        if iss.severity < min_ack_severity:
            continue
        iid = iss.issue_instance_id
        if iid in acknowledged_ids:
            acknowledged_severities.append(iss.severity)
            continue
        waiver = waiver_by_id.get(iid)
        if waiver is None:
            missing.append(iid)
            continue
        # Validate the waiver.
        reason = waiver.get("reason_code")
        rationale = (waiver.get("rationale") or "").strip()
        approved = bool(waiver.get("approved"))
        if not _valid_reason(reason):
            bad_waivers.append(f"{iid}: invalid reason_code {reason!r}")
            missing.append(iid)
            continue
        if len(rationale) < 12:
            bad_waivers.append(f"{iid}: rationale too thin")
            missing.append(iid)
            continue
        if rationale_counts[rationale.lower()] > 1:
            bad_waivers.append(f"{iid}: boilerplate rationale reused")
            missing.append(iid)
            continue
        # HIGH/CRITICAL or any security location needs out-of-band approval.
        needs_approval = iss.severity >= Severity.HIGH or iss.location_type in (
            "secret",
        )
        if needs_approval and not approved:
            bad_waivers.append(f"{iid}: HIGH/CRITICAL waiver not out-of-band approved")
            missing.append(iid)
            continue
        # A validly-waived issue still counts toward effective severity.
        acknowledged_severities.append(iss.severity)

    effective = (
        max(acknowledged_severities, key=lambda s: s.rank)
        if acknowledged_severities
        else Severity.INFO
    )
    return RecallResult(
        ok=not missing and not bad_waivers,
        missing_instance_ids=missing,
        effective_severity=effective,
        bad_waivers=bad_waivers,
    )
