"""Core data models for the CRUCIBLE audit gate.

Flat-module layout: every harness module lives at audit/ root and imports its
siblings by bare name. This module declares the shared enums and Pydantic models
used across recon / tools / normalize / domain / verifier.

Design rule (CRUCIBLE house rules):
- Total, hash-bound, fail-closed policies. Unknowns never silently downgrade.
- The verifier owns identity (cluster_fingerprint / issue_instance_id); the
  producer may only *reference* verifier-emitted ids.
"""

from __future__ import annotations

import enum
import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Canonical enums
# ---------------------------------------------------------------------------
class Severity(str, enum.Enum):
    """The canonical 5-level severity scale. Ordering is load-bearing."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Disposition(str, enum.Enum):
    """The ONLY three dispositions. Severity is independent of disposition."""

    SHIP = "SHIP"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


class RunStatus(str, enum.Enum):
    """Machine enum for a tool run's outcome.

    Only `ok` / `nonzero_exit` may back a finding (R3). `tool_blocked` /
    `timeout` may back only a coverage gap.
    """

    OK = "ok"
    NONZERO_EXIT = "nonzero_exit"
    TIMEOUT = "timeout"
    TOOL_BLOCKED = "tool_blocked"


LocationType = Literal["source", "dependency", "secret", "config", "artifact"]
EvidenceClass = Literal[
    "static_reproducible", "dynamic_live", "heuristic", "domain_integrity"
]


# ---------------------------------------------------------------------------
# Tool capability contract
# ---------------------------------------------------------------------------
class Tool(BaseModel):
    """A capability contract, not just a binary name.

    If `critical_capable` and `required_when` matches the scoped repo, then a
    missing binary / timeout / unparsable artifact / uncovered present surface
    is a coverage finding that caps the disposition.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    category: str
    binary: str
    build_argv: list[str]
    ecosystems: list[str]
    timeout_sec: int = 600
    required_when: list[str] = Field(default_factory=list)
    critical_capable: bool = False
    evidence_class: EvidenceClass = "static_reproducible"
    parser_required: bool = True
    raw_artifact_required: bool = True
    disposition_cap_on_absent: Literal["HOLD", "BLOCK"] = "HOLD"
    # nonzero exit is normal "findings present" for many scanners
    nonzero_is_finding: bool = True
    db_backed: bool = False


# ---------------------------------------------------------------------------
# Run record (one per executed command)
# ---------------------------------------------------------------------------
class ToolRun(BaseModel):
    """The record of one tool invocation. Full stdout/stderr live on disk under
    audit/results/artifacts/; this record carries the excerpt + digests."""

    run_id: str
    tool_name: str
    category: str
    argv: list[str]
    cwd: str
    status: RunStatus
    exit_code: int | None = None
    duration_sec: float = 0.0
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    stdout_sha256: str | None = None
    stdout_path: str | None = None
    stdout_bytes: int = 0
    parsed_ok: bool | None = None
    parse_error: str | None = None
    blocked_reason: str | None = None

    @property
    def completed(self) -> bool:
        """Only completed runs may back a finding (R3)."""
        return self.status in (RunStatus.OK, RunStatus.NONZERO_EXIT)


# ---------------------------------------------------------------------------
# Normalized issue + content-anchored multiset identity
# ---------------------------------------------------------------------------
def _h(*parts: str) -> str:
    """Stable sha256 over canonical-joined parts."""
    joined = "\x1f".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def cluster_fingerprint(
    canonical_tool: str,
    rule_id: str,
    subject: str,
    path_or_package: str,
    message_class_or_vuln_id: str,
    normalized_snippet: str,
) -> str:
    """Content-anchored identity that EXCLUDES the line number (survives
    `ruff format`). This is the load-bearing dedup key."""
    return _h(
        canonical_tool,
        rule_id,
        subject,
        path_or_package,
        message_class_or_vuln_id,
        normalized_snippet,
    )


def issue_instance_id(
    cluster_fp: str,
    occurrence_ordinal: int,
    source_manifest_digest: str,
    tool_id: str,
    rule_id: str,
) -> str:
    """Per-instance id (recall is per-instance, identity is a multiset)."""
    return _h(
        cluster_fp,
        str(occurrence_ordinal),
        source_manifest_digest,
        tool_id,
        rule_id,
    )


class NormalizedIssue(BaseModel):
    """One normalized finding. Identity is computed by the verifier/normalizer
    from raw tool output; the producer may only reference these ids."""

    model_config = ConfigDict(frozen=False)

    tool: str
    rule_id: str
    severity: Severity
    location_type: LocationType
    path: str | None = None
    line: int | None = None
    package: str | None = None
    version: str | None = None
    vuln_id: str | None = None
    advisory_id: str | None = None
    cvss_base: float | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    tool_native_fingerprint: str | None = None
    message: str = ""
    normalized_snippet: str = ""
    cluster_fingerprint: str = ""
    issue_instance_id: str = ""
    occurrence_ordinal: int = 0
    run_id: str = ""

    @property
    def is_critical_floor(self) -> bool:
        """A hash-bound CRITICAL floor cannot be waived to SHIP. Recomputed,
        never trusted from the producer."""
        return self.severity == Severity.CRITICAL


class CoverageGap(BaseModel):
    """A missing/blocked/unparsable required instrument or uncovered surface.
    A coverage gap is a finding, never a silence."""

    gap_id: str
    detail: str
    cap: Literal["HOLD", "BLOCK", "NONE"]
    instrument: str | None = None
    surface: str | None = None
    run_id: str | None = None


class WaiverReason(str, enum.Enum):
    """Closed enum of acceptable waiver reason-codes (R1 discipline)."""

    FALSE_POSITIVE = "false_positive"
    NOT_EXPLOITABLE = "not_exploitable"
    ACCEPTED_RISK = "accepted_risk"
    COMPENSATING_CONTROL = "compensating_control"
    OUT_OF_SCOPE = "out_of_scope"
    TEST_FIXTURE = "test_fixture"
