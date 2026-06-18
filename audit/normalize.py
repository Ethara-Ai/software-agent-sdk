"""Normalize raw tool output into NormalizedIssue with content-anchored,
verifier-owned identity.

Parsing FAILS CLOSED: a parse error on a required tool becomes a coverage gap
that caps HOLD. The severity map is total; unknowns fail closed to MEDIUM.

The verifier (not the producer) computes cluster_fingerprint + issue_instance_id
from raw output; the producer may only reference verifier-emitted ids.
"""

from __future__ import annotations

import json
import re

from cvss import CVSSError, base_score
from models import (
    NormalizedIssue,
    Severity,
    ToolRun,
    cluster_fingerprint,
    issue_instance_id,
)
from policy import map_severity

_WS_RE = re.compile(r"\s+")


def _normalize_snippet(text: str) -> str:
    """Whitespace-collapsed, lowercased message class — line-number-free so the
    cluster_fingerprint survives `ruff format`."""
    return _WS_RE.sub(" ", text.strip().lower())[:240]


def _message_class(message: str) -> str:
    """A coarse, deterministic message class for fingerprinting (strip digits
    and paths so reformatting / line shifts don't fork identity)."""
    cleaned = re.sub(r"\d+", "#", message.lower())
    cleaned = re.sub(r"[\"'`].*?[\"'`]", "<v>", cleaned)
    return _WS_RE.sub(" ", cleaned).strip()[:120]


def _finalize(
    issues: list[NormalizedIssue],
    run_id: str,
    source_manifest_digest: str,
) -> list[NormalizedIssue]:
    """Assign multiset identity: per-cluster occurrence ordinals + instance ids."""
    ordinals: dict[str, int] = {}
    for iss in issues:
        iss.run_id = run_id
        fp = cluster_fingerprint(
            iss.tool,
            iss.rule_id,
            iss.path or iss.package or "",
            iss.path or iss.package or "",
            iss.vuln_id or _message_class(iss.message),
            iss.normalized_snippet or _normalize_snippet(iss.message),
        )
        iss.cluster_fingerprint = fp
        ordinal = ordinals.get(fp, 0)
        ordinals[fp] = ordinal + 1
        iss.occurrence_ordinal = ordinal
        iss.issue_instance_id = issue_instance_id(
            fp, ordinal, source_manifest_digest, iss.tool, iss.rule_id
        )
    return issues


def finalize_issues(
    issues: list[NormalizedIssue],
    run_id: str,
    source_manifest_digest: str,
) -> list[NormalizedIssue]:
    """Public wrapper: assign verifier-owned identity to externally-produced
    issues (e.g. domain checks) so recall can match them by instance id."""
    return _finalize(issues, run_id, source_manifest_digest)


# ---------------------------------------------------------------------------
# Per-tool parsers. Each returns list[NormalizedIssue] or raises on malformed.
# ---------------------------------------------------------------------------
def _parse_bandit(stdout: str) -> list[NormalizedIssue]:
    data = json.loads(stdout or "{}")
    out: list[NormalizedIssue] = []
    for r in data.get("results", []):
        out.append(
            NormalizedIssue(
                tool="bandit",
                rule_id=str(r.get("test_id", "")),
                severity=map_severity(
                    r.get("issue_severity"), from_required_instrument=True
                ),
                location_type="source",
                path=r.get("filename"),
                line=r.get("line_number"),
                cwe=str((r.get("issue_cwe") or {}).get("id") or "") or None,
                message=r.get("issue_text", ""),
                normalized_snippet=_normalize_snippet(r.get("issue_text", "")),
                tool_native_fingerprint=str(r.get("test_id", "")),
            )
        )
    return out


def _parse_semgrep(stdout: str, tool: str = "semgrep_pinned") -> list[NormalizedIssue]:
    data = json.loads(stdout or "{}")
    out: list[NormalizedIssue] = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        out.append(
            NormalizedIssue(
                tool=tool,
                rule_id=str(r.get("check_id", "")),
                severity=map_severity(
                    extra.get("severity"), from_required_instrument=True
                ),
                location_type="source",
                path=r.get("path"),
                line=(r.get("start") or {}).get("line"),
                cwe=_first_cwe(meta.get("cwe")),
                message=extra.get("message", ""),
                normalized_snippet=_normalize_snippet(extra.get("message", "")),
                tool_native_fingerprint=str(r.get("check_id", "")),
            )
        )
    return out


def _first_cwe(cwe: object) -> str | None:
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])
    if isinstance(cwe, str):
        return cwe
    return None


def _parse_pip_audit(stdout: str) -> list[NormalizedIssue]:
    data = json.loads(stdout or "{}")
    out: list[NormalizedIssue] = []
    if isinstance(data, dict):
        items = data.get("dependencies", [])
    else:
        items = data
    for dep in items:
        name = dep.get("name")
        version = dep.get("version")
        for vuln in dep.get("vulns", []) or []:
            out.append(
                NormalizedIssue(
                    tool="pip_audit",
                    rule_id=str(vuln.get("id", "")),
                    severity=Severity.HIGH,  # CVE present -> fail-closed >= HIGH
                    location_type="dependency",
                    package=name,
                    version=version,
                    vuln_id=str(vuln.get("id", "")),
                    message=(vuln.get("description") or "")[:500],
                    normalized_snippet=_normalize_snippet(f"{name} {vuln.get('id')}"),
                    tool_native_fingerprint=str(vuln.get("id", "")),
                )
            )
    return out


def _parse_osv(stdout: str) -> list[NormalizedIssue]:
    data = json.loads(stdout or "{}")
    out: list[NormalizedIssue] = []
    for res in data.get("results", []):
        for pkg in res.get("packages", []):
            info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                vid = vuln.get("id", "")
                out.append(
                    NormalizedIssue(
                        tool="osv_scanner",
                        rule_id=str(vid),
                        severity=Severity.HIGH,
                        location_type="dependency",
                        package=info.get("name"),
                        version=info.get("version"),
                        vuln_id=str(vid),
                        message=(vuln.get("summary") or "")[:500],
                        normalized_snippet=_normalize_snippet(
                            f"{info.get('name')} {vid}"
                        ),
                        tool_native_fingerprint=str(vid),
                    )
                )
    return out


def _parse_gitleaks(stdout: str, tool: str) -> list[NormalizedIssue]:
    text = (stdout or "").strip()
    if not text:
        return []
    data = json.loads(text)
    out: list[NormalizedIssue] = []
    for f in data if isinstance(data, list) else []:
        out.append(
            NormalizedIssue(
                tool=tool,
                rule_id=str(f.get("RuleID", "")),
                severity=Severity.CRITICAL,  # a live secret is CRITICAL-floor
                location_type="secret",
                path=f.get("File"),
                line=f.get("StartLine"),
                message=f"secret: {f.get('Description', '')}"[:300],
                normalized_snippet=_normalize_snippet(
                    f"{f.get('RuleID')} {f.get('File')}"
                ),
                tool_native_fingerprint=str(f.get("Fingerprint", "")),
            )
        )
    return out


def _parse_hadolint(stdout: str) -> list[NormalizedIssue]:
    text = (stdout or "").strip()
    if not text:
        return []
    data = json.loads(text)
    out: list[NormalizedIssue] = []
    for f in data if isinstance(data, list) else []:
        out.append(
            NormalizedIssue(
                tool="hadolint",
                rule_id=str(f.get("code", "")),
                severity=map_severity(f.get("level"), from_required_instrument=True),
                location_type="config",
                path=f.get("file"),
                line=f.get("line"),
                message=f.get("message", ""),
                normalized_snippet=_normalize_snippet(f.get("message", "")),
                tool_native_fingerprint=str(f.get("code", "")),
            )
        )
    return out


def _parse_trivy(stdout: str) -> list[NormalizedIssue]:
    data = json.loads(stdout or "{}")
    out: list[NormalizedIssue] = []
    for res in data.get("Results", []) or []:
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            cvss_base_val = _trivy_cvss(v)
            out.append(
                NormalizedIssue(
                    tool="trivy_fs",
                    rule_id=str(v.get("VulnerabilityID", "")),
                    severity=map_severity(
                        v.get("Severity"), from_required_instrument=True
                    ),
                    location_type="dependency",
                    path=target,
                    package=v.get("PkgName"),
                    version=v.get("InstalledVersion"),
                    vuln_id=str(v.get("VulnerabilityID", "")),
                    cvss_base=cvss_base_val,
                    message=(v.get("Title") or v.get("Description") or "")[:500],
                    normalized_snippet=_normalize_snippet(
                        f"{v.get('PkgName')} {v.get('VulnerabilityID')}"
                    ),
                    tool_native_fingerprint=str(v.get("VulnerabilityID", "")),
                )
            )
    return out


def _trivy_cvss(v: dict) -> float | None:
    cvss = v.get("CVSS") or {}
    for src in ("nvd", "redhat", "ghsa"):
        entry = cvss.get(src) or {}
        score = entry.get("V3Score")
        if isinstance(score, (int, float)):
            return float(score)
    return None


def _parse_ruff(stdout: str) -> list[NormalizedIssue]:
    text = (stdout or "").strip()
    if not text:
        return []
    data = json.loads(text)
    out: list[NormalizedIssue] = []
    for f in data if isinstance(data, list) else []:
        loc = f.get("location") or {}
        out.append(
            NormalizedIssue(
                tool="ruff",
                rule_id=str(f.get("code") or "RUFF"),
                severity=Severity.LOW,  # hygiene tier
                location_type="source",
                path=f.get("filename"),
                line=loc.get("row"),
                message=f.get("message", ""),
                normalized_snippet=_normalize_snippet(f.get("message", "")),
                tool_native_fingerprint=str(f.get("code") or ""),
            )
        )
    return out


_PARSERS = {
    "ruff": _parse_ruff,
    "bandit": _parse_bandit,
    "semgrep_pinned": lambda s: _parse_semgrep(s, "semgrep_pinned"),
    "semgrep_node": lambda s: _parse_semgrep(s, "semgrep_node"),
    "pip_audit": _parse_pip_audit,
    "osv_scanner": _parse_osv,
    "gitleaks_working_tree": lambda s: _parse_gitleaks(s, "gitleaks_working_tree"),
    "gitleaks_full_history": lambda s: _parse_gitleaks(s, "gitleaks_full_history"),
    "hadolint": _parse_hadolint,
    "trivy_fs": _parse_trivy,
}


def normalize_run(
    run: ToolRun,
    raw_stdout: str,
    source_manifest_digest: str,
) -> tuple[list[NormalizedIssue], bool, str | None]:
    """Parse one completed run. Returns (issues, parsed_ok, parse_error).

    Fails closed: a parser error sets parsed_ok=False; the caller turns that
    into a coverage gap that caps HOLD for required tools.
    """
    parser = _PARSERS.get(run.tool_name)
    if parser is None:
        # ruff_format and prose-only tools have no structured parser by design.
        return [], True, None
    try:
        issues = parser(raw_stdout)
    except (
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
    ) as exc:
        return [], False, f"parse error: {exc}"
    # Recompute CVSS-derived severity escalation deterministically (R4 input).
    for iss in issues:
        if iss.cvss_base is not None and iss.cvss_base >= 9.0:
            iss.severity = Severity.CRITICAL
        if iss.cvss_vector:
            try:
                if base_score(iss.cvss_vector) >= 9.0:
                    iss.severity = Severity.CRITICAL
            except CVSSError:
                pass
    return _finalize(issues, run.run_id, source_manifest_digest), True, None
