"""Policy: the hash-bound, total, fail-closed decision layer.

Owns:
- The scope sentinel (Phase 0.5): recompute sha256(scope.yaml) == scope.approved
  or REFUSE to scaffold / verify.
- The severity map: a TOTAL function. Unknown native severity fails closed to
  >= MEDIUM, never INFO. A required-instrument finding is never below MEDIUM.
- The required-instrument set, read from the APPROVED scope only.
- The CRITICAL floor: classes that cannot be waived to SHIP.

Nothing here trusts producer-supplied labels.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml

from models import Severity

REQUIRED_POLICY_VERSION = 1

# Repo root = parent of the audit/ dir this file lives in.
AUDIT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AUDIT_DIR.parent
SCOPE_PATH = AUDIT_DIR / "scope.yaml"
SCOPE_APPROVED_PATH = AUDIT_DIR / "scope.approved"


class ScopeError(RuntimeError):
    """Raised when the scope sentinel refuses to proceed."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def assert_scope_approved(
    scope_path: Path = SCOPE_PATH,
    approved_path: Path = SCOPE_APPROVED_PATH,
) -> str:
    """Phase 0.5 hard precondition. Returns the matched digest or raises.

    This is the scaffolder's first action AND a verifier pre-check (§1.10 scope
    integrity). A missing file or mismatched digest fails closed.
    """
    if not scope_path.exists():
        raise ScopeError(f"scope.yaml missing at {scope_path}")
    if not approved_path.exists():
        raise ScopeError(
            "scope.approved missing — Phase 0.5 sign-off not performed. "
            f"Write sha256({scope_path.name}) into {approved_path}."
        )
    actual = sha256_file(scope_path)
    approved = approved_path.read_text().strip()
    if actual != approved:
        raise ScopeError(
            "scope digest mismatch — scope.yaml changed since sign-off.\n"
            f"  approved: {approved}\n  actual:   {actual}\n"
            "Re-approve (re-run Phase 0.5) before proceeding."
        )
    return actual


def load_scope(scope_path: Path = SCOPE_PATH) -> dict:
    with scope_path.open() as fh:
        return yaml.safe_load(fh)


def required_instrument_ids(scope: dict) -> list[str]:
    """The required-instrument set — read from the APPROVED scope ONLY (R1)."""
    return [item["id"] for item in scope.get("required_instruments", [])]


def cap_for_instrument(scope: dict, instrument_id: str) -> str:
    for item in scope.get("required_instruments", []):
        if item["id"] == instrument_id:
            return item.get("cap_on_absent", "HOLD")
    return "HOLD"


# ---------------------------------------------------------------------------
# Severity map — a TOTAL function. Fail closed.
# ---------------------------------------------------------------------------
# Native-severity tokens we recognise per tool family, lowercased.
_NATIVE_SEVERITY: dict[str, Severity] = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "note": Severity.INFO,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "warning": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "error": Severity.HIGH,
    "high": Severity.HIGH,
    "important": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "blocker": Severity.CRITICAL,
}


def map_severity(
    native: str | None,
    *,
    from_required_instrument: bool = False,
) -> Severity:
    """Total severity map. Unknown -> fail closed to MEDIUM (never INFO).

    A finding from a required instrument is never mapped below MEDIUM.
    """
    mapped = Severity.MEDIUM  # fail-closed default for unknown tokens
    if native is not None:
        token = native.strip().lower()
        mapped = _NATIVE_SEVERITY.get(token, Severity.MEDIUM)
    if from_required_instrument and mapped < Severity.MEDIUM:
        return Severity.MEDIUM
    return mapped


def severity_map_digest() -> str:
    """Hash-bound: the severity map must be stable across the gate."""
    canonical = ";".join(f"{k}={v.value}" for k, v in sorted(_NATIVE_SEVERITY.items()))
    return sha256_text(canonical)


# ---------------------------------------------------------------------------
# CRITICAL floor — classes that cannot be waived to SHIP (hash-bound).
# ---------------------------------------------------------------------------
CRITICAL_FLOOR_CLASSES: tuple[str, ...] = (
    "injection",
    "unsafe_deserialization",
    "ssrf",
    "authz_bypass",
    "secret_exposure",
    "memory_corruption",
    "cvss_ge_9",
    "kev",
    "container_escape",
    "dataset_leakage",
    "agent_writable_reward",
    "rollout_miscount",
)

# Substring patterns (lowercased) used to classify a normalized issue's message
# into a CRITICAL-floor class. Conservative: these CORROBORATE a CRITICAL, they
# do not downgrade anything. NOTE: tokens below are DETECTION LITERALS used to
# scan AUDITED code; they are not executable calls in this module.
_FLOOR_PATTERNS: dict[str, tuple[str, ...]] = {
    "injection": (
        "sql injection",
        "command injection",
        "os command",
        "code injection",
        "template injection",
        "subprocess",
        "shell=true",
    ),
    "unsafe_deserialization": (
        "pickle",
        "yaml.load",
        "marshal",
        "deserializ",
        "insecure deserial",
    ),
    "ssrf": ("ssrf", "server-side request forgery", "request forgery"),
    "authz_bypass": (
        "authz",
        "authorization bypass",
        "privilege escalation",
        "missing authentication",
        "auth bypass",
    ),
    "secret_exposure": (
        "secret",
        "api key",
        "private key",
        "credential",
        "password",
        "token leaked",
        "aws_secret",
    ),
    "memory_corruption": (
        "use-after-free",
        "buffer overflow",
        "out-of-bounds",
        "use after free",
        "double free",
    ),
    "container_escape": (
        "container escape",
        "privileged container",
        "docker socket",
    ),
}


def classify_floor(message: str, cvss_base: float | None = None) -> set[str]:
    """Return the set of CRITICAL-floor classes a message/CVSS triggers.

    Total + deterministic. Used to corroborate (never downgrade) severity.
    """
    classes: set[str] = set()
    low = message.lower()
    for klass, pats in _FLOOR_PATTERNS.items():
        if any(p in low for p in pats):
            classes.add(klass)
    if cvss_base is not None and cvss_base >= 9.0:
        classes.add("cvss_ge_9")
    if re.search(r"\bkev\b|known exploited", low):
        classes.add("kev")
    return classes
