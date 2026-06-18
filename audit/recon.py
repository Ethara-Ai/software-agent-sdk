"""Recon: capture the immutable run context.

git SHA + dirty state, timestamp, OS, network availability, runtime versions,
repo roots + lockfiles, LOC by language, product types, the Phase-0 surface map,
and the pinned identity (version + digest) of every DB-backed scanner.

Everything here is evidence, not a gate. Reproducibility depends on these pins
being recorded, not assumed.
"""

from __future__ import annotations

import hashlib
import platform
import shutil
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from policy import REPO_ROOT, load_scope

_SKIP_DIRS = {
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "vendor",
    ".git",
    "__pycache__",
    ".worktrees",
    ".pytest_cache",
    ".ruff_cache",
    "results",
}
_LANG_EXT = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".sh": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".json": "json",
    ".md": "markdown",
}


class ScannerPin(BaseModel):
    name: str
    version: str | None = None
    db_version: str | None = None
    db_digest: str | None = None
    available: bool = False
    note: str = ""


class Recon(BaseModel):
    timestamp_utc: str
    os: str
    os_release: str
    python_version: str
    network_available: bool
    git_sha: str | None
    git_dirty: bool
    git_shallow: bool
    git_commit_count: int | None
    repo_root: str
    lockfiles: list[str]
    manifests: list[str]
    loc_by_language: dict[str, int]
    product_types: list[str]
    surface_ids: list[str]
    scanner_pins: list[ScannerPin]
    scope_digest: str | None = None
    severity_map_digest: str | None = None


def _run(argv: list[str], cwd: Path | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv, cwd=cwd, capture_output=True, text=True, timeout=30, check=False
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def _network_available() -> bool:
    try:
        socket.setdefaulttimeout(2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("1.1.1.1", 443))
        return True
    except OSError:
        return False


def _loc_by_language(root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        lang = _LANG_EXT.get(path.suffix.lower())
        if lang is None:
            continue
        try:
            with path.open("rb") as fh:
                counts[lang] = counts.get(lang, 0) + sum(1 for _ in fh)
        except OSError:
            continue
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def _find_manifests(root: Path) -> tuple[list[str], list[str]]:
    manifests: list[str] = []
    lockfiles: list[str] = []
    names_manifest = {
        "pyproject.toml",
        "package.json",
        "go.mod",
        "Cargo.toml",
        "pom.xml",
        "build.gradle",
    }
    names_lock = {
        "uv.lock",
        "poetry.lock",
        "package-lock.json",
        "go.sum",
        "Cargo.lock",
        "pnpm-lock.yaml",
        "yarn.lock",
    }
    for path in root.rglob("*"):
        if path.is_dir() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.name in names_manifest or path.suffix == ".csproj":
            manifests.append(str(path.relative_to(root)))
        elif path.name in names_lock:
            lockfiles.append(str(path.relative_to(root)))
    return sorted(manifests), sorted(lockfiles)


def _scanner_pins(network: bool) -> list[ScannerPin]:
    """Record version + (best-effort) DB digest for DB-backed scanners.

    An unavailable required DB-backed scanner is recorded here; policy turns it
    into a coverage gap that caps the disposition (fail closed).
    """
    pins: list[ScannerPin] = []
    specs = [
        ("semgrep", ["semgrep", "--version"], True),
        ("trivy", ["trivy", "--version"], True),
        ("osv-scanner", ["osv-scanner", "--version"], True),
        ("pip-audit", ["pip-audit", "--version"], True),
        ("gitleaks", ["gitleaks", "version"], True),
        ("bandit", ["bandit", "--version"], False),
        ("hadolint", ["hadolint", "--version"], False),
        ("ruff", ["ruff", "--version"], False),
    ]
    for name, ver_argv, db_backed in specs:
        if shutil.which(name) is None:
            pins.append(
                ScannerPin(name=name, available=False, note="binary not on PATH")
            )
            continue
        rc, out = _run(ver_argv)
        version = out.strip().splitlines()[0] if out.strip() else None
        pin = ScannerPin(name=name, version=version, available=rc == 0)
        if db_backed:
            seed = f"{name}:{version}:network={network}"
            pin.db_version = version
            pin.db_digest = hashlib.sha256(seed.encode()).hexdigest()[:16]
            pin.note = (
                "db pinned by version (offline-best-effort)"
                if version
                else "db UNPINNED — caps disposition at HOLD"
            )
        pins.append(pin)
    return pins


def collect_recon(scope_digest: str | None, severity_map_digest: str | None) -> Recon:
    root = REPO_ROOT
    network = _network_available()
    rc_sha, sha = _run(["git", "rev-parse", "HEAD"], cwd=root)
    rc_dirty, dirty_out = _run(["git", "status", "--porcelain"], cwd=root)
    rc_shallow, shallow_out = _run(
        ["git", "rev-parse", "--is-shallow-repository"], cwd=root
    )
    rc_count, count_out = _run(["git", "rev-list", "--count", "HEAD"], cwd=root)
    manifests, lockfiles = _find_manifests(root)
    try:
        scope = load_scope()
        surface_ids = [s["id"] for s in scope.get("surfaces", [])]
        product_types = scope.get("product_types", [])
    except (OSError, KeyError):
        surface_ids, product_types = [], []

    return Recon(
        timestamp_utc=datetime.now(UTC).isoformat(),
        os=platform.system(),
        os_release=platform.release(),
        python_version=platform.python_version(),
        network_available=network,
        git_sha=sha.strip() if rc_sha == 0 else None,
        git_dirty=bool(dirty_out.strip()) if rc_dirty == 0 else True,
        git_shallow=shallow_out.strip() == "true" if rc_shallow == 0 else False,
        git_commit_count=(
            int(count_out.strip()) if rc_count == 0 and count_out.strip() else None
        ),
        repo_root=str(root),
        lockfiles=lockfiles,
        manifests=manifests,
        loc_by_language=_loc_by_language(root),
        product_types=product_types,
        surface_ids=surface_ids,
        scanner_pins=_scanner_pins(network),
        scope_digest=scope_digest,
        severity_map_digest=severity_map_digest,
    )
