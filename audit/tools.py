"""Instrument registry + runner.

For each applicable tool: run it, capture the REAL exit code, write full
stdout/stderr to disk under audit/results/artifacts/, record a machine status
enum (ok / nonzero_exit / timeout / tool_blocked), bound output volume.

The registry is derived from the APPROVED scope's required_instruments; the
producer does not get to choose the set.
"""

from __future__ import annotations

import gzip
import hashlib
import shutil
import subprocess
import time
from pathlib import Path

from models import RunStatus, Tool, ToolRun
from policy import AUDIT_DIR, REPO_ROOT

RESULTS_DIR = AUDIT_DIR / "results"
ARTIFACTS_DIR = RESULTS_DIR / "artifacts"
_EXCERPT_HEAD = 4000
_EXCERPT_TAIL = 2000

# Dockerfiles in this repo (from scope).
_DOCKERFILES = [
    "openhands-agent-server/openhands/agent_server/docker/Dockerfile",
    "examples/02_remote_agent_server/06_custom_tool/Dockerfile",
]
_NODE_DIR = (
    "openhands-agent-server/openhands/agent_server/vscode_extensions/openhands-settings"
)
_PY_PKGS = [
    "openhands-sdk",
    "openhands-tools",
    "openhands-workspace",
    "openhands-agent-server",
]


def build_registry() -> list[Tool]:
    """The CRITICAL-capable instrument registry for THIS repo's surfaces.

    `required_when` strings name surface ids from scope.yaml; a tool fires when
    its surface is present. Hygiene tier is necessary, never sufficient.
    """
    return [
        # --- hygiene tier (necessary, not sufficient) ---
        Tool(
            name="ruff",
            category="hygiene_lint",
            binary="ruff",
            build_argv=["ruff", "check", "--output-format", "json", "."],
            ecosystems=["python"],
            required_when=["python_code"],
            critical_capable=False,
            evidence_class="static_reproducible",
            disposition_cap_on_absent="HOLD",
        ),
        Tool(
            name="ruff_format",
            category="hygiene_format",
            binary="ruff",
            build_argv=["ruff", "format", "--check", "."],
            ecosystems=["python"],
            required_when=["python_code"],
            critical_capable=False,
            parser_required=False,
            nonzero_is_finding=True,
            disposition_cap_on_absent="HOLD",
        ),
        # --- python SAST depth ---
        Tool(
            name="bandit",
            category="sast",
            binary="bandit",
            build_argv=["bandit", "-r", *_PY_PKGS, "-f", "json", "-q"],
            ecosystems=["python"],
            required_when=["python_code"],
            critical_capable=True,
            evidence_class="static_reproducible",
            disposition_cap_on_absent="HOLD",
        ),
        # --- taint-aware SAST (pinned packs, NEVER --config auto) ---
        Tool(
            name="semgrep_pinned",
            category="sast_taint",
            binary="semgrep",
            build_argv=[
                "semgrep",
                "--config",
                "p/owasp-top-ten",
                "--config",
                "p/r2c-security-audit",
                "--config",
                "p/secrets",
                "--config",
                ".crucible/semgrep",
                "--metrics=off",
                "--json",
                "--quiet",
                ".",
            ],
            ecosystems=["python"],
            required_when=["python_code"],
            critical_capable=True,
            evidence_class="static_reproducible",
            db_backed=True,
            timeout_sec=900,
            disposition_cap_on_absent="HOLD",
        ),
        Tool(
            name="semgrep_node",
            category="sast",
            binary="semgrep",
            build_argv=[
                "semgrep",
                "--config",
                "p/javascript",
                "--metrics=off",
                "--json",
                "--quiet",
                _NODE_DIR,
            ],
            ecosystems=["node"],
            required_when=["node_code"],
            critical_capable=False,
            db_backed=True,
            timeout_sec=600,
            disposition_cap_on_absent="HOLD",
        ),
        # --- dependency CVE ---
        Tool(
            name="pip_audit",
            category="dependency_cve",
            binary="pip-audit",
            build_argv=["pip-audit", "--format", "json"],
            ecosystems=["python"],
            required_when=["python_code"],
            critical_capable=True,
            db_backed=True,
            timeout_sec=900,
            disposition_cap_on_absent="HOLD",
        ),
        Tool(
            name="osv_scanner",
            category="dependency_cve",
            binary="osv-scanner",
            build_argv=["osv-scanner", "--lockfile=uv.lock", "--format=json"],
            ecosystems=["python"],
            required_when=["python_code"],
            critical_capable=True,
            db_backed=True,
            timeout_sec=900,
            disposition_cap_on_absent="HOLD",
        ),
        # --- secrets (working tree + full history) ---
        Tool(
            name="gitleaks_working_tree",
            category="secret_scan",
            binary="gitleaks",
            build_argv=[
                "gitleaks",
                "detect",
                "--source",
                ".",
                "--no-git",
                "--report-format",
                "json",
                "--redact",
                "--report-path",
                "__REPORT_PATH__",
            ],
            ecosystems=["all"],
            required_when=["git_history"],
            critical_capable=True,
            db_backed=True,
            disposition_cap_on_absent="HOLD",
        ),
        Tool(
            name="gitleaks_full_history",
            category="secret_scan",
            binary="gitleaks",
            build_argv=[
                "gitleaks",
                "detect",
                "--source",
                ".",
                "--report-format",
                "json",
                "--redact",
                "--report-path",
                "__REPORT_PATH__",
                "--log-opts=--all",
            ],
            ecosystems=["all"],
            required_when=["git_history"],
            critical_capable=True,
            db_backed=True,
            timeout_sec=900,
            disposition_cap_on_absent="HOLD",
        ),
        # --- containers ---
        Tool(
            name="hadolint",
            category="container_lint",
            binary="hadolint",
            build_argv=["hadolint", "--format", "json", *_DOCKERFILES],
            ecosystems=["docker"],
            required_when=["container_build"],
            critical_capable=True,
            disposition_cap_on_absent="HOLD",
        ),
        Tool(
            name="trivy_fs",
            category="container_cve",
            binary="trivy",
            build_argv=["trivy", "fs", "--format", "json", "--quiet", "."],
            ecosystems=["docker"],
            required_when=["container_build"],
            critical_capable=True,
            db_backed=True,
            timeout_sec=900,
            disposition_cap_on_absent="HOLD",
        ),
    ]


def _excerpt(text: str) -> str:
    if len(text) <= _EXCERPT_HEAD + _EXCERPT_TAIL:
        return text
    return (
        text[:_EXCERPT_HEAD]
        + f"\n...[{len(text) - _EXCERPT_HEAD - _EXCERPT_TAIL} bytes elided]...\n"
        + text[-_EXCERPT_TAIL:]
    )


def _persist_stdout(run_id: str, stdout: str) -> tuple[str, str, int]:
    """Write full stdout to disk (plain + gzip). Returns (path, sha256, bytes)."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    raw = stdout.encode("utf-8", errors="replace")
    txt_path = ARTIFACTS_DIR / f"{run_id}.stdout.txt"
    txt_path.write_bytes(raw)
    (ARTIFACTS_DIR / f"{run_id}.stdout.txt.gz").write_bytes(gzip.compress(raw))
    digest = hashlib.sha256(raw).hexdigest()
    return str(txt_path), digest, len(raw)


# Markers that mean a scanner FATALLY crashed rather than "found findings".
# A required CRITICAL-capable tool that crashes must fail closed (tool_blocked),
# never masquerade as a clean parse — that is the starvation bypass.
_CRASH_MARKERS = (
    "permission denied",
    "ftl ",
    "fatal:",
    "panic:",
    "traceback (most recent call last)",
    "command not found",
    "no such file or directory",
    "could not",
    "unable to",
)


def _looks_fatal(stdout: str, stderr: str, exit_code: int) -> str | None:
    """Return a reason if a nonzero exit with empty stdout shows a crash marker."""
    if exit_code == 0 or stdout.strip():
        return None
    low = stderr.lower()
    for marker in _CRASH_MARKERS:
        if marker in low:
            return f"fatal tool error: {marker.strip()!r} in stderr, empty stdout"
    return None


def run_tool(tool: Tool, run_id: str) -> ToolRun:
    """Execute one tool, capturing real exit code + full output. Fails closed:
    a missing binary becomes tool_blocked, a timeout becomes timeout, a fatal
    crash (empty output + crash marker) becomes tool_blocked."""
    if shutil.which(tool.binary) is None:
        return ToolRun(
            run_id=run_id,
            tool_name=tool.name,
            category=tool.category,
            argv=tool.build_argv,
            cwd=str(REPO_ROOT),
            status=RunStatus.TOOL_BLOCKED,
            blocked_reason=f"binary '{tool.binary}' not on PATH",
        )
    # Some tools (gitleaks) cannot stream JSON to stdout portably; route their
    # report through a real temp file substituted for the __REPORT_PATH__ token.
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    report_file: Path | None = None
    argv = list(tool.build_argv)
    if "__REPORT_PATH__" in argv:
        report_file = ARTIFACTS_DIR / f"{run_id}.report.json"
        rf_posix = report_file.as_posix()
        argv = [rf_posix if a == "__REPORT_PATH__" else a for a in argv]
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=tool.timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolRun(
            run_id=run_id,
            tool_name=tool.name,
            category=tool.category,
            argv=argv,
            cwd=str(REPO_ROOT),
            status=RunStatus.TIMEOUT,
            duration_sec=time.monotonic() - start,
            blocked_reason=f"timeout after {tool.timeout_sec}s",
        )
    except OSError as exc:
        return ToolRun(
            run_id=run_id,
            tool_name=tool.name,
            category=tool.category,
            argv=argv,
            cwd=str(REPO_ROOT),
            status=RunStatus.TOOL_BLOCKED,
            blocked_reason=f"OSError: {exc}",
        )
    duration = time.monotonic() - start
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    # If the tool wrote to a report file, that file IS the effective stdout.
    if report_file is not None and report_file.exists():
        try:
            stdout = report_file.read_text(errors="replace") or stdout
        except OSError:
            pass

    # Fail closed on a fatal crash that produced no usable output.
    fatal = _looks_fatal(stdout, stderr, proc.returncode)
    if fatal:
        path, digest, nbytes = _persist_stdout(run_id, stdout)
        return ToolRun(
            run_id=run_id,
            tool_name=tool.name,
            category=tool.category,
            argv=argv,
            cwd=str(REPO_ROOT),
            status=RunStatus.TOOL_BLOCKED,
            exit_code=proc.returncode,
            duration_sec=round(duration, 3),
            stdout_excerpt=_excerpt(stdout),
            stderr_excerpt=_excerpt(stderr),
            stdout_sha256=digest,
            stdout_path=path,
            stdout_bytes=nbytes,
            blocked_reason=fatal,
        )

    path, digest, nbytes = _persist_stdout(run_id, stdout)
    status = RunStatus.OK if proc.returncode == 0 else RunStatus.NONZERO_EXIT
    return ToolRun(
        run_id=run_id,
        tool_name=tool.name,
        category=tool.category,
        argv=argv,
        cwd=str(REPO_ROOT),
        status=status,
        exit_code=proc.returncode,
        duration_sec=round(duration, 3),
        stdout_excerpt=_excerpt(stdout),
        stderr_excerpt=_excerpt(stderr),
        stdout_sha256=digest,
        stdout_path=path,
        stdout_bytes=nbytes,
    )


def applicable_tools(registry: list[Tool], present_surface_ids: set[str]) -> list[Tool]:
    """A tool fires iff any of its required_when surfaces is present."""
    return [
        t
        for t in registry
        if not t.required_when or (set(t.required_when) & present_surface_ids)
    ]
