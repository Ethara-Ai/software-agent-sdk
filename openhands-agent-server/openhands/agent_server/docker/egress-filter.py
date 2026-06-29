"""mitmproxy addon: Phase-3 default-deny anti-reward-hacking egress filter."""

from __future__ import annotations

import os
import re

from mitmproxy import http


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


TASK_ORG = _env("TASK_BLOCK_ORG")
TASK_REPO = _env("TASK_BLOCK_REPO")
TASK_PACKAGE = (_env("TASK_BLOCK_PACKAGE") or _env("TASK_BLOCK_PKG")).lower()
TASK_VER = _env("TASK_BLOCK_VER")

BLOCKED_HOSTS = frozenset({
    "api.github.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
    "github.com",
    "patch-diff.githubusercontent.com",
    "objects.githubusercontent.com",
    "cdn.jsdelivr.net",
    "github.dev",
})

REGISTRY_HOSTS = frozenset({
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "proxy.golang.org",
    "repo1.maven.org",
    "repo.maven.apache.org",
    "plugins.gradle.org",
    "dl.google.com",
})

LLM_PASSTHROUGH_HOSTS = frozenset({
    "openai.com",
    "googleapis.com",
    "google.com",
    "gstatic.com",
})

_REPO_RE: re.Pattern[str] | None = (
    re.compile(rf"/{re.escape(TASK_ORG)}/{re.escape(TASK_REPO)}([/.@?]|$)")
    if TASK_ORG and TASK_REPO
    else None
)

_PKG_RE: re.Pattern[str] | None = (
    re.compile(rf"/{re.escape(TASK_PACKAGE)}([/_\-.@]|$)")
    if TASK_PACKAGE
    else None
)

_NUMERIC_REPO_RE = re.compile(r"^/repositories/\d+")


def _host_in(host: str, hostset: frozenset[str]) -> bool:
    return any(host == h or host.endswith("." + h) for h in hostset)


def _deny(flow: http.HTTPFlow, reason: str) -> None:
    flow.response = http.Response.make(
        403,
        f"egress-filter: 403 {reason}\n".encode("utf-8"),
        {"content-type": "text/plain; charset=utf-8"},
    )


class EgressFilter:
    def request(self, flow: http.HTTPFlow) -> None:
        host = (flow.request.pretty_host or "").lower()
        path = flow.request.path or "/"

        if _host_in(host, LLM_PASSTHROUGH_HOSTS):
            return

        if not (TASK_ORG or TASK_REPO or TASK_PACKAGE):
            return

        if _host_in(host, BLOCKED_HOSTS):
            if _REPO_RE is not None and _REPO_RE.search(path):
                _deny(flow, f"task repo on {host}")
                return
            if host == "api.github.com" and _NUMERIC_REPO_RE.match(path):
                _deny(flow, "api.github.com numeric repo id")
                return
            return

        if _host_in(host, REGISTRY_HOSTS):
            lowpath = path.lower()
            if _PKG_RE is not None and _PKG_RE.search(lowpath):
                _deny(flow, f"task package on {host}")
                return
            if _REPO_RE is not None and _REPO_RE.search(path):
                _deny(flow, f"task repo on registry {host}")
                return
            return

        _deny(flow, f"default-deny ({host})")


addons = [EgressFilter()]
