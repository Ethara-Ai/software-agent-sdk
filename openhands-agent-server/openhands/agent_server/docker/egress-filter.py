"""mitmproxy addon: Phase-3 default-deny anti-reward-hacking full egress block.

Every request that reaches this addon is denied. LLM / model-API traffic never
reaches here: it is carved out at the network layer by the container entrypoint
(iptables ACCEPT for LLM_DIRECT_HOST) and by mitmdump --ignore-hosts. There is
no selective allow, no task-repo/package matching, and no registry passthrough,
so a solver cannot fetch the gold PR, a mirror, or any upstream artifact.
"""

from __future__ import annotations

from mitmproxy import http


def decide(host: str) -> str:
    """Full egress block: always returns a denial reason for any host."""
    return f"blocked by full egress block ({host})"


def _deny(flow: http.HTTPFlow, reason: str) -> None:
    flow.response = http.Response.make(
        403,
        f"egress-filter: 403 {reason}\n".encode("utf-8"),
        {"content-type": "text/plain; charset=utf-8"},
    )


class EgressFilter:
    def request(self, flow: http.HTTPFlow) -> None:
        host = (flow.request.pretty_host or "").lower()
        _deny(flow, decide(host))


addons = [EgressFilter()]
