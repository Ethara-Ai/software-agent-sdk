#!/usr/bin/env bash
set -u

if [ "${EGRESS_FILTER_DISABLE:-}" = "1" ]; then
    echo "[entrypoint] EGRESS_FILTER_DISABLE=1: skipping egress filter"
    rm -f /home/fix.patch /home/test.patch 2>/dev/null || true
    exec /agent-server/.venv/bin/python -m openhands.agent_server "$@"
fi

rm -f /home/fix.patch /home/test.patch 2>/dev/null || true

MITM_PORT="${MITM_PORT:-8888}"
EGRESS_LOG="${EGRESS_LOG:-/tmp/egress-filter.log}"

EGRESS_IGNORE_HOSTS='(^|\.)(openai\.com|googleapis\.com|google\.com|gstatic\.com)(:[0-9]+)?$'

mitmdump \
    -s /usr/local/bin/egress-filter.py \
    --listen-host 127.0.0.1 \
    --listen-port "$MITM_PORT" \
    --set confdir=/etc/mitmproxy \
    --ignore-hosts "$EGRESS_IGNORE_HOSTS" \
    > "$EGRESS_LOG" 2>&1 &
MITM_PID=$!

for _ in $(seq 1 60); do
    if curl -s -o /dev/null --max-time 1 -x "http://127.0.0.1:$MITM_PORT" \
            "http://127.0.0.1/" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$MITM_PID" 2>/dev/null; then
        echo "[entrypoint] FATAL: mitmdump died before becoming ready; see $EGRESS_LOG"
        exit 1
    fi
    sleep 0.5
done

# --- LLM direct-egress carve-out (bypasses the full egress block) ---
LLM_DIRECT_HOST="${LLM_DIRECT_HOST:-}"
LLM_DIRECT_PORT="${LLM_DIRECT_PORT:-443}"
if [ -n "$LLM_DIRECT_HOST" ]; then
    iptables -I OUTPUT -p tcp -d "$LLM_DIRECT_HOST" \
        --dport "$LLM_DIRECT_PORT" -j ACCEPT || \
        echo "[entrypoint] WARN: could not add LLM_DIRECT_HOST iptables carve-out"
fi

export HTTP_PROXY="http://127.0.0.1:$MITM_PORT"
export HTTPS_PROXY="http://127.0.0.1:$MITM_PORT"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
export no_proxy="127.0.0.1,localhost${LLM_DIRECT_HOST:+,${LLM_DIRECT_HOST}}"
export NO_PROXY="$no_proxy"

num_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
           "https://api.github.com/repositories/1" 2>/dev/null || echo "000")
if [ "$num_code" != "403" ]; then
    echo "[entrypoint] FATAL: numeric-repo-id endpoint not blocked (got $num_code, expected 403)"
    exit 1
fi

go_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
          "https://proxy.golang.org/any/module/@v/list" 2>/dev/null || echo "000")
if [ "$go_code" != "403" ]; then
    echo "[entrypoint] FATAL: Go module proxy not blocking task repo (got $go_code, expected 403)"
    exit 1
fi

deny_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
            "https://pypi.tuna.tsinghua.edu.cn/simple/pip/" 2>/dev/null || echo "000")
if [ "$deny_code" != "403" ]; then
    echo "[entrypoint] FATAL: default-deny inactive (got $deny_code, expected 403)"
    exit 1
fi

echo "[entrypoint] egress filter active (pid=$MITM_PID); all 3 pre-flight checks passed"

exec /agent-server/.venv/bin/python -m openhands.agent_server "$@"
