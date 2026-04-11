#!/bin/bash
set -euo pipefail

#
# benchmark.sh — Measure Proxymate proxy overhead.
#
# Prerequisites: Proxymate running with proxy enabled.
# Uses curl to fire requests through the proxy and measure latency.
#
# Usage:
#   ./scripts/benchmark.sh                    # default: 1000 requests
#   ./scripts/benchmark.sh 5000               # custom count
#   ./scripts/benchmark.sh 1000 8080          # custom count + proxy port
#

COUNT="${1:-1000}"
PROXY_PORT="${2:-}"
TARGET="http://httpbin.org/status/200"
DIRECT_TARGET="http://1.1.1.1/"  # fast, no DNS needed

# Auto-detect proxy port from system settings
if [[ -z "$PROXY_PORT" ]]; then
    PROXY_PORT=$(networksetup -getwebproxy Wi-Fi 2>/dev/null | grep "Port:" | awk '{print $2}')
    if [[ -z "$PROXY_PORT" || "$PROXY_PORT" == "0" ]]; then
        echo "ERROR: No proxy detected. Enable Proxymate first or specify port."
        echo "Usage: $0 [count] [proxy_port]"
        exit 1
    fi
fi

PROXY="http://127.0.0.1:${PROXY_PORT}"
echo "==> Proxymate Benchmark"
echo "    Proxy: $PROXY"
echo "    Requests: $COUNT"
echo ""

# Function to run N requests and report stats
run_bench() {
    local label="$1"
    local proxy_arg="$2"
    local target="$3"
    local count="$4"
    local total=0
    local min=999999
    local max=0
    local failures=0
    local times=()

    echo -n "    $label: "

    for ((i=1; i<=count; i++)); do
        local t
        t=$(curl -o /dev/null -s -w "%{time_total}" \
            --connect-timeout 5 --max-time 10 \
            $proxy_arg "$target" 2>/dev/null || echo "FAIL")

        if [[ "$t" == "FAIL" ]]; then
            ((failures++))
            continue
        fi

        # Convert to microseconds
        local us=$(echo "$t * 1000000" | bc | cut -d. -f1)
        times+=("$us")
        total=$((total + us))

        if ((us < min)); then min=$us; fi
        if ((us > max)); then max=$us; fi
    done

    local success=${#times[@]}
    if ((success == 0)); then
        echo "ALL FAILED ($failures failures)"
        return
    fi

    local avg=$((total / success))

    # Sort for percentiles
    IFS=$'\n' sorted=($(sort -n <<<"${times[*]}")); unset IFS
    local p50=${sorted[$((success / 2))]}
    local p95=${sorted[$((success * 95 / 100))]}
    local p99=${sorted[$((success * 99 / 100))]}
    local rps=$(echo "scale=1; $success / ($total / 1000000)" | bc)

    printf "%d req | avg=%dµs p50=%dµs p95=%dµs p99=%dµs max=%dµs | %.1f req/s" \
        "$success" "$avg" "$p50" "$p95" "$p99" "$max" "$rps"
    if ((failures > 0)); then printf " | %d failures" "$failures"; fi
    echo ""
}

# Warm up
echo "==> Warming up..."
for i in $(seq 1 10); do
    curl -o /dev/null -s --proxy "$PROXY" "$DIRECT_TARGET" 2>/dev/null || true
done

# Benchmark: direct (no proxy)
echo "==> Direct (no proxy):"
run_bench "Direct" "" "$DIRECT_TARGET" "$COUNT"

# Benchmark: through proxy
echo "==> Through Proxymate:"
run_bench "Proxy " "--proxy $PROXY" "$DIRECT_TARGET" "$COUNT"

# Benchmark: through proxy with WAF-heavy target
echo "==> Proxy + WAF check (full pipeline):"
run_bench "WAF   " "--proxy $PROXY" "http://example.com/" "$COUNT"

# Memory check
echo ""
echo "==> Memory:"
PID=$(pgrep -f "proxymate.app" | head -1)
if [[ -n "$PID" ]]; then
    RSS=$(ps -o rss= -p "$PID" | tr -d ' ')
    echo "    RSS: $((RSS / 1024)) MB (PID $PID)"
else
    echo "    Could not find Proxymate process"
fi

echo ""
echo "==> Done."
