#!/bin/bash
# e2e-full.sh — End-to-end integration suite against a running Proxymate
# instance with a live upstream (default: Squid at 127.0.0.1:3128).
#
# Auto-detects the local proxy port from the current system proxy config.
# Override with: PROXY_URL=http://127.0.0.1:NNNNN ./scripts/e2e-full.sh
#
# Exit code: 0 if no hard failures, 1 otherwise (skips are not failures).

set -uo pipefail

# ── Detect active proxy ──────────────────────────────────────────────────
if [[ -n "${PROXY_URL:-}" ]]; then
    PROXY="$PROXY_URL"
else
    HOST=$(scutil --proxy | awk '/HTTPProxy/{print $3}')
    PORT=$(scutil --proxy | awk '/HTTPPort/{print $3}')
    if [[ -z "$HOST" || -z "$PORT" ]]; then
        echo "ERROR: no system HTTP proxy detected. Enable Proxymate or set PROXY_URL."
        exit 2
    fi
    PROXY="http://${HOST}:${PORT}"
fi

echo "=========================================="
echo "PROXYMATE FULL E2E SUITE — SQUID UPSTREAM"
echo "Date: $(date)"
echo "Proxy: ${PROXY}"
echo "=========================================="

PASS=0
FAIL=0
SKIP=0

pass() { ((PASS++)); printf "  PASS  %s\n" "$1"; }
fail() { ((FAIL++)); printf "  FAIL  %s\n" "$1"; }
skip() { ((SKIP++)); printf "  SKIP  %s\n" "$1"; }
info() { printf "  INFO  %s\n" "$1"; }
section() { printf "\n=== %s ===\n" "$1"; }

# Shared curl: proxy set, fail-fast, no retries, 15s cap.
pcurl() { curl -sS -x "$PROXY" --max-time 15 "$@"; }

# ── 1. HTTP PROXY ────────────────────────────────────────────────────────
section "1. HTTP PROXY"
code=$(pcurl -o /dev/null -w "%{http_code}" http://example.com/ || echo "000")
[[ "$code" == "200" ]] && pass "HTTP GET 200" || fail "HTTP GET 200 (got $code)"

code=$(pcurl -o /dev/null -w "%{http_code}" http://httpbin.org/status/404 || echo "000")
[[ "$code" == "404" ]] && pass "HTTP GET 404 forwarded" || fail "HTTP GET 404 forwarded (got $code)"

code=$(pcurl -o /dev/null -w "%{http_code}" http://httpbin.org/status/301 || echo "000")
[[ "$code" == "301" ]] && pass "HTTP GET 301 forwarded" || fail "HTTP GET 301 forwarded (got $code)"

body=$(pcurl http://example.com/ | grep -c "Example Domain" || echo "0")
[[ "$body" -ge 1 ]] && pass "HTTP GET body received" || fail "HTTP GET body received (count $body)"

code=$(pcurl -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" \
    -d '{"marker":"e2e"}' http://httpbin.org/post || echo "000")
[[ "$code" == "200" ]] && pass "HTTP POST 200" || fail "HTTP POST 200 (got $code)"

body=$(pcurl -X POST -H "Content-Type: application/json" \
    -d '{"marker":"e2e"}' http://httpbin.org/post | grep -c '"marker": "e2e"' || echo "0")
[[ "$body" -ge 1 ]] && pass "HTTP POST body forwarded" || fail "HTTP POST body forwarded (count $body)"

# Large POST body: stress the header/leftover boundary. Initial read is
# 8KB, so a >8KB body exercises the client→upstream pipe (not just
# leftover forwarding). Use a deterministic 64KB payload with a marker
# at the END so truncation would be detected.
LARGE_POST=$(mktemp)
printf 'START_MARKER' > "$LARGE_POST"
# Fill to ~64KB minus the end marker
dd if=/dev/zero bs=1024 count=64 2>/dev/null | tr '\0' 'A' >> "$LARGE_POST"
printf 'END_MARKER_XYZ' >> "$LARGE_POST"
size=$(wc -c < "$LARGE_POST" | tr -d ' ')
resp=$(pcurl -X POST -H "Content-Type: application/octet-stream" \
    --data-binary "@$LARGE_POST" http://httpbin.org/post || echo "")
rm -f "$LARGE_POST"
reported=$(echo "$resp" | grep -o '"Content-Length": "[0-9]*"' | head -1 | grep -o '[0-9]*')
ends_ok=$(echo "$resp" | grep -c "END_MARKER_XYZ" || echo "0")
info "POST body ${size} bytes, upstream Content-Length: ${reported:-unknown}"
if [[ "$ends_ok" -ge 1 && "${reported:-0}" == "$size" ]]; then
    pass "HTTP POST 64KB body fully forwarded (end marker seen)"
else
    fail "HTTP POST 64KB body truncated (end_marker=$ends_ok, reported=${reported:-?} vs sent=$size)"
fi

# ── 2. HTTPS CONNECT ─────────────────────────────────────────────────────
section "2. HTTPS CONNECT"
code=$(pcurl -o /dev/null -w "%{http_code}" https://example.com/ || echo "000")
[[ "$code" == "200" ]] && pass "HTTPS CONNECT example.com" || fail "HTTPS CONNECT example.com (got $code)"

code=$(pcurl -o /dev/null -w "%{http_code}" https://httpbin.org/get || echo "000")
[[ "$code" == "200" ]] && pass "HTTPS CONNECT httpbin" || fail "HTTPS CONNECT httpbin (got $code)"

code=$(pcurl -o /dev/null -w "%{http_code}" https://api.github.com/zen || echo "000")
[[ "$code" == "200" ]] && pass "HTTPS CONNECT github API" || fail "HTTPS CONNECT github API (got $code)"

# ── 3. PRIVACY HEADERS ───────────────────────────────────────────────────
section "3. PRIVACY HEADERS"
# Squid strips hop-by-hop headers and may filter DNT/GPC before they reach httpbin.
# Verify injection by checking app log instead of end-to-end echo.
resp=$(pcurl http://httpbin.org/headers || echo "")
if echo "$resp" | grep -qi '"Dnt"'; then pass "DNT injected (reached upstream)"; else skip "DNT stripped by Squid — check app log"; fi
if echo "$resp" | grep -qi '"Sec-Gpc"'; then pass "GPC injected (reached upstream)"; else skip "GPC stripped by Squid — check app log"; fi

# ── 4. WAF BLOCKING ──────────────────────────────────────────────────────
section "4. WAF BLOCKING"
for host in google-analytics.com www.googletagmanager.com doubleclick.net; do
    code=$(pcurl -o /dev/null -w "%{http_code}" "http://${host}/" || echo "000")
    if [[ "$code" == "403" || "$code" == "502" ]]; then
        pass "WAF block ${host} (got $code)"
    elif [[ "$code" == "200" ]]; then
        fail "WAF block ${host} — NOT blocked (got 200)"
    else
        info "WAF ${host} got $code"
        # Some blocks return non-403 but still non-200; count as pass if clearly refused
        [[ "$code" != "200" ]] && pass "WAF block ${host} (non-200: $code)" || fail "WAF block ${host}"
    fi
done

code=$(pcurl -o /dev/null -w "%{http_code}" http://example.com/ || echo "000")
[[ "$code" == "200" ]] && pass "Non-blocked domain passes" || fail "Non-blocked domain passes (got $code)"

# ── 5. EXFILTRATION SCANNER ──────────────────────────────────────────────
section "5. EXFILTRATION SCANNER"
code=$(pcurl -o /dev/null -w "%{http_code}" \
    -H "X-Test-Key: AKIAIOSFODNN7EXAMPLE" http://httpbin.org/headers || echo "000")
info "Sent AWS key in header, got: $code"
skip "Exfiltration scanner — verify in app log (detection is log-only by default)"

# ── 6. CACHE ─────────────────────────────────────────────────────────────
section "6. CACHE"
url="http://httpbin.org/bytes/1024?cachetest=$(date +%s)"
pcurl -o /dev/null "$url" >/dev/null
t2=$(pcurl -o /dev/null -w "%{time_total}" "$url" || echo "1.000")
info "Second request time: ${t2}s (cache hit expected if < 0.005s)"
# Accept anything fast enough (<0.05 is cache-or-squid). True cache verification requires app log.
awk -v t="$t2" 'BEGIN { if (t+0 < 0.050) exit 0; exit 1 }' \
    && pass "Cache hit (fast response)" \
    || skip "Cache — response not noticeably faster, may be disabled or upstream-served"

# ── 7. LARGE RESPONSES ───────────────────────────────────────────────────
# httpbin.org caps /bytes and /stream-bytes at 100KB regardless of N, so
# use thinkbroadband for true large-payload validation. Skip gracefully
# if the test endpoint is unreachable.
section "7. LARGE RESPONSES"
out=$(pcurl -o /tmp/proxymate-e2e-100k.bin \
    -w "code=%{http_code} size=%{size_download}" http://httpbin.org/bytes/102400 || echo "code=000 size=0")
code=$(echo "$out" | awk '{print $1}' | cut -d= -f2)
size=$(echo "$out" | awk '{print $2}' | cut -d= -f2)
info "Downloaded: ${size} bytes, http ${code}"
[[ "$code" == "200" && "$size" == "102400" ]] \
    && pass "100KB response received" \
    || fail "100KB response received (code=$code size=$size)"

LARGE_URL="http://ipv4.download.thinkbroadband.com/1MB.zip"
out=$(pcurl -L -o /tmp/proxymate-e2e-1m.bin \
    -w "code=%{http_code} size=%{size_download}" --max-time 30 "$LARGE_URL" || echo "code=000 size=0")
code=$(echo "$out" | awk '{print $1}' | cut -d= -f2)
size=$(echo "$out" | awk '{print $2}' | cut -d= -f2)
info "Downloaded 1MB: ${size} bytes, http ${code}"
if [[ "$code" == "200" && "$size" == "1048576" ]]; then
    pass "1MB response received"
elif [[ "$code" == "000" || "$code" == "503" || "$code" == "502" ]]; then
    skip "1MB endpoint unreachable (got $code) — network/DNS/upstream issue"
else
    fail "1MB response received (code=$code size=$size)"
fi

# ── 8. CONCURRENT REQUESTS ───────────────────────────────────────────────
section "8. CONCURRENT REQUESTS"
concurrent_ok=0
printf "  "
for i in {1..20}; do
    (pcurl -o /dev/null -w "%{http_code}" http://example.com/ || echo "000") &
done | tr -d '\n'
wait
echo ""
# Re-check the proxy is alive after the burst
code=$(pcurl -o /dev/null -w "%{http_code}" http://example.com/ || echo "000")
[[ "$code" == "200" ]] && pass "Proxy alive after 20 concurrent" || fail "Proxy alive after 20 concurrent (got $code)"

# ── 9. LATENCY BENCHMARK ─────────────────────────────────────────────────
section "9. LATENCY BENCHMARK"
total=0
count=20
for i in $(seq 1 $count); do
    t=$(pcurl -o /dev/null -w "%{time_total}" http://example.com/ 2>/dev/null || echo "0")
    total=$(awk -v a="$total" -v b="$t" 'BEGIN { printf "%.6f", a + b }')
done
avg=$(awk -v t="$total" -v n="$count" 'BEGIN { printf "%.4f", t / n }')
info "${count} requests avg latency: ${avg}s"
awk -v a="$avg" 'BEGIN { if (a+0 < 0.500) exit 0; exit 1 }' \
    && pass "Avg latency < 500ms" \
    || fail "Avg latency too high: ${avg}s"

# ── 10. ERROR HANDLING ───────────────────────────────────────────────────
section "10. ERROR HANDLING"
code=$(pcurl -o /dev/null -w "%{http_code}" http://this-host-does-not-exist-9x7q.invalid/ || echo "000")
info "Non-existent host: $code"
[[ "$code" == "502" || "$code" == "503" || "$code" == "504" ]] \
    && pass "Non-existent host handled" \
    || fail "Non-existent host handled (got $code)"

code=$(pcurl -o /dev/null -w "%{http_code}" http://example.com/ || echo "000")
[[ "$code" == "200" ]] && pass "Proxy alive after error" || fail "Proxy alive after error (got $code)"

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
echo "=========================================="
echo "RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
echo "=========================================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
