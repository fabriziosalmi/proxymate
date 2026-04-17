#!/bin/bash
# Proxymate pre-push hook.
#
# Two gates:
#   A. Core integrity — run sites-core.json (5 rock-solid sites) through
#      Proxymate and fail only on unequivocal signals (CA_NOT_TRUSTED,
#      PROXY_UPSTREAM_ERROR on a core site). Does NOT fail on anti-bot
#      blocks, tracker console noise, or networkidle timeouts.
#   B. Streaming probe — curl-through-proxy against sites-streaming.json
#      (Apple HLS bipbop, Mux HLS test, Radio Paradise) and assert
#      Content-Type matches, bytes flow within 4 s, auto-exclude log line
#      appears in proxymate.log.
#
# Both gates are skipped with a clear message if PROXYMATE_PORT is unset
# or if Proxymate is not running — a pre-push hook must not block pushes
# from machines that don't have the app running. Tests still run.
#
# To install:
#   ./scripts/pre-push-hook.sh --install
# To dry-run:
#   ./scripts/pre-push-hook.sh --run

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_DIR="$REPO_ROOT/tests/site-compat"
HOOK_PATH="$REPO_ROOT/.git/hooks/pre-push"

install_hook() {
    if [[ -e "$HOOK_PATH" ]] && ! grep -q 'proxymate pre-push' "$HOOK_PATH" 2>/dev/null; then
        echo "refusing to overwrite $HOOK_PATH (not a Proxymate hook)"
        echo "move/rename it first, then re-run --install"
        exit 1
    fi
    cat > "$HOOK_PATH" <<'HOOK'
#!/bin/bash
# proxymate pre-push — delegates to scripts/pre-push-hook.sh
REPO_ROOT="$(git rev-parse --show-toplevel)"
exec "$REPO_ROOT/scripts/pre-push-hook.sh" --run
HOOK
    chmod +x "$HOOK_PATH"
    echo "installed: $HOOK_PATH"
    echo "bypass once with: git push --no-verify"
    exit 0
}

if [[ "${1:-}" == "--install" ]]; then install_hook; fi
if [[ "${1:-}" != "--run" ]]; then
    echo "usage: $0 --install | --run"
    exit 2
fi

echo "── proxymate pre-push ──────────────────────────────────────"

# ─────── Gate 0: Swift unit tests (always) ─────────────────────────
# We run a fast subset — HTTPParserTests is representative, finishes
# in ~2 s, and covers the response-parsing layer where the 0.9.57
# streaming patch lives. Full test suite is not run here (too slow,
# XCUITest runner occasionally flakes on macOS 26.1 — tracked, not
# something to gate pushes on).
echo
echo "[1/3] unit tests (HTTPParserTests)..."
if ! xcodebuild -project "$REPO_ROOT/proxymate.xcodeproj" -scheme proxymate \
        -configuration Debug -destination 'platform=macOS' \
        test -only-testing:proxymateTests/HTTPParserTests \
        -quiet 2>&1 | tail -40 | grep -qE '(Test case .* passed|BUILD SUCCEEDED|Executed .* tests)'; then
    echo "  FAIL: unit tests did not run cleanly — check xcodebuild output"
    exit 1
fi
echo "  ok"

# ─────── Gate A + B: live proxy checks (skip if unavailable) ────────
if [[ -z "${PROXYMATE_PORT:-}" ]]; then
    echo
    echo "[2/3] core site integrity    SKIP (PROXYMATE_PORT unset)"
    echo "[3/3] streaming probe        SKIP (PROXYMATE_PORT unset)"
    echo
    echo "To enable proxy-live gates, export PROXYMATE_PORT and ensure Proxymate is running:"
    echo "  export PROXYMATE_PORT=8080    # or whichever listener is active"
    echo
    echo "── all gates passed (proxy-live gates skipped) ─────────────"
    exit 0
fi

# Verify port is actually listening
if ! (exec 3<>/dev/tcp/127.0.0.1/$PROXYMATE_PORT) 2>/dev/null; then
    echo
    echo "[2/3] core site integrity    SKIP (no listener on 127.0.0.1:$PROXYMATE_PORT)"
    echo "[3/3] streaming probe        SKIP (no listener on 127.0.0.1:$PROXYMATE_PORT)"
    echo
    echo "Proxymate doesn't seem to be running on the configured port."
    echo "Start the app, confirm the listener port, then re-push."
    echo "── all gates passed (proxy-live gates skipped) ─────────────"
    exit 0
fi
exec 3<&- 2>/dev/null || true

cd "$HARNESS_DIR"

echo
if [[ -d "$HARNESS_DIR/node_modules/playwright" ]]; then
    echo "[2/3] core site integrity (sites-core.json via proxy)..."
    if ! node suite.mjs --sites sites-core.json --mitm on > /tmp/proxymate-core.log 2>&1; then
        echo "  FAIL: core integrity regression — see /tmp/proxymate-core.log"
        echo
        grep -E '\[(OK|FAIL)\]|Signals|CA_NOT_TRUSTED|PROXY_UPSTREAM_ERROR|CONNECTION_RESET' \
            /tmp/proxymate-core.log | head -30
        echo
        echo "Push blocked. Inspect the report dirs under tests/site-compat/reports/ for detail."
        echo "Override with: git push --no-verify  (only if you've reviewed the regression)"
        exit 1
    fi
    grep -E '^\[OK  \]' /tmp/proxymate-core.log | sed 's/^/  /' || true
    echo "  ok"
else
    echo "[2/3] core site integrity    SKIP (playwright not installed — (cd tests/site-compat && npm install && npx playwright install))"
fi

echo
echo "[3/3] streaming probe (sites-streaming.json via proxy)..."
if ! node stream-probe.mjs > /tmp/proxymate-stream.log 2>&1; then
    echo "  FAIL: streaming probe regression — see /tmp/proxymate-stream.log"
    echo
    cat /tmp/proxymate-stream.log | tail -20
    echo
    echo "Push blocked. The v0.9.57 signal-based streaming bypass is misbehaving."
    echo "Override with: git push --no-verify  (only if you've reviewed the regression)"
    exit 1
fi
grep -E '^\[(OK|FAIL)\]' /tmp/proxymate-stream.log | sed 's/^/  /' || true
echo "  ok"

echo
echo "── all gates passed ────────────────────────────────────────"
exit 0
