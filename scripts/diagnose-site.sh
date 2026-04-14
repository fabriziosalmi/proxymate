#!/bin/bash
# diagnose-site.sh — drives Playwright through Proxymate to capture why a site
# fails to load (failed requests, CORS errors, nav errors, bypass signals).
#
# Usage:
#   ./scripts/diagnose-site.sh https://github.com                # single URL
#   ./scripts/diagnose-site.sh https://github.com firefox        # pick browser
#   ./scripts/diagnose-site.sh --suite                           # run full suite
#
# Reads Proxymate's active listener port from scutil --proxy. Proxymate must
# be Enabled (system proxy set) before running this.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TESTS_DIR="${PROJECT_DIR}/tests/site-compat"

# Resolve Proxymate listener port from scutil --proxy
PORT="$(scutil --proxy | awk '/HTTPSPort/ {print $3; exit}')"
if [[ -z "${PORT}" || "${PORT}" == "0" ]]; then
    echo "Proxymate doesn't appear to be the active system proxy."
    echo "Enable it from the menu-bar before running this script."
    exit 2
fi

cd "${TESTS_DIR}"

# First run: install playwright + browsers
if [[ ! -d node_modules/playwright ]]; then
    echo "==> Installing Playwright (first run only)..."
    npm install --silent
    npx playwright install chromium firefox
fi

export PROXYMATE_PORT="${PORT}"
export PROXYMATE_CA_PATH="${HOME}/Library/Application Support/Proxymate/ca/ca.pem"

case "${1:-}" in
    --suite)
        BROWSER="${2:-chromium}"
        exec node suite.mjs "${BROWSER}"
        ;;
    ""|-h|--help)
        echo "Usage: $0 <url> [chromium|firefox] [label]"
        echo "       $0 --suite [chromium|firefox]"
        exit 2
        ;;
    *)
        exec node diagnose.mjs "$@"
        ;;
esac
