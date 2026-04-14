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

# Resolve Proxymate listener port from scutil --proxy (skip if --no-proxy)
PORT=""
if ! printf '%s\n' "$@" | grep -qx -- '--no-proxy'; then
    PORT="$(scutil --proxy | awk '/HTTPSPort/ {print $3; exit}')"
    if [[ -z "${PORT}" || "${PORT}" == "0" ]]; then
        echo "Proxymate doesn't appear to be the active system proxy."
        echo "Enable it from the menu-bar, or pass --no-proxy for baseline mode."
        exit 2
    fi
fi

cd "${TESTS_DIR}"

# First run: install playwright + browsers
if [[ ! -d node_modules/playwright ]]; then
    echo "==> Installing Playwright (first run only)..."
    npm install --silent
    npx playwright install chromium firefox
fi

[[ -n "${PORT}" ]] && export PROXYMATE_PORT="${PORT}"
export PROXYMATE_CA_PATH="${HOME}/Library/Application Support/Proxymate/ca/ca.pem"
export PROXYMATE_LOG_DIR="${HOME}/Library/Application Support/Proxymate/logs"

case "${1:-}" in
    --suite)
        shift
        exec node suite.mjs "$@"
        ;;
    --compare)
        shift
        exec node compare.mjs "$@"
        ;;
    ""|-h|--help)
        cat <<EOF
Proxymate site-compat diagnostic

Single URL:
  $0 <url> [--browser chromium|firefox] [--label tag]
  $0 <url> --no-proxy                        # baseline without proxy
  $0 <url> --mitm on|off                     # tag run by MITM state
  $0 <url> --headed                          # visible browser (anti-bot friendly)

Suite (runs all of sites.json):
  $0 --suite [--browser ...] [--no-proxy] [--mitm on|off] [--headed]

Compare latest runs across modes:
  $0 --compare <modeA> <modeB>
  e.g. $0 --compare direct proxy-mitm-on
       $0 --compare proxy-mitm-off proxy-mitm-on

Workflow to isolate a regression:
  1. $0 --suite --no-proxy                   # baseline, MITM state irrelevant
  2. Enable Proxymate + disable MITM
     $0 --suite --mitm off
  3. Enable MITM
     $0 --suite --mitm on
  4. $0 --compare direct proxy-mitm-on       # regressions caused by proxy+MITM
     $0 --compare proxy-mitm-off proxy-mitm-on  # regressions caused by MITM alone
EOF
        exit 2
        ;;
    *)
        exec node diagnose.mjs "$@"
        ;;
esac
