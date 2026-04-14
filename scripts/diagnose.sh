#!/bin/bash
# diagnose.sh — Draconian, single-pass health snapshot of a Proxymate install.
#
# Run when something looks off, paste the output to a maintainer (or attach
# to a GitHub issue). The script emits OK/WARN/FAIL/SKIP verdict tags, then
# a summary at the end. Exit codes: 0 clean, 1 warnings, 2 hard failures —
# slots into CI / launchd healthchecks unchanged.
#
# Output contains: macOS version, app version, listener ports, system proxy
# state, signed-code verdict, entitlements, CA encryption state, keychain
# presence (NOT contents), recent log lines, live forward test, sidecar
# process tree, recent crash reports, OSLog tail.
#
# Output does NOT contain: request bodies, cookies, response headers, the
# CA private key, keychain passphrases, or any URL beyond what's already in
# your own configured rule list.

set +e
LC_ALL=C
SCRIPT_VERSION=3

PROXYMATE_LOG_DIR="$HOME/Library/Application Support/Proxymate/logs"
PROXYMATE_LOG="$PROXYMATE_LOG_DIR/proxymate.log"
CA_DIR="$HOME/Library/Application Support/Proxymate/ca"
CA_KEY="$CA_DIR/ca.key"
CA_PEM="$CA_DIR/ca.pem"
PREFS_PATH="$HOME/Library/Preferences/fabriziosalmi.proxymate"
KEYCHAIN_SVC="fabriziosalmi.proxymate.tls"

# ── Color (TTY-only; plain text when piped to file/CI) ──────────────────
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RESET=$'\033[0m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    RED=$'\033[31m'
    BLUE=$'\033[34m'
    CYAN=$'\033[36m'
    GRAY=$'\033[90m'
else
    BOLD=""; DIM=""; RESET=""; GREEN=""; YELLOW=""; RED=""; BLUE=""; CYAN=""; GRAY=""
fi

# ── Verdict counters ────────────────────────────────────────────────────
total_ok=0; total_warn=0; total_fail=0; total_skip=0

ok()   { printf "  ${GREEN}✓${RESET} %s\n" "$1"; total_ok=$((total_ok+1)); }
warn() { printf "  ${YELLOW}!${RESET} %s\n" "$1"; total_warn=$((total_warn+1)); }
fail() { printf "  ${RED}✗${RESET} %s\n" "$1"; total_fail=$((total_fail+1)); }
skip() { printf "  ${GRAY}–${RESET} ${GRAY}%s${RESET}\n" "$1"; total_skip=$((total_skip+1)); }
note() { printf "    ${DIM}%s${RESET}\n" "$1"; }
hr()   { printf "    ${DIM}────────${RESET}\n"; }

section() {
    printf "\n${BOLD}${CYAN}━━━ %s ━━━${RESET}\n" "$1"
}

# ── 1. Environment fingerprint ──────────────────────────────────────────
section "1. Environment"
SW_PV=$(sw_vers -productVersion 2>/dev/null)
SW_BV=$(sw_vers -buildVersion 2>/dev/null)
ARCH=$(uname -m)
KERNEL=$(uname -r)
UPTIME=$(uptime | awk -F'load' '{print $1}' | sed 's/^ *//;s/, *$//')
HOST=$(hostname -s)
printf "  ${DIM}macOS:${RESET}   %s (%s)\n" "$SW_PV" "$SW_BV"
printf "  ${DIM}Arch:${RESET}    %s · ${DIM}kernel:${RESET} %s\n" "$ARCH" "$KERNEL"
printf "  ${DIM}Date:${RESET}    %s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
printf "  ${DIM}Uptime:${RESET}  %s\n" "$UPTIME"
printf "  ${DIM}Host:${RESET}    %s\n" "$HOST"
printf "  ${DIM}Diagnose:${RESET} v%s\n" "$SCRIPT_VERSION"
echo
case "${SW_PV%%.*}" in
  26|27|28) ok "macOS $SW_PV is supported" ;;
  *)        fail "macOS $SW_PV unsupported (Proxymate requires 26+)" ;;
esac
[[ "$ARCH" == "arm64" ]] && ok "Apple Silicon (arm64)" \
                          || fail "Architecture $ARCH not supported"

# ── 2. Process + build identity ─────────────────────────────────────────
section "2. Process"
PID=$(pgrep -x proxymate | head -1)
if [[ -z "$PID" ]]; then
  fail "Proxymate process not running"
  PID=""; BIN=""; APP_PATH=""
else
  RSS=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
  ETIME=$(ps -o etime= -p "$PID" 2>/dev/null | tr -d ' ')
  BIN=$(ps -o comm= -p "$PID" 2>/dev/null)
  APP_PATH="$(cd "$(dirname "$BIN")/../.." 2>/dev/null && pwd -P)"

  printf "  ${DIM}PID:${RESET}     %s\n" "$PID"
  printf "  ${DIM}RSS:${RESET}     %s KB · ${DIM}etime:${RESET} %s\n" "$RSS" "$ETIME"
  printf "  ${DIM}App:${RESET}     %s\n" "$APP_PATH"

  PLIST="$(dirname "$BIN")/../Info.plist"
  if [[ -f "$PLIST" ]]; then
    SHORT_VER=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$PLIST" 2>/dev/null)
    BUILD_VER=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$PLIST" 2>/dev/null)
    printf "  ${DIM}Version:${RESET} %s (build %s)\n" "$SHORT_VER" "$BUILD_VER"
    case "$BIN" in
      */DerivedData/*) BUILD_KIND="Debug build (Xcode)"; IS_DEBUG=1 ;;
      /Applications/*) BUILD_KIND="Release (Applications)"; IS_DEBUG=0 ;;
      *)               BUILD_KIND="other"; IS_DEBUG=0 ;;
    esac
    printf "  ${DIM}Build:${RESET}   %s\n" "$BUILD_KIND"
  fi
  echo
  ok "Process running"

  FD_COUNT=$(lsof -nP -p "$PID" 2>/dev/null | wc -l | tr -d ' ')
  if [[ $FD_COUNT -lt 50 ]];   then ok "FD count healthy ($FD_COUNT)"
  elif [[ $FD_COUNT -lt 500 ]]; then ok "FD count normal ($FD_COUNT)"
  elif [[ $FD_COUNT -lt 2000 ]];then warn "FD count elevated ($FD_COUNT) — possible leak"
  else                               fail "FD count very high ($FD_COUNT) — likely leak"
  fi
fi

# ── 3. Code signature ──────────────────────────────────────────────────
section "3. Code signature"
if [[ -n "$APP_PATH" && -d "$APP_PATH" ]]; then
  SIGN_INFO=$(codesign -dv --verbose=2 "$APP_PATH" 2>&1)
  echo "$SIGN_INFO" | grep -E "^(Identifier|TeamIdentifier|Authority|Signed Time)" | sed "s/^/  ${DIM}/" | sed "s/$/${RESET}/"
  echo
  if codesign --verify --strict "$APP_PATH" 2>/dev/null; then
    ok "codesign --verify --strict passed"
  else
    warn "codesign --verify --strict reported issues"
  fi
  SPCTL_OUT=$(spctl -a -vv "$APP_PATH" 2>&1)
  if echo "$SPCTL_OUT" | grep -q "accepted"; then
    ok "Gatekeeper would accept"
  else
    warn "Gatekeeper assessment: $(echo "$SPCTL_OUT" | head -1)"
  fi
  if stapler validate "$APP_PATH" 2>&1 | grep -q "worked"; then
    ok "Notarization ticket stapled"
  elif [[ "$IS_DEBUG" == "1" ]]; then
    skip "Stapled ticket not present (expected on Debug build)"
  else
    warn "No stapled notarization ticket"
  fi
else
  skip "(no app bundle resolved)"
fi

# ── 4. Entitlements ─────────────────────────────────────────────────────
section "4. Entitlements"
if [[ -n "$BIN" && -f "$BIN" ]]; then
  ENT_DUMP=$(codesign -d --entitlements - "$BIN" 2>/dev/null)
  for key in \
      "com.apple.security.network.server" \
      "com.apple.security.network.client" \
      "com.apple.security.cs.allow-unsigned-executable-memory" \
      "com.apple.security.cs.disable-library-validation"; do
    if echo "$ENT_DUMP" | grep -q "$key"; then
      ok "$key"
    else
      fail "Missing: $key"
    fi
  done
else
  skip "(no binary)"
fi

# ── 5. Listeners + sidecar ports ────────────────────────────────────────
section "5. Listeners + sidecar ports"
LISTEN_PORT=""
if [[ -n "$PID" ]]; then
  PROXY_LISTEN=$(lsof -nP -p "$PID" 2>/dev/null | awk '/LISTEN/ {print}')
  if [[ -z "$PROXY_LISTEN" ]]; then
    fail "Process running but no LISTEN socket"
  else
    echo "$PROXY_LISTEN" | sed "s/^/  ${DIM}/" | sed "s/$/${RESET}/"
    LISTEN_PORT=$(echo "$PROXY_LISTEN" | head -1 | awk '{print $9}' | sed 's/.*://' | head -1)
    [[ -n "$LISTEN_PORT" ]] && ok "Listener bound on :$LISTEN_PORT"
  fi
fi

echo
printf "  ${DIM}Sidecar ports:${RESET}\n"
for p in 3128 8080 18080 18095 1080 9199; do
  ROW=$(lsof -nP -iTCP:$p -sTCP:LISTEN 2>/dev/null | grep -v COMMAND)
  if [[ -n "$ROW" ]]; then
    OWNER=$(echo "$ROW" | awk '{print $1, "(pid "$2")"}')
    case $p in
      3128)  printf "    %-7s %-30s %s\n" ":3128"  "Squid"               "$OWNER" ;;
      8080)  printf "    %-7s %-30s %s\n" ":8080"  "mitmproxy alt"        "$OWNER" ;;
      18080) printf "    %-7s %-30s %s\n" ":18080" "mitmproxy MITM bridge" "$OWNER" ;;
      18095) printf "    %-7s %-30s %s\n" ":18095" "PAC server"           "$OWNER" ;;
      1080)  printf "    %-7s %-30s %s\n" ":1080"  "SOCKS5"               "$OWNER" ;;
      9199)  printf "    %-7s %-30s %s\n" ":9199"  "Prometheus metrics"   "$OWNER" ;;
    esac
  fi
done

# ── 6. System proxy ─────────────────────────────────────────────────────
section "6. System proxy"
SCUTIL=$(scutil --proxy 2>/dev/null)
echo "$SCUTIL" | grep -E 'HTTP(S)?Enable|HTTP(S)?Port|HTTP(S)?Proxy|ProxyAutoConfigEnable|ProxyAutoConfigURLString' | sed "s/^/  ${DIM}/" | sed "s/$/${RESET}/"
echo

HTTP_HOST=$(echo "$SCUTIL" | awk '/HTTPProxy/{print $3}')
HTTP_PORT=$(echo "$SCUTIL" | awk '/HTTPPort/{print $3}')
HTTP_EN=$(echo "$SCUTIL" | awk '/HTTPEnable/{print $3}')

if [[ "$HTTP_EN" != "1" ]]; then
  warn "System HTTP proxy is OFF"
  note "If Proxymate's UI says On, the toggle didn't reach the system."
elif [[ -n "$LISTEN_PORT" && "$HTTP_PORT" == "$LISTEN_PORT" && "$HTTP_HOST" == "127.0.0.1" ]]; then
  ok "System proxy points at Proxymate listener (:$LISTEN_PORT)"
elif [[ "$HTTP_HOST" == "127.0.0.1" && "$HTTP_PORT" == "3128" ]]; then
  fail "System proxy points at :3128 (Squid) DIRECTLY, not at Proxymate"
  note "Browser traffic bypasses Proxymate. NWPathMonitor hijack — fixed in 0.9.51"
elif [[ "$HTTP_HOST" == "127.0.0.1" ]]; then
  warn "System proxy on loopback :$HTTP_PORT but listener on :$LISTEN_PORT"
else
  warn "System proxy is $HTTP_HOST:$HTTP_PORT (not loopback)"
fi

echo
printf "  ${DIM}Per-service:${RESET}\n"
networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*' | while IFS= read -r svc; do
  HTTP_INFO=$(networksetup -getwebproxy "$svc" 2>/dev/null | awk '
    /Server:/{server=$2}
    /Port:/{port=$2}
    /Enabled:/{en=$2}
    END{printf "%s %s:%s", en, server, port}')
  printf "    %-20s %s\n" "$svc" "$HTTP_INFO"
done

# ── 7. Sidecar processes ────────────────────────────────────────────────
section "7. Sidecar processes"
# Use -x for exact COMM match to avoid catching shells whose argv contains
# the strings "squid" or "mitmdump" (e.g. the shell running this script).
SIDECAR_PIDS=$(pgrep -x mitmdump 2>/dev/null; pgrep -x squid 2>/dev/null)
if [[ -z "$SIDECAR_PIDS" ]]; then
  skip "No mitmdump or squid processes running"
else
  printf "  ${DIM}%-6s %-12s %-10s %-15s %s${RESET}\n" "PID" "PARENT" "RSS" "ETIME" "NAME"
  echo "$SIDECAR_PIDS" | while IFS= read -r SCPID; do
    [[ -z "$SCPID" ]] && continue
    PPID_=$(ps -o ppid= -p "$SCPID" 2>/dev/null | tr -d ' ')
    PARENT_COMM=$(ps -o comm= -p "$PPID_" 2>/dev/null | sed 's|.*/||')
    RSS=$(ps -o rss= -p "$SCPID" 2>/dev/null | tr -d ' ')
    ETIME=$(ps -o etime= -p "$SCPID" 2>/dev/null | tr -d ' ')
    NAME=$(ps -o comm= -p "$SCPID" 2>/dev/null | sed 's|.*/||')
    printf "  %-6s %-12s %-10s %-15s %s\n" "$SCPID" "${PARENT_COMM:-?}" "${RSS:-?}K" "${ETIME:-?}" "$NAME"
    case "$PARENT_COMM" in
      proxymate|launchd|init) ;;
      *) warn "  PID $SCPID has unexpected parent: $PARENT_COMM" ;;
    esac
  done
fi

# ── 8. Root CA on disk ──────────────────────────────────────────────────
section "8. Root CA on disk"
if [[ -f "$CA_KEY" ]]; then
  PERMS=$(stat -f "%Sp" "$CA_KEY")
  SIZE=$(stat -f "%z" "$CA_KEY")
  HEAD=$(head -1 "$CA_KEY" 2>/dev/null)
  printf "  ${DIM}ca.key:${RESET}  %s, %sB\n" "$PERMS" "$SIZE"
  if [[ "$PERMS" == "-rw-------" ]]; then ok "ca.key permissions correct (0600)"
  else                                     warn "ca.key permissions unexpected: $PERMS"
  fi
  if [[ "$HEAD" == *"ENCRYPTED"* ]]; then
    ok "ca.key AES-encrypted at rest"
  else
    warn "ca.key plaintext (migration runs at first MITM signing)"
  fi
else
  skip "ca.key not present (no MITM CA generated)"
fi

if [[ -f "$CA_PEM" ]]; then
  EXP=$(openssl x509 -enddate -noout -in "$CA_PEM" 2>/dev/null | cut -d= -f2)
  if [[ -n "$EXP" ]]; then
    EXP_EPOCH=$(date -j -f "%b %d %T %Y %Z" "$EXP" "+%s" 2>/dev/null)
    NOW=$(date "+%s")
    if [[ -n "$EXP_EPOCH" ]]; then
      DAYS=$(( (EXP_EPOCH - NOW) / 86400 ))
      if [[ $DAYS -lt 0 ]];   then fail "CA expired $((0-DAYS)) days ago"
      elif [[ $DAYS -lt 30 ]]; then warn "CA expires in $DAYS days"
      else                          ok "CA valid (expires in $DAYS days)"
      fi
    fi
  fi
else
  skip "ca.pem not present"
fi

# ── 9. Root CA in keychain ──────────────────────────────────────────────
section "9. Root CA in keychain"
LOGIN_HIT=$(security find-certificate -c "Proxymate Root CA" -Z ~/Library/Keychains/login.keychain-db 2>/dev/null | grep -c "SHA-1 hash")
SYSTEM_HIT=$(security find-certificate -c "Proxymate Root CA" -Z /Library/Keychains/System.keychain 2>/dev/null | grep -c "SHA-1 hash")
printf "  ${DIM}login keychain:${RESET}  %s entries\n" "$LOGIN_HIT"
printf "  ${DIM}system keychain:${RESET} %s entries\n" "$SYSTEM_HIT"
if [[ $SYSTEM_HIT -gt 0 ]]; then ok "CA in system keychain (system-wide trust)"
elif [[ $LOGIN_HIT -gt 0 ]]; then warn "CA only in login keychain (limited trust scope)"
else                              skip "CA not in any keychain"
fi
if [[ -f "$CA_PEM" ]]; then
  TRUST=$(security verify-cert -c "$CA_PEM" 2>&1)
  if echo "$TRUST" | grep -q "successful"; then ok "security verify-cert: trusted"
  else                                          warn "verify-cert: $TRUST"
  fi
fi

# ── 10. Keychain secrets (presence) ─────────────────────────────────────
section "10. Keychain secrets"
for acct in ca-key-passphrase-v1 leaf-p12-passphrase-v1; do
  if security find-generic-password -s "$KEYCHAIN_SVC" -a "$acct" >/dev/null 2>&1; then
    ok "$acct present"
  else
    skip "$acct not yet generated"
  fi
done

# ── 11. UserDefaults snapshot ───────────────────────────────────────────
section "11. UserDefaults"
# Real keys carry a version suffix (.v1 / .v2). The bundle id resolves to a
# misleading container path on macOS 26 so we hit the prefs file by full
# path instead.
if [[ ! -f "${PREFS_PATH}.plist" ]]; then
  warn "Prefs file not found at ${PREFS_PATH}.plist"
else
  SIZE=$(stat -f "%z" "${PREFS_PATH}.plist")
  printf "  ${DIM}File:${RESET} %s (%s bytes)\n\n" "${PREFS_PATH}.plist" "$SIZE"
  for key in proxies pools overrides rules selected privacy cache mitm pac socks5 \
             ai aiagent allowlist blacklists cloudsync webhook metrics dns \
             beaconing c2 loopbreaker; do
    # try both v1 and v2 versioned keys
    for v in v1 v2; do
      val=$(defaults read "$PREFS_PATH" "proxymate.$key.$v" 2>/dev/null)
      if [[ -n "$val" ]]; then
        size=$(echo "$val" | wc -c | tr -d ' ')
        printf "    ${DIM}proxymate.%s.%s${RESET}  %s bytes\n" "$key" "$v" "$size"
        break
      fi
    done
  done
  echo
  WAS_ENABLED=$(defaults read "$PREFS_PATH" "proxymate.wasEnabled" 2>/dev/null)
  ONBOARDED=$(defaults read "$PREFS_PATH" "proxymate.onboarded" 2>/dev/null)
  printf "  ${DIM}wasEnabled:${RESET} %s\n" "${WAS_ENABLED:-<not set>}"
  printf "  ${DIM}onboarded:${RESET}  %s\n" "${ONBOARDED:-<not set>}"
fi

# ── 12. Persistent log ──────────────────────────────────────────────────
section "12. Persistent log"
if [[ -f "$PROXYMATE_LOG" ]]; then
  TOTAL=$(wc -l < "$PROXYMATE_LOG" | tr -d ' ')
  INFO_C=$(grep -c '"info"'  "$PROXYMATE_LOG" 2>/dev/null)
  WARN_C=$(grep -c '"warn"'  "$PROXYMATE_LOG" 2>/dev/null)
  ERR_C=$(grep -c '"error"' "$PROXYMATE_LOG" 2>/dev/null)
  printf "  ${DIM}Total entries:${RESET} %s · ${BLUE}info %s${RESET} / ${YELLOW}warn %s${RESET} / ${RED}error %s${RESET}\n" \
      "$TOTAL" "$INFO_C" "$WARN_C" "$ERR_C"
  echo
  printf "  ${DIM}Last 30 entries:${RESET}\n"
  tail -n 30 "$PROXYMATE_LOG" 2>/dev/null | python3 -c "
import sys, json, os
green='\033[32m' if sys.stdout.isatty() else ''
yellow='\033[33m' if sys.stdout.isatty() else ''
red='\033[31m' if sys.stdout.isatty() else ''
gray='\033[90m' if sys.stdout.isatty() else ''
reset='\033[0m' if sys.stdout.isatty() else ''
for raw in sys.stdin:
    try:
        j = json.loads(raw)
        ts = j.get('timestamp', '')[11:19]
        lvl = j.get('level', '?')
        msg = j.get('message', '')[:120]
        c = {'info':green,'warn':yellow,'error':red}.get(lvl, gray)
        print(f'    {gray}{ts}{reset} {c}{lvl:5}{reset}  {msg}')
    except Exception:
        pass
" 2>/dev/null
  RECENT_FAILS=$(tail -n 200 "$PROXYMATE_LOG" 2>/dev/null | grep -c '"error"')
  [[ $RECENT_FAILS -gt 0 ]] && warn "$RECENT_FAILS error-level entries in last 200 lines"
else
  skip "No persistent log at $PROXYMATE_LOG"
fi

ROT_COUNT=$(ls -1 "$PROXYMATE_LOG_DIR"/proxymate-*.log 2>/dev/null | wc -l | tr -d ' ')
[[ $ROT_COUNT -gt 0 ]] && note "Rotated logs: $ROT_COUNT (kept policy: 5)"

# ── 13. Live forward test ───────────────────────────────────────────────
section "13. Live forward test"
if [[ -n "$LISTEN_PORT" ]]; then
  printf "  ${DIM}Probing 127.0.0.1:%s${RESET}\n" "$LISTEN_PORT"
  echo
  RES=$(curl -sS -o /dev/null -w "code=%{http_code} time=%{time_total}s size=%{size_download}" \
    -x "http://127.0.0.1:$LISTEN_PORT" --max-time 10 http://example.com/ 2>&1)
  printf "  ${DIM}HTTP plain (example.com):${RESET}    %s\n" "$RES"
  if echo "$RES" | grep -q "code=200"; then ok "HTTP forward works"
  else                                       fail "HTTP forward failed"
  fi
  RES=$(curl -sS -o /dev/null -w "code=%{http_code} time=%{time_total}s" \
    -x "http://127.0.0.1:$LISTEN_PORT" --max-time 10 https://example.com/ 2>&1)
  printf "  ${DIM}HTTPS CONNECT (example.com):${RESET} %s\n" "$RES"
  if echo "$RES" | grep -q "code=200"; then ok "HTTPS CONNECT works"
  else                                       fail "HTTPS CONNECT failed"
  fi
  RES=$(curl -sS -X POST -H "Content-Type: application/json" \
    -d '{"diagnose":"echo-test"}' -x "http://127.0.0.1:$LISTEN_PORT" --max-time 10 \
    http://httpbin.org/post 2>/dev/null)
  if echo "$RES" | grep -q '"diagnose"'; then ok "POST body forwarded intact"
  else                                         warn "POST body echo not present"
  fi
else
  skip "(no listener port)"
fi

# ── 14. DNS resolver health ─────────────────────────────────────────────
section "14. DNS resolver health"
DOH_ENABLED=$(defaults read "$PREFS_PATH" "proxymate.dns.v1" 2>/dev/null | grep -c '"enabled" = 1')
if [[ $DOH_ENABLED -gt 0 ]]; then
  RESULT=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "accept: application/dns-json" \
    "https://1.1.1.1/dns-query?name=example.com&type=A" 2>&1)
  if [[ "$RESULT" == "200" ]]; then ok "DoH endpoint reachable (Cloudflare)"
  else                              warn "DoH unreachable (HTTP $RESULT)"
  fi
else
  skip "DoH not enabled"
fi

# ── 15. Active network interfaces ───────────────────────────────────────
section "15. Network interfaces"
networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*' | head -10 | while IFS= read -r svc; do
  IFACE=$(networksetup -listallhardwareports 2>/dev/null | awk -v svc="$svc" '
    $1=="Hardware" && $2=="Port:" {p=substr($0,16)}
    $1=="Device:" {d=$2}
    p==svc {print d; exit}')
  IP=""
  [[ -n "$IFACE" ]] && IP=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}')
  printf "  %-22s %-10s %s\n" "$svc" "${IFACE:-?}" "${IP:-no-IP}"
done

# ── 16. Recent crash reports ────────────────────────────────────────────
section "16. Crash reports"
CRASH_DIR="$HOME/Library/Logs/DiagnosticReports"
RECENT=$(find "$CRASH_DIR" -name "proxymate*" -mtime -7 2>/dev/null)
if [[ -z "$RECENT" ]]; then
  ok "No proxymate crashes in last 7 days"
else
  COUNT=$(echo "$RECENT" | wc -l | tr -d ' ')
  fail "$COUNT crash report(s) in last 7 days"
  echo "$RECENT" | sed "s/^/    ${DIM}/" | sed "s/$/${RESET}/"
fi

# ── 17. OSLog errors (last 1h) ──────────────────────────────────────────
section "17. OSLog errors (last 1h)"
LOG_OUT=$(/usr/bin/log show --predicate 'process == "proxymate"' --last 1h 2>&1 | grep -E "Error|error" | grep -v EOF | head -10)
if [[ -z "$LOG_OUT" ]]; then
  ok "No errors logged by proxymate to OSLog"
else
  COUNT=$(echo "$LOG_OUT" | wc -l | tr -d ' ')
  warn "$COUNT error-level OSLog entries"
  # Detect the SO_ERROR Connection refused signature (the 0.9.50 mitmdump
  # race that the waitForLocalPort fix in 0.9.51 should have killed)
  if echo "$LOG_OUT" | grep -q "Connection refused"; then
    note "Detected 'Connection refused' — usually historic if you're now on 0.9.51+"
  fi
fi

# ── 18. Bundled sidecar binaries ────────────────────────────────────────
section "18. Bundled sidecar binaries"
if [[ -n "$APP_PATH" ]]; then
  RES_BIN="$APP_PATH/Contents/Resources/bin"
  if [[ -d "$RES_BIN" ]]; then
    for sub in "mitmproxy.app/Contents/MacOS/mitmdump" "squid"; do
      P="$RES_BIN/$sub"
      if [[ -x "$P" ]]; then
        SIZE=$(stat -f "%z" "$P")
        BASE=$(basename "$sub")
        printf "  %-12s %s bytes\n" "$BASE" "$SIZE"
        if codesign --verify "$P" 2>/dev/null; then
          ok "$BASE signature valid"
        elif [[ "$IS_DEBUG" == "1" ]]; then
          skip "$BASE signature mismatch (expected on Debug — release rebuilds re-sign)"
        else
          warn "$BASE signature issue (release build should be re-signed)"
        fi
      else
        warn "Missing or non-exec: $sub"
      fi
    done
  else
    warn "Resources/bin not present in app bundle"
  fi
fi

# ── 19. Memory pressure history ─────────────────────────────────────────
section "19. Memory pressure events"
if [[ -f "$PROXYMATE_LOG" ]]; then
  MP=$(grep -F "Memory pressure" "$PROXYMATE_LOG" 2>/dev/null | tail -5)
  if [[ -z "$MP" ]]; then
    ok "No memory pressure events in app log"
  else
    echo "$MP" | python3 -c "
import sys, json, os
gray='\033[90m' if sys.stdout.isatty() else ''
reset='\033[0m' if sys.stdout.isatty() else ''
for raw in sys.stdin:
    try:
        j = json.loads(raw)
        print(f\"    {gray}{j.get('timestamp','')}{reset}  {j.get('message','')}\")
    except Exception: pass
" 2>/dev/null
    note "Frequent events (multiple/hour) suggest device-wide memory pressure."
  fi
else
  skip "(no log)"
fi

# ── Verdict summary ─────────────────────────────────────────────────────
section "Verdict summary"
printf "  ${GREEN}✓ %d OK${RESET}    ${YELLOW}! %d WARN${RESET}    ${RED}✗ %d FAIL${RESET}    ${GRAY}– %d SKIP${RESET}\n\n" \
    "$total_ok" "$total_warn" "$total_fail" "$total_skip"

if [[ $total_fail -gt 0 ]]; then
  printf "  Overall: ${RED}${BOLD}FAIL${RESET}  — %d hard failure(s); search for ${RED}✗${RESET} markers above.\n" "$total_fail"
  EXIT=2
elif [[ $total_warn -gt 0 ]]; then
  printf "  Overall: ${YELLOW}${BOLD}WARN${RESET}  — %d warning(s); review ${YELLOW}!${RESET} markers above.\n" "$total_warn"
  EXIT=1
else
  printf "  Overall: ${GREEN}${BOLD}OK${RESET}    — all checks passed.\n"
  EXIT=0
fi

echo
printf "${DIM}Diagnose complete. If reporting an issue, paste this entire output.${RESET}\n"
exit $EXIT
