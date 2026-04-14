#!/bin/bash
# diagnose.sh — Draconian, single-pass health snapshot of a Proxymate install.
#
# Run when something looks off, paste the output to a maintainer (or attach
# to a GitHub issue). The script is intentionally exhaustive: every common
# misconfiguration class has its own section, every section emits a verdict
# tag (OK / WARN / FAIL / SKIP) so a reader can grep for FAIL and find every
# real problem in one read.
#
# Output contains: macOS version, app version, listener ports, system proxy
# state, signed-code verdict, entitlements, CA encryption state, keychain
# presence (NOT contents), recent log lines, live forward test, sidecar
# process tree, recent crash reports.
#
# Output does NOT contain: request bodies, cookies, response headers, the
# CA private key, keychain passphrases, or any URL beyond what's already in
# your own configured rule list.

set +e
LC_ALL=C
SCRIPT_VERSION=2

PROXYMATE_LOG_DIR="$HOME/Library/Application Support/Proxymate/logs"
PROXYMATE_LOG="$PROXYMATE_LOG_DIR/proxymate.log"
CA_DIR="$HOME/Library/Application Support/Proxymate/ca"
CA_KEY="$CA_DIR/ca.key"
CA_PEM="$CA_DIR/ca.pem"
DEFAULTS_DOMAIN="fabriziosalmi.proxymate"
KEYCHAIN_SVC="fabriziosalmi.proxymate.tls"

# ── Verdict counters (for the summary at the end) ───────────────────────
total_ok=0
total_warn=0
total_fail=0
total_skip=0

# Current section's per-line verdict markers go through these.
ok()   { printf "  [OK]   %s\n" "$1"; total_ok=$((total_ok+1)); }
warn() { printf "  [WARN] %s\n" "$1"; total_warn=$((total_warn+1)); }
fail() { printf "  [FAIL] %s\n" "$1"; total_fail=$((total_fail+1)); }
skip() { printf "  [SKIP] %s\n" "$1"; total_skip=$((total_skip+1)); }
note() { printf "         %s\n" "$1"; }

section() { printf "\n========== %s ==========\n" "$1"; }
hr() { printf -- "  ----------\n"; }

# ── 1. Environment fingerprint ──────────────────────────────────────────
section "1. Environment"
sw_vers
echo "Architecture: $(uname -m)"
echo "Kernel:       $(uname -r)"
echo "Date (UTC):   $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Uptime:       $(uptime | awk -F'load' '{print $1}' | sed 's/^ *//;s/, *$//')"
echo "Hostname:     $(hostname -s)"
echo "Diagnose v$SCRIPT_VERSION"
case "$(sw_vers -productVersion | cut -d. -f1)" in
  26|27|28) ok "macOS version supported" ;;
  *)        fail "macOS version unsupported (Proxymate requires 26+)" ;;
esac
[[ "$(uname -m)" == "arm64" ]] && ok "Apple Silicon (arm64)" || fail "Architecture not arm64 — Proxymate is Apple Silicon only"

# ── 2. Process + build identity ─────────────────────────────────────────
section "2. Process"
PID=$(pgrep -x proxymate | head -1)
if [[ -z "$PID" ]]; then
  fail "Proxymate process not running"
  PID=""
else
  ok "Process running (PID $PID)"
  ps -o pid,etime,rss,vsz,nlwp,user,comm -p "$PID" 2>/dev/null
  BIN=$(ps -o comm= -p "$PID" 2>/dev/null)
  PLIST="$(dirname "$BIN")/../Info.plist"
  if [[ -f "$PLIST" ]]; then
    SHORT_VER=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$PLIST" 2>/dev/null)
    BUILD_VER=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$PLIST" 2>/dev/null)
    echo "  Binary:      $BIN"
    stat -f "  Mtime:       %Sm" -t "%Y-%m-%d %H:%M:%S" "$BIN"
    echo "  Version:     $SHORT_VER (build $BUILD_VER)"
    case "$BIN" in
      */DerivedData/*) note "Source: Xcode Debug build (DerivedData)" ;;
      /Applications/*) note "Source: /Applications (likely brew or DMG install)" ;;
      *)               note "Source: $BIN" ;;
    esac
  else
    warn "Info.plist not found at $PLIST"
  fi

  # File descriptor count (catches fd leak issues over long sessions)
  FD_COUNT=$(lsof -nP -p "$PID" 2>/dev/null | wc -l | tr -d ' ')
  echo "  Open file descriptors: $FD_COUNT"
  if [[ "$FD_COUNT" -lt 50 ]];   then ok "FD count healthy"
  elif [[ "$FD_COUNT" -lt 500 ]]; then ok "FD count normal"
  elif [[ "$FD_COUNT" -lt 2000 ]];then warn "FD count elevated ($FD_COUNT) — possible leak"
  else                                 fail "FD count very high ($FD_COUNT) — likely leak"
  fi
fi

# ── 3. Code signature integrity ─────────────────────────────────────────
section "3. Code signature"
if [[ -n "$BIN" ]]; then
  APP_PATH="$(dirname "$BIN")/../.."
  APP_PATH="$(cd "$APP_PATH" 2>/dev/null && pwd -P)"
  if [[ -d "$APP_PATH" ]]; then
    echo "  App bundle: $APP_PATH"
    echo
    SIGN_INFO=$(codesign -dv --verbose=2 "$APP_PATH" 2>&1)
    echo "$SIGN_INFO" | grep -E "^(Identifier|TeamIdentifier|Authority|Signed Time|Hash type|CDHash)" | sed 's/^/  /'
    echo
    if codesign --verify --strict "$APP_PATH" 2>&1 | grep -q .; then
      warn "codesign --verify --strict reported issues:"
      codesign --verify --strict "$APP_PATH" 2>&1 | sed 's/^/    /'
    else
      ok "codesign --verify --strict passed"
    fi
    SPCTL_OUT=$(spctl -a -vv "$APP_PATH" 2>&1)
    echo "$SPCTL_OUT" | sed 's/^/  spctl: /'
    if echo "$SPCTL_OUT" | grep -q "accepted"; then ok "Gatekeeper would accept"
    else                                              warn "Gatekeeper assessment failed"
    fi
    if stapler validate "$APP_PATH" 2>&1 | grep -q "worked"; then
      ok "Notarization ticket stapled"
    else
      note "stapler: $(stapler validate "$APP_PATH" 2>&1 | tail -1)"
    fi
  fi
else
  skip "(no binary path resolved)"
fi

# ── 4. Entitlements ─────────────────────────────────────────────────────
section "4. Entitlements"
if [[ -n "$BIN" && -f "$BIN" ]]; then
  ENT_DUMP=$(codesign -d --entitlements - "$BIN" 2>/dev/null | tail +2)
  if [[ -z "$ENT_DUMP" ]]; then
    fail "No entitlements found on signed binary"
  else
    REQUIRED_KEYS=(
      "com.apple.security.network.server"
      "com.apple.security.network.client"
      "com.apple.security.cs.allow-unsigned-executable-memory"
      "com.apple.security.cs.disable-library-validation"
    )
    for key in "${REQUIRED_KEYS[@]}"; do
      if echo "$ENT_DUMP" | grep -q "$key"; then ok "$key"
      else                                       fail "Missing entitlement: $key"
      fi
    done
  fi
else
  skip "(no binary)"
fi

# ── 5. Listeners & port conflicts ───────────────────────────────────────
section "5. Listeners + sidecars"
if [[ -n "$PID" ]]; then
  PROXY_LISTEN=$(lsof -nP -p "$PID" 2>/dev/null | awk '/LISTEN/ {print}')
  if [[ -z "$PROXY_LISTEN" ]]; then
    fail "Proxymate process running but no LISTEN socket — listener not bound"
  else
    echo "$PROXY_LISTEN" | sed 's/^/  /'
    LISTEN_PORT=$(echo "$PROXY_LISTEN" | head -1 | awk '{print $9}' | sed 's/.*://' | head -1)
    [[ -n "$LISTEN_PORT" ]] && ok "Listener bound on :$LISTEN_PORT"
  fi
else
  skip "(no proxymate PID)"
fi

echo
echo "  Sidecar ports:"
for p in 3128 8080 18080 18095 1080 9199; do
  ROW=$(lsof -nP -iTCP:$p -sTCP:LISTEN 2>/dev/null | grep -v COMMAND)
  if [[ -n "$ROW" ]]; then
    OWNER=$(echo "$ROW" | awk '{print $1, $2}')
    case $p in
      3128)  printf "    :3128  squid (expected)        — %s\n" "$OWNER" ;;
      8080)  printf "    :8080  mitmproxy (alt)         — %s\n" "$OWNER" ;;
      18080) printf "    :18080 mitmproxy MITM bridge   — %s\n" "$OWNER" ;;
      18095) printf "    :18095 PAC server (default)    — %s\n" "$OWNER" ;;
      1080)  printf "    :1080  SOCKS5 (default)        — %s\n" "$OWNER" ;;
      9199)  printf "    :9199  Prometheus metrics      — %s\n" "$OWNER" ;;
    esac
  fi
done

# ── 6. System proxy state ───────────────────────────────────────────────
section "6. System proxy"
SCUTIL=$(scutil --proxy 2>/dev/null)
echo "$SCUTIL" | grep -E 'HTTP(S)?Enable|HTTP(S)?Port|HTTP(S)?Proxy|ProxyAutoConfigEnable|ProxyAutoConfigURLString' | sed 's/^/  /'

# Sanity check: does scutil's HTTPProxy point at our listener?
HTTP_HOST=$(echo "$SCUTIL" | awk '/HTTPProxy/{print $3}')
HTTP_PORT=$(echo "$SCUTIL" | awk '/HTTPPort/{print $3}')
HTTP_EN=$(echo "$SCUTIL" | awk '/HTTPEnable/{print $3}')

echo
if [[ "$HTTP_EN" != "1" ]]; then
  warn "System HTTP proxy is OFF (HTTPEnable != 1)"
  note "If Proxymate's UI says On, the toggle didn't reach the system."
elif [[ -n "$LISTEN_PORT" && "$HTTP_PORT" == "$LISTEN_PORT" && "$HTTP_HOST" == "127.0.0.1" ]]; then
  ok "System proxy correctly points at Proxymate listener (:$LISTEN_PORT)"
elif [[ "$HTTP_HOST" == "127.0.0.1" && "$HTTP_PORT" == "3128" ]]; then
  fail "System proxy points at :3128 (Squid) DIRECTLY, not at Proxymate"
  note "Browser traffic bypasses Proxymate. This is the NWPathMonitor hijack"
  note "bug fixed in 0.9.51 — upgrade if you're on an older release."
elif [[ "$HTTP_HOST" == "127.0.0.1" ]]; then
  warn "System proxy on loopback :$HTTP_PORT but Proxymate listens on :$LISTEN_PORT"
  note "Some other process owns :$HTTP_PORT — traffic bypasses Proxymate."
else
  warn "System proxy points at $HTTP_HOST:$HTTP_PORT, not loopback"
fi

echo
echo "  Per-service:"
networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*' | while IFS= read -r svc; do
  printf "    [%s]\n" "$svc"
  networksetup -getwebproxy "$svc" 2>/dev/null | sed 's/^/      HTTP  /'
  networksetup -getsecurewebproxy "$svc" 2>/dev/null | sed 's/^/      HTTPS /'
done

# ── 7. Sidecar process tree ─────────────────────────────────────────────
section "7. Sidecar processes"
SIDECAR_PROCS=$(pgrep -lfd, "mitmdump|squid" 2>/dev/null | tr ',' '\n')
if [[ -z "$SIDECAR_PROCS" ]]; then
  note "No mitmdump or squid processes detected"
else
  echo "$SIDECAR_PROCS" | while IFS= read -r line; do
    SCPID=$(echo "$line" | awk '{print $1}')
    [[ -z "$SCPID" ]] && continue
    PPID_=$(ps -o ppid= -p "$SCPID" 2>/dev/null | tr -d ' ')
    PARENT_COMM=$(ps -o comm= -p "$PPID_" 2>/dev/null | sed 's|.*/||')
    RSS=$(ps -o rss= -p "$SCPID" 2>/dev/null | tr -d ' ')
    ETIME=$(ps -o etime= -p "$SCPID" 2>/dev/null | tr -d ' ')
    NAME=$(ps -o comm= -p "$SCPID" 2>/dev/null | sed 's|.*/||')
    printf "  PID %-6s  parent=%s  rss=%sK  etime=%s  %s\n" \
        "$SCPID" "${PARENT_COMM:-?}" "${RSS:-?}" "${ETIME:-?}" "$NAME"
    if [[ "$PARENT_COMM" != "proxymate" ]] && [[ "$PARENT_COMM" != "launchd" ]]; then
      warn "  └─ unexpected parent: $PARENT_COMM"
    fi
  done
fi

# ── 8. Root CA on disk ──────────────────────────────────────────────────
section "8. Root CA on disk"
if [[ -f "$CA_KEY" ]]; then
  PERMS=$(stat -f "%Sp" "$CA_KEY")
  SIZE=$(stat -f "%z" "$CA_KEY")
  HEAD=$(head -1 "$CA_KEY" 2>/dev/null)
  echo "  ca.key:     $PERMS, ${SIZE}B"
  echo "    First line: $HEAD"
  if [[ "$PERMS" == "-rw-------" ]]; then ok "ca.key permissions correct (0600)"
  else                                     warn "ca.key permissions unexpected: $PERMS"
  fi
  if [[ "$HEAD" == *"ENCRYPTED"* ]]; then
    ok "ca.key is AES-encrypted at rest"
  else
    warn "ca.key is plaintext (-----BEGIN PRIVATE KEY-----)"
    note "Migration to encrypted PEM hasn't run yet. Trigger by enabling MITM"
    note "and signing one leaf — ensureCAKeyEncrypted() runs at first signing."
  fi
else
  skip "ca.key not present (no MITM CA generated)"
fi

if [[ -f "$CA_PEM" ]]; then
  echo "  ca.pem:     present"
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
echo "  login keychain entries:  $LOGIN_HIT"
echo "  system keychain entries: $SYSTEM_HIT"
if [[ $SYSTEM_HIT -gt 0 ]]; then ok "CA in system keychain (would apply system-wide trust)"
elif [[ $LOGIN_HIT -gt 0 ]]; then warn "CA in login keychain only — trust may not apply to all apps"
else                              skip "CA not in any keychain"
fi

if [[ -f "$CA_PEM" ]]; then
  TRUST=$(security verify-cert -c "$CA_PEM" 2>&1)
  if echo "$TRUST" | grep -q "successful"; then ok "security verify-cert: trusted"
  else                                          warn "security verify-cert reports: $TRUST"
  fi
fi

# ── 10. Keychain-stored secrets (presence only) ─────────────────────────
section "10. Keychain secrets (presence)"
for acct in ca-key-passphrase-v1 leaf-p12-passphrase-v1; do
  if security find-generic-password -s "$KEYCHAIN_SVC" -a "$acct" >/dev/null 2>&1; then
    ok "$acct present"
  else
    skip "$acct not present (CA never generated, or older build)"
  fi
done

# ── 11. UserDefaults snapshot ───────────────────────────────────────────
section "11. Settings sizes"
KEYS=(proxies pools poolOverrides rules allowlist privacy cacheSettings
      diskCacheSettings mitmSettings aiSettings socks5Settings pacSettings
      blacklistSources webhookSettings metricsSettings dnsSettings
      cloudSyncSettings exfiltrationPacks beaconingSettings c2Settings
      loopBreakerSettings)
for key in "${KEYS[@]}"; do
  size=$(defaults read "$DEFAULTS_DOMAIN" "proxymate.$key" 2>/dev/null | wc -c | tr -d ' ')
  printf "  %-22s  %6s bytes\n" "$key" "$size"
done
echo
SELECTED=$(defaults read "$DEFAULTS_DOMAIN" "proxymate.selectedProxyID" 2>/dev/null)
WAS_ENABLED=$(defaults read "$DEFAULTS_DOMAIN" "proxymate.wasEnabled" 2>/dev/null)
ONBOARDED=$(defaults read "$DEFAULTS_DOMAIN" "proxymate.onboarded" 2>/dev/null)
echo "  selectedProxyID: ${SELECTED:-<not set>}"
echo "  wasEnabled:      ${WAS_ENABLED:-<not set>}"
echo "  onboarded:       ${ONBOARDED:-<not set>}"
[[ -z "$SELECTED" ]] && warn "No selected proxy — enable() will warn 'No proxy selected'"

# ── 12. Persistent log ──────────────────────────────────────────────────
section "12. Recent persistent log"
if [[ -f "$PROXYMATE_LOG" ]]; then
  TOTAL=$(wc -l < "$PROXYMATE_LOG" | tr -d ' ')
  INFO_C=$(grep -c '"info"'  "$PROXYMATE_LOG" 2>/dev/null)
  WARN_C=$(grep -c '"warn"'  "$PROXYMATE_LOG" 2>/dev/null)
  ERR_C=$(grep -c '"error"' "$PROXYMATE_LOG" 2>/dev/null)
  echo "  Total entries: $TOTAL  (info $INFO_C / warn $WARN_C / error $ERR_C)"
  echo "  Last 50 entries:"
  tail -n 50 "$PROXYMATE_LOG" 2>/dev/null | python3 -c "
import sys, json
for raw in sys.stdin:
    try:
        j = json.loads(raw)
        ts = (j.get('timestamp', '')[11:19])
        lvl = j.get('level', '?')[:5]
        msg = j.get('message', '')[:130]
        print(f'    {ts} {lvl:5}  {msg}')
    except Exception:
        pass
" 2>/dev/null
  RECENT_FAILS=$(tail -n 200 "$PROXYMATE_LOG" 2>/dev/null | grep -c '"error"')
  [[ $RECENT_FAILS -gt 0 ]] && warn "$RECENT_FAILS error-level entries in last 200 lines"
else
  skip "No persistent log at $PROXYMATE_LOG"
fi

# Rotated log files
ROT_COUNT=$(ls -1 "$PROXYMATE_LOG_DIR"/proxymate-*.log 2>/dev/null | wc -l | tr -d ' ')
[[ $ROT_COUNT -gt 0 ]] && note "Rotated logs in directory: $ROT_COUNT (kept policy: 5)"

# ── 13. Live forward test ───────────────────────────────────────────────
section "13. Live forward test"
if [[ -n "$LISTEN_PORT" ]]; then
  echo "  Probing listener on 127.0.0.1:$LISTEN_PORT"
  hr
  # HTTP plain
  RESULT=$(curl -sS -o /dev/null -w "code=%{http_code} time=%{time_total}s size=%{size_download}" \
    -x "http://127.0.0.1:$LISTEN_PORT" --max-time 10 http://example.com/ 2>&1)
  echo "  HTTP plain (example.com):  $RESULT"
  if echo "$RESULT" | grep -q "code=200"; then ok "HTTP forward works"
  else                                          fail "HTTP forward failed"
  fi
  # HTTPS CONNECT
  RESULT=$(curl -sS -o /dev/null -w "code=%{http_code} time=%{time_total}s" \
    -x "http://127.0.0.1:$LISTEN_PORT" --max-time 10 https://example.com/ 2>&1)
  echo "  HTTPS CONNECT (example):   $RESULT"
  if echo "$RESULT" | grep -q "code=200"; then ok "HTTPS CONNECT works"
  else                                          fail "HTTPS CONNECT failed"
  fi
  # POST body integrity (catches the leftover-buffer regression we fixed)
  RESULT=$(curl -sS -X POST -H "Content-Type: application/json" \
    -d '{"diagnose":"echo-test"}' -x "http://127.0.0.1:$LISTEN_PORT" --max-time 10 \
    http://httpbin.org/post 2>/dev/null)
  if echo "$RESULT" | grep -q '"diagnose"'; then ok "POST body forwarded intact"
  else                                            warn "POST body echo not present in response"
  fi
else
  skip "(no listener port)"
fi

# ── 14. DNS-over-HTTPS reachability ─────────────────────────────────────
section "14. DNS resolver health"
DOH_ENABLED=$(defaults read "$DEFAULTS_DOMAIN" "proxymate.dnsSettings" 2>/dev/null | grep -c '"enabled" = 1')
if [[ $DOH_ENABLED -gt 0 ]]; then
  RESULT=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 \
    -H "accept: application/dns-json" \
    "https://1.1.1.1/dns-query?name=example.com&type=A" 2>&1)
  if [[ "$RESULT" == "200" ]]; then ok "DoH endpoint reachable (Cloudflare)"
  else                              warn "DoH unreachable (curl returned $RESULT)"
  fi
else
  skip "DoH not enabled"
fi

# ── 15. Network interface state ─────────────────────────────────────────
section "15. Active network interfaces"
networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*' | head -10 | while IFS= read -r svc; do
  IFACE=$(networksetup -listallhardwareports 2>/dev/null | awk -v svc="$svc" '
    $1=="Hardware" && $2=="Port:" {p=substr($0,16)}
    $1=="Device:" {d=$2}
    p==svc {print d; exit}')
  IP=""
  if [[ -n "$IFACE" ]]; then
    IP=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}')
  fi
  printf "  %-25s %-10s %s\n" "$svc" "${IFACE:-?}" "${IP:-no-IP}"
done

# ── 16. Recent crash reports ────────────────────────────────────────────
section "16. Recent crash reports"
CRASH_DIR="$HOME/Library/Logs/DiagnosticReports"
RECENT=$(find "$CRASH_DIR" -name "proxymate*" -mtime -7 2>/dev/null)
if [[ -z "$RECENT" ]]; then
  ok "No proxymate crashes in last 7 days"
else
  COUNT=$(echo "$RECENT" | wc -l | tr -d ' ')
  fail "$COUNT crash report(s) in last 7 days"
  echo "$RECENT" | sed 's/^/    /'
  echo
  echo "  Most recent crash header:"
  echo "$RECENT" | head -1 | xargs -I{} head -20 {} 2>/dev/null | sed 's/^/    /'
fi

# ── 17. Console.app errors (last 1h) ────────────────────────────────────
section "17. System log (last 1h, level=error, predicate=proxymate)"
LOG_OUT=$(/usr/bin/log show --predicate 'process == "proxymate"' --last 1h \
  --info --debug 2>&1 | grep -E "Error|error" | grep -v "EOF" | head -20)
if [[ -z "$LOG_OUT" ]]; then
  ok "No errors logged by proxymate to OSLog in the last hour"
else
  COUNT=$(echo "$LOG_OUT" | wc -l | tr -d ' ')
  warn "$COUNT error-level OSLog entries in last hour:"
  echo "$LOG_OUT" | head -10 | sed 's/^/    /'
fi

# ── 18. Sidecar binary integrity ────────────────────────────────────────
section "18. Bundled sidecar binaries"
if [[ -n "$APP_PATH" ]]; then
  RES_BIN="$APP_PATH/Contents/Resources/bin"
  if [[ -d "$RES_BIN" ]]; then
    for sub in "mitmproxy.app/Contents/MacOS/mitmdump" "squid"; do
      P="$RES_BIN/$sub"
      if [[ -x "$P" ]]; then
        SIZE=$(stat -f "%z" "$P")
        printf "  %-50s %s bytes\n" "$sub" "$SIZE"
        # Codesign verdict on the sidecar binary
        if codesign --verify "$P" 2>/dev/null; then
          ok "  $(basename "$sub") signature valid"
        else
          warn "  $(basename "$sub") signature issue"
        fi
      else
        warn "  Missing or non-exec: $sub"
      fi
    done
  else
    warn "Resources/bin not present in app bundle"
  fi
fi

# ── 19. Memory pressure history ─────────────────────────────────────────
section "19. Memory pressure events (last 5)"
if [[ -f "$PROXYMATE_LOG" ]]; then
  MP=$(grep -F "Memory pressure" "$PROXYMATE_LOG" 2>/dev/null | tail -5)
  if [[ -z "$MP" ]]; then
    ok "No memory pressure events in app log"
  else
    echo "$MP" | python3 -c "
import sys, json
for raw in sys.stdin:
    try:
        j = json.loads(raw)
        print(f\"    {j.get('timestamp','')}  {j.get('message','')}\")
    except Exception: pass
" 2>/dev/null
    note "If frequent (multiple per day), the device is under memory load."
  fi
else
  skip "(no log)"
fi

# ── Verdict summary ─────────────────────────────────────────────────────
section "Verdict summary"
printf "  OK:   %d\n" "$total_ok"
printf "  WARN: %d\n" "$total_warn"
printf "  FAIL: %d\n" "$total_fail"
printf "  SKIP: %d\n" "$total_skip"
echo
if [[ $total_fail -gt 0 ]]; then
  echo "  Overall: ❌  ${total_fail} hard failure(s) — search for [FAIL] tags above."
  EXIT=2
elif [[ $total_warn -gt 0 ]]; then
  echo "  Overall: ⚠️  ${total_warn} warning(s) — review [WARN] tags."
  EXIT=1
else
  echo "  Overall: ✅  All checks passed"
  EXIT=0
fi

echo
echo "Diagnose complete. If reporting an issue, paste this entire output."
exit $EXIT
