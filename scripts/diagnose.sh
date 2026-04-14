#!/bin/bash
# diagnose.sh — Single-pass health snapshot of a running Proxymate install.
# Run it when something looks off and paste the output to a maintainer
# (or to the "Logs" issue template in the repo). Every section is
# self-contained, so partial failures don't break the rest.
#
# Output is plain text designed to be diff-friendly and grep-friendly.
# No PII is captured beyond hostnames you've already configured.

set +e
PROXYMATE_LOG="$HOME/Library/Application Support/Proxymate/logs/proxymate.log"

section() { printf "\n========== %s ==========\n" "$1"; }
hr() { printf -- "----------\n"; }

section "1. Versions"
sw_vers
echo "uname -m: $(uname -m)"
echo "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

section "2. Process"
PID=$(pgrep -x proxymate | head -1)
if [[ -z "$PID" ]]; then
  echo "STATUS: NOT RUNNING — proxymate process not found."
else
  echo "PID: $PID"
  ps -o pid,etime,rss,comm,args -p "$PID" 2>/dev/null
  echo
  BIN=$(ps -o comm= -p "$PID" 2>/dev/null)
  if [[ -n "$BIN" && -f "$BIN" ]]; then
    stat -f "Binary: %N%nMtime:  %Sm" -t "%Y-%m-%d %H:%M:%S" "$BIN"
    if [[ -f "$BIN/../Info.plist" ]] || [[ -f "$(dirname "$BIN")/../Info.plist" ]]; then
      PLIST="$(dirname "$BIN")/../Info.plist"
      VER=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$PLIST" 2>/dev/null)
      BUILD=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$PLIST" 2>/dev/null)
      echo "Version: $VER (build $BUILD)"
    fi
  fi
fi

section "3. Listeners"
if [[ -n "$PID" ]]; then
  lsof -nP -p "$PID" 2>/dev/null | awk '/LISTEN/ {print}'
else
  echo "(skipped — no proxymate PID)"
fi
echo
echo "Sidecars (port 3128 squid, 18080 mitmproxy):"
lsof -nP -iTCP:3128 -sTCP:LISTEN 2>/dev/null | grep -v COMMAND
lsof -nP -iTCP:18080 -sTCP:LISTEN 2>/dev/null | grep -v COMMAND

section "4. System proxy state"
scutil --proxy 2>/dev/null | grep -E 'HTTP(S)?Enable|HTTP(S)?Port|HTTP(S)?Proxy|ProxyAutoConfigEnable|ProxyAutoConfigURLString|ExceptionsList' || echo "(scutil produced no output)"
echo
echo "networksetup per-service:"
networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*' | while IFS= read -r svc; do
  printf "  [%s]\n" "$svc"
  networksetup -getwebproxy "$svc" 2>/dev/null | sed 's/^/    HTTP /'
  networksetup -getsecurewebproxy "$svc" 2>/dev/null | sed 's/^/    HTTPS /'
done

section "5. Root CA state"
echo "On disk:"
CA_KEY="$HOME/Library/Application Support/Proxymate/ca/ca.key"
CA_PEM="$HOME/Library/Application Support/Proxymate/ca/ca.pem"
for f in "$CA_KEY" "$CA_PEM"; do
  if [[ -f "$f" ]]; then
    perms=$(stat -f "%Sp" "$f")
    size=$(stat -f "%z" "$f")
    head1=$(head -1 "$f" 2>/dev/null)
    echo "  $f  ($perms, ${size}B, $head1)"
  else
    echo "  $f  MISSING"
  fi
done
echo
echo "In Keychain:"
security find-certificate -c "Proxymate Root CA" -Z /Library/Keychains/System.keychain 2>/dev/null | grep -E "SHA-1|labl" | head -4
security find-certificate -c "Proxymate Root CA" -Z ~/Library/Keychains/login.keychain-db 2>/dev/null | grep -E "SHA-1|labl" | head -4
echo
echo "Trust verdict:"
if [[ -f "$CA_PEM" ]]; then
  openssl verify -CAfile "$CA_PEM" "$CA_PEM" 2>&1 | head -3
fi

section "6. Last 30 app log entries"
if [[ -f "$PROXYMATE_LOG" ]]; then
  tail -n 30 "$PROXYMATE_LOG" | while IFS= read -r line; do
    # Pretty-print level + message; trim ID + timestamp noise for readability
    echo "$line" | python3 -c "
import sys, json
for raw in sys.stdin:
  try:
    j = json.loads(raw)
    print(f\"  {j.get('timestamp','')[11:19]} {j.get('level','?')[:5]:5}  {j.get('message','')[:120]}\")
  except Exception:
    pass
" 2>/dev/null
  done
else
  echo "(no log at $PROXYMATE_LOG)"
fi

section "7. Live forward test through listener"
if [[ -n "$PID" ]]; then
  PORT=$(lsof -nP -p "$PID" 2>/dev/null | awk '/LISTEN/ {match($0, /:[0-9]+/); print substr($0, RSTART+1, RLENGTH-1); exit}')
  if [[ -n "$PORT" ]]; then
    echo "Probing listener on 127.0.0.1:$PORT"
    echo "  HTTP plain:"
    curl -sS -o /dev/null -w "    code=%{http_code} time=%{time_total}s size=%{size_download}\n" \
      -x "http://127.0.0.1:$PORT" --max-time 10 http://example.com/ 2>&1 || echo "    (failed)"
    echo "  HTTPS CONNECT:"
    curl -sS -o /dev/null -w "    code=%{http_code} time=%{time_total}s\n" \
      -x "http://127.0.0.1:$PORT" --max-time 10 https://example.com/ 2>&1 || echo "    (failed)"
  else
    echo "(no LISTEN port found on PID $PID)"
  fi
else
  echo "(skipped — no proxymate PID)"
fi

section "8. Settings snapshot (counts only — no rule contents)"
DEFAULTS_DOMAIN="fabriziosalmi.proxymate"
for key in proxies pools rules allowlist blacklistSources mitmSettings aiSettings privacy; do
  count=$(defaults read "$DEFAULTS_DOMAIN" "proxymate.$key" 2>/dev/null | wc -c | tr -d ' ')
  printf "  %-20s  %s bytes\n" "$key" "$count"
done
echo "  selectedProxyID:    $(defaults read "$DEFAULTS_DOMAIN" "proxymate.selectedProxyID" 2>/dev/null)"
echo "  wasEnabled:         $(defaults read "$DEFAULTS_DOMAIN" "proxymate.wasEnabled" 2>/dev/null)"
echo "  onboarded:          $(defaults read "$DEFAULTS_DOMAIN" "proxymate.onboarded" 2>/dev/null)"

section "Diagnose complete"
echo "If reporting an issue, paste this whole output (it does not include"
echo "request bodies, cookies, or anything beyond what's in your config)."
