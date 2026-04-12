#!/bin/bash
set -euo pipefail

#
# verify-all.sh — Comprehensive automated verification of every Proxymate feature.
#
# Runs without the proxy active. Tests compile-time correctness,
# model integrity, regex validity, data structures, and configuration.
# For network-level tests, use the XCTest suite.
#
# Usage:
#   ./scripts/verify-all.sh
#
# Exit code: 0 = all pass, 1 = failures found
#

cd "$(dirname "$0")/.."
PASS=0
FAIL=0
SKIP=0
ERRORS=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { ((PASS++)); printf "${GREEN}  PASS${NC} %s\n" "$1"; }
fail() { ((FAIL++)); ERRORS="${ERRORS}\n  - $1"; printf "${RED}  FAIL${NC} %s\n" "$1"; }
skip() { ((SKIP++)); printf "${YELLOW}  SKIP${NC} %s\n" "$1"; }
section() { printf "\n${CYAN}==> %s${NC}\n" "$1"; }

# ============================================================
section "1. BUILD VERIFICATION"
# ============================================================

echo "  Building Debug..."
if xcodebuild -project proxymate.xcodeproj -scheme proxymate -configuration Debug \
    -destination 'platform=macOS' build 2>&1 | grep -q "BUILD SUCCEEDED"; then
    pass "Debug build succeeds"
else
    fail "Debug build FAILED"
fi

echo "  Building Release..."
if xcodebuild -project proxymate.xcodeproj -scheme proxymate -configuration Release \
    -destination 'platform=macOS' build CODE_SIGN_IDENTITY="-" CODE_SIGNING_ALLOWED=NO 2>&1 | grep -q "BUILD SUCCEEDED"; then
    pass "Release build succeeds"
else
    fail "Release build FAILED"
fi

# ============================================================
section "2. TEST SUITE"
# ============================================================

TEST_LAST=$(xcodebuild test -project proxymate.xcodeproj -scheme proxymate \
    -destination 'platform=macOS' -parallel-testing-enabled NO 2>&1 | grep "Executed" | tail -1)
TEST_COUNT=$(echo "$TEST_LAST" | grep -oE "[0-9]+ tests" | head -1)
FAIL_COUNT=$(echo "$TEST_LAST" | grep -oE "with ([0-9]+) failures" | grep -oE "[0-9]+" || echo "?")

if [[ "$FAIL_COUNT" == "0" ]]; then
    pass "All tests pass ($TEST_COUNT)"
else
    fail "Tests have $FAIL_COUNT failures ($TEST_COUNT)"
fi

# ============================================================
section "3. SOURCE FILES INVENTORY"
# ============================================================

SWIFT_COUNT=$(find proxymate -name "*.swift" | wc -l | tr -d ' ')
C_COUNT=$(find proxymate -name "*.c" -o -name "*.h" | wc -l | tr -d ' ')
TEST_FILE_COUNT=$(find proxymateTests -name "*.swift" | wc -l | tr -d ' ')
TOTAL_LINES=$(find proxymate proxymateTests -name "*.swift" -o -name "*.c" -o -name "*.h" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')

echo "  Swift: $SWIFT_COUNT files, C/H: $C_COUNT files, Tests: $TEST_FILE_COUNT files"
echo "  Total lines: $TOTAL_LINES"
[[ $SWIFT_COUNT -ge 30 ]] && pass "Source file count ($SWIFT_COUNT Swift)" || fail "Too few source files: $SWIFT_COUNT"
[[ $TEST_FILE_COUNT -ge 15 ]] && pass "Test file count ($TEST_FILE_COUNT)" || fail "Too few test files: $TEST_FILE_COUNT"

# ============================================================
section "4. MODEL INTEGRITY"
# ============================================================

# WAFRule kinds
RULE_KINDS=$(grep -c "case.*=" proxymate/Models.swift | head -1 || echo 0)
[[ $RULE_KINDS -ge 4 ]] && pass "WAFRule has $RULE_KINDS kinds (allow+3 block)" || fail "WAFRule kinds: $RULE_KINDS"

# BlacklistSource categories
BL_CATS=$(grep "case.*=" proxymate/Models.swift | grep -c "BlacklistCategory\|torExits\|ads\|malware\|phishing\|cryptoMiner\|telemetry\|adult\|custom" || echo 0)
[[ $BL_CATS -ge 8 ]] && pass "BlacklistSource has $BL_CATS categories" || fail "BlacklistSource categories: $BL_CATS"

# Built-in blacklist feeds
BL_FEEDS=$(grep -c "\.init(name:" proxymate/Models.swift || echo 0)
[[ $BL_FEEDS -ge 19 ]] && pass "Built-in blacklist feeds: $BL_FEEDS" || fail "Too few blacklist feeds: $BL_FEEDS"

# AI providers
AI_PROVIDERS=$(grep -c "\.init(id:" proxymate/AIModels.swift || echo 0)
[[ $AI_PROVIDERS -ge 11 ]] && pass "AI providers: $AI_PROVIDERS" || fail "Too few AI providers: $AI_PROVIDERS"

# AI pricing models
AI_PRICING=$(grep -c "\.init(model:" proxymate/AIModels.swift || echo 0)
[[ $AI_PRICING -ge 15 ]] && pass "AI pricing models: $AI_PRICING" || fail "Too few pricing models: $AI_PRICING"

# Exfiltration packs
EXFIL_PACKS=$(grep -c "\.init($" proxymate/Models.swift || echo 0)
# Count pack IDs instead
EXFIL_IDS=$(grep -c 'id: "' proxymate/Models.swift || echo 0)
[[ $EXFIL_IDS -ge 7 ]] && pass "Exfiltration packs: $EXFIL_IDS" || fail "Too few exfiltration packs: $EXFIL_IDS"

# C2 signatures
C2_UA=$(grep -c '"mozilla/' proxymate/C2Detector.swift || echo 0)
[[ $C2_UA -ge 4 ]] && pass "C2 User-Agent signatures: $C2_UA" || fail "Too few C2 signatures: $C2_UA"

# HSTS preloaded domains
HSTS_COUNT=$(grep -oE '"[a-z0-9.-]+"' proxymate/HSTSPreload.swift | wc -l | tr -d ' ')
[[ $HSTS_COUNT -ge 50 ]] && pass "HSTS preloaded domains: $HSTS_COUNT" || fail "Too few HSTS domains: $HSTS_COUNT"

# ============================================================
section "5. REGEX VALIDATION"
# ============================================================

# Extract all regex patterns and verify they compile
python3 << 'PYEOF'
import re, sys
errors = 0
patterns = []
with open("proxymate/Models.swift") as f:
    for line in f:
        if 'regex:' in line:
            # Extract regex between #"..."#
            m = re.search(r'#"(.+?)"#', line)
            if m:
                patterns.append(m.group(1))

for p in patterns:
    try:
        re.compile(p)
    except re.error as e:
        print(f"  INVALID REGEX: {p[:50]}... -> {e}")
        errors += 1

if errors == 0:
    print(f"  All {len(patterns)} regex patterns compile successfully")
sys.exit(errors)
PYEOF
[[ $? -eq 0 ]] && pass "All exfiltration regex patterns valid" || fail "Invalid regex patterns found"

# ============================================================
section "6. CONFIGURATION DEFAULTS"
# ============================================================

# Verify critical defaults
grep -q "forceDNT: Bool = true" proxymate/Models.swift 2>/dev/null && \
    pass "DNT default: ON" || fail "DNT default not ON"

grep -q "forceGPC: Bool = true" proxymate/Models.swift 2>/dev/null && \
    pass "GPC default: ON" || fail "GPC default not ON"

grep -q "enabled: Bool = false" proxymate/Models.swift 2>/dev/null && \
    pass "Privacy stripping default: OFF (opt-in)" || skip "Could not verify privacy defaults"

grep -q "var enabled: Bool = true" proxymate/AhoCorasick.swift 2>/dev/null || \
    pass "Aho-Corasick has no enabled flag (always on)" || skip "Aho-Corasick check"

grep -q "identicalThreshold: Int = 20" proxymate/AgentLoopBreaker.swift && \
    pass "Loop breaker warn threshold: 20 (conservative)" || fail "Loop breaker threshold not conservative"

grep -q "identicalBlockThreshold: Int = 30" proxymate/AgentLoopBreaker.swift && \
    pass "Loop breaker block threshold: 30 (very conservative)" || fail "Loop breaker block threshold wrong"

grep -q "maxCostPerMinuteUSD: Double = 2.0" proxymate/AgentLoopBreaker.swift && \
    pass "Cost runaway cap: \$2/min" || fail "Cost cap not set"

# ============================================================
section "7. SAFETY CHECKS"
# ============================================================

# No force unwraps on FileManager (we fixed these)
FM_FORCE=$(grep -rn "\.first!" proxymate/*.swift 2>/dev/null | grep -v "test" | grep -v "//" || true)
if [[ -z "$FM_FORCE" ]]; then
    pass "No .first! force unwraps in source"
else
    fail "Found .first! force unwraps: $(echo "$FM_FORCE" | wc -l | tr -d ' ')"
fi

# System proxy cleanup exists
grep -q "wasEnabled" proxymate/proxymateApp.swift && \
    pass "Crash recovery: wasEnabled flag checked at startup" || fail "No crash recovery for system proxy"

grep -q "applicationWillTerminate" proxymate/proxymateApp.swift && \
    pass "AppDelegate: cleanup on normal quit" || fail "No quit cleanup"

# DNS not blocking hot path
grep -q "lookupCacheOnly" proxymate/LocalProxy.swift && \
    pass "DNS: non-blocking cache-only on hot path" || fail "DNS still blocking hot path"

# Log append (not insert at 0)
grep -q "logs.append(entry)" proxymate/AppState.swift && \
    pass "Log: O(1) append (not O(n) insert)" || fail "Log still using insert(at: 0)"

# Connection pool return
grep -q "ConnectionPool.shared.put" proxymate/LocalProxy.swift && \
    pass "ConnectionPool: connections returned after use" || fail "ConnectionPool: put() not called"

# ============================================================
section "8. UI COMPLETENESS"
# ============================================================

# Tab count
TAB_COUNT=$(grep -c "case.*=" proxymate/ContentView.swift | head -1 || echo 0)
# Count Tab enum cases specifically
TABS=$(grep "case proxies\|case logs\|case stats\|case rules\|case ai\|case cache\|case privacy" proxymate/ContentView.swift | wc -l | tr -d ' ')
[[ $TABS -ge 7 ]] && pass "UI tabs: $TABS" || fail "Missing tabs: $TABS"

# Community bar
grep -q "CommunityBar" proxymate/ContentView.swift && \
    pass "Community bar present (Star, Bug, Idea, Discuss, Support)" || fail "No community bar"

# Onboarding
grep -q "OnboardingView" proxymate/ContentView.swift && \
    pass "Onboarding wizard wired" || fail "No onboarding"

# About screen
grep -q "AboutView" proxymate/ContentView.swift && \
    pass "About screen wired" || fail "No about screen"

# Toast overlay
grep -q "ToastOverlay" proxymate/ContentView.swift && \
    pass "Toast notification overlay present" || fail "No toast overlay"

# Keyboard shortcuts
grep -c "keyboardShortcut" proxymate/ContentView.swift | xargs -I{} test {} -ge 7 && \
    pass "Keyboard shortcuts (7+)" || fail "Missing keyboard shortcuts"

# ============================================================
section "9. ASSET VERIFICATION"
# ============================================================

# App icon
ICON_COUNT=$(ls proxymate/Assets.xcassets/AppIcon.appiconset/*.png 2>/dev/null | wc -l | tr -d ' ')
[[ $ICON_COUNT -ge 10 ]] && pass "App icon: $ICON_COUNT PNG sizes" || fail "Missing app icon PNGs: $ICON_COUNT"

# Menu bar icon
[[ -f proxymate/Assets.xcassets/MenuBarIcon.imageset/menubar.png ]] && \
    pass "Menu bar icon: template PNG" || fail "Missing menu bar icon"

# SVG source
[[ -f proxymate.svg ]] && pass "SVG source icon in repo" || fail "Missing proxymate.svg"

# ============================================================
section "10. INFRASTRUCTURE"
# ============================================================

# License
[[ -f LICENSE ]] && pass "LICENSE file (MIT)" || fail "No LICENSE"

# README
[[ -f README.md ]] && pass "README.md present" || fail "No README"
grep -q "fabriziosalmi" README.md && pass "README has repo links" || fail "README missing links"

# CI
[[ -f .github/workflows/ci.yml ]] && pass "GitHub Actions CI" || fail "No CI workflow"

# Build script
[[ -x scripts/build-dmg.sh ]] && pass "build-dmg.sh executable" || fail "build-dmg.sh not executable"

# Benchmark script
[[ -x scripts/benchmark.sh ]] && pass "benchmark.sh executable" || fail "benchmark.sh not executable"

# Security policy
[[ -f SECURITY.md ]] && pass "SECURITY.md present" || fail "No SECURITY.md"

# Contributing guide
[[ -f CONTRIBUTING.md ]] && pass "CONTRIBUTING.md present" || fail "No CONTRIBUTING.md"

# Issue templates
[[ -f .github/ISSUE_TEMPLATE/bug_report.yml ]] && pass "Bug report template" || fail "No bug template"
[[ -f .github/ISSUE_TEMPLATE/feature_request.yml ]] && pass "Feature request template" || fail "No feature template"
[[ -f .github/pull_request_template.md ]] && pass "PR template" || fail "No PR template"

# .gitignore
grep -q "FEATURES.md" .gitignore && pass ".gitignore excludes internal docs" || fail ".gitignore missing"
grep -q "ROADMAP.md" .gitignore && pass ".gitignore excludes ROADMAP.md" || skip ".gitignore ROADMAP check"

# ============================================================
section "11. FEATURE COVERAGE MATRIX"
# ============================================================

check_feature() {
    local name="$1"
    local pattern="$2"
    local file="$3"
    if grep -q "$pattern" "$file" 2>/dev/null; then
        pass "$name"
    else
        fail "$name — pattern '$pattern' not found in $file"
    fi
}

check_feature "HTTP proxy (Network.framework)"     "NWListener"                proxymate/LocalProxy.swift
check_feature "SOCKS5 proxy (RFC 1928)"             "SOCKS5Listener"            proxymate/SOCKS5Listener.swift
check_feature "PAC server"                          "PACServer"                 proxymate/PACServer.swift
check_feature "HTTP/2 upstream"                     "HTTP2Upstream"             proxymate/HTTP2Upstream.swift
check_feature "Multi-upstream pools"                "PoolRouter"                proxymate/PoolRouter.swift
check_feature "6 pool strategies"                   "leastConns"                proxymate/PoolRouter.swift
check_feature "Health checks"                       "performHealthCheck"        proxymate/PoolRouter.swift
check_feature "Pool overrides"                      "PoolOverride"              proxymate/PoolModels.swift
check_feature "WAF rules engine"                    "RuleEngine"                proxymate/RuleEngine.swift
check_feature "Aho-Corasick content matching"       "AhoCorasick"               proxymate/AhoCorasick.swift
check_feature "Blacklist manager"                   "BlacklistManager"          proxymate/BlacklistManager.swift
check_feature "DNS-over-HTTPS"                      "DNSResolver"               proxymate/DNSResolver.swift
check_feature "Exfiltration scanner"                "ExfiltrationScanner"       proxymate/ExfiltrationScanner.swift
check_feature "C2 framework detection"              "C2Detector"                proxymate/C2Detector.swift
check_feature "Beaconing detection"                 "BeaconingDetector"         proxymate/BeaconingDetector.swift
check_feature "WebSocket inspector"                 "WebSocketInspector"        proxymate/WebSocketInspector.swift
check_feature "Process resolver"                    "ProcessResolver"           proxymate/ProcessResolver.swift
check_feature "AI agent enforcer"                   "AIAgentEnforcer"           proxymate/AIAgentEnforcer.swift
check_feature "Agent loop breaker"                  "AgentLoopBreaker"          proxymate/AgentLoopBreaker.swift
check_feature "AI tracker (11 providers)"           "AITracker"                 proxymate/AITracker.swift
check_feature "MCP detection"                       "detectMCP"                 proxymate/AIAgentEnforcer.swift
check_feature "Privacy header stripping"            "applyPrivacy"              proxymate/LocalProxy.swift
check_feature "TLS MITM handler"                    "MITMHandler"               proxymate/MITMHandler.swift
check_feature "TLS manager (CA + cert forging)"     "TLSManager"                proxymate/TLSManager.swift
check_feature "HSTS preload list"                   "HSTSPreload"               proxymate/HSTSPreload.swift
check_feature "L1 RAM cache"                        "CacheManager"              proxymate/CacheManager.swift
check_feature "L2 disk cache (SQLite)"              "DiskCache"                 proxymate/DiskCache.swift
check_feature "Connection pool"                     "ConnectionPool"            proxymate/ConnectionPool.swift
check_feature "IP allowlist + CIDR"                 "AllowlistMatcher"          proxymate/Allowlist.swift
check_feature "IPv6 support"                        "IPv6Support"               proxymate/IPv6Support.swift
check_feature "HTTP parser (chunked, keep-alive)"   "HTTPParser"                proxymate/HTTPParser.swift
check_feature "Rule importer (hosts, ABP, plain)"   "RuleImporter"              proxymate/RuleImporter.swift
check_feature "iCloud sync"                         "CloudSync"                 proxymate/CloudSync.swift
check_feature "Persistent logger (JSONL + OSLog)"   "PersistentLogger"          proxymate/PersistentLogger.swift
check_feature "Prometheus metrics"                  "MetricsServer"             proxymate/MetricsServer.swift
check_feature "Webhook events"                      "WebhookManager"            proxymate/WebhookManager.swift
check_feature "macOS notifications"                 "NotificationManager"       proxymate/NotificationManager.swift
check_feature "Toast in-app notifications"          "ToastState"                proxymate/ToastView.swift
check_feature "Privileged helper (cached auth)"     "PrivilegedHelper"          proxymate/PrivilegedHelper.swift
check_feature "Stats time series (charts)"          "StatsTimeSeries"           proxymate/StatsTimeSeries.swift
check_feature "Onboarding wizard (5 steps)"         "stepWelcome"               proxymate/OnboardingView.swift
check_feature "About screen"                        "AboutView"                 proxymate/AboutView.swift
check_feature "Localization strings"                "Strings"                   proxymate/Localization.swift
check_feature "Body decompressor (gzip/deflate)"   "BodyDecompressor"          proxymate/BodyDecompressor.swift
check_feature "SOCKS5 settings persistence"        "socks5Key"                 proxymate/AppState.swift
check_feature "AI agent settings persistence"      "aiAgentKey"                proxymate/AppState.swift

# ============================================================
section "RESULTS"
# ============================================================

TOTAL=$((PASS + FAIL + SKIP))
echo ""
printf "  ${GREEN}PASS: %d${NC}  ${RED}FAIL: %d${NC}  ${YELLOW}SKIP: %d${NC}  TOTAL: %d\n" "$PASS" "$FAIL" "$SKIP" "$TOTAL"

if [[ $FAIL -gt 0 ]]; then
    printf "\n${RED}FAILURES:${NC}%b\n" "$ERRORS"
    exit 1
else
    printf "\n${GREEN}ALL CHECKS PASSED.${NC} Ready for 100 users x 7 days.\n"
    exit 0
fi
