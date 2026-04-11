<p align="center">
  <img src="proxymate.svg" width="80" alt="Proxymate icon">
</p>

# Proxymate

[![CI](https://github.com/fabriziosalmi/proxymate/actions/workflows/ci.yml/badge.svg)](https://github.com/fabriziosalmi/proxymate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![macOS](https://img.shields.io/badge/macOS-15%2B-black.svg)](https://www.apple.com/macos/)
[![Swift](https://img.shields.io/badge/Swift-5-orange.svg)](https://swift.org)
[![Tests](https://img.shields.io/badge/tests-134%20passed-brightgreen.svg)](#)
[![Zero Telemetry](https://img.shields.io/badge/telemetry-zero-purple.svg)](#privacy)

A macOS menu bar app for HTTP/HTTPS proxy management with built-in WAF, privacy protection, AI agent enforcement, and threat intelligence. Free and open source, forever.

## Features

**Proxy Management**
- One-click system proxy toggle from the menu bar
- Multi-upstream pools with 6 load balancing strategies (round-robin, weighted, failover, lowest-latency, least-connections, random)
- Health checks with automatic failover
- Host-pattern routing overrides (e.g. `*.github.com` → specific pool)

**Security**
- WAF rules: block/allow by IP, domain, or content pattern
- Bulk blacklist ingestion: TOR exit nodes, ad/tracking domains, malware C2, crypto miners
- DNS-level blocking: resolves domains via DoH and blocks if IP is blacklisted
- Credential exfiltration scanner: AWS keys, GitHub PATs, Stripe keys, Slack tokens, PII (IBAN, credit cards, fiscal codes, SSN)
- IP allowlist with CIDR range support and port/protocol scoping
- macOS notifications on first block per rule

**Privacy**
- Strip/replace User-Agent, Referer, ETag (anti-supercookie)
- Remove tracking cookies (`_ga`, `_fbp`, `__utm`, etc.)
- Inject `DNT: 1` and `Sec-GPC: 1` headers
- DNS-over-HTTPS (Cloudflare, Quad9, Google, or custom provider)
- TLS MITM with active HTTPS interception (root CA, leaf cert forging, SSLContext)
- Response header stripping (Server, X-Powered-By) via MITM

**AI/LLM Observability & Enforcement**
- Auto-detect 11 providers (OpenAI, Anthropic, Google, Mistral, Cohere, Together, Groq, DeepSeek, Perplexity, xAI, Ollama)
- Token counting from JSON responses and SSE streams
- Cost estimation with built-in pricing table (17 models)
- Daily and monthly budget caps with auto-block
- Model allowlist/blocklist (block expensive models)
- AI agent detection (Claude Code, Cursor, Windsurf, Aider, Copilot, Codex CLI)
- MCP (Model Context Protocol) traffic detection and server allowlist
- Agent loop breaker: detects stuck LLMs, rapid-fire loops, MCP router loops, cost runaway

**Threat Detection**
- C2 framework signatures (Cobalt Strike, Sliver, Mythic, Empire, Havoc, Metasploit)
- Beaconing detection (fixed-interval request patterns)
- WebSocket frame parsing with WAF inspection on text frames
- Process-aware rules (PID to bundle ID, per-app allow/block/direct)
- 19 built-in threat intelligence feeds across 8 categories

**Caching**
- L1 RAM cache with full HTTP semantics (Cache-Control, Vary, ETag, Expires)
- L2 disk cache (SQLite metadata + sharded filesystem bodies)
- LRU eviction, configurable size and TTL
- Tracking parameter stripping from cache keys (`utm_*`, `fbclid`, etc.)

**Protocol Support**
- HTTP/HTTPS forward proxy (Network.framework)
- SOCKS5 proxy (RFC 1928)
- HTTP/2 upstream forwarding

**Rule Management**
- Import from hosts files, Adblock Plus, plain domain/IP lists
- Auto-detect format, deduplicate on import
- Export as JSON or hosts file
- iCloud sync between Macs
- Drag-reorder for priority control

**Logging & Monitoring**
- Persistent JSONL logs with rotation (survives restarts)
- OSLog integration (visible in Console.app)
- Prometheus /metrics endpoint (opt-in, localhost only)
- Webhook events on block/exfiltration/budget (JSON POST)
- macOS notifications on first block per rule
- Live search and filter by text, host, or level
- Click-to-rule: right-click a log entry to block or allow the host
- Real-time req/sec charts (Apple Charts)

## Requirements

- macOS 15.0 or later
- Xcode 26+ (for building from source)

## Install

### From DMG (recommended)

Download the latest DMG from [Releases](../../releases), open it, and drag Proxymate to Applications.

### From source

```bash
git clone https://github.com/fabriziosalmi/proxymate.git
cd proxymate
open proxymate.xcodeproj
# Press ⌘R to build and run
```

### Build a DMG

```bash
# Dev build (no notarization)
./scripts/build-dmg.sh --skip-notarize

# Production build (requires Developer ID certificate + notarytool credentials)
./scripts/build-dmg.sh
```

## Usage

1. Click the shield icon in the menu bar
2. Select an upstream proxy or create a pool
3. Toggle the switch to enable — admin password required once per session
4. Configure rules, privacy, cache, and AI settings in the respective tabs

### Keyboard shortcuts

| Shortcut | Action |
|----------|--------|
| `⌘T` | Toggle proxy on/off |
| `⌘1`–`⌘7` | Switch tabs |

## Architecture

```
App traffic → System Proxy → LocalProxy (in-process)
                                 ├─ Allowlist check
                                 ├─ WAF rules
                                 ├─ Blacklist + DNS-level block
                                 ├─ Exfiltration scanner
                                 ├─ Privacy header rewriting
                                 ├─ Cache lookup
                                 ├─ AI provider detection
                                 └─ PoolRouter → upstream
```

All processing happens in a single in-process proxy on `127.0.0.1`. No external dependencies, no background daemons, no network calls except your traffic and optional DoH/blacklist refresh.

## Privacy

- Zero telemetry
- Zero cloud accounts or logins
- No analytics SDKs
- No network calls on launch (blacklist refresh is opt-in)
- All data stays on your Mac (`~/Library/Application Support/Proxymate/`)

## License

MIT
