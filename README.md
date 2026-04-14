<p align="center">
  <img src="proxymate.svg" width="96" alt="Proxymate icon">
</p>

<h1 align="center">Proxymate</h1>

<p align="center">
  <em>Your Mac. Your traffic. Your rules.</em>
</p>

<p align="center">
  <a href="https://fabriziosalmi.github.io/proxymate/"><img src="https://img.shields.io/badge/docs-live-0A84FF.svg" alt="Documentation"></a>
  <a href="https://github.com/fabriziosalmi/proxymate/releases/latest"><img src="https://img.shields.io/github/v/release/fabriziosalmi/proxymate?color=blue&label=release" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/macOS-26%2B-black.svg" alt="macOS 26+">
  <img src="https://img.shields.io/badge/notarized-yes-success.svg" alt="Notarized">
  <img src="https://img.shields.io/badge/telemetry-zero-purple.svg" alt="Zero telemetry">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
</p>

A privacy-first **menu-bar HTTP/HTTPS/SOCKS proxy for macOS**, with a built-in WAF, transparent TLS interception, AI agent controls, credential-exfiltration scanner, and multi-upstream pool routing. Zero telemetry, zero cloud accounts, signed and notarized by Apple.

📖 **Full documentation:** [fabriziosalmi.github.io/proxymate](https://fabriziosalmi.github.io/proxymate/)

## Install

### Homebrew (recommended)

```bash
brew tap fabriziosalmi/proxymate
brew install --cask proxymate
```

### DMG

Download the latest `Proxymate-<version>.dmg` from the [releases page](https://github.com/fabriziosalmi/proxymate/releases/latest), verify the hash, and drag the app into `/Applications`:

```bash
shasum -a 256 ~/Downloads/Proxymate-*.dmg
# compare against the SHA-256 printed in the release notes
```

The DMG is notarized and stapled — no "Cannot verify developer" dialog. Requires macOS 26 (Tahoe) or newer, Apple Silicon.

## What it does

**Traffic routing** — local HTTP/HTTPS forward proxy on a loopback-bound port, SOCKS5 listener, transparent CONNECT tunnels with optional MITM interception.

**Filtering** — Block Domain / Block IP (CIDR) / Block Content (Aho-Corasick) rules. Ships with 19 curated blacklist feeds (~90 K entries across ads, malware, phishing, TOR exits). Shadow-mode evaluation for rule authoring without breaking traffic.

**Privacy rewriting** — strip `User-Agent`, `Referer`, `ETag`, tracking cookies; inject `DNT: 1` / `Sec-GPC: 1`. Per-host policy.

**TLS interception** — per-installation Root CA stored AES-256 encrypted with a Keychain-bound passphrase; leaf certs forged on demand through a bundled `mitmproxy` sidecar. Auto-excludes pinned apps (Signal, WhatsApp, banking, Apple services).

**AI agent controls** — detects Claude Code, Cursor, Codex, Aider, MCP clients. Tracks tokens for 11 providers, estimates cost, enforces per-model allowlists, breaks runaway loops.

**Threat detection** — beaconing heuristic, C2 framework fingerprints (Cobalt Strike, Sliver, Mythic, Havoc, Empire, Metasploit), credential-exfiltration scanner with 7 pattern packs.

**Routing** — multi-upstream pools with 6 load-balancing strategies, per-pool health checks, circuit breaker on member failure.

**Everything else** — PAC server with smart bypass, DoH resolver, L1 RAM + L2 SQLite cache, Prometheus metrics endpoint, webhook events, iCloud sync for rule sets, persistent JSONL logs with rotation.

See the [features overview](https://fabriziosalmi.github.io/proxymate/guide/features) for a deeper tour.

## Quick start

1. Install the DMG, launch from `/Applications`
2. Menu-bar icon → **Enable** (one admin-password prompt for `networksetup`)
3. In **Preferences → MITM**, install the Root CA (another prompt for keychain trust)
4. Watch the **Logs** tab; every app's traffic now routes through Proxymate

The five-step onboarding wizard ships sensible defaults so the first-run experience is complete in ~30 seconds.

## Privacy

- **Zero telemetry.** The binary contains no analytics endpoint.
- **Zero cloud accounts.** No login, no sign-up, no server-side anything.
- **Local data only.** Everything lives under `~/Library/Application Support/Proxymate/` and your login Keychain.
- **Only outbound calls on its own:** blacklist refresh URLs you opt into, DoH resolver of your choosing.

See the [security model](https://fabriziosalmi.github.io/proxymate/guide/security) for threat model + CA lifecycle details.

## Build from source

```bash
git clone https://github.com/fabriziosalmi/proxymate.git
cd proxymate
open proxymate.xcodeproj
# ⌘R to run a Debug build
```

For a signed release build with notarization pipeline:

```bash
./scripts/build-dmg.sh            # requires Developer ID + notarytool credentials
./scripts/build-dmg.sh --skip-notarize   # local ad-hoc DMG
```

## Architecture

```
App traffic → System proxy → LocalProxy (loopback, random port)
                                ├─ Allowlist (CIDR + domain)
                                ├─ WAF (domain / IP / content)
                                ├─ Blacklist feeds (19 sources)
                                ├─ DNS-resolved IP blocklist
                                ├─ Exfiltration scanner
                                ├─ C2 / beaconing detection
                                ├─ AI agent enforcement
                                ├─ Privacy header rewriting
                                ├─ L1 RAM / L2 SQLite cache
                                └─ PoolRouter → upstream
```

Single-process. Network.framework + swift-nio. No frameworks, no background daemons, no external processes on the hot path. MITM uses a signed `mitmproxy` sidecar spawned on demand when interception is enabled.

## Testing

```bash
# Unit + integration tests (XCTest)
xcodebuild test -project proxymate.xcodeproj -scheme proxymate \
    -destination 'platform=macOS' -parallel-testing-enabled NO

# Full end-to-end suite against a running instance
./scripts/e2e-full.sh
# Baseline: 22 passed / 0 failed / 2 skipped
```

The e2e suite exercises every major capability through a live listener + Squid upstream: HTTP + HTTPS CONNECT, privacy header injection, WAF blocking, cache hits, 1 MB payload integrity, 20-way concurrency, latency ceiling.

### Site compatibility triage

When a user reports "site X doesn't work", the Playwright-based harness under `tests/site-compat/` reproduces the problem in one command and cross-references failures against the live proxy log to classify each failed host as **BYPASS** (never reached the proxy), **PROXY_ERROR** (reached the proxy but got an error), or **BROWSER** (succeeded at the proxy; browser surfaced the failure):

```bash
./scripts/diagnose-site.sh https://example.com                    # single URL
./scripts/diagnose-site.sh --suite --mitm on                      # full suite
./scripts/diagnose-site.sh --compare proxy-mitm-off proxy-mitm-on # MITM-only regressions
```

See [`tests/site-compat/README.md`](tests/site-compat/README.md) for modes, signals, and the calibration notes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The code is currently in a trusted-reviewer phase; external PRs will open up with the v1.0 public release.

## Security

Found something sensitive? Report privately via GitHub Security Advisories or by email to the address in `SECURITY.md`. Please do not open a public issue for suspected vulnerabilities.

## License

MIT — see [LICENSE](LICENSE).

---

<sub>Built by one person in Italy, for people who want to know what their Mac is actually sending on the wire. No VC, no Series A, no growth hacks.</sub>
