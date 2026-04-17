# Features overview

A one-page tour of every capability. Grouped by layer; each section links to deeper docs when relevant.

## Traffic layer

- **HTTP/HTTPS forward proxy** on a random loopback port, bound to 127.0.0.1 only
- **SOCKS5 listener** (RFC 1928) on a separate port for apps that prefer SOCKS
- **CONNECT tunnels** for TLS, with optional MITM interception per-host
- **Chunked Transfer-Encoding**, keep-alive, pipelining
- **IPv6** end-to-end (address literals, CIDR in allowlist, NWConnection IPv6)

## Filtering layer

- **Block Domain** rules with O(1) Set lookup — ~90 K built-in entries
- **Block IP** rules with CIDR range matching
- **Block Content** rules using Aho-Corasick multi-pattern search (URL + headers + body)
- **Mock action** — stealth 200 OK so trackers don't retry
- **Shadow mode** — log-only evaluation, useful for rule authoring without breaking traffic
- **Allowlist** with domain + CIDR entries, evaluated first

## Blacklist feeds

19 built-in feeds, 8 categories, refreshable in background:

| Source | Category |
|---|---|
| Steven Black Hosts (Ads/Tracking) | Ads |
| NoCoin Filter | Crypto mining |
| URLhaus Malware Domains | Malware |
| Malware Domain List | Malware |
| Coinblocker | Crypto |
| Phishing Army | Phishing |
| OISD | Mixed (trackers, malware, phishing) |
| TOR Exit Nodes | Network |

## Privacy layer

Per-host policy. Every option is a checkbox.

- Strip `User-Agent` (rewrite to a configurable stock value)
- Strip `Referer` (fully, origin-only, or keep)
- Inject `DNT: 1` and `Sec-GPC: 1`
- Filter tracking cookies by prefix (`_ga`, `_fbp`, `utma`, `fbm_`, …)
- Rewrite `ETag` (cache-busting tracker)
- Strip `Accept-Language` minor variants that enable fingerprinting

## TLS interception (MITM)

- Per-installation root CA, generated on first enable
- AES-256 encrypted at rest; passphrase in Keychain
- Leaf certs forged on demand per hostname, with SAN
- Bundled `mitmproxy` sidecar (88 MB, Python 3.14, OpenSSL 3.5) handles the TLS dance
- Auto-exclude for pinned apps, `*.apple.com`, banking, `*.signal.org`, etc.
- Curated streaming-media exclude list (RAI, Mediaset, La7, Netflix, Spotify, Twitch, YouTube media CDN, Disney+, DAZN, Brightcove, Akamai media subdomains)
- Runtime auto-exclude after 3 consecutive pinning failures per host
- Runtime auto-exclude on streaming-media `Content-Type` (`audio/*`, `video/*`, HLS `m3u8`, DASH `mpd`) — catches webradio, podcasts, independent broadcasters, any stream the hand-curated list misses. 0.9.58 hardens the signal with magic-byte corroboration (HTML/JSON tagged as audio is refused) and a 2-response / 60 s threshold so a one-off notification MP3 doesn't disable MITM for the whole host
- **Browser compatibility hardening** (0.9.54 – 0.9.58): `Alt-Svc` stripped to keep browsers on HTTP/2 inside the tunnel, HTTP/2 disabled on the downstream leg to prevent connection coalescing across hosts, one-click **Export Root CA** for Firefox import
- **Export** button in Preferences → TLS Interception writes `~/Downloads/proxymate-ca.pem` and reveals it in Finder — ready to drag-drop into Firefox's Certificate Authorities

See [security model](/guide/security.md) for the full CA lifecycle and [MITM & browser trust](/guide/mitm-browser-trust.md) for the Firefox / HSTS / HTTP/3 / coalescing writeup.

## AI / agent controls

- Detects Claude Code, Cursor, Codex, Continue.dev, Aider, MCP clients
- Tracks OpenAI, Anthropic, Google, Mistral, Groq, Together, Deepseek, …
- Per-token + per-request cost estimation (configurable per-provider pricing)
- Agent loop breaker — identical-request rapid-fire threshold
- Budget caps with block action when exceeded
- Model allowlist/blocklist per provider

## Observability

- **Persistent logger** (JSONL + OSLog), rotates at 2 MB, keeps 5 files
- **Prometheus metrics** server on a configurable local port
- **Webhook events** for allow / block / AI detection / C2 hit
- **macOS notifications** for high-severity events
- **Stats tab** with real-time counters, per-host memory, latency histograms

## Threat detection

- **Beaconing detector** — periodic callback patterns (interval + jitter)
- **C2 framework fingerprints** — Cobalt Strike, Sliver, Mythic, Havoc, Empire
- **Exfiltration scanner** — 7 pattern packs, 28 patterns (AWS keys, JWT, card numbers, PII)
- **HSTS preload enforcement** — 65 high-value domains

## Caching

- **L1 RAM cache** with TTL
- **L2 SQLite disk cache**, configurable size
- Respects `Cache-Control`, `Vary`, `ETag`, `Last-Modified`

## Routing

Multi-upstream pools with 6 load-balancing strategies:

- Round-robin
- Least connections
- Weighted random
- Weighted round-robin
- Latency-based (health-probe driven)
- Sticky (session affinity by cookie or src-ip)

Per-pool health checks with circuit breaker — unhealthy members drop out, return after recovery.

## Everything else

- PAC server (dynamic `proxy.pac` with smart bypass for LAN + VPN endpoints)
- DNS-over-HTTPS (RFC 8484 JSON API, configurable resolver)
- HSTS preload list (65 domains)
- iCloud sync of rule sets and allowlist (NSUbiquitousKeyValueStore)
- Process resolver — maps active port → app name in logs
- Request fingerprinting (SHA256 of header order) — detect suspicious clients
- Rule importer — hosts files, ABP, plain text
