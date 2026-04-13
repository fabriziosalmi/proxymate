# Configuration reference

All settings are managed from the app UI. For automation (scripts, Git-versioned team configs), the underlying stores are:

## Storage layout

```
~/Library/Application Support/Proxymate/
├── ca/
│   ├── ca.key              # AES-256 encrypted, 0o600
│   ├── ca.pem              # Public cert
│   └── leaves/             # Per-host leaf P12 cache
├── cache/
│   └── responses.sqlite    # L2 cache (configurable size)
├── blacklists/
│   └── <source>.txt        # Refreshed feeds
└── logs/
    ├── proxymate.log       # Active log
    └── proxymate-<ts>.log  # Rotated (max 5, 2 MB each)
```

## UserDefaults keys

| Key | Type | Purpose |
|---|---|---|
| `proxymate.wasEnabled` | Bool | Session-resume flag for clean shutdown |
| `proxymate.selectedProxyID` | UUID | Which upstream is active |
| `proxymate.rules` | Data (JSON) | WAF rule set |
| `proxymate.allowlist` | Data (JSON) | Domain + CIDR allowlist |
| `proxymate.privacySettings` | Data (JSON) | Per-host privacy policy |
| `proxymate.mitmSettings` | Data (JSON) | MITM enabled + exclude list |
| `proxymate.aiSettings` | Data (JSON) | AI provider + agent policy |

## iCloud sync

`NSUbiquitousKeyValueStore` is used for rule-set sync only — **not** for traffic data. Keys mirror `proxymate.*` in UserDefaults. Disabled by default; enable from **Preferences → Sync**.

Conflicts resolve last-write-wins per-key (no 3-way merge — this is a small key/value store). Expected for a single-user, multi-Mac setup.

## Listener ports

Proxymate binds to random ephemeral ports on 127.0.0.1 (never `0.0.0.0`):

- HTTP/HTTPS proxy: random in 1024–65535
- SOCKS5: configurable, default same-range-random
- PAC server: 18095 (configurable)
- Metrics (Prometheus): disabled by default, 9100 when enabled

Port numbers are logged on each start — check **Logs** tab or `proxymate.log`.

## Network services bypass

The system-proxy config includes these in the bypass list automatically:

- `localhost`, `127.0.0.1`, `::1`
- `*.local`
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- `169.254.0.0/16`

Traffic to these destinations skips the proxy entirely — so your local dev server, Bonjour discovery, and LAN-only services continue to work with zero configuration.

## Prometheus metrics

When enabled, exposes on `http://127.0.0.1:9100/metrics`:

- `proxymate_requests_total{outcome,upstream}` — counter
- `proxymate_latency_seconds` — histogram
- `proxymate_active_connections` — gauge
- `proxymate_blacklist_hits_total{source,category}` — counter
- `proxymate_ai_tokens_total{provider,model,direction}` — counter
- `proxymate_cost_usd_total{provider}` — counter

Standard scrape integration: point Prometheus at `127.0.0.1:9100`.

## Webhooks

Per-event subscription. Configure URL + event mask in **Preferences → Integrations**.

Event payload example (`application/json`):

```json
{
  "event": "blocked",
  "timestamp": "2026-04-14T10:22:13Z",
  "host": "tracker.example.com",
  "rule_name": "Block Domain: tracker.example.com",
  "method": "GET",
  "url": "https://tracker.example.com/collect"
}
```

Debounced at 5 s per (event, host) pair to prevent flooding.
