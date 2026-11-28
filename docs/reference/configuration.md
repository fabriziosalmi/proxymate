# Configuration reference

All settings are managed from the app UI. For automation (scripts, Git-versioned team configs), the underlying stores are:

## Storage layout

```
~/Library/Application Support/Proxymate/
├── ca/
│   ├── ca.key              # RSA 2048, AES-256 encrypted, 0o600
│   ├── ca.pem              # Public cert
│   ├── ca.der              # DER copy of the cert
│   └── leaves/             # Per-host leaf cache: <host>.p12
├── blacklists/
│   └── <source-uuid>.txt   # Refreshed feeds
└── logs/
    ├── proxymate.log       # Active log (JSONL)
    └── proxymate-<ts>.log  # Rotated (2 MB per file, 5 rotated files kept)

~/Library/Caches/Proxymate/http/   # L2 disk cache (default, directory is configurable)
├── cache.db                # SQLite metadata
└── bodies/                 # Sharded response bodies
```

The L2 cache size limit defaults to 512 MB.

## UserDefaults keys

Each value is a JSON-encoded `Data` blob of the matching settings struct, except where noted. Keys carry a version suffix; when a settings shape changes the suffix is bumped (for example `proxymate.mitm.v2`, `proxymate.loopbreaker.v2`).

| Key | Purpose |
|---|---|
| `proxymate.proxies.v1` | Upstream proxy list |
| `proxymate.pools.v1` | Upstream pools |
| `proxymate.overrides.v1` | Pool overrides |
| `proxymate.selected.v1` | Selected upstream (UUID string) |
| `proxymate.rules.v1` | WAF rule set |
| `proxymate.allowlist.v1` | Domain + CIDR allowlist |
| `proxymate.blacklists.v1` | Blacklist sources |
| `proxymate.privacy.v1` | Privacy policy |
| `proxymate.mitm.v2` | MITM enabled + exclude list |
| `proxymate.exfiltration.v1` | Exfiltration pattern packs |
| `proxymate.ai.v1` | AI provider settings |
| `proxymate.aiagent.v1` | AI agent policy |
| `proxymate.loopbreaker.v2` | Agent loop breaker thresholds |
| `proxymate.beaconing.v1` | Beaconing detector settings |
| `proxymate.c2.v1` | C2 detector settings |
| `proxymate.processrules.v1` | Per-process rules |
| `proxymate.cache.v1` | L1 RAM cache settings |
| `proxymate.diskcache.v1` | L2 disk cache settings |
| `proxymate.dns.v1` | DNS-over-HTTPS settings |
| `proxymate.pac.v1` | PAC server settings |
| `proxymate.socks5.v1` | SOCKS5 listener settings |
| `proxymate.metrics.v1` | Prometheus endpoint settings |
| `proxymate.webhook.v1` | Webhook settings |
| `proxymate.cloudsync.v1` | iCloud sync settings |
| `proxymate.wasEnabled` | Bool, session-resume flag for clean shutdown |
| `proxymate.onboarded` | Bool, onboarding completed |

## iCloud sync

`NSUbiquitousKeyValueStore` is used for the WAF rule set and the allowlist only, **not** for traffic data. The keys are `proxymate.cloud.rules` and `proxymate.cloud.allowlist`, and each can be switched off separately. Sync is opt-in (disabled by default) and capped at 1 MB in total.

On a remote change, incoming rules are merged with the local ones (union by pattern, newer enabled state wins) rather than overwriting them.

## Listener ports

Proxymate binds to 127.0.0.1 (never `0.0.0.0`). Ports:

- HTTP/HTTPS proxy: assigned by the system on each start
- SOCKS5: 1080 (optional)
- PAC server: 9280 (optional)
- Metrics (Prometheus): 9199, disabled by default

The proxy port is logged on each start: check the **Logs** tab or `proxymate.log`.

## Network services bypass

The system-proxy config includes these in the bypass list automatically:

- `localhost`, `127.0.0.1`, `::1`
- `*.local`
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- `169.254.0.0/16`

Traffic to these destinations skips the proxy entirely — so your local dev server, Bonjour discovery, and LAN-only services continue to work with zero configuration.

## Prometheus metrics

When enabled, exposes on `http://127.0.0.1:9199/metrics` (the port is configurable). All series are unlabelled:

- Requests: `proxymate_requests_allowed_total`, `proxymate_requests_blocked_total`, `proxymate_blacklist_blocked_total`, `proxymate_exfiltration_blocked_total`, `proxymate_privacy_actions_total`
- AI: `proxymate_ai_requests_total`, `proxymate_ai_blocked_total`, `proxymate_ai_cost_usd` (gauge, session total)
- TLS: `proxymate_mitm_intercepted_total`
- L1 cache: `proxymate_cache_l1_hits_total`, `proxymate_cache_l1_misses_total`, `proxymate_cache_l1_entries`, `proxymate_cache_l1_size_bytes`
- L2 cache: `proxymate_cache_l2_hits_total`, `proxymate_cache_l2_misses_total`, `proxymate_cache_l2_size_bytes`
- DNS: `proxymate_dns_queries_total`, `proxymate_dns_cache_hits_total`, `proxymate_dns_errors_total`

Standard scrape integration: point Prometheus at `127.0.0.1:9199`.

## Webhooks

Per-event subscription: enable each of `block`, `exfiltration` and `budget_exceeded` separately and give one or more target URLs. Each event is sent as an `application/json` POST.

```json
{
  "event": "block",
  "host": "tracker.example.com",
  "rule": "Block Domain: tracker.example.com",
  "timestamp": "2026-04-14T10:22:13Z"
}
```

An `exfiltration` event carries `host`, `pattern`, `severity`, `preview` and `timestamp`; a `budget_exceeded` event carries `provider`, `reason` and `timestamp`.

Debounced at 5 s by default (configurable) per event key (rule name, pattern name or provider) to prevent flooding.
