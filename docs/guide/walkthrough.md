# Walkthrough

This walkthrough covers the complete first day with Proxymate: installation, the onboarding wizard, and a tab-by-tab reference of every control in the menu bar panel. Every claim made here corresponds to behavior in the current release — if something doesn't match, it's a bug.

## 1. Requirements

| | |
| --- | --- |
| macOS | 26 (Tahoe) or newer. The binary declares `minos 26.1` in `LC_BUILD_VERSION`; older versions refuse to launch. |
| Architecture | Apple Silicon only (`arm64`). The DMG is single-architecture. |
| Privileges | A standard user account, with the ability to enter an admin password for two specific operations: `networksetup` proxy configuration and `security add-trusted-cert` for the root CA. |
| Disk | ~150 MB installed. The bundled `mitmproxy.app` nested bundle accounts for 88 MB of that (Python 3.14 runtime + OpenSSL). |

Verify your environment before installing:

```bash
sw_vers -productVersion     # expect 26.x or higher
uname -m                    # expect arm64
```

## 2. Installing

Two paths. Either works; Homebrew is easier to upgrade.

### Homebrew tap

```bash
brew tap fabriziosalmi/proxymate
brew install --cask proxymate
```

The tap lives at [github.com/fabriziosalmi/homebrew-proxymate](https://github.com/fabriziosalmi/homebrew-proxymate) and pulls the DMG from GitHub Releases. Upgrades: `brew upgrade --cask proxymate`. Uninstall with `brew uninstall --cask --zap proxymate` — the `--zap` removes `~/Library/Application Support/Proxymate` and the caches along with the app.

### Direct DMG

```bash
curl -LO https://github.com/fabriziosalmi/proxymate/releases/latest/download/Proxymate-0.9.55.dmg
shasum -a 256 Proxymate-0.9.55.dmg
# expected: 6670f2d66ad5e50bb84d79c6a41a4bb03abcf6185613a21be0b845fbda81b8c8
```

Verify the SHA before mounting. The release page publishes the same hash in `Proxymate-0.9.55.dmg.sha256`. Because the DMG is notarized and stapled, `spctl` accepts it without a network round-trip:

```bash
spctl -a -t open --context context:primary-signature Proxymate-0.9.55.dmg
# /path/to/Proxymate-0.9.55.dmg: accepted
```

Mount, drag `Proxymate.app` to `/Applications`, eject. The first launch is silent — no Gatekeeper dialog, no right-click-then-Open workaround.

## 3. The menu bar icon

Proxymate runs as a menu-bar app with no Dock icon. The only persistent UI surface is a shield glyph next to the system clock.

**Clicking it** opens the main panel (an `NSPanel`, not a popover, so focus and keyboard input work normally). The panel contains:

- Header with status text and the enable/disable toggle
- Seven tabs: Proxies, Logs, Stats, Rules, AI, Cache, Privacy
- Footer with a Quit button

**Status line** states:

- `Off` — the listener is not running; the system proxy is unchanged from whatever macOS had before
- `On` — the local HTTP listener is bound and the system proxy points at it

Confirm from a terminal while the app is On:

```bash
scutil --proxy | grep -E 'HTTPProxy|HTTPPort|HTTPEnable'
#   HTTPEnable : 1
#   HTTPPort : 52486
#   HTTPProxy : 127.0.0.1

lsof -nP -p "$(pgrep proxymate)" | grep LISTEN
# proxymate ... TCP *:52486 (LISTEN)
```

**Quit** (footer button, ⌘Q, or menu-bar right-click) disables the proxy, clears PAC settings, stops the MITM and Squid sidecars, flushes the persistent log buffer, and removes the lock file under `/tmp/proxymate-$USER.lock` before the process exits. The cleanup is bounded at 8 seconds — enough for `networksetup` over `osascript` on a cold wake.

**Force-quit** (⌥⌘⎋, or SIGKILL) skips the cleanup path. The consequence: your system proxy remains configured to point at `127.0.0.1:<dead port>`, and you'll lose internet access until you either re-launch Proxymate and toggle off, or manually clear the setting from **System Settings → Network → Details → Proxies**.

## 4. The onboarding wizard

On the first launch after install, a wizard sheet opens over the main panel. It has six steps tracked by a progress bar at the top and navigation buttons at the bottom.

The wizard persists completion status under the UserDefaults key `proxymate.onboarded`. The flag flips to `true` only from `applyAndDismiss()` — when you reach the final step and click **Finish** (or **Finish & Enable**). Any other dismissal path — ESC, click outside the sheet, window close, the **Skip for now** button on step 1 — leaves the flag at `false`, and the wizard reappears on the next launch. This is intentional: an accidental dismissal should never trap a user with an unconfigured app.

### Step 1 — Profile

Five profile presets. Selecting one determines which blacklist feeds, privacy defaults, and allowlist entries are applied at the end.

| Profile | Blacklists applied | Privacy | Extras |
| --- | --- | --- | --- |
| **Privacy** (default) | Ads, Telemetry, CryptoMiner, Malware, Phishing | inherits slider | DoH on |
| **Developer** | Malware, CryptoMiner | inherits slider | Cache on |
| **Enterprise** | Malware, Phishing, Ads, CryptoMiner, TorExits | inherits slider | Allowlist seeded with `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| **Family Safety** | Malware, Phishing, Ads, CryptoMiner, Telemetry, Adult | inherits slider | — |
| **Minimal** | _none_ | inherits slider | — |

An inline note appears under **Minimal** (`"No blacklists, no privacy actions, no cache — you configure everything manually."`) so the "Ready to Go" summary later doesn't feel like a lie.

### Step 2 — Upstream proxy

Single toggle: **I have an upstream proxy**.

- **Off** — Proxymate will use its bundled Local Squid sidecar (127.0.0.1:3128) as the upstream. Traffic flow: `client → Proxymate listener → bundled Squid → internet`.
- **On** — fill in `host` and `port` (defaults to `8080`). The Next button is disabled until both validate. Rules:
  - Host: 1–253 characters, must match `[A-Za-z0-9.-:]`. Shell metacharacters rejected to prevent injection into the privileged `networksetup` call downstream.
  - Port: integer in `1...65535`.

Validation failure surfaces inline in orange: `"Host cannot be empty"`, `"Host contains invalid characters"`, or `"Port must be 1–65535"`.

There is no "no upstream / direct forwarding" mode in the current architecture. Either the bundled Squid is used, or a configured remote proxy is used. Any selected upstream is reachable from Proxymate's listener — if it isn't, every request returns 502.

### Step 3 — Privacy level

A three-position slider (`Minimal` / `Moderate` / `Maximum`) controls the `PrivacySettings` struct:

| Slider position | Fields set to `true` |
| --- | --- |
| Minimal | `forceDNT`, `forceGPC` |
| Moderate | above + `stripTrackingCookies` |
| Maximum | above + `stripUserAgent`, `stripReferer` (policy: `originOnly`), `stripETag` |

A separate toggle below the slider enables DNS-over-HTTPS through Cloudflare (`one.one.one.one`, RFC 8484 JSON API). When off, Proxymate uses the system resolver.

You can verify header injection by probing an echo service while the proxy is on:

```bash
curl -s -x http://127.0.0.1:$(scutil --proxy | awk '/HTTPPort/{print $3}') \
    http://httpbin.org/headers | grep -iE 'Dnt|Sec-Gpc|User-Agent'
#   "Dnt": "1",
#   "Sec-Gpc": "1",
#   "User-Agent": "Mozilla/5.0 ... "
```

### Step 4 — AI observability

Single toggle. When on:

- Outbound requests to the 11 built-in providers (OpenAI, Anthropic, Google, Mistral, Cohere, Together, Groq, DeepSeek, Perplexity, xAI, Ollama) are tagged as AI traffic.
- Token usage is parsed from response bodies (including SSE streams and gzipped responses — the `Content-Encoding: gzip` branch was fixed in 0.9.49).
- Cost is estimated using a built-in pricing table covering 17 models.
- User-Agent and request headers are scanned for agent fingerprints (Claude Code, Cursor, Windsurf, Aider, Copilot, Codex CLI).
- The loop breaker watches for rapid-fire identical requests — stuck agents.

The toggle has no side effect on non-AI traffic. Budget caps and model allowlists are configured later in the AI tab; the onboarding step only chooses whether the pipeline runs at all.

### Step 5 — HTTPS inspection

Generates a local root CA and adds it to the system trust store. Required for MITM (deep HTTPS inspection); optional otherwise.

Clicking **Install Certificate** runs this state machine:

1. **Generating** — openssl runs on a detached task; UI shows a spinner labeled `Generating…`. Duration: ~3 seconds.
2. **Waiting for trust** — `security add-trusted-cert` is invoked via `osascript with administrator privileges`. You see the native admin prompt. UI shows `Waiting for trust confirmation…`.
3. **Installed & trusted** — the app polls `SecTrustEvaluate` every 500 ms for up to 15 seconds. As soon as the OS reports the CA as trusted, the UI flips to green: `Certificate installed & trusted`.
4. **Error** — if you cancel the admin prompt or the poll times out, the UI shows an orange error instead of a false green checkmark. The CA file exists on disk but isn't trusted; you can retry from this step or later from **Privacy → MITM**.

The CA private key lives at `~/Library/Application Support/Proxymate/ca/ca.key` as an AES-256 encrypted PEM (`-----BEGIN ENCRYPTED PRIVATE KEY-----`). The 32-byte symmetric passphrase is stored in your login Keychain under service `fabriziosalmi.proxymate.tls`, account `ca-key-passphrase-v1`, accessibility `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (not iCloud-syncable).

### Step 6 — Summary & finish

A summary card lists your choices, followed by a final toggle **Enable the proxy now** (defaults on). The button label tracks the toggle:

- Toggle on → button reads **Finish & Enable**; clicking it persists settings, marks you onboarded, and immediately calls `AppState.enable()`.
- Toggle off → button reads **Finish**; clicking it persists settings and closes the wizard without enabling.

The admin prompt for `networksetup` appears at this step only if **Enable the proxy now** is on. Cancelling it logs `System proxy apply failed` and leaves the app disabled; settings are still saved and you can retry from the header toggle whenever.

## 5. Enabling the proxy

The enable flow is a deterministic seven-stage chain. Knowing the order helps when something doesn't look right — each stage logs its own entry so the Logs tab gives you a trace of where the sequence stopped.

1. **Validate selection.** The selected `ProxyConfig` must exist and have a port in `1...65535`. Otherwise the log shows `warn: No proxy selected` or `error: Invalid upstream port` and nothing else runs.
2. **Check current system state.** `SCDynamicStoreCopyProxies` reads the live config. If it already matches the target host:port, the privileged call is skipped. This is why wake-from-sleep and network interface changes (Wi-Fi ↔ Ethernet, VPN up/down) no longer trigger admin prompts — the app recognizes when nothing needs doing.
3. **Ensure local sidecar.** If the selected upstream is `127.0.0.1:3128` (the bundled Local Squid), `SquidSidecar.start()` is called before forwarding. If another process already holds port 3128, the foreign process is reused; no port collision, no error.
4. **Bind local listener.** `NWListener` on `127.0.0.1` with an OS-assigned ephemeral port (typically 5 digits, e.g. 52486). The port is published to `localPort` on success.
5. **Apply system proxy.** `networksetup -setwebproxy` + `-setsecurewebproxy` for every active network service, plus `-setproxybypassdomains` for the default bypass list (`localhost`, `127.0.0.1`, `::1`, `*.local`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`). Executed via `osascript do shell script with administrator privileges` — the admin prompt appears here.
6. **Verify apply took effect.** `SCDynamicStore` is read back; if `host` or `port` don't match expectations, `ProxyManagerError.verificationFailed(expected: ..., actual: ...)` is thrown. This guard exists because the macOS 26 `AuthorizationExecuteWithPrivileges` API could return success while doing nothing — the first major bug that triggered the v0.9.48 audit.
7. **Start optional listeners.** PAC server, SOCKS5 listener, and Prometheus metrics endpoint each try to bind if enabled. Bind failures are logged explicitly, never silent:
   - `[PACServer] bind on :18095 failed: Address already in use`
   - `[MetricsServer] bind on :9199 failed: ...`
   - `SOCKS5 bind on :1080 failed: ...`

When the chain completes, the header toggle turns blue, the status line reads `On`, and the Logs tab begins filling as applications open their first TLS connections through the proxy.

## 6. Tab: Proxies

**Where:** Menu bar → Proxies tab. Three sub-sections selectable by a segmented control: **Quick**, **Pools**, **PAC**.

### Quick (single upstream)

A flat list of saved upstream proxies. The selected one (marked with a blue dot) is the current forwarding target for new connections.

**What it shows:** each row is `name · host · port · applyToHTTPS`. The two default entries present after install are `Local Squid` (`127.0.0.1:3128`, HTTPS on) and `Local mitmproxy` (`127.0.0.1:8080`, HTTPS on).

**Controls:**

- **Tap** a row to select it as the active upstream. If the proxy is currently enabled, `LocalProxy.updateUpstream()` is called immediately — no disable/re-enable cycle needed.
- **Right-click → Use this proxy / Create Pool from this / Delete.** The Delete action opens a confirmation dialog naming the proxy and showing its `host:port` — a right-click misfire cannot destroy data silently.
- **+ Add** (bottom-left) — opens a sheet with Name, Host, Port, "Apply to HTTPS too". The Add button disables until host and port validate; host follows the same rules as Step 2 of the wizard.
- **Quit** (bottom-right) — duplicate of the footer Quit.

**Expected behavior:** switching the selection while enabled triggers `Switched upstream to <name>` in the Logs tab. If the new upstream is a bundled sidecar (Local Squid), `SquidSidecar.start()` is called alongside the updateUpstream so there's no 502 while the switch settles. This gap was a P1 lifecycle bug closed in 0.9.49.

**Gotchas:**

- Deleting the currently-selected proxy sets `selectedProxyID` to `nil`; the next enable will fail with `No proxy selected` until you pick another.
- You cannot add a duplicate `host:port` pair — the add sheet accepts the click but the second entry is a separate row pointing at the same target. No merging.

### Pools

Multi-member upstreams with a load-balancing strategy and health checks. Used by users running several upstream proxies (redundant corporate gateways, multi-region exits, etc.).

**What it shows:** each row is `pool name · member count · strategy · default flag`. Strategies available: `roundRobin`, `leastConnections`, `weightedRandom`, `weightedRoundRobin`, `latency`, `sticky`.

**Controls:**

- **Right-click → Set as Default / Delete.** Only the default pool is used automatically; non-default pools must be targeted via a routing override.
- **+ Add** — sheet with Name, First Member Host, First Member Port, Strategy picker. Additional members are added later via right-click on the pool row (the comment under the sheet says so explicitly).
- **Route** — appears when at least one pool exists. Opens the add-override sheet to map a host pattern (`*.github.com`) to a specific pool.

**Expected behavior:** the pool members table below each row shows per-member status — `healthy / unhealthy / degraded` — and active connection counts. Health checks run every 30 seconds per pool; failures count against a circuit breaker (3 consecutive fails → member removed from rotation; first success → reinstated).

**Gotchas:**

- Creating a pool with zero members is allowed but the router treats it as empty and falls back to the Quick-selected proxy. A log warning helps here but the behavior is easy to mistake for "routing is broken."
- Deleting a pool that has overrides pointing at it leaves the overrides orphaned; the confirmation dialog names the member count so you get a hint about impact.

### PAC

The Proxy Auto-Configuration server. Generates a dynamic `proxy.pac` reflecting the current upstream + bypass list + direct domains. Applied to the system via `networksetup -setautoproxyurl`.

**What it shows:** toggle, port input (default 18095), and the current PAC URL (`http://127.0.0.1:18095/proxy.pac`) that your browsers / applications would fetch.

**Controls:**

- **Enabled toggle** — starts `PACServer`, applies the system autoproxy URL, and configures browsers that respect system PAC to fetch it.
- **Port** — numeric input. Changes rebind the listener and re-apply system config.

**Gotchas:**

- Port bind failures now log to Console.app (`[PACServer] bind on :18095 failed: ...`) — before 0.9.49 the toggle stayed on with no server listening.
- The app does not debounce port input, so typing `1809` then `5` issues one rebind per keystroke. Pre-plan the value before tweaking the field.

## 7. Tab: Logs

**Where:** Menu bar → Logs tab.

**What it shows:** a live feed of structured log entries. Each entry has a level (`debug`/`info`/`warn`/`error`), a message, an optional host field, and a timestamp. New entries appear at the top.

**Controls:**

- **Search field** — debounced at 300 ms, case-insensitive substring match against message + host.
- **Level filter** — monospace toggles `All / I / W / E`. Click one to filter to that level only; click the active one to clear the filter.
- **Right-click on a row** — quick actions per host: `Block <host>`, `Allow <host>`, `Search: <host>`, `Copy`, `Copy as JSON`.
- **Clear** (bottom-right) — confirmation dialog shows the count. Clearing drops only in-memory entries; the persistent JSONL files on disk are untouched. Clear also resets the per-event dedupe set, so after clearing you'll see the same class of event log again (before 0.9.49 it stayed suppressed).

**Expected behavior:** in-memory buffer is capped at 500 entries (oldest dropped). Persistent log is at `~/Library/Application Support/Proxymate/logs/proxymate.log`, rotated at 2 MB, 5-file retention. Format is JSON Lines:

```json
{"timestamp":"2026-04-14T10:22:13Z","level":"warn","message":"BLOCKED doubleclick.net — Block Domain: doubleclick.net","host":"doubleclick.net","id":"..."}
```

**Gotchas:**

- Noise suppression: repeat events within a session are logged once by default (BLOCKED, BLACKLIST, AGENT detection, AI detection). The first occurrence passes; subsequent occurrences of the same `(event, host, rule)` key are muted until the dedupe set is cleared (on disable or on Clear Logs).
- Allowed requests are intentionally not logged individually — they would dominate everything else. The Stats tab carries the count.

## 8. Tab: Stats

**Where:** Menu bar → Stats tab.

**What it shows:** ten counter cards and a 60-second live chart of requests/sec.

**Counters:**

- **Status** — On / Off
- **Active Since** — relative time since last enable (`"2 minutes ago"`)
- **Allowed** — requests that passed every filter
- **WAF Blocked** — requests rejected by domain/IP/content rules
- **Blacklisted** — hits from one of the 19 feeds
- **Exfiltration** — pattern matches in headers/URL (AWS keys, JWTs, …)
- **Privacy** — header rewrites applied
- **MITM** — TLS handshakes intercepted
- **Cache Hit Rate** — L1+L2, percentage (`—` if no cache activity yet)
- **Log Entries** — in-memory count

**Chart:** `requests/sec` plotted as two area marks (allowed in blue, blocked in red) over the last 60 seconds. Updates every second via a shared `statsTick` publisher at 1 Hz. Before 0.9.49 the chart was seeded at zero and stayed flat — the fix re-publishes the nested `StatsTimeSeries` ObservableObject through AppState so SwiftUI re-renders.

**Controls:** none. The tab is read-only.

**Gotchas:**

- Counters persist across disable/re-enable within the same app launch. They don't reset on disable (this is intentional, but can be confusing if you expect per-session isolation). App quit clears them.
- `Active Since` resets to `—` on disable and restarts on the next enable.

## 9. Tab: Rules

**Where:** Menu bar → Rules tab. Three sub-sections: **WAF**, **Blacklists**, **Exfiltration**.

### WAF

Hand-authored rules grouped by category. Supported kinds: `Block Domain`, `Block IP`, `Block Content` (literal substring), `Block Regex`, `Allow Domain`, `Mock Domain` (stealth 200 OK instead of 403).

**Controls:**

- **Row tap** — toggles enabled.
- **Right-click → Delete** — confirmation shows rule kind and pattern.
- **+ Add** — sheet with Name, Kind picker, Pattern, Category. For `Block Regex`, the pattern is compiled with `NSRegularExpression` at input time; invalid regexes disable the Add button and show an orange hint (`"Regex doesn't compile — check the pattern syntax"`). This prevents the crash-at-first-match that pre-0.9.49 builds had.
- **Import** — parses hosts files, Adblock Plus filters, or plain domain lists. Duplicate patterns are skipped.

### Blacklists

Feed-backed denylists. Two sections: built-in (Steven Black, OISD, URLhaus, etc.) and custom URL sources the user adds.

**Controls:**

- **Refresh** — kicks off a concurrent refresh of all enabled sources. The spinner runs as long as `state.refreshingBlacklistsCount > 0`; before 0.9.49 it was a hardcoded 2-second fake.
- **+ Add Custom** — sheet requires a valid `http(s)` URL (validated via `URL(string:)` + scheme + host check). Empty or non-URL input disables the Add button.

**Aggregate row** at the bottom of the list: `Total · Unique · Sources`. All three numbers depend on the 1 Hz `statsTick` to refresh — `BlacklistManager` is not an `ObservableObject`.

### Exfiltration

Pre-built pattern packs that scan outbound request headers and URLs for AWS access keys, GitHub PATs, Stripe secrets, Slack tokens, JWTs, IBAN/credit-card/SSN shapes, and common PII patterns. Checkboxes to enable/disable each pack.

Matches fire either a 403 (default for HIGH/CRITICAL severity) or a tarpit response (holds the connection indefinitely so the client doesn't know they were blocked — useful against malicious apps that retry on error).

## 10. Tab: AI

**Where:** Menu bar → AI tab.

**What it shows:** three sections — Providers, Spend Summary, Budget + Model controls, and Loop Breaker.

**Providers grid:** the 11 built-in providers. Each card shows request count and cumulative tokens (`input + output`). Cards only appear for providers that have observed at least one request; non-detected providers are hidden.

**Spend Summary:** `Today` and `This Month` cumulative cost in USD, computed via `AITracker.getTotalSpend()`. Depends on `statsTick` for live updates.

**Budget controls:**

- **Daily limit** / **Monthly limit** — currency inputs. `0 = no limit`. Values are clamped to `max(0, value)` on write — the input field cannot hold a negative number. Values `> 0` engage the budget cap: when cumulative spend exceeds the limit, `AITracker.isBlocked()` returns true and outbound AI requests get a 403 with `AI Budget: daily cap reached`.
- **Model allowlist / blocklist** — per-provider text fields. Comma-separated model names. If the allowlist is non-empty, only listed models are permitted; if the blocklist is non-empty, listed models are rejected. The two lists are checked in that order.

**Loop Breaker settings:**

- **Rapid-fire threshold** — N identical requests within M seconds triggers a warn log; beyond a higher threshold triggers a block with a 15-second cooldown.
- **Cooldown seconds** — how long a blocked loop stays blocked.
- **Cost runaway cap** — $/minute. Exceeding this across all AI traffic triggers a hard block regardless of daily/monthly budget.

**Gotchas:**

- The budget cap operates on the cost estimate, not actual invoice figures. Pricing is approximate; treat it as a warning signal, not a billing truth.
- Blocked requests still count against the rate-limit counters of the remote provider. A blocked request at Proxymate is a rejected request from your app's perspective, not a suppressed one at Anthropic.

## 11. Tab: Cache

**Where:** Menu bar → Cache tab. Two sub-sections: **HTTP Response Cache** (L1 RAM) and **Disk Cache** (L2 SQLite).

### L1 RAM cache

**Toggle:** enable/disable L1 caching entirely.

**Controls:**

- **Max size (MB)** — LRU eviction when exceeded.
- **TTL (seconds)** — upper bound on cache entry lifetime, in addition to the `Cache-Control` / `Expires` headers of the response itself.
- **Strip tracking params** — removes `utm_*`, `fbclid`, `gclid`, etc. from the cache key. Two URLs differing only in `utm_source` hit the same cache entry.

**Statistics row:** `Hits · Misses · Size`. All three depend on `statsTick` because `CacheManager` is not an `ObservableObject`.

### L2 Disk cache

**Toggle:** enable/disable L2 caching.

**Controls:**

- **Max size (MB)** — SQLite metadata + a sharded filesystem of body files under `~/Library/Caches/com.fabriziosalmi.proxymate/cache/bodies/`.
- **Purge** — confirmation dialog before deleting. Clears both the SQLite rows and the body files; `currentSizeMB` resets to 0.

**Expected behavior:** Full HTTP semantics — `Cache-Control: no-store` skips caching; `Vary` spawns per-header-set entries; conditional revalidation uses `ETag` / `Last-Modified`. Only GET responses are stored; POST/PUT/DELETE never cache.

**Gotchas:**

- The L2 cache is per-user, not system-wide. `sudo` tools and your user share no cache.
- Purge acts on both L1 and L2 if you click it from the L2 section; the L1 section has its own separate (non-confirmed) clear.

## 12. Tab: Privacy

**Where:** Menu bar → Privacy tab. Everything not covered by the other tabs: privacy headers, MITM settings, DoH, webhooks, metrics, SOCKS5.

### Privacy headers

Four toggles + a picker:

- **Force DNT** — `DNT: 1`
- **Force GPC** — `Sec-GPC: 1`
- **Strip User-Agent** — replaces with `customUserAgent` (configurable text field)
- **Strip Referer** — picker for policy: `strip` (remove entirely) or `originOnly` (reduce to scheme + host).
- **Strip tracking cookies** — filters `_ga`, `_fbp`, `utma`, `fbm_`, and other prefixes listed in `PrivacySettings.trackingCookiePrefixes`.
- **Strip ETag** — defeat supercookies.

Changes apply immediately to new connections (no reload required). Privacy actions are counted in `stats.privacyActions`.

### MITM inspection

**Toggle** — on only if the CA is installed and trusted. When the toggle is on, HTTPS CONNECTs chain through the bundled `mitmproxy` sidecar on `127.0.0.1:18080`, which decrypts the stream and re-encrypts toward upstream.

**Exclude hosts field** — text input below the toggle for per-host MITM opt-out. Wildcard patterns supported (`*.banking.com`). The default exclude list covers Apple services, iCloud, banking, Signal, WhatsApp, Telegram, and Mozilla services.

**Runtime excludes** — a separate, auto-populated list shown below the manual excludes. Hosts that fail TLS handshake 3 consecutive times (indicating certificate pinning) are auto-added here and never intercepted again. Cleared on CA removal.

**Controls:**

- **Install Certificate** / **Remove** — both are async with explicit state transitions (`installing → waiting for trust → trusted | error`). Remove is behind a confirmation dialog explaining the impact.
- **Trust** — only visible if the CA file exists but isn't trusted yet. Re-runs `security add-trusted-cert`.

### DNS-over-HTTPS

Toggle + provider picker (`Cloudflare`, `Quad9`, `Google`, `Custom`). Queries go to the provider's RFC 8484 JSON API. When on, Proxymate's DNS resolution for upstream hostnames uses DoH instead of the system resolver; client DNS queries (e.g. from your browser) continue to use the OS resolver unless you also point your browser at a DoH endpoint.

### Webhooks

List of URLs to POST event payloads to. Events: block, blacklist, exfiltration, budget-exceeded. Payload is `application/json`:

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

Debounced at 5 seconds per `(event, host)` pair to prevent flooding. Delivery failures are logged to Console.app as `[Webhook] POST <url> failed: ...` — before 0.9.49 they were silent.

### Metrics

Toggle + port (default 9199). Exposes Prometheus text-format metrics at `http://127.0.0.1:<port>/metrics`:

```
proxymate_requests_total{outcome="allowed",upstream="Local Squid"} 1284
proxymate_requests_total{outcome="blocked",upstream="Local Squid"} 47
proxymate_latency_seconds_bucket{le="0.005"} 1125
proxymate_active_connections 12
proxymate_blacklist_hits_total{source="Steven Black Hosts (Ads)",category="Ads"} 38
proxymate_ai_tokens_total{provider="anthropic",model="claude-opus-4-6",direction="output"} 4912
proxymate_cost_usd_total{provider="anthropic"} 0.1204
```

### SOCKS5 listener

Toggle + port (default 1080). When on, a SOCKS5 server listens on loopback, sharing the same WAF/privacy pipeline as the HTTP listener. Useful for CLIs that prefer SOCKS (e.g. `ssh -D`).

Port bind failures log through the app's event bus: `SOCKS5 bind on :1080 failed: ...`.

## 13. When things go wrong

Common failure signatures and where to look.

**Every request returns 502.** The selected upstream is unreachable. Check the Logs tab for `Upstream failed: Failed to connect`. If the upstream is `Local Squid` (127.0.0.1:3128), verify the sidecar started: `lsof -nP -iTCP:3128 -sTCP:LISTEN`. If nothing listens, force a fresh toggle off/on — the ensure-sidecar bootstrap runs on every enable.

**Browser says "Cannot verify developer".** You launched the DMG without mounting it, or the DMG is not the notarized release. Re-download from the official release page and re-verify the SHA.

**CA step loops at "Waiting for trust confirmation"** for 15 seconds then errors out. You cancelled the admin prompt or left it unanswered. Retry from the Privacy tab.

**HTTPS sites break for one specific app.** It's cert-pinned. Look for `pinning failure on <host>` in the Logs; after 3 such failures Proxymate auto-adds the host to the runtime exclude list. Force-quit-proof: the exclude survives a quit.

**System proxy won't turn off after quit.** Force-quit skipped the cleanup path. Open System Settings → Network → Details → Proxies, toggle off `Web Proxy` and `Secure Web Proxy`. Or relaunch Proxymate and toggle the header off — the idempotent apply will clear correctly.

**Stats counters don't move but traffic is flowing.** You're on a build older than 0.9.49 — the singleton-read publisher wasn't wired up. Upgrade.

**"No proxy selected" warning on enable.** The previously-selected proxy was deleted. Open Proxies → Quick and tap a row to select.

**Admin password asked repeatedly.** This happens if the system proxy state drifted (external config tool, sleep/wake race) and the idempotent short-circuit can't match the target. Typically one prompt per intentional toggle is expected; more than that is worth reporting.
