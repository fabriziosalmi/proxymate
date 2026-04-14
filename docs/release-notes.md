# Release notes

## 0.9.56 — fix Root CA generation on macOS, add Export CA button, site-compat harness

*Released 2026-04-14*

Three unrelated fixes/additions bundled.

### 1. Root CA generation no longer fails on macOS out-of-the-box

macOS ships LibreSSL as `/usr/bin/openssl`, and both LibreSSL and modern OpenSSL 3.x have removed `-aes256` as an inline flag for `req -newkey`. The single-command CA generation in earlier builds silently depended on a legacy form that no longer works on a stock macOS — the UI reported `openssl req -x509 failed` and MITM was unusable until the user manually copied a CA in place.

Fix: generation is now two `openssl` invocations — `genpkey -aes-256-cbc` for the encrypted key, then `req -x509 -new -key` for the self-signed cert. Portable across LibreSSL and OpenSSL 3.x. No user-visible change beyond "it works".

### 2. Export Root CA button in the MITM section

Firefox uses its own certificate store and doesn't read the macOS system keychain. Users importing Proxymate's CA into Firefox needed to know the on-disk path (`~/Library/Application Support/Proxymate/ca/ca.pem`) — undiscoverable without the docs.

Preferences → Privacy → TLS Interception now has an **Export** button next to Trust / Remove that copies the CA to `~/Downloads/proxymate-ca.pem` and reveals it in Finder. Drag-drop straight into Firefox → Certificates → Authorities → Import.

### 3. `tests/site-compat/` — Playwright diagnostic harness

New on-demand tool for when a user reports "site X doesn't work." `./scripts/diagnose-site.sh https://example.com` drives a real browser through Proxymate, captures failed requests, console/CORS errors, page errors; cross-references each failed host against the live proxy log to classify as **BYPASS** (never reached the proxy), **PROXY_ERROR** (reached the proxy but got 4xx/5xx), or **BROWSER** (reached the proxy fine; browser surfaced the failure anyway).

Suite mode (`--suite`) runs across a canonical list of sites and supports baseline (`--no-proxy`), MITM-off/on tagging, and cross-mode diff (`--compare direct proxy-mitm-on`). Zero telemetry outbound — all local. Full docs in `tests/site-compat/README.md`.

### Artifact

```
File:    Proxymate-0.9.56.dmg
Size:    64 MB
SHA-256: 568cc6e76b54634bce2245bbd184005adba265095104511dcbb2da0a6e2051ae
Signed:  Developer ID Application: Fabrizio Salmi (7FC7ZTYMYU)
Notary:  Accepted, stapled, spctl-verified
```

## 0.9.55 — disable HTTP/2 downstream to stop browser connection coalescing

*Released 2026-04-14*

Finishes the MITM reliability work started in 0.9.54. The Alt-Svc strip closed the QUIC bypass; this closes the HTTP/2 coalescing hole that was breaking GitHub, LinkedIn, and any site whose assets live on a sibling CDN host under the same edge.

### The mechanism

Browsers — Firefox most aggressively ([Bugzilla 1420777](https://bugzilla.mozilla.org/show_bug.cgi?id=1420777)) — reuse a single HTTP/2 connection across different hosts that resolve to the same IP and are covered by a compatible certificate. `github.com` + `github.githubassets.com` (Fastly), `www.linkedin.com` + `static.licdn.com`. When mitm is in the middle the per-host leaf certs should break the heuristic, but Firefox bases it partly on destination IP and coalesces anyway. The browser then sends subresource requests with an `:authority` that doesn't match the stream's SNI, mitmproxy treats that as a protocol violation and resets the stream, and everything surfaces as `CORS request failed. Status code: (null)` on `<script type="module" crossorigin>` tags. Invisible in the Logs tab because no flow ever completes.

### The fix

`--set http2=false` passed to mitmdump. Browser ↔ mitm traffic falls back to HTTP/1.1 which has no coalescing — one connection per host, no `:authority` mismatch. The upstream leg (mitm → Squid) was already HTTP/1.1 so there is no protocol downgrade on that side.

Cost: a few extra TCP connections to the loopback port. On localhost this is free.

Reference: [mitmproxy #7191 — HTTP/2 fails, HTTP/1.1 works](https://github.com/mitmproxy/mitmproxy/discussions/7191) documents the same pattern from the other direction.

### Artifact

```
File:    Proxymate-0.9.55.dmg
Size:    64 MB
SHA-256: 43e5404847cbbac8047f30b1d682907eee7aa3afc3f193f28870f313a0085bfc
Signed:  Developer ID Application: Fabrizio Salmi (7FC7ZTYMYU)
Notary:  Accepted, stapled, spctl-verified
```

## 0.9.54 — strip Alt-Svc to keep browsers on HTTP/2 inside the MITM tunnel

*Released 2026-04-14*

Fixes a silent MITM-bypass path that broke LinkedIn and any site whose subresources advertise HTTP/3 endpoints.

### The problem

macOS system proxies (`networksetup -setwebproxy`, `-setsecurewebproxy`) only proxy **TCP**. UDP — which carries QUIC / HTTP/3 — has no system-level proxy hook. When a server responds with `Alt-Svc: h3=":443"`, browsers open a QUIC connection directly to the origin on UDP/443 and bypass Proxymate entirely. For an HTML document loaded via MITM, subsequent `<script type="module" crossorigin>` fetches to a sibling CDN (e.g. `static.licdn.com`) then upgrade to HTTP/3 on a path Proxymate cannot see — and if that path fails for any reason the browser surfaces `CORS request failed. Status code: (null)` rather than retrying on HTTP/2.

This is invisible in the Proxymate Logs tab because the failing traffic never touches the proxy.

### The fix

`proxymate_addon.py` now strips `Alt-Svc` from every response when MITM is active. Browsers never learn that HTTP/3 is available, stay on the existing HTTP/2 connection through mitm, and everything keeps flowing through the tunnel.

This does not break sites — HTTP/3 is an optimization, not a requirement. It does mean that **when MITM is on, Proxymate sees all traffic; when MITM is off, QUIC traffic bypasses Proxymate** (macOS limitation, documented in `guide/mitm-browser-trust`).

### Artifact

```
File:    Proxymate-0.9.54.dmg
Size:    64 MB
SHA-256: 591bcb53225ea562927e7c367f9cff7455691371cdf719b7e056a412447306ce
Signed:  Developer ID Application: Fabrizio Salmi (7FC7ZTYMYU)
Notary:  Accepted, stapled, spctl-verified
```

## 0.9.53 — window-title version label, streaming-CDN excludes, browser trust guide

*Released 2026-04-13*

Small-surface polish release on top of 0.9.52.

### 1. Version visible in the main window header

The header button now shows `Proxymate 0.9.53` inline — version read from `CFBundleShortVersionString` at startup, so what the window shows is always what's running. Makes tester bug reports self-identifying without needing to ask "which build are you on?".

### 2. Streaming-media CDN defaults in the MITM exclude list

Expanded `MITMSettings.excludeHosts` with the audio/video hosts that reliably cert-pin: Italian broadcasters (`*.rai.it`, `*.raiplay.it`, `*.raiplaysound.it`, `*.mediaset.it`, `*.la7.it`), YouTube/Vimeo/Twitch/Spotify media CDNs, Netflix, Disney+/Hulu, DAZN, Brightcove, plus the Akamai *media* subdomains (`*.akamaihd.net`, `*.akamaized.net`) — not the generic Akamai tenant pool. Generic multi-tenant edges (Cloudflare, CloudFront, plain `akamai.net`) stay in MITM because opting them out means opting out half the web.

Fixes the RadioRai regression reported against 0.9.51 and the Mediaset / La7 segment-load failures that showed up in Logs as `pinning failure`.

### 3. New docs page: `guide/mitm-browser-trust`

Per-browser CA trust matrix (Safari auto, Chromium via system keychain, Firefox manual import) and a section explaining why HSTS and HSTS-preload do *not* block MITM when the CA is trusted — only certificate pinning does. The shortest possible answer to "I installed the CA, why does site X still fail?".

### Artifact

```
File:    Proxymate-0.9.53.dmg
Size:    64 MB
SHA-256: b185708c366bbfbfa3e6b777a3466450f283ee5e63cfa4df73ad7048368fd9b7
Signed:  Developer ID Application: Fabrizio Salmi (7FC7ZTYMYU)
Notary:  Accepted, stapled, spctl-verified
```

## 0.9.52 — proactive CA-encryption migration + sidecar timeout headroom + diagnose v3

*Released 2026-04-14*

Cleanup release after the 0.9.51 critical fix. Three concrete changes plus a tooling upgrade. Same signed, notarized, stapled distribution.

### 1. CA encryption migration now runs at app launch

Earlier builds gated `ensureCAKeyEncrypted()` behind `identityForHost`, which has two early-return paths: memory cache hit, then disk cache hit. Any user with a warm leaf-cert cache from before the encryption work landed never reached the migration code, and the CA key stayed in plaintext indefinitely.

Fix: `migrateCAEncryptionIfNeeded()` is a public no-arg entry point, called from `AppState.init` alongside the CA-expiry check. Idempotent — early-returns when the file is already encrypted, costs ~5 ms (a single 256-byte read) when nothing needs doing.

### 2. mitmdump startup timeout 10 s → 20 s

Tester reported `"mitmdump didn't accept connections on :18080 within 10 s"` while macOS was under sustained memory pressure. The CPython import phase normally takes ~1.5 s, but page-cache thrashing stretches it to 10–15 s. Bumped the `waitForLocalPort` ceiling in `MITMProxySidecar.start` to 20 s. No effect when the sidecar starts quickly; just headroom for the rare slow-start case.

### 3. scripts/diagnose.sh v3 — color, accuracy, polish

The triage tool from 0.9.50 got a substantial pass:

- **Color output** when run on a TTY (green ✓, yellow !, red ✗, gray –). Plain text when piped to file/CI/gist so grep-friendly tooling stays unchanged.
- **Section 7 false-positive fixed**: `pgrep -lf "mitmdump|squid"` matched any process whose argv contained those strings — including the shell running diagnose itself. Now uses `pgrep -x` to match exact process names.
- **Section 11 (UserDefaults) reads correctly**: previously returned `0 bytes` for every key because keys carry version suffixes (`.v1`/`.v2`) and `defaults read fabriziosalmi.proxymate` resolves to a leftover sandbox container path on macOS 26. Now reads the prefs file by full path with both versioned suffixes probed.
- **Section 18 distinguishes Debug vs Release**: bundled squid signature mismatch on Debug builds is expected (release rebuilds re-sign with Developer ID); Debug now gets a SKIP, release still WARNs.

Verdict summary at the end shows colored OK / WARN / FAIL counts and an exit code (0/1/2) that slots into CI or launchd healthchecks.

### What 0.9.52 does NOT include

No new user-facing features. No protocol changes. No schema changes. Existing 0.9.51 configs work without migration.

### Artifact

```
File:    Proxymate-0.9.52.dmg
Size:    64 MB
SHA-256: 6670f2d66ad5e50bb84d79c6a41a4bb03abcf6185613a21be0b845fbda81b8c8
Signed:  Developer ID Application: Fabrizio Salmi (7FC7ZTYMYU)
Notary:  Accepted, stapled, spctl-verified
```

## 0.9.51 — system proxy hijack fix + admin-prompt batching

*Released 2026-04-14*

Two issues fixed; both observable in tester sessions.

### 1. NWPathMonitor / systemDidWake silently rewrote system proxy

When the proxy was enabled and macOS reported a network path change (Wi-Fi reassociate, VPN up/down, sleep/wake, anything `NWPathMonitor` flags), the handler called `ProxyManager.enable(proxy: <user-selected upstream>)` instead of `ProxyManager.enable(proxy: <synthetic loopback proxy on the listener port>)`. With the default selection of `Local Squid` (host `127.0.0.1`, port `3128`), the system proxy got rewritten from `127.0.0.1:<listener>` back to `127.0.0.1:3128`. Browsers then bypassed Proxymate entirely and went straight to Squid; the Stats counters stayed at zero and the Logs tab never received an event.

The original Enable wrote the right thing to scutil; a few hundred milliseconds later, the path-change handler overwrote it. The bug was entirely invisible in the app log — which only showed `Enabled — local 127.0.0.1:NNNNN → upstream Local Squid` — and required `scutil --proxy` to see.

Fix: new `AppState.reapplySystemProxyIfNeeded()` reconstructs the synthetic config from `localPort` and calls `ProxyManager.enable` with that. Both `NWPathMonitor.pathUpdateHandler` and `systemDidWake` now route through this method instead of building a wrong-pointer `ProxyConfig` themselves.

### 2. Enable / Disable cost multiple admin prompts

Each `runAsRoot` call is its own `osascript` invocation; macOS 26's "with administrator privileges" cache doesn't bridge between distinct invocations. With PAC enabled, a single Enable click cost two prompts (`networksetup -setwebproxy`, then `networksetup -setautoproxyurl`), and a Disable cost two more. Path-monitor wake-ups added more.

Fix: batched both networksetup transactions into a single shell that's run by one `osascript`. `ProxyManager.enable(proxy:pacURL:)` now accepts an optional PAC URL and writes both the web proxy and the autoproxy URL in the same loop. `ProxyManager.disable()` clears both states the same way; the separate `PACServer.clearSystemPAC` call in `AppState.disable` is gone.

Net effect: Enable = 1 prompt regardless of PAC. Disable = 1 prompt regardless of PAC. Wake/path-change = 0 prompts (idempotent skip on the synthetic config still works).

### Bonus: scripts/diagnose.sh v2

The triage tool added at the end of the 0.9.50 cycle is now exhaustive — 19 sections, OK/WARN/FAIL verdict tags on every check, summary at the end with an exit code. Coverage:

1. Environment (macOS, arch, kernel, uptime)
2. Process (PID, RSS, fd count, build identity)
3. Code signature (codesign --strict, spctl, stapler ticket)
4. Entitlements (every required key)
5. Listeners + sidecar port conflict scan
6. System proxy state (with explicit detection of the NWPathMonitor hijack signature)
7. Sidecar process tree with parent-PID validation
8. Root CA on disk (perms + encryption envelope + expiry days)
9. Root CA in keychain (system + login + trust verdict)
10. Keychain passphrases (presence only — never values)
11. UserDefaults size snapshot for every settings key
12. Persistent log entry counts by level + last 50 lines
13. Live forward test (HTTP, HTTPS CONNECT, POST body integrity)
14. DoH endpoint reachability (if enabled)
15. Active network interfaces with IP
16. Recent crash reports (last 7 days)
17. OSLog errors filtered to proxymate (last 1h)
18. Bundled sidecar binary signatures
19. Memory pressure event history

Each verdict is a grep-friendly token (`[OK]`, `[WARN]`, `[FAIL]`, `[SKIP]`); the script exits 0 when clean, 1 on warnings, 2 on hard failures so it slots into CI or a launchd healthcheck without further parsing.

Self-test on this release found the new release's binary clean. On the bug it surfaces (the system-proxy hijack), the diagnose now prints the exact `[FAIL]` line referencing the hijack and naming this release as the fix.

### Artifact

```
File:    Proxymate-0.9.51.dmg
Size:    64 MB
SHA-256: db11e2499397453035a88587032df7355a562e60cd3f9220476de7caabc47f6a
Signed:  Developer ID Application: Fabrizio Salmi (7FC7ZTYMYU)
Notary:  Accepted, stapled, spctl-verified
```

## 0.9.50 — sidecar startup race fix

*Released 2026-04-14*

Point release fixing a single observable regression in 0.9.49: the first request after enabling the proxy could fail with `Connection refused` before the `mitmproxy` sidecar had finished binding its listener.

### Root cause

`Process.run()` returns as soon as `exec(2)` succeeds. `mitmdump` then spends ~1.5 s importing CPython modules and initializing its TLS machinery before it calls `bind()` + `listen()`. During that window, `MITMProxySidecar.start()` had already marked `_isRunning = true` and returned, so `LocalProxy` happily forwarded the first CONNECT into a port that nothing was listening on yet. The failure surfaced in Console.app as:

```
nw_socket_handle_socket_event [C2:1] Socket SO_ERROR [61: Connection refused]
nw_endpoint_flow_failed_with_error [C2 127.0.0.1:18080 ...] already failing
```

### Fix

Both `MITMProxySidecar.start()` and `SquidSidecar.start()` now poll the listener port via a raw Darwin `connect()` every 100 ms until the kernel accepts the handshake. Timeouts: 10 s for mitmdump, 15 s for Squid (slower cold-start because of its config parse + cache dir init). On timeout the subprocess is terminated and the caller receives a `launchFailed` error with a descriptive message rather than a false success.

No other behavioural changes; 0.9.50 is 0.9.49 plus the two `waitForLocalPort` calls.

### Artifact

```
File:    Proxymate-0.9.50.dmg
Size:    64 MB
SHA-256: db313cc0e7757cab97f79517c73304c3dd608f6794e0cb96572e2e499ad475e6
Signed:  Developer ID Application: Fabrizio Salmi (7FC7ZTYMYU)
Notary:  Accepted, stapled, spctl-verified
```

## 0.9.49 — UI robustness + lifecycle hardening

*Released 2026-04-14*

Follow-up to the first notarized release. Zero new features — every commit in this tag fixes something a tester was likely to trip over. Same signed, notarized, stapled distribution as 0.9.48.

### UI robustness

Several UI surfaces were "lying" about the app's state — a toggle or badge showed one thing while the code did another. All fixed, each with a verifiable reproduction.

- **Stats tab live chart** was frozen at zero. Nested `StatsTimeSeries` changes weren't republished through `AppState.objectWillChange`; SwiftUI never re-rendered the chart after the first paint. Fixed by a one-line Combine forward.
- **Four more stat panels** (Cache L1/L2, DNS, HostMemory, Blacklists, AI spend, TLS runtime excludes) read from singletons that aren't `ObservableObject`. Added a 1 Hz `statsTick` publisher on AppState so these panels repaint once per second. Required `let _ = state.statsTick` at the top of each section.
- **Clear Logs** silently suppressed subsequent events. The dedupe set (`seenAgents`) tracking already-logged `(rule, host)` pairs was cleared on proxy disable but not on Clear Logs — so after clearing, the same BLOCKED / AGENT / AI events were muted by the dedupe. Fixed.
- **Blacklist aggregate row** (`Total · Unique · Sources`) never updated after the first render. Same singleton-read pattern, same statsTick fix.

### Onboarding wizard

The first-run experience had multiple fail paths that left the user with a blank, onboarded app.

- **Premature dismissal** (ESC, click outside, window close) flipped `proxymate.onboarded = true` even though no settings had been applied. Fix: the flag is now persisted only from the final step's `applyAndDismiss()`.
- **"Start Proxying" button** didn't start the proxy — it only saved settings. Renamed to **Finish & Enable** with a toggle controlling whether `state.enable()` runs immediately; the button label tracks the toggle.
- **Certificate "installed" checkmark** appeared immediately after clicking Install, before the admin prompt had even been accepted. Rewrote the state machine with explicit phases (`installing → waiting for trust → trusted | error`) and a 15-second poll of `SecTrustEvaluate`. A cancelled admin prompt now surfaces a real error instead of a false green checkmark.
- **SquidSidecar never started.** The default upstream `Local Squid` points at `127.0.0.1:3128`, but nothing in the app launched Squid on enable. Fresh Mac without brew-installed squid → every request 502. Added `ensureLocalSidecarForUpstream()` to both enable and upstream switch paths.
- **Step-2 proxy input had no validation** — any string, any port. Added strict host/port validation with inline hints; Next stays disabled until the entry passes.
- Added a **Skip for now** button on Step 1 and a **Minimal profile** info hint so the happy path cannot accidentally strand the user.
- Accessibility labels added to every wizard control.

### Input validation

Four Add sheets in the main panel committed trivially-bad input silently.

- **AddProxy / AddPool:** port field did `Int(port) ?? 8080` — "abc" became 8080 silently. Host was gated only on empty. Now both validate; submit button disables when invalid.
- **AddRule** with regex kind: pattern was checked only on empty. An invalid regex persisted, then crashed `NSRegularExpression(pattern:)` at first match. Now the regex is compiled at input time; an inline orange hint shows when it doesn't compile.
- **AddCustomBlacklist:** accepted "not a url" as a source. Now validated via `URL(string:)` + scheme + host.

### Destructive actions behind confirmation

Seven one-click delete paths (proxy, pool, pool override, WAF rule, Clear Logs, Remove Root CA, and a duplicate wizard sheet in PrivacyView with the same onDisappear bug) wiped state silently from a right-click misfire. All now require confirmation; the dialog names the target and explains the blast radius.

### Async feedback

- **Blacklist refresh** used a hardcoded 2-second sleep to fake a spinner. Replaced with a real counter (`refreshingBlacklistsCount`) that decrements on each completion — the spinner now reflects actual work.
- **Generate Root CA** blocked the main thread for ~3 s of openssl work. Moved to a detached Task; UI shows "Generating…" with a spinner and the button stays disabled during.

### Silent failures surfaced

Three listeners inherited a `guard let l = try? NWListener(...) else { return }` pattern that ate bind failures.

- **SOCKS5, PAC, Metrics** bind failures now log (through `onEvent` for SOCKS5, through `NSLog` for the other two). Before: toggle stayed green with nothing listening.
- **Webhook POST** had no completion handler — delivery failures were silent. Added a handler that logs transport errors and non-2xx status codes.
- **PAC cleanup on disable** wrapped its privileged call in `try?`. Now surfaces failures through the app log.

### Lifecycle hardening

- `LocalProxy.stop()` now drains `activeSessions` instead of relying on each session's 5-minute self-cleanup. An enable/disable/re-enable cycle no longer stacks zombie sessions.
- `select()` mid-session calls `ensureLocalSidecarForUpstream` so switching to Local Squid while the proxy is enabled no longer produces 502s.
- `PersistentLogger.flushNow()` is invoked from `applicationWillTerminate` so the last log lines before quit reach disk.
- `deinit` on AppState now cancels the memory pressure DispatchSource and the blacklist Timer.
- Quit cleanup timeout bumped from 3 s to 8 s — enough for a cold wake-from-sleep.

### Security tightening

- **Budget fields** (`dailyBudgetUSD`, `monthlyBudgetUSD`) clamp to `max(0, value)` on write. Before: a negative number was persisted, and the `> 0` gate in AITracker silently treated it as "no limit".

### Integrity

- **HTTP/2 upstream** claim removed from README, docs landing, and features guide. The `HTTP2Upstream.swift` class was dead code — defined but never called — and the landing page was advertising a capability the binary didn't have. Deleted the class; the feature is scheduled for a post-v1.0 wiring pass when ProxySession gets a proper H2 branch.

### Artifact

```
File:    Proxymate-0.9.49.dmg
Size:    64 MB
SHA-256: e972121acbba37a2e5042ef2d2654d0ef81fbc8e7a9440ecb35b7b3fb4a9201f
Signed:  Developer ID Application: Fabrizio Salmi (7FC7ZTYMYU)
Notary:  Accepted, stapled, spctl-verified
```

## 0.9.48 — first notarized release

*Released 2026-04-14*

The release that can finally be dragged into /Applications with no ceremony. Signed with Developer ID, notarized by Apple, stapled offline-verifiable.

### Security hardening

- **CA key AES-256 at rest, Keychain-bound passphrase.** Earlier builds stored the root CA private key in plaintext on disk despite a misleading comment. Transparent in-place migration on first launch — no user action required.
- **Leaf P12 bundles** now use a per-installation random passphrase (no more `"proxymate"` literal).
- **Shell injection hardening** on `ProxyManager.enable/disable` — proxy host/port are now strictly validated (IPv4/IPv6/hostname + 1–65535 range) before interpolation into the privileged shell script.

### Platform fixes

- **macOS 26 authorization path.** `AuthorizationExecuteWithPrivileges` silently no-ops on recent macOS; replaced with `osascript do shell script with administrator privileges`. Added post-apply verification via `SCDynamicStore` — no more "enabled" lies when the system config didn't actually change.
- **Entitlements file** added, covers `network.server/client`, `cs.allow-unsigned-executable-memory` (for bundled Python), `cs.disable-library-validation` (for bundled squid).
- **Nested `mitmproxy.app` re-signing** in `build-dmg.sh`: bottom-up walk over 85+ embedded binaries (dylibs, Python native modules, mitmdump, Python.framework), re-signed with Developer ID before the outer app.

### User-visible fixes

- **HTTP request smuggling** (`Transfer-Encoding + Content-Length`) now rejected with 400 at the parser — prevents CL.TE/TE.CL WAF bypass.
- **AI token tracking on gzip responses** — responses are decompressed before token extraction. Every major provider defaults to gzip; previously, token/cost tracking silently reported zero.
- **Quit freeze** up to 3 seconds on app termination — moved cleanup to a detached Task so the main-thread semaphore no longer deadlocks awaited work.
- **Idempotent enable/disable** — re-applying the same system-proxy config no longer triggers an admin prompt. Wake-from-sleep and Wi-Fi/Ethernet transitions are now silent.

### Leak fixes

- `PersistentLogger.flushTimer` now cancelled in `deinit`
- `RuleImporter` URLSession now invalidated after each import

### Packaging

- Bundle size: 148 MB (up from ~35 MB) — we now ship the full `mitmproxy.app` nested bundle so MITM works without homebrew. Previous "flat binary" approach failed at runtime because PyInstaller requires the sibling `Python.framework` layout.
- Dead code removed: `SOCKSProxy.swift` (never instantiated — actual SOCKS5 impl is `SOCKS5Listener.swift`), `proxymate-v0.9.8-report.pdf`.

### New in this release

- `scripts/e2e-full.sh` — reproducible end-to-end test suite (22 pass / 0 fail / 2 skip baseline on any running instance)
- `scripts/bundle-binaries.sh` + Xcode Run Script phase — auto-populates sidecars from homebrew during build

### Known issues / deferred

- **Admin password prompts.** Still one per intentional toggle (enable / disable / CA install). An `SMAppService`-based privileged helper with XPC (one prompt at install, zero afterward) is planned for a future release.
- **Public documentation / Homebrew Cask.** This docs site is new; Homebrew Cask submission follows v1.0.
- **README screenshots.** Generic SVG placeholders for now; real app shots in the next polish cycle.

### Artifact

```
File:    Proxymate-0.9.48.dmg
Size:    64 MB
SHA-256: b56ecfbc53d0a2132d60f563232ab597c931616db0b1089318620d5c9834cae9
Signed:  Developer ID Application: Fabrizio Salmi (7FC7ZTYMYU)
Notary:  Accepted, stapled, spctl-verified
```
