# Release notes

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
