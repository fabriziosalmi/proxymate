# Release notes

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
