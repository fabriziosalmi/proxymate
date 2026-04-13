# Security model

Proxymate handles three classes of sensitive material:

1. Your network traffic (contents of every HTTP request you make)
2. A locally-generated TLS root CA (with its private key)
3. System proxy configuration (which requires admin privileges to change)

This page explains exactly what each one is, where it lives, and what an attacker would need to compromise to subvert it.

## CA lifecycle

### Where the key lives

The CA private key (`~/Library/Application Support/Proxymate/ca/ca.key`) is written as an AES-256 encrypted PEM envelope (`-----BEGIN ENCRYPTED PRIVATE KEY-----`). The symmetric passphrase is a 32-byte random blob stored in your login Keychain:

- Service: `fabriziosalmi.proxymate.tls`
- Account: `ca-key-passphrase-v1`
- Accessibility: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`

That accessibility flag means:

- **Never exported** via iCloud Keychain backup (device-only)
- Available to Proxymate only after the first device unlock post-boot
- Accessible to processes running as your user (standard Keychain trust model)

### Threat model

An attacker who has your CA private key can forge TLS certificates for any hostname, then — if they can also install a rogue CA or intercept traffic — impersonate any site to you. To get it, they need **all** of:

1. Read access to `ca.key` (POSIX 0o600, your-user-only)
2. Access to the Keychain passphrase item (requires user session unlock)
3. The ability to load the forged cert into your active TLS session (proxy position or malware on-device)

None of these alone is sufficient. Full-disk encryption (FileVault) protects (1) at rest. The Keychain's `ThisDeviceOnly` accessibility protects (2) against backups. (3) requires malware already running as you, at which point the whole trust boundary is gone anyway.

### Legacy migration

Earlier builds stored the CA key in plaintext (despite a misleading comment claiming otherwise). On first launch of 0.9.48+, Proxymate detects an unencrypted key and transparently re-encrypts it in place. Leaf cert caches are invalidated and regenerated on demand — no user action required.

## Traffic privacy

### What Proxymate sees

Everything your Mac sends, in the clear:

- Plain HTTP — full request (line, headers, body) and response
- HTTPS **without** MITM — only the `CONNECT host:port` tunnel negotiation. The encrypted body passes through opaquely.
- HTTPS **with** MITM — after the user trusts the root CA, Proxymate decrypts the TLS stream, applies filters, and re-encrypts toward upstream. Observable by Proxymate, not by anyone else on the wire.

### What it does with that data

- **Logs** (JSONL, local disk, rotating 2 MB × 5 files max)
- **Stats** (aggregated counters, in-process)
- **Rules** (matched against WAF / blacklist / exfiltration / AI detection)
- **Optionally**: webhooks (if you configured any), Prometheus metrics (if enabled), iCloud sync (if enabled — sync your rules, not your traffic)

### What it never does

- Upload logs anywhere (no telemetry endpoint in the binary)
- Send request bodies to a cloud service
- Call home for updates (yet — Sparkle integration deferred to v1.0)
- Collect analytics, device identifiers, or user-agent fingerprints

The only outbound calls Proxymate makes on its own are list-refresh fetches to the URLs in `BlacklistManager` (Steven Black, OISD, NoCoin, URLhaus, etc.), and those only when enabled and only on the hosts you see.

## Privilege boundary

### What needs admin

Two things:

1. Modifying system proxy settings (`networksetup -setwebproxy`). Required once per toggle (idempotent — re-applied only when the setting actually drifts).
2. Installing the root CA with `trustRoot` attribute into the system keychain. Once, at CA trust time.

Nothing else in the app runs as root. The listener, WAF, MITM pipeline, logger, rule engine, and all UI run as your user.

### How privilege is requested

Proxymate invokes `osascript` with `do shell script ... with administrator privileges`. macOS renders the native authorization dialog (including Touch ID if enabled). The prompt is short-lived — the auth is cached for ~5 minutes per the macOS default.

There is **no privileged helper daemon** in the current build. No launchd plist is installed. Quitting Proxymate removes the privilege entirely; nothing remains root on your Mac.

A proper helper via `SMAppService` (one prompt at install, zero afterward) is planned for a future release.

## Entitlements

Proxymate ships with the minimum hardened-runtime entitlements to function:

| Entitlement | Why |
|---|---|
| `com.apple.security.network.server` | Bind the local HTTP listener on 127.0.0.1:* |
| `com.apple.security.network.client` | Outbound upstream proxy, DoH, blacklist refresh |
| `com.apple.security.cs.allow-unsigned-executable-memory` | CPython inside bundled mitmdump needs writable+executable pages for its eval loop |
| `com.apple.security.cs.disable-library-validation` | Bundled squid loads bundled OpenSSL, signed under the same Developer ID |

No access to camera, microphone, contacts, documents, or any other privacy-gated resource. No `com.apple.security.get-task-allow` in release builds.

## Code signing

All releases ship:

- Signed with a valid Apple Developer ID (Team `7FC7ZTYMYU`)
- Hardened runtime enabled
- Trusted timestamp via Apple's TSA
- Notarized by Apple (submission scanned for known malware + entitlements sanity)
- Stapled — Gatekeeper verification works offline

`spctl --assess --type open` on the DMG returns `accepted` on a fresh Mac.

## What Proxymate cannot protect you from

- A compromised Mac. If malware runs as your user, it can read `~/Library/Application Support/Proxymate` and the Keychain item as easily as Proxymate itself can.
- A compromised upstream. If you configure Proxymate to forward via a hostile upstream proxy, that upstream sees everything Proxymate sends it.
- TLS 1.3 + encrypted Client Hello (ECH). Where the SNI is encrypted, Proxymate cannot match rules on the hostname before the tunnel is established. For these sites, MITM is required — or don't filter them.
- DNS-level tracking. Proxymate doesn't run a DNS server. If your OS resolver leaks, Proxymate can't fix that.
