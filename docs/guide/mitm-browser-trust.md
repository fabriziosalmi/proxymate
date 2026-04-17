# MITM and browser trust

When MITM is enabled and you've installed Proxymate's root CA into the macOS system keychain, **most** HTTPS traffic is decrypted, inspected, and re-encrypted toward the upstream. But not everything — and the reasons sit in three different places.

## The short version

| Browser | Honors macOS system trust? | Action needed |
| --- | --- | --- |
| Safari | Yes | Nothing — works out of the box |
| Chrome / Edge / Brave | Partially (uses its own root store on some platforms) | Import the CA into Chrome's settings (see below) |
| Firefox | No (independent root store) | Import the CA into Firefox preferences |
| App-level pinned (Signal, WhatsApp, banking) | N/A — pinning bypasses CA trust entirely | Add to MITM exclude list (auto-detected after 3 failed handshakes) |

## Why HTTP/2 downstream is disabled (browser ↔ mitm)

HTTP/2 allows a browser to reuse one connection for multiple hosts that share an IP and a compatible certificate — this is called **connection coalescing**. Firefox in particular ([Bugzilla 1420777](https://bugzilla.mozilla.org/show_bug.cgi?id=1420777)) is aggressive about this: `github.com` and `github.githubassets.com` both resolve to Fastly, share a wildcard cert, and the browser sends requests for both hosts down the same HTTP/2 stream. Same for `www.linkedin.com` + `static.licdn.com`.

When mitmproxy sits in the middle, it issues per-host leaf certificates — so the browser's coalescing heuristic *shouldn't* trigger. In practice it still does, because Firefox also bases the decision on the destination IP. The browser then sends subresource requests with an `:authority` header that doesn't match the stream's TLS SNI, mitmproxy treats the mismatch as a protocol violation and resets the stream, and the browser surfaces the reset as `CORS request failed. Status code: (null)` on the affected `<script type="module" crossorigin>` tags.

Proxymate works around this by passing `--set http2=false` to mitmdump, which forces the browser-facing side to HTTP/1.1. HTTP/1.1 has no coalescing — each host gets its own connection — and the issue disappears. The upstream leg (mitmproxy → Squid) is already HTTP/1.1 for independent reasons, so there is no protocol downgrade on that side.

Cost: marginally more TCP connections from the browser to the loopback mitm port. On localhost this is free. The tradeoff is favourable for every site that uses multi-host CDN coalescing (most modern large sites).

## Why HTTP/3 (QUIC) is stripped, not supported

macOS system proxies (`networksetup -setwebproxy` / `-setsecurewebproxy`) only proxy **TCP**. UDP — which is what HTTP/3 / QUIC rides on — has no system-level proxy hook. If the browser successfully opens a QUIC connection to an origin on UDP/443, it bypasses Proxymate entirely: no TLS interception, no WAF inspection, no logging.

Browsers learn about HTTP/3 endpoints in two ways:

1. **`Alt-Svc` response header** (`Alt-Svc: h3=":443"; ma=86400`) — the dominant signal.
2. **DNS HTTPS records (RFC 9460)** — newer, less widespread, and both Chrome and Firefox fall back to HTTP/2 quickly when QUIC fails.

When MITM is active, the mitm addon **strips `Alt-Svc` from every response** before handing it to the browser. The browser therefore never upgrades to HTTP/3 and every subsequent subresource fetch stays on HTTP/2 inside the proxied TCP connection — where MITM can see it.

If you notice a site loading its main document but failing with `CORS request failed. Status code: (null)` on `<script type="module" crossorigin>` subresources from a sibling CDN host (the LinkedIn `static.licdn.com` case), that is the QUIC-bypass failure mode. Proxymate 0.9.53+ prevents it by default.

This also means that when MITM is **off**, Proxymate does not proxy QUIC traffic at all — browsers talk HTTP/3 directly to origins, outside Proxymate's visibility. This is a macOS limitation, not a Proxymate choice.

## Why HSTS doesn't actually block MITM

HSTS (HTTP Strict Transport Security) is often confused with cert pinning. They're different:

- **HSTS** says "this site uses HTTPS only — never let me load it over HTTP." It enforces transport security, not certificate identity. If your browser already trusts our CA, HSTS is silent on the matter.
- **HSTS preload** is a hardcoded list inside the browser of sites that MUST be HTTPS. Same as above — it's about HTTP-vs-HTTPS, not about which CA signed the cert.
- **Certificate pinning** (HPKP, expect-CT, app-level pinning) is what actually blocks MITM. It says "I expect a specific certificate (or one of a small set), no matter what your CA store says."

So if a site is in the HSTS preload list AND your browser trusts our CA, MITM works fine. If a site uses cert pinning — which is rare on the modern web (HPKP was deprecated and removed) but still present in mobile and desktop apps — MITM will fail no matter what.

## Browser-by-browser setup

### Safari

No action needed. Safari uses the macOS system keychain. Once you've installed Proxymate's CA via the onboarding wizard or **Preferences → MITM → Install Certificate**, Safari sees it as trusted automatically.

### Chrome (and Brave, Arc, Vivaldi, other Chromium browsers)

On macOS, Chrome uses the system keychain by default — so the same install works. To verify:

1. Open Chrome → Settings → Privacy and security → Security → **Manage device certificates**.
2. The system Keychain Access opens. Find "Proxymate Root CA" under **System** keychain.
3. Double-click → **Trust** → **When using this certificate: Always Trust**.

If you're seeing TLS errors in Chrome but Safari works, Chrome is using its own internal store for the affected site. Workaround:

```bash
# Add the Proxymate CA to Chrome's per-profile NSS database (rare)
PROFILE_DIR="$HOME/Library/Application Support/Google/Chrome/Default"
# Chrome on macOS doesn't actually use NSS — it uses the system store.
# If a specific site fails, the issue is almost always app-level pinning.
```

If a single site keeps failing in Chrome but works in Safari, it's pinning. Add the host to **Preferences → MITM → Excludes**.

### Firefox

Firefox ships with its own root store (`cert9.db`) and **does not** consult the system keychain by default. You have to import the CA explicitly:

1. **Preferences → MITM → Export Root CA** in Proxymate (saves `proxymate-ca.pem` to your Downloads).
2. In Firefox: **Preferences → Privacy & Security** → scroll to **Certificates** → **View Certificates...** → **Authorities** tab → **Import...**.
3. Pick the `proxymate-ca.pem` file, check **Trust this CA to identify websites**, click OK.
4. Restart Firefox.

To verify it took: visit `about:certificate?cert=` and look for "Proxymate Root CA" under Authorities.

### Other Chromium browsers (Brave, Arc, Vivaldi)

Same as Chrome: they use the system keychain. The Proxymate CA install via the wizard is enough.

## When MITM fails despite the CA being trusted

The site is using application-level certificate pinning. Examples:

- **Signal, WhatsApp, Telegram desktop apps** — pin specific certificates; nothing you do at the OS level changes their behavior.
- **Banking and finance apps** (most of them) — pin against their issuer's intermediate.
- **Apple's own services** (iCloud sync, push, software update) — pin against Apple's internal CA. Already in Proxymate's default exclude list.
- **Streaming media players** — HLS/DASH segment fetches over Akamai/Brightcove often pin to defeat reverse-engineering. Default excludes cover the common platforms (RAI, Mediaset, Netflix, Disney+, Twitch, Spotify, YouTube media CDN), and Proxymate 0.9.57+ auto-excludes any host that returns a streaming `Content-Type` (`audio/*`, `video/*`, HLS `m3u8`, DASH `mpd`) — so webradio, podcasts, and independent broadcasters bypass MITM without needing to be on a curated list.

Proxymate auto-detects pinning via consecutive handshake failures. After 3 strikes against the same host, it adds the host to a runtime exclude list and stops attempting MITM there. You can also add hosts manually via **Preferences → MITM → Excludes**.

## What to do if everything else still feels broken

1. Run `./scripts/diagnose.sh` from the repo and check section 6 (system proxy) and section 9 (CA trust). Both should be green.
2. Check the Proxymate Logs tab for repeated `pinning failure` lines on the same host — those are the cert-pinned sites you need to add to excludes.
3. If a specific browser fails but `curl -x http://127.0.0.1:<listener> https://<site>` works, the issue is browser-side trust (Firefox is the usual culprit).
4. If `curl` also fails with a TLS error, the host is genuinely cert-pinned. Add to excludes.

Cert pinning was a much bigger problem five years ago. Today it's mostly the things you'd expect: messaging, finance, Apple internal, and media DRM. Everything else MITMs cleanly.
