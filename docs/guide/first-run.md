# First run

Proxymate ships with a 5-step onboarding wizard. Takes about 30 seconds.

## 1. Choose a profile

Five curated starting points, each a pre-built bundle of rules, privacy settings, and AI policy:

- **Developer** — minimal WAF, AI agents allowed, privacy headers normalized
- **Privacy** — aggressive tracker blocking, cookie filtering, DNT + GPC injected
- **Security** — paranoid WAF, C2/beaconing enabled, cert-pinned apps auto-excluded
- **Casual** — Steven Black ad/tracker list + HTTPS-everywhere nudge
- **Custom** — opt-in to every rule pack manually

You can switch profiles anytime; rules are additive layers, not exclusive modes.

## 2. Install the root CA

Required for MITM. Skip if you only need plain proxying + WAF on HTTP.

- Proxymate generates a local Root CA (`Proxymate Root CA`) stored encrypted on disk
- Clicks "Install" → enter admin password once → adds the CA to the system keychain with `trustRoot`
- The CA is local to this Mac; it cannot be used by anyone without your user passphrase

See the [security model](/guide/security.md#ca-lifecycle) for details on what this actually does and does not mean.

## 3. Pick an upstream

What sits between Proxymate and the wider internet.

- **Direct** — Proxymate forwards to the destination itself. Simplest.
- **Local Squid** — bundled caching HTTP proxy on `127.0.0.1:3128`. Good if you want disk caching without an external service.
- **Local mitmproxy** — bundled sidecar on `127.0.0.1:8080`. Required for full MITM with script automation.
- **Custom** — any upstream host:port. Works with corporate proxies, Tailscale, Cloudflare Zero Trust, your home VPN.

## 4. Flip the toggle

Menu bar → Proxymate → **Enable**. System proxy is configured (admin prompt), listener starts, traffic begins flowing through.

From this point on, every HTTP, HTTPS, and SOCKS request from any app on your Mac passes through Proxymate first.

## 5. Watch the logs

The **Logs** tab shows live traffic with:

- **Green** — allowed
- **Red** — blocked (WAF / blacklist / content match)
- **Yellow** — shadowed (would have been blocked, allowed for audit)
- **Blue** — AI / agent-detected

Click any row to see full headers, matched rule, response status.
