# Site compatibility harness

Playwright-driven diagnostic that loads real sites through Proxymate (or directly, for baseline) and captures everything the browser observes that the proxy cannot see from its own vantage point: failed subresource fetches, CORS/module errors, page errors, non-2xx responses. Then cross-references each failed host against the live Proxymate log to classify the failure as **BYPASS**, **PROXY_ERROR**, or **BROWSER**.

## When to use

- A tester reports "site X doesn't work" → reproduce in one command, ship the generated report dir instead of screenshots
- Before shipping a MITM-adjacent change → run baseline + MITM-on, compare, spot regressions
- Debug navigation issues whose cause is outside the proxy's direct visibility (QUIC bypass, ECH, HTTPS-RR, H/2 coalescing)

## Workflow to isolate a problem

```bash
# 1. Baseline without Proxymate (what the site looks like on this network,
#    this OS, with this browser, with no proxy at all)
./scripts/diagnose-site.sh --suite --no-proxy

# 2. Enable Proxymate, disable MITM, re-run
./scripts/diagnose-site.sh --suite --mitm off

# 3. Enable MITM, re-run
./scripts/diagnose-site.sh --suite --mitm on

# 4. Compute regressions
./scripts/diagnose-site.sh --compare direct proxy-mitm-on
./scripts/diagnose-site.sh --compare proxy-mitm-off proxy-mitm-on
```

This separates three failure classes automatically:

| Comparison | What a regression tells you |
| --- | --- |
| `direct` → `proxy-mitm-on`  | Proxy+MITM combined caused the break |
| `direct` → `proxy-mitm-off` | Proxy alone caused the break (rare — check excludeHosts / forwarding) |
| `proxy-mitm-off` → `proxy-mitm-on` | MITM alone caused the break — typical pinning / coalescing / SNI issue |

## Single-URL form

```bash
./scripts/diagnose-site.sh https://github.com                 # proxy, current MITM state
./scripts/diagnose-site.sh https://github.com --browser firefox
./scripts/diagnose-site.sh https://github.com --no-proxy      # baseline
./scripts/diagnose-site.sh https://github.com --mitm on       # tag run
```

## Host-level verdict

For every host that failed in the browser, `report.json` contains a classification derived from `proxymate.log`:

- **BYPASS** — the host never appeared in the proxy log during the run window. Traffic went around Proxymate: QUIC via HTTPS-RR, direct connection, or protocol the system proxy can't see.
- **PROXY_ERROR** — the host did reach the proxy but got a 4xx/5xx or handshake failure there. Actionable on the proxy side (check excludes, upstream connectivity, cert chain).
- **BROWSER** — the host got a successful 2xx through the proxy, but the browser surfaced a failure anyway. Root cause is browser-side: SRI mismatch, CORS, H/2 coalescing, SNI, ECH.

## Top-level signal classifier

- `CA_NOT_TRUSTED` — browser would have refused Proxymate's cert
- `CONNECTION_RESET` — H/2 stream reset or pinning mid-handshake
- `QUIC_FAILURE` — HTTP/3 attempts failing outright
- `MANY_CORS_MODULE_ERRORS` — browser console reports many CORS/module errors; usually a downstream effect of a BYPASS or RESET
- `BYPASS_CONFIRMED` — at least one failed host was never seen in the proxy log
- `PROXY_UPSTREAM_ERROR` — at least one failed host was seen at the proxy layer with an error

## Output layout

```
tests/site-compat/reports/
  <label>/
    direct/              # baseline runs
      2026-04-14T.../
        report.json
        screenshot.png
    proxy-mitm-on/       # proxied runs, MITM on
      2026-04-14T.../
        ...
    proxy-mitm-off/
      ...
  _suite/
    <mode>/<timestamp>/summary.json
```

First `--suite` run installs Playwright + Chromium + Firefox into `node_modules/` (one-time, ~300 MB).

## Calibration — read this before chasing a green suite

The OK/FAIL badge is a **secondary** signal. The authoritative output is the per-host `hostClassification` and the top-level `signals[]` field in `report.json`. Don't optimize for 10/10 green — you will lose to the long tail of the real web.

Sources of noise that will never fully go away:

- **Anti-bot detection.** Apple iCloud, most banking portals, some airlines run Akamai Bot Manager / Arkose Labs / Cloudflare Challenge. They fingerprint Playwright-headless Chromium specifically and serve a 403 or an infinite challenge page. `--headed` mitigates some of them. Full bypass requires `playwright-extra` + `stealth` plugin — out of scope here.
- **HTTPS-RR bypass on sub-resource CDNs.** Browsers discover HTTP/3 endpoints via DNS HTTPS records (RFC 9460). That lookup bypasses Proxymate entirely because the macOS system proxy is TCP-only. Sub-resource hosts that advertise HTTP/3 this way will show up as `BYPASS` in the report even when the main page loads fine — it's an OS-level limitation, not a Proxymate bug. See `docs/guide/mitm-browser-trust` for the full writeup.
- **Consent/tracking SDK crashes.** When Proxymate's WAF blocks a tracker, the site's loader often receives a 403 HTML page instead of the expected JS bundle and throws (`SyntaxError: Unexpected token '<'`, `"No options detected"` from OneTrust, iubenda helpers). We mark these benign but they'll still show in `consoleErrors`.
- **`networkidle` timeouts.** Modern sites keep long-lived analytics / realtime / WebSocket connections open by design. We use `load` + 2s settle instead, but some sites (RAI, Mediaset in certain load paths) still exceed 30s if the consent wall blocks their main bundle.

Realistic passing rate on the bundled `sites.json` against Proxymate with MITM on: **6-8 out of 10**. The sites that fail in a given run will rotate depending on which tracker is currently down, which consent vendor deployed a breaking change this week, and which anti-bot vendor's cache has your IP flagged.

**Use the suite as a classifier, not a pass/fail gate.** If a user reports site X broken, run it, read the `hostClassification` and `signals`, and you'll know in 30 seconds whether the issue is:

- in Proxymate's proxy/MITM stack (`PROXY_ERROR`, `CA_NOT_TRUSTED`, `CONNECTION_RESET`)
- outside Proxymate's reach (`BYPASS`, `MANY_CORS_MODULE_ERRORS`)
- in the browser or on the site (`BROWSER`, real `pageErrors`)

Act on the first category. Document the second. Ignore the third.

## Three tiers, three purposes

| File | Purpose | Gate-able? |
| --- | --- | --- |
| `sites-core.json` | 5 rock-solid sites (Cloudflare, Microsoft, Google, Wikipedia, httpbingo) used for the pre-push integrity gate. If any of these shows `CA_NOT_TRUSTED` or `PROXY_UPSTREAM_ERROR`, the proxy is broken. | Yes |
| `sites.json` | Broader diagnostic set — includes anti-bot-fronted sites (iCloud, LinkedIn, intesa), state-pinned streaming platforms (RAI, Mediaset, Twitch). Run manually as a classifier. | No |
| `sites-streaming.json` | Direct media URLs (Apple HLS bipbop, Mux HLS test, Radio Paradise MP3/AAC) exercised by `stream-probe.mjs`. Validates the signal-based streaming auto-exclude shipped in 0.9.57. | Yes |

Add sites to whichever tier fits the job:

```json
{ "url": "https://example.com", "label": "example" }
```

Labels become directory names — keep them short and filesystem-safe. Default timeout is 30 s per site.

## Stream probe

`node stream-probe.mjs` doesn't launch a browser — it curls each stream URL through Proxymate, caps at 4 s, and asserts:

1. HTTP status is `200` or `206`
2. Response `Content-Type` matches the per-stream `expectedContentTypeRe`
3. ≥ 8 KB of body bytes arrived within the window (the player would see audio flowing)
4. `proxymate.log` contains `MITM: streaming media (…) from <host>, auto-excluding` within the probe window

A failure on (3) with a streaming Content-Type on (2) means the 0.9.57 patch regressed — the response is being buffered instead of streamed. Missing (4) when (3) passes is informational only: the host may already have been auto-excluded in a prior run (present in `ignore_hosts` → the log line fires only once per host per Proxymate process).

```
node stream-probe.mjs                  # all streams
node stream-probe.mjs --label mux-hls-test   # just one
```

Requires `PROXYMATE_PORT`.

## Pre-push gate

`scripts/pre-push-hook.sh --install` wires a git pre-push hook that runs three gates:

1. **Swift unit tests** — `HTTPParserTests` only (fast, covers the parsing layer the streaming patch touches)
2. **Core site integrity** — `suite.mjs --sites sites-core.json --mitm on`, blocks on unequivocal signals
3. **Streaming probe** — `stream-probe.mjs`, blocks on 0 bytes / wrong Content-Type

Gates 2 and 3 are **skipped with a clear message** when `PROXYMATE_PORT` is unset or no listener is bound on it — the hook must not block pushes from machines where the app isn't currently running. Bypass once with `git push --no-verify`.

The hook intentionally does not run the broader `sites.json` suite. That list is 6-8/10 green on a good day (anti-bot detection, consent-wall SDKs, HTTPS-RR bypass), and gating on it would train the reflex to `--no-verify` after a few pushes. Use it as a classifier, not a gate.
