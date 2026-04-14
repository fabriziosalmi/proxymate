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

## Extending

Add sites to `sites.json`:

```json
{ "url": "https://example.com", "label": "example" }
```

Labels become directory names — keep them short and filesystem-safe. Default timeout is 30 s per site.
