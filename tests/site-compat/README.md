# Site compatibility harness

Playwright-driven diagnostic that loads real sites through Proxymate and captures everything the browser observes that the proxy cannot see from its own vantage point: failed subresource fetches, console/CORS errors, non-2xx responses, and pattern-classified bypass signals.

## When to use

- A tester reports "site X doesn't work" → reproduce in one command, attach the generated report dir instead of screenshots
- Before shipping a MITM-adjacent change → run the full suite, spot regressions
- Investigating navigation issues whose cause is outside the proxy's direct visibility (QUIC bypass, ECH, HTTPS-RR, H/2 coalescing)

## Prerequisites

- Proxymate is running and set as the system proxy (MITM enabled or disabled per the test you want)
- Root CA is trusted in the system keychain (Chromium honors it automatically on macOS; Firefox requires a separate import — for diagnostic purposes `ignoreHTTPSErrors: true` is set so Playwright proceeds and still records the signal)

## Run

```bash
# single URL (Chromium by default)
./scripts/diagnose-site.sh https://github.com

# specify browser
./scripts/diagnose-site.sh https://www.linkedin.com firefox

# full suite (sites.json)
./scripts/diagnose-site.sh --suite
./scripts/diagnose-site.sh --suite firefox
```

First run installs Playwright + browsers into `tests/site-compat/node_modules`. Reports land in `tests/site-compat/reports/<label>/<timestamp>/`:

- `report.json` — structured record of every failure, error, and classified signal
- `screenshot.png` — full-page screenshot at `networkidle`

## What the signals mean

- `CA_NOT_TRUSTED` — the browser would have refused Proxymate's cert. Expected on a fresh install before running the CA trust step.
- `CONNECTION_RESET` — H/2 stream reset or cert-pinning mid-handshake. Check MITM exclude list.
- `QUIC_FAILURE` — HTTP/3 attempts failing outright. Alt-Svc strip is working but the browser is still trying QUIC (HTTPS-RR / ECH).
- `BYPASS_SUSPECTED` — many CORS/module errors while failures are concentrated on specific hosts. Browser likely bypassed the proxy entirely for those subresource hosts (HTTPS-RR record → direct QUIC, or ECH, or an OS-level routing rule).

## Extending

Add sites to `sites.json`:

```json
{ "url": "https://example.com", "label": "example" }
```

Labels become directory names — keep them short and filesystem-safe.
