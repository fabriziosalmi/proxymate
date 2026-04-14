// Diagnose a single URL via Playwright using Proxymate as upstream proxy.
//
// Usage:  node diagnose.mjs <url> [chromium|firefox] [label]
// Env:    PROXYMATE_PORT (required), PROXYMATE_CA_PATH (optional, Firefox only)
//
// Output: JSON + screenshot under ./reports/<label>/<timestamp>/
// Stdout: human-readable summary + path to report dir
//
// Collects: failed requests, console errors, non-2xx responses, page errors.
// Classifies bypass patterns (QUIC, ECH, pinning) from observed signal.

import { chromium, firefox } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import { URL } from 'node:url';
import { resolve } from 'node:path';

const [, , targetUrl, browserKind = 'chromium', labelArg] = process.argv;
if (!targetUrl) {
  console.error('usage: node diagnose.mjs <url> [chromium|firefox] [label]');
  process.exit(2);
}

const proxyPort = process.env.PROXYMATE_PORT;
if (!proxyPort) {
  console.error('PROXYMATE_PORT env var required (see scripts/diagnose-site.sh)');
  process.exit(2);
}

const parsed = new URL(targetUrl);
const label = labelArg || parsed.host.replace(/[^a-z0-9]+/gi, '-');
const ts = new Date().toISOString().replace(/[:.]/g, '-');
const reportDir = resolve('./reports', label, ts);
await mkdir(reportDir, { recursive: true });

const launcher = browserKind === 'firefox' ? firefox : chromium;
const browser = await launcher.launch({
  proxy: { server: `http://127.0.0.1:${proxyPort}` },
  headless: true,
});

const context = await browser.newContext({
  ignoreHTTPSErrors: true,  // let Playwright see failures even if our CA isn't in its trust store
  viewport: { width: 1400, height: 900 },
});

const page = await context.newPage();

const failures = [];
const consoleErrors = [];
const pageErrors = [];
const responses = [];

page.on('requestfailed', (req) => {
  const errText = req.failure()?.errorText || 'unknown';
  // net::ERR_ABORTED on fetch/xhr is almost always the page cancelling its
  // own deferred hovercard/prefetch requests during navigation — not a
  // real network failure. Record but flag as benign for exit-code purposes.
  const benign = errText === 'net::ERR_ABORTED' &&
    ['fetch', 'xhr'].includes(req.resourceType());
  failures.push({
    url: req.url(),
    method: req.method(),
    resourceType: req.resourceType(),
    failure: errText,
    benign,
  });
});

page.on('console', (msg) => {
  if (msg.type() === 'error' || msg.type() === 'warning') {
    consoleErrors.push({ type: msg.type(), text: msg.text() });
  }
});

page.on('pageerror', (err) => {
  pageErrors.push({ name: err.name, message: err.message });
});

page.on('response', async (resp) => {
  const status = resp.status();
  if (status === 0 || status >= 400) {
    responses.push({ url: resp.url(), status });
  }
});

let navError = null;
try {
  await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: 30000 });
} catch (e) {
  navError = String(e.message || e);
}

await page.screenshot({ path: resolve(reportDir, 'screenshot.png'), fullPage: true });

const hostsRequested = new Set();
const hostsFailed = new Set();
for (const f of failures) {
  try { hostsFailed.add(new URL(f.url).host); } catch {}
}

// Heuristic classification
const signals = [];
const failureTexts = failures.map(f => f.failure.toLowerCase()).join(' ');
if (/net::err_cert|unknown_ca|ssl_error/.test(failureTexts)) {
  signals.push('CA_NOT_TRUSTED — browser does not trust Proxymate CA in this context');
}
if (failures.some(f => f.failure === 'net::ERR_EMPTY_RESPONSE' || f.failure === 'NS_ERROR_NET_RESET')) {
  signals.push('CONNECTION_RESET — likely H/2 stream reset (coalescing) or pinning');
}
if (failures.some(f => /ERR_QUIC|quic/i.test(f.failure))) {
  signals.push('QUIC_FAILURE — HTTP/3 attempts failing, check Alt-Svc strip / HTTPS-RR');
}
const crossOriginModuleFail = consoleErrors.filter(c =>
  /CORS|cross-origin|module source URI/i.test(c.text)).length;
if (crossOriginModuleFail > 5 && hostsFailed.size > 0) {
  signals.push(`BYPASS_SUSPECTED — ${crossOriginModuleFail} CORS/module errors; browser likely bypassed proxy for subresource hosts (QUIC via HTTPS-RR / ECH / direct)`);
}

const report = {
  target: targetUrl,
  label,
  timestamp: ts,
  browser: browserKind,
  proxyPort: Number(proxyPort),
  navError,
  counts: {
    failures: failures.length,
    consoleErrors: consoleErrors.length,
    pageErrors: pageErrors.length,
    nonOkResponses: responses.length,
  },
  hostsFailed: Array.from(hostsFailed).sort(),
  signals,
  failures: failures.slice(0, 100),
  consoleErrors: consoleErrors.slice(0, 100),
  pageErrors,
  nonOkResponses: responses.slice(0, 100),
};

await writeFile(resolve(reportDir, 'report.json'), JSON.stringify(report, null, 2));

await browser.close();

// Summary to stdout
const line = '─'.repeat(60);
console.log(line);
console.log(`target    ${targetUrl}`);
console.log(`browser   ${browserKind}`);
console.log(`report    ${reportDir}`);
console.log(line);
const benignCount = failures.filter(f => f.benign).length;
console.log(`failed requests      ${failures.length} (${benignCount} benign, ${failures.length - benignCount} real)`);
console.log(`console errors       ${consoleErrors.length}`);
console.log(`page errors          ${pageErrors.length}`);
console.log(`non-2xx responses    ${responses.length}`);
if (signals.length) {
  console.log('\nSignals:');
  for (const s of signals) console.log('  • ' + s);
}
if (hostsFailed.size) {
  console.log('\nHosts with failures:');
  for (const h of hostsFailed) console.log('  - ' + h);
}
if (navError) {
  console.log(`\nnav error: ${navError}`);
}

// Exit non-zero only if we have actionable signal: classified pattern,
// page-level errors, or at least one non-benign network failure. Plain
// ERR_ABORTED hovercards alone don't make a site "broken".
const realFailures = failures.filter(f => !f.benign).length;
process.exit(signals.length || pageErrors.length || realFailures ? 1 : 0);
