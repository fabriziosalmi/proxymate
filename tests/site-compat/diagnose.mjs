// Diagnose a single URL via Playwright, optionally routed through Proxymate.
//
// Usage:
//   node diagnose.mjs <url> [--browser chromium|firefox] [--label <tag>]
//                          [--no-proxy] [--mitm on|off]
//
// Env: PROXYMATE_PORT (required unless --no-proxy)
//      PROXYMATE_LOG_DIR (default: ~/Library/Application Support/Proxymate/logs)
//
// Output: JSON + screenshot under ./reports/<label>/<mode>/<timestamp>/
//   where mode = "direct" | "proxy-mitm-on" | "proxy-mitm-off" | "proxy-mitm-unknown"
//
// Collects failures, console errors, page errors, non-2xx responses.
// Correlates per-host failures with the Proxymate log in the same time
// window to classify each failed host as BYPASS / PROXY_ERROR / BROWSER.

import { chromium, firefox } from 'playwright';
import { mkdir, writeFile, readFile, readdir, stat } from 'node:fs/promises';
import { URL } from 'node:url';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';

const rawArgs = process.argv.slice(2);
const positional = [];
const opts = {};
for (let i = 0; i < rawArgs.length; i++) {
  const a = rawArgs[i];
  if (a === '--no-proxy') opts.noProxy = true;
  else if (a === '--headed') opts.headed = true;
  else if (a.startsWith('--')) { opts[a.slice(2)] = rawArgs[i + 1]; i++; }
  else positional.push(a);
}
const targetUrl = positional[0];
const browserKind = opts.browser || 'chromium';
const labelArg = opts.label || null;
const noProxy = !!opts.noProxy;
const headed = !!opts.headed;
const mitmArg = opts.mitm || null;

if (!targetUrl) {
  console.error('usage: node diagnose.mjs <url> [--browser chromium|firefox] [--label <tag>] [--no-proxy] [--mitm on|off]');
  process.exit(2);
}

const proxyPort = process.env.PROXYMATE_PORT;
if (!noProxy && !proxyPort) {
  console.error('PROXYMATE_PORT env var required (or pass --no-proxy for baseline)');
  process.exit(2);
}

const parsed = new URL(targetUrl);
const label = labelArg || parsed.host.replace(/[^a-z0-9]+/gi, '-');
const mode = noProxy ? 'direct' : `proxy-mitm-${mitmArg || 'unknown'}`;
const ts = new Date().toISOString().replace(/[:.]/g, '-');
const reportDir = resolve('./reports', label, mode, ts);
await mkdir(reportDir, { recursive: true });

const runStartMs = Date.now();

const launcher = browserKind === 'firefox' ? firefox : chromium;
const browser = await launcher.launch({
  proxy: noProxy ? undefined : { server: `http://127.0.0.1:${proxyPort}` },
  headless: !headed,
});

const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  viewport: { width: 1400, height: 900 },
});

const page = await context.newPage();

const failures = [];
const consoleErrors = [];
const pageErrors = [];
const responses = [];
const hostsTouched = new Set();

page.on('request', (req) => {
  try { hostsTouched.add(new URL(req.url()).host); } catch {}
});

// Hosts whose failure is expected and/or desirable when routed through
// Proxymate — tracking beacons, telemetry pixels, analytics SDKs,
// crash-reporting endpoints. The WAF / blacklist layer blocks many of
// these on purpose. A failure on one of these hosts is not a real
// browsing issue for a human user.
const TRACKING_HOST_RE = new RegExp([
  'tracking', 'telemetry', 'analytics', 'beacon', 'pixel', 'logging',
  'ponf\\.', 'metrics\\.', 'stats\\.', 'collect\\.',
  'doubleclick', 'google-analytics', 'googletagmanager', 'googleadservices',
  'segment\\.io', 'mixpanel', 'amplitude', 'hotjar', 'fullstory',
  'datadoghq', 'newrelic', 'sentry\\.io',
].join('|'), 'i');

function isTrackingHost(host) {
  return TRACKING_HOST_RE.test(host);
}

page.on('requestfailed', (req) => {
  const errText = req.failure()?.errorText || 'unknown';
  let host = '';
  try { host = new URL(req.url()).host; } catch {}
  const rt = req.resourceType();
  // Benign patterns we don't count as user-visible failures:
  //  - ERR_ABORTED on fetch/xhr: page cancelled its own prefetch
  //  - tracking/telemetry hosts: expected to be blocked, irrelevant to UX
  //  - beacon resource type: fire-and-forget, never user-visible
  const benign =
    (errText === 'net::ERR_ABORTED' && ['fetch', 'xhr', 'image'].includes(rt)) ||
    isTrackingHost(host) ||
    rt === 'beacon';
  failures.push({
    url: req.url(),
    method: req.method(),
    resourceType: rt,
    failure: errText,
    benign,
    category: benign ? (isTrackingHost(host) ? 'tracking' : 'aborted') : 'real',
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

// 'load' fires when the main document and its direct subresources are
// done; 'networkidle' never resolves on modern sites that keep tracking
// or real-time connections alive (LinkedIn beacons, Twitch EventSource,
// Gmail long-poll, etc.), producing spurious timeouts.
let navError = null;
try {
  await page.goto(targetUrl, { waitUntil: 'load', timeout: 30000 });
  // Give late-binding JS a couple seconds to crash if it's going to.
  await page.waitForTimeout(2000);
} catch (e) {
  navError = String(e.message || e);
}

const runEndMs = Date.now();

await page.screenshot({ path: resolve(reportDir, 'screenshot.png'), fullPage: true });
await browser.close();

const hostsFailed = new Set();
for (const f of failures) {
  if (f.benign) continue;
  try { hostsFailed.add(new URL(f.url).host); } catch {}
}

// Soft timeout — if the nav timed out but the page got meaningful content
// and no real failures surfaced, don't treat it as a failure. Sites with
// long-lived tracking/EventSource connections (LinkedIn, Gmail, Twitch)
// never reach networkidle by design.
const navTimedOutSoftly = navError && /Timeout/i.test(navError) &&
  hostsTouched.size >= 3 && hostsFailed.size === 0;
if (navTimedOutSoftly) {
  navError = `${navError.split('\n')[0]} — soft timeout (page loaded ${hostsTouched.size} hosts, no hard failures)`;
}

// -----------------------------------------------------------------------
// Proxymate log cross-reference
//
// Scan proxymate.log for lines within [runStart-2s, runEnd+5s]. For each
// host the browser actually failed on, decide:
//
//   BYPASS       — host never seen in proxy log during window
//                  (traffic went around the proxy: QUIC/HTTPS-RR/direct)
//   PROXY_ERROR  — host seen with 4xx/5xx/handshake fail in proxy log
//                  (proxy touched it but something broke upstream)
//   BROWSER      — host seen with 2xx in proxy log — browser reported
//                  failure anyway (SRI / CORS / SNI mismatch / coalescing)
// -----------------------------------------------------------------------

const hostClassification = {};
const logDirEnv = process.env.PROXYMATE_LOG_DIR;
const logDir = logDirEnv || join(homedir(), 'Library/Application Support/Proxymate/logs');
const logFile = join(logDir, 'proxymate.log');

let logHosts = null;
try {
  await stat(logFile);
  const raw = await readFile(logFile, 'utf8');
  const inWindow = [];
  for (const line of raw.split('\n')) {
    if (!line) continue;
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }
    const t = Date.parse(entry.timestamp);
    if (!Number.isFinite(t)) continue;
    // window = [runStart - 2s, runEnd + 5s]
    if (t >= runStartMs - 2000 && t <= runEndMs + 5000) {
      inWindow.push(entry);
    }
  }

  // Build host → {seen, statuses} from "MITM response: host (code)" pattern
  // plus any message that contains a known host substring.
  logHosts = new Map();  // host -> { statuses: Set<int>, errors: Set<string> }
  for (const entry of inWindow) {
    const msg = entry.message || '';
    let m = msg.match(/MITM response:\s+([a-z0-9.-]+)\s+\((\d+)\)/i);
    if (m) {
      const [, h, code] = m;
      if (!logHosts.has(h)) logHosts.set(h, { statuses: new Set(), errors: new Set() });
      logHosts.get(h).statuses.add(Number(code));
      continue;
    }
    m = msg.match(/(tls|handshake|certificate|pinning).*?([a-z0-9-]+\.[a-z0-9.-]+)/i);
    if (m) {
      const h = m[2];
      if (!logHosts.has(h)) logHosts.set(h, { statuses: new Set(), errors: new Set() });
      logHosts.get(h).errors.add(msg.slice(0, 120));
    }
  }

  for (const h of hostsFailed) {
    const rec = logHosts.get(h);
    if (!rec) {
      hostClassification[h] = 'BYPASS';
    } else if (rec.errors.size > 0 || [...rec.statuses].some(s => s >= 400)) {
      hostClassification[h] = 'PROXY_ERROR';
    } else {
      hostClassification[h] = 'BROWSER';
    }
  }
} catch {
  // log unavailable (no_proxy mode or file missing) — leave classification empty
}

// Heuristic signals derived from failure mix
const signals = [];
const failureTexts = failures.map(f => f.failure.toLowerCase()).join(' ');
if (/net::err_cert|unknown_ca|ssl_error|sec_error/.test(failureTexts)) {
  signals.push('CA_NOT_TRUSTED — browser does not trust Proxymate CA in this context');
}
if (failures.some(f => f.failure === 'net::ERR_EMPTY_RESPONSE' || f.failure === 'NS_ERROR_NET_RESET' || /http2_protocol_error/i.test(f.failure))) {
  signals.push('CONNECTION_RESET — H/2 stream reset (coalescing) or pinning mid-handshake');
}
if (failures.some(f => /ERR_QUIC|quic/i.test(f.failure))) {
  signals.push('QUIC_FAILURE — HTTP/3 attempts failing');
}
const corsModFail = consoleErrors.filter(c =>
  /CORS|cross-origin|module source URI/i.test(c.text)).length;
if (corsModFail > 5 && hostsFailed.size > 0) {
  signals.push(`MANY_CORS_MODULE_ERRORS — ${corsModFail} errors across ${hostsFailed.size} host(s)`);
}
const bypassHosts = Object.entries(hostClassification).filter(([, v]) => v === 'BYPASS').map(([k]) => k);
if (bypassHosts.length) {
  signals.push(`BYPASS_CONFIRMED — ${bypassHosts.length} host(s) never touched proxy: ${bypassHosts.slice(0, 5).join(', ')}${bypassHosts.length > 5 ? '...' : ''}`);
}
const proxyErrHosts = Object.entries(hostClassification).filter(([, v]) => v === 'PROXY_ERROR').map(([k]) => k);
if (proxyErrHosts.length) {
  signals.push(`PROXY_UPSTREAM_ERROR — ${proxyErrHosts.length} host(s) failed at the proxy layer: ${proxyErrHosts.slice(0, 5).join(', ')}`);
}

const report = {
  target: targetUrl,
  label,
  mode,
  timestamp: ts,
  browser: browserKind,
  proxyPort: noProxy ? null : Number(proxyPort),
  navError,
  durationMs: runEndMs - runStartMs,
  counts: {
    failures: failures.length,
    failuresReal: failures.filter(f => !f.benign).length,
    consoleErrors: consoleErrors.length,
    pageErrors: pageErrors.length,
    nonOkResponses: responses.length,
    hostsTouched: hostsTouched.size,
  },
  hostsFailed: Array.from(hostsFailed).sort(),
  hostClassification,
  signals,
  failures: failures.slice(0, 100),
  consoleErrors: consoleErrors.slice(0, 100),
  pageErrors,
  nonOkResponses: responses.slice(0, 100),
};

await writeFile(resolve(reportDir, 'report.json'), JSON.stringify(report, null, 2));

// Summary to stdout
const line = '─'.repeat(60);
console.log(line);
console.log(`target    ${targetUrl}`);
console.log(`mode      ${mode}   browser: ${browserKind}`);
console.log(`report    ${reportDir}`);
console.log(line);
const realFails = failures.filter(f => !f.benign).length;
console.log(`requests   ${hostsTouched.size} hosts touched, ${realFails} real failures, ${pageErrors.length} page errors`);
console.log(`console    ${consoleErrors.length} errors/warnings`);
if (Object.keys(hostClassification).length) {
  console.log('\nFailed host verdict:');
  for (const [h, v] of Object.entries(hostClassification)) {
    console.log(`  [${v.padEnd(12)}] ${h}`);
  }
}
if (signals.length) {
  console.log('\nSignals:');
  for (const s of signals) console.log('  • ' + s);
}
if (navError) {
  console.log(`\nnav error: ${navError}`);
}

// Actionable failures only — tracking/aborted fetches don't count.
// Soft nav timeout (page loaded, no hard failures) is not a FAIL.
const hardNavError = navError && !navTimedOutSoftly;
process.exit(signals.length || pageErrors.length || realFails || hardNavError ? 1 : 0);
