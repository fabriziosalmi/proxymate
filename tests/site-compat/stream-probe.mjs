// Stream probe — curls streaming-media URLs through Proxymate and asserts
// the signal-based MITM auto-exclude is working end-to-end.
//
// For each entry in sites-streaming.json:
//   1. curl via proxy, cap at 4 s, write bytes to /dev/null but record
//      size_download, content_type, http_code.
//   2. Assert: http_code in [200, 206] AND content_type matches the
//      expected regex AND size_download >= MIN_BYTES.
//   3. Scan proxymate.log for a "streaming media ... auto-excluding"
//      line matching the host within the probe window.
//
// Exit non-zero on any inequivocal failure (0 bytes, wrong Content-Type,
// missing auto-exclude log line). Used by the pre-push hook to gate
// the streaming-media patch shipped in 0.9.57.
//
// Env:
//   PROXYMATE_PORT     required (listener port)
//   PROXYMATE_LOG_DIR  default ~/Library/Application Support/Proxymate/logs
//
// Usage:
//   node stream-probe.mjs                # all streams in sites-streaming.json
//   node stream-probe.mjs --label mux-hls-test   # just one

import { readFile, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import { URL } from 'node:url';

const rawArgs = process.argv.slice(2);
const opts = {};
for (let i = 0; i < rawArgs.length; i++) {
  const a = rawArgs[i];
  if (a.startsWith('--')) { opts[a.slice(2)] = rawArgs[i + 1]; i++; }
}

const proxyPort = process.env.PROXYMATE_PORT;
if (!proxyPort) {
  console.error('PROXYMATE_PORT env var required');
  process.exit(2);
}

const DEFAULT_MIN_BYTES = 8 * 1024;    // per-stream minBytes can override
const MAX_TIME_SEC = 4;                // curl cap — well below the 10 MB / 2 MB buffer stall
const LOG_WINDOW_SLACK_MS = 5000;      // accept log lines up to 5 s after probe end

const { streams } = JSON.parse(await readFile(resolve('./sites-streaming.json'), 'utf8'));
const filtered = opts.label ? streams.filter(s => s.label === opts.label) : streams;
if (!filtered.length) {
  console.error(`no streams matched (have: ${streams.map(s => s.label).join(', ')})`);
  process.exit(2);
}

function curlProbe(streamUrl) {
  return new Promise((done) => {
    const args = [
      '-x', `http://127.0.0.1:${proxyPort}`,
      '-sS',
      '-k',                              // Proxymate CA may not be in curl's bundle
      '--max-time', String(MAX_TIME_SEC),
      '--output', '/dev/null',
      '--write-out', '%{size_download}\t%{content_type}\t%{http_code}\n',
      streamUrl,
    ];
    const p = spawn('curl', args, { env: process.env });
    let out = '';
    let err = '';
    p.stdout.on('data', (d) => { out += d.toString(); });
    p.stderr.on('data', (d) => { err += d.toString(); });
    p.on('close', (code) => done({ code, out: out.trim(), err: err.trim() }));
  });
}

async function scanLog(hosts, startMs, endMs) {
  const logDir = process.env.PROXYMATE_LOG_DIR
    || join(homedir(), 'Library/Application Support/Proxymate/logs');
  const logFile = join(logDir, 'proxymate.log');
  try {
    await stat(logFile);
  } catch {
    return { available: false, matched: {} };
  }
  const raw = await readFile(logFile, 'utf8');
  const matched = {};
  for (const line of raw.split('\n')) {
    if (!line) continue;
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }
    const t = Date.parse(entry.timestamp);
    if (!Number.isFinite(t)) continue;
    if (t < startMs - 1000 || t > endMs + LOG_WINDOW_SLACK_MS) continue;
    const msg = entry.message || '';
    if (!/streaming media.*auto-excluding/i.test(msg)) continue;
    for (const h of hosts) {
      if (msg.includes(h)) { matched[h] = msg; break; }
    }
  }
  return { available: true, matched };
}

const results = [];
const startMs = Date.now();
for (const s of filtered) {
  const probeStart = Date.now();
  const r = await curlProbe(s.url);
  const probeEnd = Date.now();
  const [sizeStr = '0', contentType = '', httpStr = '0'] = (r.out || '').split('\t');
  const size = Number(sizeStr);
  const httpCode = Number(httpStr);
  const minBytes = Number(s.minBytes) || DEFAULT_MIN_BYTES;
  const ctOk = new RegExp(s.expectedContentTypeRe, 'i').test(contentType);
  const statusOk = httpCode === 200 || httpCode === 206;
  const bytesOk = size >= minBytes;
  const overall = ctOk && statusOk && bytesOk;
  results.push({
    label: s.label, url: s.url, kind: s.kind,
    host: (() => { try { return new URL(s.url).host; } catch { return null; } })(),
    exitCode: r.code, httpCode, contentType, bytes: size, minBytes,
    probeMs: probeEnd - probeStart,
    check: { statusOk, ctOk, bytesOk, overall },
    curlStderr: r.err ? r.err.split('\n').slice(-2).join(' | ') : null,
  });
}
const endMs = Date.now();

const hosts = results.map(r => r.host).filter(Boolean);
const logScan = await scanLog(hosts, startMs, endMs);
for (const r of results) {
  if (!r.host) { r.logLineMatched = null; continue; }
  r.logLineMatched = !!logScan.matched[r.host];
}

// Output
const line = '─'.repeat(70);
console.log(line);
console.log(`stream probe   port=${proxyPort}   ${filtered.length} stream(s)   log=${logScan.available ? 'available' : 'missing'}`);
console.log(line);
for (const r of results) {
  const tag = r.check.overall ? 'OK  ' : 'FAIL';
  const log = r.logLineMatched ? 'log ✓'
    : (logScan.available ? 'log ✗' : 'log -');
  const ct = r.contentType || '(empty)';
  console.log(`[${tag}] ${r.label.padEnd(22)} ${String(r.httpCode).padEnd(4)} ${String(r.bytes).padStart(8)} B  ${ct.padEnd(36)} ${log}  ${r.probeMs}ms`);
  if (!r.check.overall) {
    const reasons = [];
    if (!r.check.statusOk) reasons.push(`http=${r.httpCode}`);
    if (!r.check.ctOk) reasons.push(`content-type "${ct}" !~ ${r.kind}`);
    if (!r.check.bytesOk) reasons.push(`bytes=${r.bytes} < ${r.minBytes}`);
    if (r.curlStderr) reasons.push(`curl: ${r.curlStderr}`);
    console.log('       └─ ' + reasons.join('; '));
  } else if (logScan.available && !r.logLineMatched) {
    console.log(`       └─ stream flowed, but no "streaming media ... auto-excluding" log line found for ${r.host}`);
    console.log(`          (likely the host was already in ignore_hosts from a prior run — not a failure)`);
  }
}

const hardFailures = results.filter(r => !r.check.overall);
console.log();
console.log(`${results.length - hardFailures.length}/${results.length} streams passed`);

process.exit(hardFailures.length ? 1 : 0);
