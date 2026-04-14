// Runs diagnose.mjs across sites.json. Forwards flags to each child.
//
// Usage:
//   node suite.mjs                                  # chromium, via proxy, mitm=unknown
//   node suite.mjs --browser firefox
//   node suite.mjs --no-proxy                       # baseline without Proxymate
//   node suite.mjs --mitm on|off                    # tag runs with MITM state
//   node suite.mjs --browser firefox --mitm on

import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

const rawArgs = process.argv.slice(2);
const opts = {};
for (let i = 0; i < rawArgs.length; i++) {
  const a = rawArgs[i];
  if (a === '--no-proxy') opts.noProxy = true;
  else if (a.startsWith('--')) { opts[a.slice(2)] = rawArgs[i + 1]; i++; }
}

const browserKind = opts.browser || 'chromium';
const noProxy = !!opts.noProxy;
const mitmArg = opts.mitm || null;
const mode = noProxy ? 'direct' : `proxy-mitm-${mitmArg || 'unknown'}`;

const { sites } = JSON.parse(await readFile(resolve('./sites.json'), 'utf8'));

const ts = new Date().toISOString().replace(/[:.]/g, '-');
const suiteDir = resolve('./reports/_suite', mode, ts);
await mkdir(suiteDir, { recursive: true });

function runOne(site) {
  return new Promise((done) => {
    const chunks = [];
    const childArgs = ['diagnose.mjs', site.url, '--browser', browserKind, '--label', site.label];
    if (noProxy) childArgs.push('--no-proxy');
    if (mitmArg) childArgs.push('--mitm', mitmArg);
    const proc = spawn('node', childArgs, { env: process.env });
    proc.stdout.on('data', (d) => chunks.push(d));
    proc.stderr.on('data', (d) => chunks.push(d));
    proc.on('close', (code) => done({ site, code, out: Buffer.concat(chunks).toString() }));
  });
}

const results = [];
for (const site of sites) {
  const r = await runOne(site);
  results.push(r);
  const status = r.code === 0 ? 'OK  ' : 'FAIL';
  console.log(`[${status}] ${site.label.padEnd(12)} ${site.url}`);
}

const summary = results.map(r => ({ label: r.site.label, url: r.site.url, code: r.code }));
await writeFile(resolve(suiteDir, 'summary.json'), JSON.stringify({ mode, browser: browserKind, results: summary }, null, 2));

const failed = results.filter(r => r.code !== 0);
console.log(`\n${results.length - failed.length}/${results.length} passed · mode=${mode} browser=${browserKind}`);
console.log(`suite report: ${suiteDir}`);
if (failed.length) {
  console.log('\nFailed:');
  for (const f of failed) console.log(`  - ${f.site.label} (${f.site.url})`);
}

process.exit(failed.length ? 1 : 0);
