// Runs diagnose.mjs across the sites listed in sites.json, emits a
// summary table to stdout and a single aggregate report.
//
// Usage:  node suite.mjs [chromium|firefox]

import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

const browserKind = process.argv[2] || 'chromium';

const { sites } = JSON.parse(await readFile(resolve('./sites.json'), 'utf8'));

const ts = new Date().toISOString().replace(/[:.]/g, '-');
const suiteDir = resolve('./reports/_suite', ts);
await mkdir(suiteDir, { recursive: true });

function runOne(site) {
  return new Promise((done) => {
    const chunks = [];
    const proc = spawn('node', ['diagnose.mjs', site.url, browserKind, site.label], {
      env: process.env,
    });
    proc.stdout.on('data', (d) => chunks.push(d));
    proc.stderr.on('data', (d) => chunks.push(d));
    proc.on('close', (code) => done({ site, code, out: Buffer.concat(chunks).toString() }));
  });
}

const results = [];
for (const site of sites) {
  const r = await runOne(site);
  results.push(r);
  const status = r.code === 0 ? 'OK' : 'FAIL';
  console.log(`[${status.padEnd(4)}] ${site.label.padEnd(12)} ${site.url}`);
}

const summary = results.map(r => ({ label: r.site.label, url: r.site.url, code: r.code }));
await writeFile(resolve(suiteDir, 'summary.json'), JSON.stringify(summary, null, 2));

const failed = results.filter(r => r.code !== 0);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
if (failed.length) {
  console.log(`\nFailed sites (see tests/site-compat/reports/<label>/ for details):`);
  for (const f of failed) console.log(`  - ${f.site.label} (${f.site.url})`);
}

process.exit(failed.length ? 1 : 0);
