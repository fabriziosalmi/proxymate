// Compare the most recent two runs per label across two modes and print
// the regressions (passed in mode A, failed in mode B).
//
// Usage:
//   node compare.mjs <modeA> <modeB>
//   e.g. node compare.mjs direct proxy-mitm-on
//        node compare.mjs proxy-mitm-off proxy-mitm-on

import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const [, , modeA, modeB] = process.argv;
if (!modeA || !modeB) {
  console.error('usage: node compare.mjs <modeA> <modeB>');
  console.error('e.g.   node compare.mjs direct proxy-mitm-on');
  process.exit(2);
}

async function latestReport(label, mode) {
  const dir = resolve('./reports', label, mode);
  try {
    const entries = await readdir(dir);
    const withStat = await Promise.all(entries.map(async e => ({
      name: e, stat: await stat(join(dir, e)),
    })));
    const latest = withStat.filter(e => e.stat.isDirectory()).sort((a, b) => b.stat.mtimeMs - a.stat.mtimeMs)[0];
    if (!latest) return null;
    const report = JSON.parse(await readFile(join(dir, latest.name, 'report.json'), 'utf8'));
    return report;
  } catch { return null; }
}

const labels = (await readdir(resolve('./reports'))).filter(n => n !== '_suite' && !n.startsWith('.'));

console.log(`Comparing: ${modeA}  →  ${modeB}`);
console.log('─'.repeat(60));

const regressions = [];
const improvements = [];
const consistent = { pass: 0, fail: 0 };
const missing = [];

for (const label of labels.sort()) {
  const [rA, rB] = await Promise.all([latestReport(label, modeA), latestReport(label, modeB)]);
  if (!rA || !rB) { missing.push({ label, hasA: !!rA, hasB: !!rB }); continue; }

  const passedA = !rA.signals.length && !rA.pageErrors.length && !rA.counts.failuresReal;
  const passedB = !rB.signals.length && !rB.pageErrors.length && !rB.counts.failuresReal;

  if (passedA && !passedB) regressions.push({ label, rA, rB });
  else if (!passedA && passedB) improvements.push({ label, rA, rB });
  else if (passedA && passedB) consistent.pass++;
  else consistent.fail++;
}

if (regressions.length) {
  console.log(`\n${regressions.length} REGRESSION(S) — passed in ${modeA}, failed in ${modeB}:\n`);
  for (const { label, rB } of regressions) {
    console.log(`  ${label}`);
    for (const s of rB.signals) console.log(`    · ${s}`);
    const cls = rB.hostClassification || {};
    for (const [h, v] of Object.entries(cls)) {
      console.log(`    [${v}] ${h}`);
    }
  }
} else {
  console.log('\nNo regressions.');
}

if (improvements.length) {
  console.log(`\n${improvements.length} improvement(s) — failed in ${modeA}, passed in ${modeB}:`);
  for (const { label } of improvements) console.log(`  + ${label}`);
}

console.log(`\nConsistent: ${consistent.pass} passed in both, ${consistent.fail} failed in both`);
if (missing.length) {
  console.log(`\nMissing data: ${missing.map(m => `${m.label}(${m.hasA ? '' : 'A'}${m.hasB ? '' : 'B'})`).join(', ')}`);
}

process.exit(regressions.length ? 1 : 0);
