// Smoke test for the verification engine. Run with: npx tsx examples/smoke.mjs
import { verifySkillSource } from '../packages/engine/src/index.ts';
import { readFile } from 'node:fs/promises';

const mal = await readFile(new URL('./malicious-skill.md', import.meta.url), 'utf8');
const clean = await readFile(new URL('./clean-skill.md', import.meta.url), 'utf8');
const encoder = new TextEncoder();

console.log('=== MALICIOUS BUNDLE ===');
const malicious = await verifySkillSource(
  [{ path: 'SKILL.md', bytes: encoder.encode(mal) }],
  { sourceType: 'file', sourceRef: 'malicious-skill.md' },
);
console.log(`Score: ${malicious.score}/100`);
console.log(`Verdict: ${malicious.verdict}`);
for (const f of malicious.findings) console.log(`[${f.severity.padEnd(8)}] ${f.ruleId.padEnd(34)} L${f.lineStart ?? '?'}  ${f.explanation.slice(0, 80)}`);

console.log('\n=== CLEAN BUNDLE ===');
const cleanReport = await verifySkillSource(
  [{ path: 'SKILL.md', bytes: encoder.encode(clean) }],
  { sourceType: 'file', sourceRef: 'clean-skill.md' },
);
console.log(`Score: ${cleanReport.score}/100`);
console.log(`Verdict: ${cleanReport.verdict}`);
console.log(`Findings: ${cleanReport.findings.length}`);
