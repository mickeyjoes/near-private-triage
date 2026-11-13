// Build the read-only guided-demo dataset from GENUINE recorded evidence.
// Every receipt here is recomputed by the real verifier from the recorded
// bundles; tamper results are produced by applying server/verifier/tamper.ts
// to a genuine bundle. Nothing is simulated.
//
// Usage: node scripts/build-demo.ts   → web/public/demo/{data.json, evidence/*.json}
import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SAMPLES } from '../shared/samples.ts';
import { evaluateBundle, type EvidenceBundle } from '../server/verifier/evidence.ts';
import { SCENARIOS } from '../server/verifier/tamper.ts';

const OUT = join('web', 'public', 'demo');
mkdirSync(join(OUT, 'evidence'), { recursive: true });
const load = (p: string) => JSON.parse(readFileSync(p, 'utf8'));

const runs: Record<string, unknown> = {};
for (const s of SAMPLES) {
  const dir = join('evidence', 'samples', s.id);
  const bundle = load(join(dir, 'evidence.json')) as EvidenceBundle;
  const { receipt } = evaluateBundle(bundle);
  const run = load(join(dir, 'run.json'));
  delete run.receipt;
  runs[s.id] = { ...run, receipt, evidence_file: `demo/evidence/${s.id}.json` };
  copyFileSync(join(dir, 'evidence.json'), join(OUT, 'evidence', `${s.id}.json`));
}

const gate1Dir = readdirSync(join('evidence', 'gate1')).sort().at(-1)!;
const gate1Bundle = load(join('evidence', 'gate1', gate1Dir, 'evidence.json')) as EvidenceBundle;
copyFileSync(join('evidence', 'gate1', gate1Dir, 'evidence.json'), join(OUT, 'evidence', 'gate1.json'));

const refusals = readdirSync(join('evidence', 'refusals')).map((d) => {
  const b = load(join('evidence', 'refusals', d, 'evidence.json')) as EvidenceBundle;
  return { model: b.model, captured_at: b.captured_at, blocked_reason: b.blocked_reason ?? null, receipt: evaluateBundle(b).receipt };
});

const outages = readdirSync(join('evidence', 'attempts'))
  .filter((d) => d.includes('blocked'))
  .map((d) => {
    const b = load(join('evidence', 'attempts', d, 'evidence.json')) as EvidenceBundle;
    return { id: d, model: b.model, captured_at: b.captured_at, blocked_reason: b.blocked_reason ?? null, disclosed: b.completion !== null, verdict: evaluateBundle(b).receipt.verdict };
  });

const base = load(join('evidence', 'samples', 'lumora-staking', 'evidence.json')) as EvidenceBundle;
const other = load(join('evidence', 'samples', 'quillmark-ssrf', 'evidence.json')) as EvidenceBundle;
const tamper = SCENARIOS.map((s) => {
  const { receipt } = evaluateBundle(s.apply(base, { other }));
  return {
    id: s.id,
    title: s.title,
    attack: s.attack,
    expect: s.expect,
    property: s.property,
    check: s.check,
    verdict: receipt.verdict,
    headline: receipt.headline,
    properties: receipt.properties.map((p) => ({ id: p.id, title: p.title, verdict: p.verdict, checks: p.checks.filter((c) => c.status !== 'pass') })),
  };
});

writeFileSync(
  join(OUT, 'data.json'),
  JSON.stringify({
    schema: 'privatetriage.demo/v1',
    note: 'Recorded genuine NEAR AI Cloud runs on fictional reports. Receipts recomputed from the recorded evidence by the PrivateTriage verifier; reproduce with `npm run verify -- evidence/samples/<id>/evidence.json`.',
    samples: SAMPLES,
    runs,
    gate1: { receipt: evaluateBundle(gate1Bundle).receipt, evidence_file: 'demo/evidence/gate1.json' },
    refusals,
    outages,
    tamper: { base: 'lumora-staking', results: tamper },
  }),
);
console.log(`demo data: ${Object.keys(runs).length} runs, ${refusals.length} refusals, ${outages.length} outage blocks, ${tamper.length} tamper results → ${OUT}`);
for (const t of tamper) if (t.verdict !== t.expect) throw new Error(`tamper ${t.id}: expected ${t.expect}, got ${t.verdict}`);
