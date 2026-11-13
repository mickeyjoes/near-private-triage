// Record GENUINE confidential triage runs of the three fictional sample reports,
// plus genuine preflight refusals for models without GPU-TEE evidence (free: the
// report is never sent). Output feeds the read-only guided demo and the tests.
//
// Usage: node scripts/record-samples.ts [--only <sample-id>] [--skip-negative] [--skip-samples]
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SAMPLES } from '../shared/samples.ts';
import { loadApiKey } from '../server/env.ts';
import { runConfidentialCompletion } from '../server/near/confidentialCompletion.ts';
import { runTriage } from '../server/triage/run.ts';

const args = process.argv.slice(2);
const only = args.indexOf('--only') >= 0 ? args[args.indexOf('--only') + 1] : undefined;

function save(dir: string, files: Record<string, string | Buffer>) {
  mkdirSync(dir, { recursive: true });
  for (const [name, data] of Object.entries(files)) writeFileSync(join(dir, name), data);
}

if (!args.includes('--skip-samples')) {
  const apiKey = loadApiKey();
  if (!apiKey) {
    console.error('NEARAI_CLOUD_API_KEY is not set. Aborting.');
    process.exit(2);
  }
  for (const s of SAMPLES.filter((x) => !only || x.id === only)) {
    const run = await runTriage({
      apiKey,
      title: s.title,
      body: s.body,
      onStage: (e) => console.log(`[${s.id}] ${(e.t_ms / 1000).toFixed(1)}s ${e.stage.padEnd(11)} ${e.detail}`),
    });
    const { evidence, ...rest } = run;
    save(join('evidence', 'samples', s.id), {
      'evidence.json': JSON.stringify(evidence, null, 1) + '\n',
      'receipt.json': JSON.stringify(run.receipt, null, 2) + '\n',
      'run.json': JSON.stringify({ sample_id: s.id, ...rest, receipt: undefined }, null, 2) + '\n',
    });
    const t = run.outcome?.triage;
    console.log(
      `[${s.id}] ${run.receipt.verdict} in ${(run.duration_ms / 1000).toFixed(1)}s · ${run.outcome?.status} · ${t?.severity} ${t?.cvss_v31_vector ?? ''} ${t?.cvss_v31_score ?? ''} · validity ${t?.validity} · confidence ${t?.confidence} · injection ${t?.injection_detected} · usage ${JSON.stringify(run.outcome?.usage)}`,
    );
    for (const c of run.outcome?.consistency ?? []) console.log(`   ${c.status} ${c.detail}`);
    for (const e of run.outcome?.errors ?? []) console.log(`   error: ${e}`);
  }
}

if (!args.includes('--skip-negative')) {
  // Genuine refusals: these models return no GPU-TEE model attestation, so the
  // preflight blocks disclosure. No API key is used and nothing is sent.
  for (const model of ['z-ai/glm-5.3', 'openai/gpt-5.4']) {
    const r = await runConfidentialCompletion({
      apiKey: '',
      model,
      requestBody: Buffer.from(JSON.stringify({ model, messages: [{ role: 'user', content: 'preflight probe (never sent)' }] })),
      preflightOnly: true,
    });
    const dir = join('evidence', 'refusals', model.replace(/[^A-Za-z0-9.-]+/g, '_'));
    save(dir, {
      'evidence.json': JSON.stringify(r.bundle, null, 1) + '\n',
      'receipt.json': JSON.stringify(r.receipt, null, 2) + '\n',
    });
    console.log(`[refusal ${model}] ${r.receipt.verdict} · disclosed=${r.receipt.disclosed} · ${r.bundle.blocked_reason}`);
  }
}
