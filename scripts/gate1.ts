// Gate 1: one real, minimal confidential inference with full verification.
// Usage: node scripts/gate1.ts [--model z-ai/glm-5.3-flash] [--out evidence/gate1]
// Writes a reproducible evidence bundle + receipt and exits 0 only on VERIFIED.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadApiKey } from '../server/env.ts';
import { runConfidentialCompletion } from '../server/near/confidentialCompletion.ts';

const args = process.argv.slice(2);
const arg = (name: string, dflt: string) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1]! : dflt;
};
const model = arg('--model', 'z-ai/glm-5.3-flash');
const outRoot = arg('--out', 'evidence/gate1');

const apiKey = loadApiKey();
if (!apiKey) {
  console.error('NEARAI_CLOUD_API_KEY is not set (env or .env). Aborting.');
  process.exit(2);
}

// Non-confidential, fixed probe prompt — safe to publish alongside the evidence.
const requestBody = Buffer.from(
  JSON.stringify({
    model,
    messages: [
      {
        role: 'user',
        content:
          'PrivateTriage Gate-1 probe (non-confidential). In one sentence: why should a security team verify where an AI model runs before sending it an unpublished vulnerability report?',
      },
    ],
    max_tokens: 1500,
    temperature: 0.2,
    stream: false,
  }),
  'utf8',
);

const t0 = Date.now();
const result = await runConfidentialCompletion({
  apiKey,
  model,
  requestBody,
  onStage: (s, d) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s] ${s.padEnd(11)} ${d}`),
});

const stamp = result.bundle.captured_at.replace(/[:.]/g, '-');
const dir = join(outRoot, stamp);
mkdirSync(dir, { recursive: true });
// Fixture content is non-confidential, so the exact bytes are published for independent re-hashing.
result.bundle.completion &&
  Object.assign(result.bundle.completion, {
    request_b64: result.requestBytes.toString('base64'),
    response_b64: result.responseBytes?.toString('base64'),
  });
writeFileSync(join(dir, 'evidence.json'), JSON.stringify(result.bundle, null, 1));
writeFileSync(join(dir, 'receipt.json'), JSON.stringify(result.receipt, null, 2));
writeFileSync(join(dir, 'request.bin'), result.requestBytes);
if (result.responseBytes) writeFileSync(join(dir, 'response.bin'), result.responseBytes);

console.log('\n=== RESULT ===');
for (const p of result.receipt.properties) {
  console.log(`${p.verdict.padEnd(10)} ${p.title}`);
  for (const c of p.checks) console.log(`   ${c.status === 'pass' ? '✓' : c.status === 'fail' ? '✗' : '?'} ${c.label} — ${c.detail}`);
}
console.log(`\nVERDICT: ${result.receipt.verdict}`);
console.log(result.receipt.headline);
console.log(`signer: ${JSON.stringify(result.receipt.signer)}`);
console.log(`evidence: ${dir}`);
process.exit(result.receipt.verdict === 'VERIFIED' ? 0 : 1);
