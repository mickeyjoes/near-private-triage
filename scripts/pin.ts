// Review the measurements NEAR AI Cloud currently attests for a model, against
// the pinned policy in server/verifier/measurements.ts. Free: attestation only,
// no API key, nothing is sent. Prints what changed so a human can review it
// (release notes, compose diff) BEFORE adding it to the pinned list.
// Usage: node scripts/pin.ts [--model Qwen/Qwen3.6-35B-A3B-FP8]
import { runConfidentialCompletion } from '../server/near/confidentialCompletion.ts';
import { PINNED_MEASUREMENTS } from '../server/verifier/measurements.ts';

const args = process.argv.slice(2);
const model = args.indexOf('--model') >= 0 ? args[args.indexOf('--model') + 1]! : 'Qwen/Qwen3.6-35B-A3B-FP8';
const r = await runConfidentialCompletion({
  apiKey: '',
  model,
  requestBody: Buffer.from(JSON.stringify({ model, messages: [{ role: 'user', content: 'pin review (never sent)' }] })),
  preflightOnly: true,
});
const rc = r.receipt;
for (const p of rc.properties.filter((x) => x.id === 'gateway_tee' || x.id === 'model_tee' || x.id === 'gpu_tee')) {
  const bad = p.checks.filter((c) => c.status !== 'pass');
  console.log(`${p.verdict.padEnd(10)} ${p.title}${bad.length ? '' : ' (all checks pass)'}`);
  for (const c of bad) console.log(`   ${c.status === 'fail' ? '✗' : '?'} ${c.id}: ${c.detail}`);
}
const show = (role: string, x: Record<string, unknown> | null) => {
  if (!x) return;
  const q = (x.quote ?? {}) as Record<string, string>;
  console.log(`\n${role}: app_id ${x.app_id}\n  os_image_hash ${x.os_image_hash}\n  mrtd ${q.mr_td}\n  rtmr1 ${q.rtmr1}\n  rtmr2 ${q.rtmr2}\n  compose_hash ${x.compose_hash}\n  images ${(x.image_digests as string[] | undefined)?.join(' ') ?? ''}`);
};
show('gateway', rc.gateway as Record<string, unknown> | null);
show('model', rc.model_tee as Record<string, unknown> | null);
console.log(`\npinned: ${PINNED_MEASUREMENTS.os.length} OS profiles, ${PINNED_MEASUREMENTS.apps.length} app identities. Add new values to server/verifier/measurements.ts only after review.`);
