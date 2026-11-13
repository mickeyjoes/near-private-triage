// Offline re-verification of a recorded evidence bundle. No API key, no network:
// the bundle carries the attestation report, Intel collateral, NVIDIA NRAS token
// + JWKS, the signature, and (for non-confidential fixtures) the exact bytes.
//
// Usage:
//   node scripts/verify-bundle.ts <evidence.json> [--receipt <receipt.json>] [--write] [--quiet]
//
// --receipt  also require the recomputed receipt to equal the saved one exactly
// --write    (re)write receipt.json next to the bundle from this verifier
// Exit code: 0 only if the verdict is VERIFIED (and the receipt matches, if given).
//
// Note: checks are evaluated "as of" the bundle's capture time, because Intel
// collateral and NVIDIA tokens expire. Freshness (the nonce) is meaningful to the
// party that chose the salt at capture time; offline, this proves the bundle is
// internally consistent and cryptographically valid.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { evaluateBundle, type EvidenceBundle } from '../server/verifier/evidence.ts';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
if (!file) {
  console.error('usage: node scripts/verify-bundle.ts <evidence.json> [--receipt receipt.json] [--write] [--quiet]');
  process.exit(2);
}
const flag = (n: string) => args.includes(n);
const receiptArg = args.indexOf('--receipt') >= 0 ? args[args.indexOf('--receipt') + 1] : undefined;

const bundle = JSON.parse(readFileSync(file, 'utf8')) as EvidenceBundle;
if (bundle.schema !== 'privatetriage.evidence/v1') {
  console.error(`unsupported evidence schema: ${String(bundle.schema)}`);
  process.exit(2);
}
const { receipt } = evaluateBundle(bundle);
const text = JSON.stringify(receipt, null, 2) + '\n';

if (!flag('--quiet')) {
  for (const p of receipt.properties) {
    console.log(`${p.verdict.padEnd(10)} ${p.title}`);
    for (const c of p.checks) console.log(`   ${c.status === 'pass' ? '✓' : c.status === 'fail' ? '✗' : '?'} ${c.label} — ${c.detail}`);
  }
  console.log(`\nVERDICT: ${receipt.verdict}\n${receipt.headline}`);
}

let match = true;
if (receiptArg) {
  const saved = readFileSync(receiptArg, 'utf8');
  match = saved === text;
  console.log(match ? `receipt: MATCHES ${receiptArg}` : `receipt: DIFFERS from ${receiptArg}`);
}
if (flag('--write')) {
  const out = join(dirname(file), 'receipt.json');
  writeFileSync(out, text);
  console.log(`receipt written: ${out}`);
}
process.exit(receipt.verdict === 'VERIFIED' && match ? 0 : 1);
