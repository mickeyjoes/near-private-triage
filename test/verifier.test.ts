// Verifier tests over GENUINE recorded evidence (no network, no API key).
// Positive: every recorded VERIFIED bundle re-verifies and its receipt reproduces
// byte-for-byte. Negative: every tamper scenario is caught by the property and
// check it targets, with the expected fail-closed verdict.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { DEFAULT_POLICY, deriveNonce, evaluateBundle, type EvidenceBundle } from '../server/verifier/evidence.ts';
import { SCENARIOS } from '../server/verifier/tamper.ts';

const load = (p: string) => JSON.parse(readFileSync(p, 'utf8')) as EvidenceBundle;
const dirs = (root: string) => readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => join(root, d.name));

const SAMPLE_DIRS = dirs('evidence/samples');
const GATE1_DIRS = dirs('evidence/gate1');
const base = load(join('evidence/samples/lumora-staking/evidence.json'));
const other = load(join('evidence/samples/quillmark-ssrf/evidence.json'));

function check(receipt: ReturnType<typeof evaluateBundle>['receipt'], property: string, id: string) {
  const p = receipt.properties.find((x) => x.id === property);
  assert.ok(p, `property ${property} present`);
  return { p, c: p.checks.find((x) => x.id === id) };
}

describe('genuine evidence', () => {
  for (const d of [...GATE1_DIRS, ...SAMPLE_DIRS]) {
    it(`${d} re-verifies offline and reproduces its receipt byte-for-byte`, () => {
      const { receipt } = evaluateBundle(load(join(d, 'evidence.json')));
      assert.equal(receipt.verdict, 'VERIFIED', receipt.headline);
      assert.equal(receipt.signer?.kind, 'provider_tee');
      assert.equal(JSON.stringify(receipt, null, 2) + '\n', readFileSync(join(d, 'receipt.json'), 'utf8'));
      for (const p of receipt.properties) for (const c of p.checks) assert.equal(c.status, 'pass', `${p.id}/${c.id}: ${c.detail}`);
    });
  }

  it('the signer is the attested model enclave, not the gateway', () => {
    const { receipt } = evaluateBundle(base);
    assert.notEqual(receipt.signer?.address?.toLowerCase(), String(receipt.gateway?.signing_address).toLowerCase());
    assert.equal(receipt.signer?.address?.toLowerCase(), String(receipt.model_tee?.signing_address).toLowerCase());
  });

  it('the attestation nonce commits to the exact request bytes', () => {
    const req = Buffer.from(base.completion!.request_b64!, 'base64');
    const h = createHash('sha256').update(req).digest('hex');
    assert.equal(h, base.nonce.request_sha256);
    assert.equal(deriveNonce(base.nonce.salt, h), base.nonce.value);
  });
});

describe('fail-closed refusals (genuine)', () => {
  for (const d of dirs('evidence/refusals')) {
    it(`${d}: no TEE attestation → not verified, report never sent`, () => {
      const b = load(join(d, 'evidence.json'));
      const { receipt } = evaluateBundle(b);
      assert.equal(receipt.verdict, 'UNVERIFIED');
      assert.equal(receipt.disclosed, false);
      assert.equal(b.completion, null);
    });
  }
  for (const d of dirs('evidence/attempts').filter((x) => x.includes('blocked'))) {
    it(`${d}: GPU attestation outage → preflight blocked disclosure`, () => {
      const b = load(join(d, 'evidence.json'));
      assert.equal(b.completion, null, 'no completion request was made');
      assert.match(String(b.blocked_reason), /attestation/i);
      assert.equal(evaluateBundle(b).receipt.verdict, 'UNVERIFIED');
    });
  }
});

describe('tamper scenarios on genuine evidence', () => {
  for (const s of SCENARIOS) {
    it(`${s.id}: ${s.title} → ${s.expect}`, () => {
      const tampered = s.apply(base, { other });
      const { receipt } = evaluateBundle(tampered);
      assert.equal(receipt.verdict, s.expect, receipt.headline);
      const { p, c } = check(receipt, s.property, s.check);
      assert.ok(c, `check ${s.property}/${s.check} present`);
      assert.notEqual(c.status, 'pass', `${s.property}/${s.check} must not pass`);
      assert.equal(c.status, s.expect === 'FAILED' ? 'fail' : 'unavailable', `${s.check}: ${c.detail}`);
      assert.equal(p.verdict, s.expect);
      // The original bundle is never mutated.
      assert.equal(evaluateBundle(base).receipt.verdict, 'VERIFIED');
    });
  }

  it('a stricter verifier policy rejects otherwise-genuine evidence', () => {
    const { receipt } = evaluateBundle(base, { policy: { ...DEFAULT_POLICY, acceptedTcbStatuses: [] } });
    assert.equal(receipt.verdict, 'FAILED');
    assert.equal(check(receipt, 'gateway_tee', 'tcb_status').c?.status, 'fail');
  });

  it('a genuine TDX guest that is not NEAR’s pinned OS image or app is UNVERIFIED and blocks disclosure', () => {
    const none = { os: [], apps: [], mr_kms: [], key_providers: [] };
    const policy = { ...DEFAULT_POLICY, measurements: none };
    const { receipt, preflight } = evaluateBundle(base, { policy });
    assert.equal(receipt.verdict, 'UNVERIFIED');
    assert.equal(preflight.ok, false, 'preflight must not allow disclosure');
    assert.equal(check(receipt, 'gateway_tee', 'os_image').c?.status, 'unavailable');
    assert.equal(check(receipt, 'model_tee', 'app_identity').c?.status, 'unavailable');
  });

  it('a second model candidate that fails blocks disclosure (every candidate must verify)', () => {
    const t = structuredClone(base);
    const a = JSON.parse(t.attestation!.body);
    const stale = JSON.parse(other.attestation!.body).model_attestations[0];
    a.model_attestations.push(stale);
    t.attestation!.body = JSON.stringify(a);
    Object.assign(t.collateral, other.collateral);
    const { receipt, preflight } = evaluateBundle(t);
    assert.equal(preflight.ok, false);
    assert.match(preflight.reason, /every candidate must verify/);
    assert.equal(receipt.verdict, 'FAILED');
  });

  it('a model report that does not name its model fails', () => {
    const t = structuredClone(base);
    const a = JSON.parse(t.attestation!.body);
    delete a.model_attestations[0].model_name;
    t.attestation!.body = JSON.stringify(a);
    assert.equal(check(evaluateBundle(t).receipt, 'model_tee', 'model_name').c?.status, 'fail');
  });

  it('a bundle that moves its own capture time is rejected by the NVIDIA-signed time anchor', () => {
    const t = structuredClone(base);
    t.captured_at_secs += 20 * 60; // small enough that the NVIDIA token is still valid
    t.captured_at = new Date(t.captured_at_secs * 1000).toISOString();
    const { receipt } = evaluateBundle(t);
    assert.notEqual(receipt.verdict, 'VERIFIED');
    assert.equal(check(receipt, 'gpu_tee', 'time_anchor').c?.status, 'fail');
  });

  it('evidence evaluated after collateral expiry fails rather than passing', () => {
    const late = structuredClone(base);
    late.captured_at_secs += 400 * 24 * 3600;
    assert.notEqual(evaluateBundle(late).receipt.verdict, 'VERIFIED');
  });

  it('no verified status is produced with any property short of VERIFIED', () => {
    for (const s of SCENARIOS) {
      const { receipt } = evaluateBundle(s.apply(base, { other }));
      const allVerified = receipt.properties.every((p) => p.verdict === 'VERIFIED');
      assert.equal(receipt.verdict === 'VERIFIED', allVerified);
    }
  });
});
