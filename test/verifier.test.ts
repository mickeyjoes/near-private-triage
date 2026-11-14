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
const SMOKE_DIRS = dirs('evidence/smoke');
const base = load(join('evidence/samples/lumora-staking/evidence.json'));
const other = load(join('evidence/samples/quillmark-ssrf/evidence.json'));

function check(receipt: ReturnType<typeof evaluateBundle>['receipt'], property: string, id: string) {
  const p = receipt.properties.find((x) => x.id === property);
  assert.ok(p, `property ${property} present`);
  return { p, c: p.checks.find((x) => x.id === id) };
}

describe('genuine evidence', () => {
  for (const d of [...GATE1_DIRS, ...SAMPLE_DIRS, ...SMOKE_DIRS]) {
    it(`${d} re-verifies offline and reproduces its receipt byte-for-byte`, () => {
      const { receipt } = evaluateBundle(load(join(d, 'evidence.json')));
      assert.equal(receipt.verdict, 'VERIFIED', receipt.headline);
      assert.equal(receipt.signer?.kind, 'provider_tee');
      assert.equal(JSON.stringify(receipt, null, 2) + '\n', readFileSync(join(d, 'receipt.json'), 'utf8'));
      for (const p of receipt.properties) for (const c of p.checks) assert.equal(c.status, 'pass', `${p.id}/${c.id}: ${c.detail}`);
    });
  }

  it('post-audit live smoke run: attestation, report POST and signature GET all used the one attested TLS socket', () => {
    assert.ok(SMOKE_DIRS.length >= 1);
    for (const d of SMOKE_DIRS) {
      const b = load(join(d, 'evidence.json'));
      const { receipt } = evaluateBundle(b);
      assert.equal(receipt.transmission, 'sent');
      assert.equal(b.signature_error ?? null, null);
      const a = b.attestation!;
      for (const x of [b.completion!, b.signature!] as { socket_id?: number; peer_spki_sha256?: string }[]) {
        assert.equal(x.socket_id, a.socket_id);
        assert.equal(x.peer_spki_sha256, a.peer_spki_sha256);
      }
    }
  });

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

describe('GPU evidence is authenticated before any GPU fact is shown (audit F3)', () => {
  const editGpu = (edit: (p: Record<string, unknown>) => void, nras?: (arr: unknown[]) => void) => {
    const t = structuredClone(base);
    const a = JSON.parse(t.attestation!.body);
    const p = JSON.parse(a.model_attestations[0].nvidia_payload);
    edit(p);
    a.model_attestations[0].nvidia_payload = JSON.stringify(p);
    t.attestation!.body = JSON.stringify(a);
    if (nras) {
      const arr = JSON.parse(t.nras['0']!.nrasResponse);
      nras(arr);
      t.nras['0'] = { ...t.nras['0']!, nrasResponse: JSON.stringify(arr) };
    }
    return t;
  };
  const original = JSON.stringify(evaluateBundle(base).receipt);

  it('genuine evidence: GPU facts come from NVIDIA-signed per-GPU claims', () => {
    const { receipt } = evaluateBundle(base);
    const gpu = receipt.model_tee?.gpu as { count: number; arch: string } | null;
    assert.equal(gpu?.count, 8);
    assert.equal(gpu?.arch, 'GH100');
    for (const id of ['gpu_device_reports', 'gpu_claims', 'gpu_inventory']) assert.equal(check(receipt, 'gpu_tee', id).c?.status, 'pass', id);
  });

  for (const [name, mutate] of [
    ['raw GPU reports replaced with null', () => editGpu((p) => { p.evidence_list = (p.evidence_list as unknown[]).map(() => null); })],
    ['one detached per-GPU token forged', () => editGpu(() => {}, (arr) => { (arr[1] as Record<string, string>)['GPU-0'] = 'this.is.forged'; })],
    ['99 invented GPUs, invented arch, detached tokens deleted', () => editGpu((p) => { p.arch = 'ATTACKER-INVENTED-GPU'; p.evidence_list = Array(99).fill({ evidence: '00', certificate: 'not-a-cert', nonce: '00' }); }, (arr) => { arr[1] = {}; })],
    ['8 invented GPU entries (count within limits)', () => editGpu((p) => { p.evidence_list = Array(8).fill({ evidence: '00', certificate: 'not-a-cert', nonce: p.nonce }); })],
    ['detached per-GPU tokens deleted', () => editGpu(() => {}, (arr) => { arr[1] = {}; })],
  ] as const) {
    it(`${name}: not VERIFIED, disclosure blocked, no GPU inventory asserted, receipt changes`, () => {
      const { receipt, preflight } = evaluateBundle(mutate());
      assert.notEqual(receipt.verdict, 'VERIFIED');
      assert.equal(preflight.ok, false);
      assert.equal(receipt.model_tee?.gpu ?? null, null);
      assert.notEqual(JSON.stringify(receipt), original);
    });
  }
});

describe('report transmission state (audit F2)', () => {
  it('refusals and preflight blocks are "not sent"', () => {
    for (const d of [...dirs('evidence/refusals'), ...dirs('evidence/attempts').filter((x) => x.includes('blocked'))]) {
      const { receipt } = evaluateBundle(load(join(d, 'evidence.json')));
      assert.equal(receipt.transmission, 'not_sent', d);
      assert.equal(receipt.disclosed, false);
    }
  });

  it('a recorded response is always "sent", whatever the bundle claims', () => {
    const t = structuredClone(base);
    t.transmission = { state: 'not_sent', detail: 'lie' };
    assert.equal(evaluateBundle(t).receipt.transmission, 'sent');
  });

  it('an older bundle with a passing preflight but no response is conservatively "may have been sent"', () => {
    const t = structuredClone(base);
    t.completion = null;
    t.signature = null;
    t.blocked_reason = 'Inference request failed: socket hang up';
    const { receipt } = evaluateBundle(t);
    assert.equal(receipt.transmission, 'may_have_been_sent');
    assert.equal(receipt.disclosed, true);
    assert.notEqual(receipt.verdict, 'VERIFIED');
  });
});

