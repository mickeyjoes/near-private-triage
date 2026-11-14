// End-to-end pipeline tests with every external dependency replaced by ARCHIVED
// genuine evidence (no network, no API key, no inference). Ports the 2026-11-14
// audit's disclosure-state probe: attestation really passes, then the report
// exchange fails in different ways, and the receipt must describe it honestly.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import https from 'node:https';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { type Exchange, PinnedConnection, type RequestOptions, SocketPinError } from '../server/near/connection.ts';
import { runConfidentialCompletion } from '../server/near/confidentialCompletion.ts';
import { type EvidenceBundle, quoteKey } from '../server/verifier/evidence.ts';

const b = JSON.parse(readFileSync('evidence/samples/lumora-staking/evidence.json', 'utf8')) as EvidenceBundle;
const requestBody = Buffer.from(b.completion!.request_b64!, 'base64');
const responseBody = Buffer.from(b.completion!.response_b64!, 'base64');

type Call = { method: string; path: string; auth: boolean; pinned: boolean };
let calls: Call[] = [];
let onPost: (opts: RequestOptions) => Promise<Exchange> = async () => assert.fail('no POST handler');
let onSignature: (opts: RequestOptions) => Promise<Exchange> = async () => assert.fail('no signature handler');

const originals = {
  randomBytes: crypto.randomBytes,
  now: Date.now,
  fetch: globalThis.fetch,
  request: PinnedConnection.prototype.request,
};
const dcap = createRequire(join(process.cwd(), 'package.json'))('@phala/dcap-qvl') as { getCollateral: unknown };
const originalCollateral = dcap.getCollateral;
let dir = '';
let tlsKey: Buffer | null = null;
let tlsCert: Buffer | null = null;

before(() => {
  // Deterministic challenge and clock, so the archived attestation answers it.
  (crypto as { randomBytes: unknown }).randomBytes = (n: number, ...rest: unknown[]) =>
    n === 32 ? Buffer.from(b.nonce.salt, 'hex') : (originals.randomBytes as (n: number, ...r: unknown[]) => Buffer)(n, ...rest);
  syncBuiltinESMExports();
  Date.now = () => b.captured_at_secs * 1000;
  dcap.getCollateral = async (_url: string, quote: Uint8Array) => b.collateral[quoteKey(Buffer.from(quote).toString('hex'))];
  globalThis.fetch = (async (url: string | URL) => {
    if (String(url).endsWith('/v3/attest/gpu')) return new Response(b.nras['0']!.nrasResponse);
    if (String(url).endsWith('/.well-known/jwks.json')) return new Response(b.nras['0']!.jwks);
    throw new Error('unexpected external request');
  }) as typeof fetch;
  PinnedConnection.prototype.request = async function (opts: RequestOptions): Promise<Exchange> {
    const auth = Object.keys(opts.headers ?? {}).some((k) => k.toLowerCase() === 'authorization');
    calls.push({ method: opts.method, path: opts.path.split('?')[0]!, auth, pinned: Boolean(opts.requireSocket) });
    if (opts.method === 'GET' && opts.path.startsWith('/v1/attestation/report')) {
      return { status: 200, body: Buffer.from(b.attestation!.body), socketId: b.attestation!.socket_id, peerSpkiSha256: b.attestation!.peer_spki_sha256, headers: {}, reusedSocket: false };
    }
    if (opts.method === 'POST') return onPost(opts);
    if (opts.path.startsWith('/v1/signature/')) return onSignature(opts);
    throw new Error(`unexpected request ${opts.method} ${opts.path}`);
  };
  dir = mkdtempSync(join(tmpdir(), 'pt-pipe-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem')], { stdio: 'ignore' });
    tlsKey = readFileSync(join(dir, 'k.pem'));
    tlsCert = readFileSync(join(dir, 'c.pem'));
  } catch {
    tlsKey = null;
  }
});

after(() => {
  (crypto as { randomBytes: unknown }).randomBytes = originals.randomBytes;
  syncBuiltinESMExports();
  Date.now = originals.now;
  globalThis.fetch = originals.fetch;
  PinnedConnection.prototype.request = originals.request;
  dcap.getCollateral = originalCollateral;
  rmSync(dir, { recursive: true, force: true });
});

const okResponse = async (): Promise<Exchange> => ({
  status: 200,
  body: responseBody,
  socketId: b.attestation!.socket_id,
  peerSpkiSha256: b.attestation!.peer_spki_sha256,
  headers: {},
  reusedSocket: true,
});
const archivedSignature = async (): Promise<Exchange> => ({
  status: 200,
  body: Buffer.from(b.signature!.body),
  socketId: b.attestation!.socket_id,
  peerSpkiSha256: b.attestation!.peer_spki_sha256,
  headers: {},
  reusedSocket: true,
});
const run = () => runConfidentialCompletion({ apiKey: 'TEST-ONLY', model: b.model, requestBody, signatureRetries: 1 });

describe('pipeline with archived genuine evidence', () => {
  it('happy path reproduces a VERIFIED receipt; every credential-bearing request is pinned', async () => {
    calls = [];
    onPost = okResponse;
    onSignature = archivedSignature;
    const r = await run();
    assert.equal(r.receipt.verdict, 'VERIFIED', r.receipt.headline);
    assert.equal(r.receipt.transmission, 'sent');
    assert.ok(calls.filter((c) => c.auth).length >= 2);
    for (const c of calls.filter((x) => x.auth)) assert.ok(c.pinned, `${c.method} ${c.path} carried the key without a socket pin`);
    assert.ok(!calls.some((c) => c.method === 'GET' && c.path.startsWith('/v1/attestation') && c.auth), 'attestation is fetched without the key');
  });

  it('audit F2 probe: the server receives the report and resets → "may have been sent", never "withheld"', async (t) => {
    if (!tlsKey || !tlsCert) return t.skip('openssl not available');
    let accepted = 0;
    const local = https.createServer({ key: tlsKey, cert: tlsCert }, (req, res) => {
      if (req.method === 'GET') return void res.end('{}');
      req.on('data', (d: Buffer) => (accepted += d.length));
      req.on('end', () => req.socket.destroy());
    });
    await new Promise<void>((r) => local.listen(0, '127.0.0.1', () => r()));
    // Route the POST through the REAL transport to a local TLS fixture that resets after the body.
    const real = new PinnedConnection(`https://localhost:${(local.address() as AddressInfo).port}`, { ca: tlsCert });
    try {
      const warm = await originals.request.call(real, { method: 'GET', path: '/warm' });
      onPost = (opts) => originals.request.call(real, { ...opts, requireSocket: { id: warm.socketId, spkiSha256: warm.peerSpkiSha256! }, timeoutMs: 3_000 });
      onSignature = async () => assert.fail('no signature may be requested without a response');
      const r = await run();
      assert.ok(accepted > 8000, 'the fixture received the report');
      assert.equal(r.bundle.completion, null, 'no response hash is invented');
      assert.equal(r.receipt.transmission, 'may_have_been_sent');
      assert.equal(r.receipt.disclosed, true);
      assert.notEqual(r.receipt.verdict, 'VERIFIED');
      assert.match(String(r.bundle.blocked_reason), /MAY HAVE BEEN SENT/);
    } finally {
      real.close();
      local.close();
    }
  });

  it('a transport that fails without proof of non-delivery is treated as "may have been sent"', async () => {
    onPost = async () => {
      throw new Error('socket hang up');
    };
    const r = await run();
    assert.equal(r.receipt.transmission, 'may_have_been_sent');
    assert.equal(r.receipt.disclosed, true);
  });

  it('a response that started but failed → "sent", no response hash invented', async () => {
    onPost = async (opts) => {
      opts.transmission!.state = 'sent';
      throw new Error('response ended before it was complete');
    };
    const r = await run();
    assert.equal(r.receipt.transmission, 'sent');
    assert.equal(r.bundle.completion, null);
    assert.equal(r.receipt.response_sha256, null);
  });

  it('a pin refusal before writing → "not sent"', async () => {
    onPost = async (opts) => {
      opts.transmission!.state = 'not_sent';
      throw new SocketPinError('The attested TLS connection is no longer available; refusing to send on an unverified connection.');
    };
    const r = await run();
    assert.equal(r.receipt.transmission, 'not_sent');
    assert.equal(r.receipt.disclosed, false);
  });

  it('audit F1: if the attested connection closes before the signature fetch, stop — UNVERIFIED, key not re-sent', async () => {
    calls = [];
    onPost = okResponse;
    let attempts = 0;
    onSignature = async (opts) => {
      attempts++;
      assert.ok(opts.requireSocket, 'signature fetch must be pinned');
      throw new SocketPinError('The attested TLS connection is no longer available; refusing to send on an unverified connection.');
    };
    const r = await runConfidentialCompletion({ apiKey: 'TEST-ONLY', model: b.model, requestBody, signatureRetries: 5 });
    assert.equal(attempts, 1, 'no retries on a replacement connection');
    assert.equal(r.receipt.verdict, 'UNVERIFIED');
    assert.equal(r.receipt.transmission, 'sent');
    assert.match(String(r.bundle.signature_error), /not sent on a replacement connection/);
    const sig = r.receipt.properties.find((p) => p.id === 'response_signature')!;
    assert.equal(sig.checks.find((c) => c.id === 'signature_present')?.status, 'unavailable');
  });
});
