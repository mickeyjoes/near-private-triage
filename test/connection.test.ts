// The report and API key must never travel on a TLS connection other than the
// attested one. Regression test for a silently re-opened keep-alive socket.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { PinnedConnection, SocketPinError } from '../server/near/connection.ts';

let dir = '';
let key: Buffer;
let cert: Buffer;
let haveOpenssl = true;

before(() => {
  dir = mkdtempSync(join(tmpdir(), 'pt-tls-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem')], { stdio: 'ignore' });
    key = readFileSync(join(dir, 'k.pem'));
    cert = readFileSync(join(dir, 'c.pem'));
  } catch {
    haveOpenssl = false;
  }
});
after(() => rmSync(dir, { recursive: true, force: true }));

function server(idleMs: number) {
  const seen: { method: string; conn: number; body: string; auth: boolean }[] = [];
  let conns = 0;
  const srv = https.createServer({ key, cert }, (req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      seen.push({ method: req.method!, conn: (req.socket as unknown as { n: number }).n, body, auth: Boolean(req.headers.authorization) });
      res.end('{}');
    });
  });
  srv.on('secureConnection', (s) => ((s as unknown as { n: number }).n = ++conns));
  srv.keepAliveTimeout = idleMs;
  return { srv, seen };
}

async function exchange(idleMs: number, waitMs: number) {
  const { srv, seen } = server(idleMs);
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  const conn = new PinnedConnection(`https://localhost:${(srv.address() as AddressInfo).port}`, { ca: cert });
  try {
    const a = await conn.request({ method: 'GET', path: '/v1/attestation/report' });
    await new Promise((r) => setTimeout(r, waitMs));
    const result = await conn
      .request({
        method: 'POST',
        path: '/v1/chat/completions',
        headers: { Authorization: 'Bearer TEST-ONLY' },
        body: Buffer.from('CONFIDENTIAL REPORT'),
        requireSocket: { id: a.socketId, spkiSha256: a.peerSpkiSha256! },
      })
      .then((x) => ({ ok: true as const, x }), (e: unknown) => ({ ok: false as const, e }));
    return { a, result, seen };
  } finally {
    conn.close();
    srv.close();
  }
}

describe('attested-connection pinning', () => {
  it('sends on the attested socket when it is still open', async (t) => {
    if (!haveOpenssl) return t.skip('openssl not available');
    const { a, result, seen } = await exchange(5_000, 20);
    assert.equal(result.ok, true);
    if (result.ok) assert.equal(result.x.socketId, a.socketId);
    assert.deepEqual(seen.map((s) => [s.method, s.conn]), [['GET', 1], ['POST', 1]]);
  });

  it('refuses to send anything if the attested socket was closed meanwhile', async (t) => {
    if (!haveOpenssl) return t.skip('openssl not available');
    const { result, seen } = await exchange(150, 500); // server drops the idle connection during "appraisal"
    assert.equal(result.ok, false);
    if (!result.ok) assert.ok(result.e instanceof SocketPinError, String(result.e));
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(seen.filter((s) => s.method === 'POST').length, 0, 'no POST may reach any connection');
    assert.equal(seen.filter((s) => s.auth).length, 0, 'the API key never left the process');
  });
});
