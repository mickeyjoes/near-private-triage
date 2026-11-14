// The report and API key must never travel on a TLS connection other than the
// attested one. Regression tests for a silently re-opened keep-alive socket, for
// the signature fetch on a replacement connection (audit F1), and for honest
// transmission state after a failed exchange (audit F2).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { PinnedConnection, SocketPinError, type TransmissionTracker } from '../server/near/connection.ts';

let dir = '';
let key: Buffer;
let cert: Buffer;
let key2: Buffer;
let cert2: Buffer;
let haveOpenssl = true;

function genCert(name: string): [Buffer, Buffer] {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(dir, `${name}-k.pem`), '-out', join(dir, `${name}-c.pem`)], { stdio: 'ignore' });
  return [readFileSync(join(dir, `${name}-k.pem`)), readFileSync(join(dir, `${name}-c.pem`))];
}

before(() => {
  dir = mkdtempSync(join(tmpdir(), 'pt-tls-'));
  try {
    [key, cert] = genCert('first');
    [key2, cert2] = genCert('replacement');
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

  it('the live sequence (attestation GET → pinned report POST → pinned signature GET) stays on one socket', async (t) => {
    if (!haveOpenssl) return t.skip('openssl not available');
    const { srv, seen } = server(5_000);
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
    const conn = new PinnedConnection(`https://localhost:${(srv.address() as AddressInfo).port}`, { ca: cert });
    try {
      const a = await conn.request({ method: 'GET', path: '/v1/attestation/report' });
      const pin = { id: a.socketId, spkiSha256: a.peerSpkiSha256! };
      const tx: TransmissionTracker = { state: 'may_have_been_sent' };
      const post = await conn.request({ method: 'POST', path: '/v1/chat/completions', headers: { Authorization: 'Bearer TEST-ONLY' }, body: Buffer.from('FICTIONAL'), requireSocket: pin, transmission: tx });
      const sig = await conn.request({ method: 'GET', path: '/v1/signature/x', headers: { Authorization: 'Bearer TEST-ONLY' }, requireSocket: pin });
      assert.equal(tx.state, 'sent');
      assert.equal(post.socketId, a.socketId);
      assert.equal(sig.socketId, a.socketId);
      assert.deepEqual(seen.map((s) => [s.method, s.conn, s.auth]), [['GET', 1, false], ['POST', 1, true], ['GET', 1, true]]);
    } finally {
      conn.close();
      srv.close();
    }
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

const listen = (srv: https.Server, port = 0) => new Promise<void>((r) => srv.listen(port, '127.0.0.1', () => r()));
const portOf = (srv: https.Server) => (srv.address() as AddressInfo).port;

describe('credential-bearing requests (audit F1)', () => {
  it('refuses any request carrying Authorization unless it is pinned to an attested socket', async (t) => {
    if (!haveOpenssl) return t.skip('openssl not available');
    const { srv, seen } = server(5_000);
    await listen(srv);
    const conn = new PinnedConnection(`https://localhost:${portOf(srv)}`, { ca: cert });
    try {
      await assert.rejects(conn.request({ method: 'GET', path: '/v1/signature/x', headers: { Authorization: 'Bearer TEST-ONLY' } }), SocketPinError);
      await new Promise((r) => setTimeout(r, 50));
      assert.equal(seen.length, 0, 'nothing reached the server');
    } finally {
      conn.close();
      srv.close();
    }
  });

  it('the audit replacement-socket PoC: a signature GET never sends the key to a replacement server', async (t) => {
    if (!haveOpenssl) return t.skip('openssl not available');
    const seen: { server: string; auth: string | null }[] = [];
    const mk = (name: string, k: Buffer, c: Buffer) =>
      https.createServer({ key: k, cert: c }, (req, res) => {
        seen.push({ server: name, auth: req.headers.authorization ?? null });
        res.end('{}');
      });
    const first = mk('first', key, cert);
    await listen(first);
    const port = portOf(first);
    // Both certificates are trusted by this client: the strongest attacker model (trusted TLS interception).
    const conn = new PinnedConnection(`https://localhost:${port}`, { ca: Buffer.concat([cert, cert2]) });
    let second: https.Server | undefined;
    try {
      const a = await conn.request({ method: 'GET', path: '/v1/attestation/report' });
      first.closeIdleConnections();
      await new Promise<void>((r) => first.close(() => r()));
      await new Promise((r) => setTimeout(r, 40));
      second = mk('replacement', key2, cert2);
      await listen(second, port);
      // Exactly the production signature-fetch options (server/near/confidentialCompletion.ts).
      await assert.rejects(
        conn.request({
          requireSocket: { id: a.socketId, spkiSha256: a.peerSpkiSha256! },
          method: 'GET',
          path: '/v1/signature/TEST-CHAT?signing_algo=ecdsa',
          headers: { Authorization: 'Bearer TEST-ONLY-NOT-A-SECRET' },
        }),
        SocketPinError,
      );
      await new Promise((r) => setTimeout(r, 50));
      assert.deepEqual(seen.filter((x) => x.server === 'replacement'), [], 'the replacement server received nothing');
      assert.equal(seen.filter((x) => x.auth).length, 0, 'no credential reached any server');
    } finally {
      conn.close();
      first.close();
      second?.close();
    }
  });
});

describe('transmission state after a failed exchange (audit F2)', () => {
  async function attempt(handler: (req: IncomingMessage, res: ServerResponse) => void, opts: { maxResponseBytes?: number } = {}) {
    let received = 0;
    const srv = https.createServer({ key, cert }, (req, res) => {
      if (req.method === 'GET') return void res.end('{}');
      req.on('data', (d: Buffer) => (received += d.length));
      req.on('end', () => handler(req, res));
    });
    await listen(srv);
    const conn = new PinnedConnection(`https://localhost:${portOf(srv)}`, { ca: cert });
    const tx: TransmissionTracker = { state: 'may_have_been_sent' };
    try {
      const a = await conn.request({ method: 'GET', path: '/v1/attestation/report' });
      const r = await conn
        .request({
          method: 'POST',
          path: '/v1/chat/completions',
          headers: { Authorization: 'Bearer TEST-ONLY' },
          body: Buffer.from('FICTIONAL REPORT '.repeat(500)),
          requireSocket: { id: a.socketId, spkiSha256: a.peerSpkiSha256! },
          transmission: tx,
          timeoutMs: 3_000,
          ...opts,
        })
        .then((x) => ({ ok: true as const, x }), (e: Error) => ({ ok: false as const, e }));
      return { r, tx: tx.state, received };
    } finally {
      conn.close();
      srv.close();
    }
  }

  it('reset after the body arrived → may_have_been_sent (never "not sent")', async (t) => {
    if (!haveOpenssl) return t.skip('openssl not available');
    const { r, tx, received } = await attempt((req) => req.socket.destroy());
    assert.equal(r.ok, false);
    assert.ok(received > 8000, 'the fixture really received the report');
    assert.equal(tx, 'may_have_been_sent');
  });

  it('truncated response → sent, and the exchange is rejected (no partial body is accepted)', async (t) => {
    if (!haveOpenssl) return t.skip('openssl not available');
    const { r, tx } = await attempt((_req, res) => {
      res.writeHead(200, { 'Content-Length': '1000' });
      res.write('{"id":"chat-');
      setTimeout(() => res.socket?.destroy(), 30);
    });
    assert.equal(r.ok, false, 'a truncated response must not resolve');
    assert.equal(tx, 'sent');
  });

  it('oversized response → sent, and the exchange is rejected', async (t) => {
    if (!haveOpenssl) return t.skip('openssl not available');
    const { r, tx } = await attempt((_req, res) => res.end('x'.repeat(64 * 1024)), { maxResponseBytes: 1024 });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.e.message, /exceeded/);
    assert.equal(tx, 'sent');
  });

  it('pin refused before writing → not_sent', async (t) => {
    if (!haveOpenssl) return t.skip('openssl not available');
    const { srv } = server(5_000);
    await listen(srv);
    const conn = new PinnedConnection(`https://localhost:${portOf(srv)}`, { ca: cert });
    const tx: TransmissionTracker = { state: 'may_have_been_sent' };
    try {
      await assert.rejects(
        conn.request({ method: 'POST', path: '/x', headers: { Authorization: 'Bearer TEST-ONLY' }, body: Buffer.from('r'), requireSocket: { id: 999_999, spkiSha256: '00' }, transmission: tx }),
        SocketPinError,
      );
      assert.equal(tx.state, 'not_sent');
    } finally {
      conn.close();
      srv.close();
    }
  });
});
