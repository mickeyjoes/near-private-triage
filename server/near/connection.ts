// A single, pinned TLS connection to the NEAR AI Cloud gateway.
//
// NEAR's TLS-binding flow requires that the peer certificate, the attestation
// report and (for our purposes) the confidential inference request all travel
// over the SAME TLS connection; two connections may reach different instances.
// This class forces one socket (maxSockets: 1, keep-alive), records the peer
// SPKI hash at handshake, and tags every exchange with the socket it used so the
// caller can prove — or refute — that the inference used the attested connection.
//
// Raw request and response bytes are returned untouched (no JSON re-encoding,
// identity transfer-encoding) because response signatures cover exact bytes.
import https from 'node:https';
import type { TLSSocket } from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { sha256Hex } from '../verifier/bytes.ts';

export interface Exchange {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  socketId: number;
  peerSpkiSha256: string | null;
  reusedSocket: boolean;
}

/**
 * What the transport can prove about a request's delivery.
 * - `not_sent`: refused before any byte (headers included) was written.
 * - `may_have_been_sent`: bytes were handed to the socket, but no response arrived
 *   (reset, timeout); the peer may have received the full request.
 * - `sent`: the peer answered, so it received the request (the response may still
 *   be incomplete or rejected).
 */
export type TransmissionState = 'not_sent' | 'may_have_been_sent' | 'sent';

/** Mutable progress record. Callers must initialise it to `may_have_been_sent`
 * (the conservative default); only the transport itself may lower it to `not_sent`. */
export interface TransmissionTracker {
  state: TransmissionState;
}

export interface RequestOptions {
  method: 'GET' | 'POST';
  path: string;
  headers?: Record<string, string>;
  body?: Buffer;
  timeoutMs?: number;
  maxResponseBytes?: number;
  /**
   * Refuse to send unless the request is assigned exactly this already-attested
   * socket (same id, same peer SPKI). Nothing — not even headers — is written
   * before the check passes, so a silently re-opened connection never carries
   * the API key or the report.
   */
  requireSocket?: { id: number; spkiSha256: string };
  /** Updated as the request progresses (see TransmissionState). */
  transmission?: TransmissionTracker;
}

const hasCredential = (h: Record<string, string> | undefined): boolean =>
  Boolean(h && Object.keys(h).some((k) => k.toLowerCase() === 'authorization' || k.toLowerCase() === 'cookie'));

export class SocketPinError extends Error {}

let nextSocketId = 1;

export class PinnedConnection {
  readonly host: string;
  readonly port: number;
  private readonly agent: https.Agent;
  private readonly socketIds = new WeakMap<TLSSocket, number>();
  private readonly spki = new WeakMap<TLSSocket, string | null>();

  private readonly ca: Buffer | undefined;

  /** `ca` is for tests against a local TLS server only; production uses the system trust store. */
  constructor(baseUrl: string, opts: { ca?: Buffer } = {}) {
    this.ca = opts.ca;
    const u = new URL(baseUrl);
    if (u.protocol !== 'https:') throw new Error('gateway base URL must be https');
    this.host = u.hostname;
    this.port = u.port ? Number(u.port) : 443;
    this.agent = new https.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1, scheduling: 'lifo' });
  }

  close(): void {
    this.agent.destroy();
  }

  private tag(socket: TLSSocket): { id: number; spki: string | null } {
    let id = this.socketIds.get(socket);
    if (id === undefined) {
      id = nextSocketId++;
      this.socketIds.set(socket, id);
    }
    if (!this.spki.has(socket)) {
      let value: string | null = null;
      try {
        const cert = socket.getPeerX509Certificate?.();
        if (cert instanceof X509Certificate) {
          value = sha256Hex(cert.publicKey.export({ type: 'spki', format: 'der' }));
        }
      } catch {
        value = null;
      }
      this.spki.set(socket, value);
    }
    return { id, spki: this.spki.get(socket) ?? null };
  }

  request(opts: RequestOptions): Promise<Exchange> {
    const limit = opts.maxResponseBytes ?? 4 * 1024 * 1024;
    const tx = opts.transmission;
    if (tx) tx.state = 'not_sent';
    // Every credential-bearing request must be pinned to an attested socket. This is
    // structural, so a future call site cannot forget it (audit finding F1).
    if (hasCredential(opts.headers) && !opts.requireSocket) {
      return Promise.reject(new SocketPinError('Refusing to send credentials on a TLS connection that is not pinned to the attested one.'));
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (e: Error) => {
        if (settled) return;
        settled = true;
        reject(e);
      };
      const headers: Record<string, string> = {
        Accept: 'application/json',
        'Accept-Encoding': 'identity',
        ...(opts.headers ?? {}),
      };
      if (opts.body) headers['Content-Length'] = String(opts.body.length);
      const req = https.request(
        {
          host: this.host,
          port: this.port,
          method: opts.method,
          path: opts.path,
          headers,
          agent: this.agent,
          servername: this.host,
          ...(this.ca ? { ca: this.ca } : {}),
        },
        (res) => {
          // The peer answered: it received the request.
          if (tx) tx.state = 'sent';
          const socket = res.socket as TLSSocket;
          const { id, spki } = this.tag(socket);
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > limit) {
              req.destroy(new Error(`response exceeded ${limit} bytes`));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            if (settled) return;
            if (!res.complete) {
              fail(new Error('response ended before it was complete'));
              return;
            }
            settled = true;
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              body: Buffer.concat(chunks),
              socketId: id,
              peerSpkiSha256: spki,
              reusedSocket: req.reusedSocket,
            });
          });
          res.on('error', fail);
          // A truncated response (peer closes mid-body) must never resolve.
          res.on('close', () => fail(new Error('response ended before it was complete')));
        },
      );
      req.setTimeout(opts.timeoutMs ?? 120_000, () => req.destroy(new Error('request timed out')));
      req.on('error', fail);
      const send = () => {
        // From here on the peer may receive the request, even if no response ever arrives.
        if (tx) tx.state = 'may_have_been_sent';
        if (opts.body) req.write(opts.body);
        req.end();
      };
      const pin = opts.requireSocket;
      if (!pin) {
        send();
        return;
      }
      // Headers are only flushed on the first write/end, so nothing leaves this
      // process until the assigned socket is proven to be the attested one.
      req.once('socket', (s) => {
        const sock = s as TLSSocket;
        const id = this.socketIds.get(sock);
        const spki = id === undefined ? null : (this.spki.get(sock) ?? null);
        let live: string | null = null;
        try {
          const cert = sock.getPeerX509Certificate?.();
          live = cert instanceof X509Certificate ? sha256Hex(cert.publicKey.export({ type: 'spki', format: 'der' })) : null;
        } catch {
          live = null;
        }
        if (id !== pin.id || spki !== pin.spkiSha256 || live !== pin.spkiSha256 || sock.destroyed) {
          req.destroy(new SocketPinError('The attested TLS connection is no longer available; refusing to send on an unverified connection.'));
          return;
        }
        send();
      });
    });
  }
}
