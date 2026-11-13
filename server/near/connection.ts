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

export interface RequestOptions {
  method: 'GET' | 'POST';
  path: string;
  headers?: Record<string, string>;
  body?: Buffer;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

let nextSocketId = 1;

export class PinnedConnection {
  readonly host: string;
  readonly port: number;
  private readonly agent: https.Agent;
  private readonly socketIds = new WeakMap<TLSSocket, number>();
  private readonly spki = new WeakMap<TLSSocket, string | null>();

  constructor(baseUrl: string) {
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
    return new Promise((resolve, reject) => {
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
        },
        (res) => {
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
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              body: Buffer.concat(chunks),
              socketId: id,
              peerSpkiSha256: spki,
              reusedSocket: req.reusedSocket,
            });
          });
          res.on('error', reject);
        },
      );
      req.setTimeout(opts.timeoutMs ?? 120_000, () => req.destroy(new Error('request timed out')));
      req.on('error', reject);
      if (opts.body) req.write(opts.body);
      req.end();
    });
  }
}
