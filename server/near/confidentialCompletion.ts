// Live pipeline: attest → (only if attestation verifies) disclose → sign → verify.
//
// 1. Build the request body ONCE; hash it; derive a fresh nonce bound to it.
// 2. On one pinned TLS connection, fetch gateway + model attestation WITHOUT the
//    API key (nothing secret crosses an unverified connection).
// 3. Verify gateway quote, TLS-key binding, every model candidate and its GPU
//    evidence. If anything fails, STOP: the confidential report is never sent.
// 4. Send the completion over the same connection (x-no-aliasing, identity
//    encoding, non-streaming so the model TEE — not the gateway — signs).
// 5. Fetch the response signature and evaluate the complete evidence bundle.
//
// Never logs the API key, request content or response content.
import { randomBytes } from 'node:crypto';
import { isRecord, sha256Hex } from '../verifier/bytes.ts';
import {
  deriveNonce,
  evaluateBundle,
  evaluatePreflight,
  type EvidenceBundle,
  quoteKey,
  type Receipt,
} from '../verifier/evidence.ts';
import { fetchNrasEvidence, type NrasEvidence, parseGpuPayload } from '../verifier/gpu.ts';
import { DEFAULT_POLICY, type ReportPolicy } from '../verifier/nearReport.ts';
import { type Collateral, fetchCollateral } from '../verifier/tdx.ts';
import { PinnedConnection } from './connection.ts';

export const DEFAULT_ENDPOINT = 'https://cloud-api.near.ai';

export type Stage =
  | 'challenge'
  | 'attestation'
  | 'appraisal'
  | 'blocked'
  | 'inference'
  | 'signature'
  | 'verdict';

export interface RunOptions {
  apiKey: string;
  model: string;
  requestBody: Buffer;
  endpoint?: string;
  policy?: ReportPolicy;
  onStage?: (stage: Stage, detail: string) => void;
  signatureRetries?: number;
  /** Attest and appraise only; never send the request (no API key needed). */
  preflightOnly?: boolean;
}

export interface RunResult {
  bundle: EvidenceBundle;
  receipt: Receipt;
  requestBytes: Buffer;
  responseBytes: Buffer | null;
}

function nowIso(): { iso: string; secs: number } {
  const ms = Date.now();
  return { iso: new Date(ms).toISOString(), secs: Math.floor(ms / 1000) };
}

async function settle<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch {
    return null;
  }
}

export async function runConfidentialCompletion(opts: RunOptions): Promise<RunResult> {
  const endpoint = opts.endpoint ?? DEFAULT_ENDPOINT;
  const stage = opts.onStage ?? (() => {});
  const requestBytes = opts.requestBody;
  const requestSha256 = sha256Hex(requestBytes);
  const salt = randomBytes(32).toString('hex');
  const nonce = deriveNonce(salt, requestSha256);
  const t = nowIso();
  const bundle: EvidenceBundle = {
    schema: 'privatetriage.evidence/v1',
    captured_at: t.iso,
    captured_at_secs: t.secs,
    endpoint,
    model: opts.model,
    nonce: { salt, request_sha256: requestSha256, value: nonce },
    attestation: null,
    collateral: {},
    nras: {},
    completion: null,
    signature: null,
    policy: opts.policy ?? DEFAULT_POLICY,
  };
  stage('challenge', `Fresh 256-bit challenge ${nonce.slice(0, 12)}… derived from request hash`);

  const conn = new PinnedConnection(endpoint);
  try {
    // --- Attestation (no API key) ---
    const q = new URLSearchParams({
      model: opts.model,
      provider: 'near',
      include_tls_fingerprint: 'true',
      signing_algo: 'ecdsa',
      nonce,
    });
    try {
      const ex = await conn.request({
        method: 'GET',
        path: `/v1/attestation/report?${q.toString()}`,
        headers: { 'x-no-aliasing': 'true' },
        timeoutMs: 60_000,
        maxResponseBytes: 8 * 1024 * 1024,
      });
      bundle.attestation = {
        status: ex.status,
        body: ex.body.toString('utf8'),
        socket_id: ex.socketId,
        peer_spki_sha256: ex.peerSpkiSha256,
      };
    } catch (e) {
      bundle.blocked_reason = `Attestation request failed: ${(e as Error).message}`;
    }
    stage('attestation', bundle.attestation ? `Attestation evidence received (HTTP ${bundle.attestation.status})` : 'Attestation unavailable');

    // --- Collect appraisal inputs: Intel collateral per quote, NVIDIA NRAS per model candidate ---
    if (bundle.attestation?.status === 200) {
      let att: unknown = null;
      try {
        att = JSON.parse(bundle.attestation.body);
      } catch {
        att = null;
      }
      if (isRecord(att)) {
        const reports: unknown[] = [att.gateway_attestation, ...(Array.isArray(att.model_attestations) ? att.model_attestations : [])];
        const quotes = [...new Set(reports.filter(isRecord).map((r) => r.intel_quote).filter((x): x is string => typeof x === 'string'))];
        const cols = await Promise.all(quotes.map((qh) => settle(fetchCollateral(qh))));
        quotes.forEach((qh, i) => {
          bundle.collateral[quoteKey(qh)] = (cols[i] as Collateral | null) ?? null;
        });
        const models = Array.isArray(att.model_attestations) ? att.model_attestations : [];
        const errors: Record<string, string> = {};
        const nras = await Promise.all(
          models.map(async (m, i): Promise<NrasEvidence | null> => {
            if (!isRecord(m)) return null;
            let p;
            try {
              p = parseGpuPayload(m.nvidia_payload);
            } catch (e) {
              errors[String(i)] = (e as Error).message;
              return null;
            }
            // Only submit evidence that answers OUR challenge.
            if (p.nonce.toLowerCase() !== nonce) {
              errors[String(i)] = 'GPU evidence does not answer our nonce; not submitted';
              return null;
            }
            // NRAS is an external service: bounded retry on transient failure.
            for (let attempt = 0; attempt < 3; attempt++) {
              try {
                return await fetchNrasEvidence(p.text);
              } catch (e) {
                errors[String(i)] = (e as Error).message;
                await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
              }
            }
            return null;
          }),
        );
        nras.forEach((n, i) => {
          bundle.nras[String(i)] = n;
          if (n) delete errors[String(i)];
        });
        if (Object.keys(errors).length) bundle.nras_errors = errors;
      }
    }

    const pre = evaluatePreflight(bundle, bundle.policy);
    stage('appraisal', pre.ok ? `Gateway + ${pre.verifiedModelSigners.length} model TEE verified` : pre.reason);
    if (!pre.ok) {
      bundle.blocked_reason = bundle.blocked_reason ?? pre.reason;
      stage('blocked', 'Report NOT sent: attestation did not verify');
      const { receipt } = evaluateBundle(bundle, { policy: bundle.policy });
      return { bundle, receipt, requestBytes, responseBytes: null };
    }
    if (opts.preflightOnly) {
      bundle.blocked_reason = 'Preflight only: attestation verified, no report was sent.';
      stage('verdict', 'Preflight passed; nothing sent');
      const { receipt } = evaluateBundle(bundle, { policy: bundle.policy });
      return { bundle, receipt, requestBytes, responseBytes: null };
    }

    // --- Confidential inference over the attested connection ---
    stage('inference', 'Sending report over the attested TLS session');
    let responseBytes: Buffer | null = null;
    try {
      const ex = await conn.request({
        method: 'POST',
        path: '/v1/chat/completions',
        headers: {
          Authorization: `Bearer ${opts.apiKey}`,
          'Content-Type': 'application/json',
          'x-no-aliasing': 'true',
        },
        body: requestBytes,
        timeoutMs: 180_000,
      });
      responseBytes = ex.body;
      let chatId: string | null = null;
      try {
        const parsed = JSON.parse(ex.body.toString('utf8'));
        if (isRecord(parsed) && typeof parsed.id === 'string') chatId = parsed.id;
      } catch {
        chatId = null;
      }
      bundle.completion = {
        status: ex.status,
        request_sha256: requestSha256,
        response_sha256: sha256Hex(ex.body),
        chat_id: chatId,
        socket_id: ex.socketId,
        peer_spki_sha256: ex.peerSpkiSha256,
      };
    } catch (e) {
      bundle.blocked_reason = `Inference request failed: ${(e as Error).message}`;
    }

    // --- Signature (bounded retry: it may take a moment to be recorded) ---
    const chatId = bundle.completion?.chat_id;
    if (bundle.completion?.status === 200 && chatId) {
      stage('signature', 'Fetching enclave signature for this completion');
      const sq = new URLSearchParams({ model: opts.model, signing_algo: 'ecdsa' });
      const tries = opts.signatureRetries ?? 5;
      for (let i = 0; i < tries; i++) {
        try {
          const ex = await conn.request({
            method: 'GET',
            path: `/v1/signature/${encodeURIComponent(chatId)}?${sq.toString()}`,
            headers: { Authorization: `Bearer ${opts.apiKey}` },
            timeoutMs: 30_000,
          });
          bundle.signature = { status: ex.status, body: ex.body.toString('utf8'), socket_id: ex.socketId, peer_spki_sha256: ex.peerSpkiSha256 };
          if (ex.status !== 404) break;
        } catch {
          bundle.signature = null;
        }
        await new Promise((r) => setTimeout(r, 800 * (i + 1)));
      }
    }

    const { receipt } = evaluateBundle(bundle, { policy: bundle.policy });
    stage('verdict', receipt.verdict);
    return { bundle, receipt, requestBytes, responseBytes };
  } finally {
    conn.close();
  }
}
