// NVIDIA GPU confidential-computing evidence, verified by NVIDIA's Remote
// Attestation Service (NRAS). Beyond the minimal flow in NEAR's docs we also
// verify the NRAS EAT (JWT) signature against NVIDIA's published JWKS and check
// that the token's eat_nonce is our nonce, so the verdict itself is a signed,
// archivable statement rather than just a TLS-authenticated HTTP response.
import { createHash, createPublicKey, verify as cryptoVerify, type JsonWebKey, type KeyObject, X509Certificate } from 'node:crypto';
import { EvidenceError, isRecord } from './bytes.ts';
import { CheckList } from './types.ts';

export const NRAS_URL = 'https://nras.attestation.nvidia.com/v3/attest/gpu';
export const NRAS_JWKS_URL = 'https://nras.attestation.nvidia.com/.well-known/jwks.json';
export const NRAS_ISSUER = 'https://nras.attestation.nvidia.com';

export interface NrasEvidence {
  /** Raw NRAS response body (JSON text). */
  nrasResponse: string;
  /** Raw JWKS document (JSON text) used to verify the token. */
  jwks: string;
}

export interface GpuCheckResult {
  checks: CheckList;
  gpuCount: number;
  arch: string | null;
  claims: Record<string, unknown> | null;
}

function b64urlJson(part: string, label: string): Record<string, unknown> {
  try {
    const v = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    if (!isRecord(v)) throw new Error('not an object');
    return v;
  } catch {
    throw new EvidenceError('malformed', `${label} is not base64url JSON`);
  }
}

/**
 * NVIDIA attestation-service intermediate CAs, pinned by SHA-256 of their DER.
 * Observed in NVIDIA's production NRAS JWKS (fetched over WebPKI) on 2026-11-13;
 * both are issued by "NVIDIA Attestation Service CA 001". The JWKS that signs an
 * NRAS verdict must chain to one of these, so an evidence bundle cannot bring
 * its own signing key. A new NVIDIA intermediate yields UNVERIFIED until pinned.
 */
export const NRAS_PINNED_INTERMEDIATES: Record<string, string> = {
  '2df8907cf4d6c277b855d407ec178a649930a8e73f7294e8fce66e6ee27c5175': 'NVIDIA Attestation Service GPU Intermediate 004 (to 2029-12-08)',
  '38e3daf3cdbd5243bb15dd7993edcdd83a7238cb6745b980f8f3bf0a31a0d343': 'NVIDIA Attestation Service GPU Intermediate 005 (to 2030-10-08)',
};

/** The JWK must be a P-384 key certified by a pinned NVIDIA intermediate, valid at nowSecs. */
function certifiedNvidiaKey(jwk: Record<string, unknown>, nowSecs: number): KeyObject {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-384') throw new EvidenceError('unsupported', 'NRAS key is not an EC P-384 key');
  const x5c = Array.isArray(jwk.x5c) ? jwk.x5c : [];
  if (x5c.length < 2 || !x5c.every((c) => typeof c === 'string')) throw new EvidenceError('unknown_key', 'NRAS key has no certificate chain (x5c)');
  let leaf: X509Certificate;
  let inter: X509Certificate;
  try {
    leaf = new X509Certificate(Buffer.from(x5c[0] as string, 'base64'));
    inter = new X509Certificate(Buffer.from(x5c[1] as string, 'base64'));
  } catch {
    throw new EvidenceError('malformed', 'NRAS key certificate chain is malformed');
  }
  const interFp = createHash('sha256').update(inter.raw).digest('hex');
  if (!NRAS_PINNED_INTERMEDIATES[interFp]) throw new EvidenceError('unknown_key', 'NRAS key is not certified by a pinned NVIDIA attestation CA');
  if (!leaf.checkIssued(inter) || !leaf.verify(inter.publicKey)) throw new EvidenceError('bad_signature', 'NRAS key certificate is not signed by the NVIDIA attestation CA');
  const t = nowSecs * 1000;
  if (t < Date.parse(leaf.validFrom) || t > Date.parse(leaf.validTo)) throw new EvidenceError('stale', 'NRAS key certificate was not valid at evaluation time');
  const { x5c: _x5c, ...publicJwk } = jwk;
  const key = createPublicKey({ key: publicJwk as JsonWebKey, format: 'jwk' });
  const der = (k: KeyObject) => k.export({ type: 'spki', format: 'der' });
  if (!der(key).equals(der(leaf.publicKey))) throw new EvidenceError('mismatch', 'NRAS JWK does not match its certificate');
  return key;
}

/** Verify an ES384 JWT against a JWKS document whose key chains to a pinned NVIDIA CA. Returns the payload. */
export function verifyNrasJwt(token: string, jwksText: string, nowSecs: number): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new EvidenceError('malformed', 'NRAS token is not a JWT');
  const header = b64urlJson(parts[0]!, 'JWT header');
  const payload = b64urlJson(parts[1]!, 'JWT payload');
  if (header.alg !== 'ES384') throw new EvidenceError('unsupported', `unexpected JWT alg ${String(header.alg)}`);
  let jwks: unknown;
  try {
    jwks = JSON.parse(jwksText);
  } catch {
    throw new EvidenceError('malformed', 'JWKS is not JSON');
  }
  const keys = isRecord(jwks) && Array.isArray(jwks.keys) ? jwks.keys : [];
  if (typeof header.kid !== 'string' || header.kid === '') throw new EvidenceError('malformed', 'NRAS token has no key id');
  const jwk = keys.find((k: unknown) => isRecord(k) && k.kid === header.kid);
  if (!jwk) throw new EvidenceError('unknown_key', `NRAS signing key ${String(header.kid)} not in NVIDIA JWKS`);
  const key = certifiedNvidiaKey(jwk as Record<string, unknown>, nowSecs);
  const ok = cryptoVerify(
    'sha384',
    Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'),
    { key, dsaEncoding: 'ieee-p1363' },
    Buffer.from(parts[2]!, 'base64url'),
  );
  if (!ok) throw new EvidenceError('bad_signature', 'NRAS token signature does not verify');
  if (payload.iss !== NRAS_ISSUER) throw new EvidenceError('mismatch', `unexpected issuer ${String(payload.iss)}`);
  const skew = 300;
  if (typeof payload.exp !== 'number' || typeof payload.iat !== 'number') throw new EvidenceError('malformed', 'NRAS token lacks exp/iat');
  if (nowSecs > payload.exp + skew) {
    throw new EvidenceError('stale', 'NRAS token expired at evaluation time');
  }
  if (typeof payload.nbf === 'number' && nowSecs + skew < payload.nbf) {
    throw new EvidenceError('stale', 'NRAS token not yet valid at evaluation time');
  }
  return payload;
}

export function parseGpuPayload(nvidiaPayload: unknown): { text: string; nonce: string; arch: string | null; count: number } {
  if (typeof nvidiaPayload !== 'string' || nvidiaPayload === '') {
    throw new EvidenceError('missing', 'Report has no nvidia_payload (GPU evidence).');
  }
  let p: unknown;
  try {
    p = JSON.parse(nvidiaPayload);
  } catch {
    throw new EvidenceError('malformed', 'nvidia_payload is not JSON');
  }
  if (!isRecord(p) || typeof p.nonce !== 'string' || !Array.isArray(p.evidence_list) || p.evidence_list.length === 0) {
    throw new EvidenceError('malformed', 'nvidia_payload lacks nonce or GPU evidence');
  }
  return {
    text: nvidiaPayload,
    nonce: p.nonce,
    arch: typeof p.arch === 'string' ? p.arch : null,
    count: p.evidence_list.length,
  };
}

/** Network step: submit GPU evidence to NRAS and fetch the JWKS. */
export async function fetchNrasEvidence(nvidiaPayloadText: string, timeoutMs = 45_000): Promise<NrasEvidence> {
  const signal = AbortSignal.timeout(timeoutMs);
  const res = await fetch(NRAS_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: nvidiaPayloadText,
    signal,
  });
  const nrasResponse = await res.text();
  if (!res.ok) throw new EvidenceError('unavailable', `NRAS returned HTTP ${res.status}`);
  const jres = await fetch(NRAS_JWKS_URL, { signal });
  const jwks = await jres.text();
  if (!jres.ok) throw new EvidenceError('unavailable', `NRAS JWKS returned HTTP ${jres.status}`);
  return { nrasResponse, jwks };
}

/** Pure step: evaluate GPU evidence + NRAS result against our nonce. */
export function checkGpuEvidence(
  nvidiaPayload: unknown,
  nonceHex: string,
  nras: NrasEvidence | null,
  nowSecs: number,
  nrasError?: string,
): GpuCheckResult {
  const c = new CheckList();
  const out: GpuCheckResult = { checks: c, gpuCount: 0, arch: null, claims: null };
  let payload;
  try {
    payload = parseGpuPayload(nvidiaPayload);
  } catch (e) {
    const code = (e as EvidenceError).code;
    if (code === 'missing') c.unavailable('gpu_evidence', 'GPU evidence present', (e as Error).message);
    else c.fail('gpu_evidence', 'GPU evidence present', (e as Error).message);
    return out;
  }
  out.gpuCount = payload.count;
  out.arch = payload.arch;
  c.pass('gpu_evidence', 'GPU evidence present', `${payload.count} × ${payload.arch ?? 'unknown arch'} GPU attestation reports.`);
  const nonceOk = c.expect(
    payload.nonce.toLowerCase() === nonceHex.toLowerCase(),
    'gpu_nonce',
    'GPU evidence answers our nonce',
    'nvidia_payload.nonce equals our client nonce.',
    'nvidia_payload.nonce differs from our nonce: GPU evidence is stale or replayed.',
  );
  if (!nonceOk) return out;
  if (!nras) {
    c.unavailable('nras_verdict', 'NVIDIA NRAS verdict', `NRAS was not reachable${nrasError ? ` (${nrasError.slice(0, 120)})` : ''}; GPU evidence not appraised.`);
    return out;
  }
  let body: unknown;
  try {
    body = JSON.parse(nras.nrasResponse);
  } catch {
    c.fail('nras_verdict', 'NVIDIA NRAS verdict', 'NRAS response is not JSON.');
    return out;
  }
  const first = Array.isArray(body) ? body[0] : null;
  const token = Array.isArray(first) && first[0] === 'JWT' && typeof first[1] === 'string' ? first[1] : null;
  if (!token) {
    c.fail('nras_verdict', 'NVIDIA NRAS verdict', 'NRAS response lacks the platform JWT.');
    return out;
  }
  let claims: Record<string, unknown>;
  try {
    claims = verifyNrasJwt(token, nras.jwks, nowSecs);
  } catch (e) {
    c.fail('nras_signature', 'NRAS verdict signed by NVIDIA', (e as Error).message);
    return out;
  }
  out.claims = claims;
  c.pass('nras_signature', 'NRAS verdict signed by NVIDIA', 'ES384 token verifies with a key certified by a pinned NVIDIA attestation CA; issuer nras.attestation.nvidia.com.');
  // Anchor the evaluation time to NVIDIA-signed time: a bundle cannot pick an arbitrary "now".
  const iat = claims.iat as number;
  c.expect(
    Math.abs(nowSecs - iat) <= 600,
    'time_anchor',
    'Capture time matches NVIDIA-signed time',
    `Evidence evaluated at ${new Date(nowSecs * 1000).toISOString()}, within 10 min of the NVIDIA-signed iat.`,
    `Evaluation time differs from the NVIDIA-signed iat (${new Date(iat * 1000).toISOString()}) by more than 10 minutes.`,
  );
  c.expect(
    typeof claims.eat_nonce === 'string' && claims.eat_nonce.toLowerCase() === nonceHex.toLowerCase(),
    'nras_nonce',
    'NRAS verdict bound to our nonce',
    'Signed eat_nonce equals our client nonce.',
    'Signed eat_nonce differs from our nonce.',
  );
  c.expect(
    claims['x-nvidia-overall-att-result'] === true,
    'nras_verdict',
    'NVIDIA NRAS verdict',
    'x-nvidia-overall-att-result = true (GPU CC mode, firmware/driver measurements, cert chains).',
    `x-nvidia-overall-att-result = ${JSON.stringify(claims['x-nvidia-overall-att-result'])}.`,
  );
  return out;
}
