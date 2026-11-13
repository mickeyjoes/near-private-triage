// NVIDIA GPU confidential-computing evidence, verified by NVIDIA's Remote
// Attestation Service (NRAS). Beyond the minimal flow in NEAR's docs we also
// verify the NRAS EAT (JWT) signature against NVIDIA's published JWKS and check
// that the token's eat_nonce is our nonce, so the verdict itself is a signed,
// archivable statement rather than just a TLS-authenticated HTTP response.
import { createPublicKey, verify as cryptoVerify, type JsonWebKey } from 'node:crypto';
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

/** Verify an ES384 JWT against a JWKS document. Returns the payload. */
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
  const jwk = keys.find((k: unknown) => isRecord(k) && k.kid === header.kid);
  if (!jwk) throw new EvidenceError('unknown_key', `NRAS signing key ${String(header.kid)} not in NVIDIA JWKS`);
  const { x5c: _x5c, ...publicJwk } = jwk as Record<string, unknown>;
  const key = createPublicKey({ key: publicJwk as JsonWebKey, format: 'jwk' });
  const ok = cryptoVerify(
    'sha384',
    Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'),
    { key, dsaEncoding: 'ieee-p1363' },
    Buffer.from(parts[2]!, 'base64url'),
  );
  if (!ok) throw new EvidenceError('bad_signature', 'NRAS token signature does not verify');
  if (payload.iss !== NRAS_ISSUER) throw new EvidenceError('mismatch', `unexpected issuer ${String(payload.iss)}`);
  const skew = 300;
  if (typeof payload.exp === 'number' && nowSecs > payload.exp + skew) {
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
  if (!isRecord(p) || typeof p.nonce !== 'string' || !Array.isArray(p.evidence_list)) {
    throw new EvidenceError('malformed', 'nvidia_payload lacks nonce/evidence_list');
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
  c.pass('nras_signature', 'NRAS verdict signed by NVIDIA', 'ES384 token verifies against NVIDIA JWKS; issuer nras.attestation.nvidia.com.');
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
