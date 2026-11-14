// NVIDIA GPU confidential-computing evidence, verified by NVIDIA's Remote
// Attestation Service (NRAS) AND re-checked locally.
//
// 1. Raw GPU reports (nvidia_payload.evidence_list, as returned by NEAR): each
//    device certificate chain must lead to NVIDIA's pinned Device Identity CA, the
//    SPDM measurement report must be signed by that device key, and the signed
//    SPDM request must carry our nonce.
// 2. The NRAS platform token (ES384, key chained to a pinned NVIDIA CA) must be
//    bound to our nonce with an overall true result.
// 3. Every per-GPU detached token must hash to the digest the platform token signs
//    in `submods`, verify under the same NVIDIA key policy, answer our nonce and
//    report secure boot / no debug / matching measurements.
// 4. The appraised GPUs (signed `ueid`) must be exactly the reported devices
//    (device-certificate serial numbers), one to one.
// Displayed GPU facts (count, model) come only from authenticated claims.
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

export interface AuthenticatedGpu {
  /** NRAS submodule key, e.g. GPU-0. */
  key: string;
  /** NVIDIA-signed unique device id (= device certificate serial, decimal). */
  ueid: string;
  hwmodel: string | null;
  driver_version: string | null;
  vbios_version: string | null;
}

export interface GpuCheckResult {
  checks: CheckList;
  /** Platform-token claims, only when its signature verified. */
  claims: Record<string, unknown> | null;
  /** Per-GPU facts, only when EVERY GPU check passed; never derived from unsigned payload fields. */
  gpus: AuthenticatedGpu[] | null;
}

/**
 * NVIDIA Device Identity CA: the self-signed root of every NVIDIA GPU device
 * certificate, pinned by SHA-256 of its DER. Matches NVIDIA's published
 * verifier_device_root.pem (github.com/NVIDIA/nvtrust, local_gpu_verifier), checked 2026-11-14.
 */
export const NVIDIA_DEVICE_ROOTS: Record<string, string> = {
  '102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48': 'NVIDIA Device Identity CA (valid to 9999-12-31)',
};

/** Detached per-GPU claims that must hold for every GPU. */
const REQUIRED_GPU_CLAIMS: [string, unknown, string][] = [
  ['measres', 'success', 'firmware/driver measurements match NVIDIA reference values'],
  ['secboot', true, 'secure boot enabled'],
  ['dbgstat', 'disabled', 'debug disabled'],
  ['x-nvidia-gpu-arch-check', true, 'architecture check passed'],
  ['x-nvidia-gpu-attestation-report-signature-verified', true, 'report signature verified by NRAS'],
  ['x-nvidia-gpu-attestation-report-cert-chain-validated', true, 'device certificate chain validated by NRAS'],
  ['x-nvidia-gpu-attestation-report-nonce-match', true, 'report nonce matched'],
];

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

export interface RawGpuEvidence {
  evidence: string;
  certificate: string;
  nonce: string | null;
}

export function parseGpuPayload(nvidiaPayload: unknown): { text: string; nonce: string; entries: RawGpuEvidence[] } {
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
  if (p.evidence_list.length > MAX_GPUS) throw new EvidenceError('malformed', `nvidia_payload lists ${p.evidence_list.length} GPUs (limit ${MAX_GPUS})`);
  const entries = p.evidence_list.map((e: unknown, i: number): RawGpuEvidence => {
    if (!isRecord(e) || typeof e.evidence !== 'string' || typeof e.certificate !== 'string' || e.evidence === '' || e.certificate === '') {
      throw new EvidenceError('malformed', `GPU evidence entry ${i} is not a {evidence, certificate} record`);
    }
    return { evidence: e.evidence, certificate: e.certificate, nonce: typeof e.nonce === 'string' ? e.nonce : null };
  });
  return { text: nvidiaPayload, nonce: p.nonce, entries };
}

/** Upper bound on GPUs per model report (each costs a chain + signature verification). */
export const MAX_GPUS = 16;

/** SPDM GET_MEASUREMENTS request header (SPDM 1.1, code 0xE0) followed by a 32-byte nonce. */
const SPDM_VERSION_1_1 = 0x11;
const SPDM_GET_MEASUREMENTS = 0xe0;
const SPDM_SIG_LEN = 96; // ECDSA P-384, r‖s

/**
 * Verify one raw GPU report offline: the device certificate chain leads to the
 * pinned NVIDIA Device Identity CA, the SPDM measurement transcript is signed by
 * the device key, and the signed request carries our nonce. Returns the device
 * serial (decimal), which NVIDIA's per-GPU claims call `ueid`.
 */
export function verifyDeviceEvidence(e: RawGpuEvidence, nonceHex: string, nowSecs: number): string {
  let certs: X509Certificate[];
  try {
    const pem = Buffer.from(e.certificate, 'base64').toString('utf8');
    certs = (pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []).map((c) => new X509Certificate(c));
  } catch {
    throw new EvidenceError('malformed', 'GPU device certificate chain is malformed');
  }
  if (certs.length < 2 || certs.length > 8) throw new EvidenceError('malformed', 'GPU device certificate chain has an unexpected length');
  const root = certs.at(-1)!;
  if (!NVIDIA_DEVICE_ROOTS[createHash('sha256').update(root.raw).digest('hex')]) {
    throw new EvidenceError('unknown_key', 'GPU device certificate does not chain to the pinned NVIDIA Device Identity CA');
  }
  if (!root.checkIssued(root) || !root.verify(root.publicKey)) throw new EvidenceError('bad_signature', 'NVIDIA device root is not self-signed');
  const t = nowSecs * 1000;
  for (let i = 0; i < certs.length; i++) {
    const c = certs[i]!;
    if (i < certs.length - 1 && (!c.checkIssued(certs[i + 1]!) || !c.verify(certs[i + 1]!.publicKey))) {
      throw new EvidenceError('bad_signature', 'GPU device certificate chain signature does not verify');
    }
    if (t < Date.parse(c.validFrom) || t > Date.parse(c.validTo)) throw new EvidenceError('stale', 'GPU device certificate not valid at evaluation time');
  }
  const leaf = certs[0]!;
  if (leaf.publicKey.asymmetricKeyDetails?.namedCurve !== 'secp384r1') throw new EvidenceError('unsupported', 'GPU device key is not P-384');
  const ev = Buffer.from(e.evidence, 'base64');
  if (ev.length < 36 + SPDM_SIG_LEN || ev[0] !== SPDM_VERSION_1_1 || ev[1] !== SPDM_GET_MEASUREMENTS) {
    throw new EvidenceError('malformed', 'GPU report is not an SPDM 1.1 GET_MEASUREMENTS transcript');
  }
  if (ev.subarray(4, 36).toString('hex') !== nonceHex.toLowerCase()) throw new EvidenceError('mismatch', 'GPU report does not answer our nonce');
  const ok = cryptoVerify(
    'sha384',
    ev.subarray(0, ev.length - SPDM_SIG_LEN),
    { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' },
    ev.subarray(ev.length - SPDM_SIG_LEN),
  );
  if (!ok) throw new EvidenceError('bad_signature', 'GPU measurement report is not signed by its device key');
  return BigInt(`0x${leaf.serialNumber}`).toString(10);
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
  const out: GpuCheckResult = { checks: c, claims: null, gpus: null };
  const nonce = nonceHex.toLowerCase();
  let payload;
  try {
    payload = parseGpuPayload(nvidiaPayload);
  } catch (e) {
    const code = (e as EvidenceError).code;
    if (code === 'missing') c.unavailable('gpu_evidence', 'GPU evidence present', (e as Error).message);
    else c.fail('gpu_evidence', 'GPU evidence present', (e as Error).message);
    return out;
  }
  c.pass('gpu_evidence', 'GPU evidence present', `${payload.entries.length} raw GPU attestation reports, as returned by NEAR (authenticated below).`);
  const nonceOk = c.expect(
    payload.nonce.toLowerCase() === nonce && payload.entries.every((e) => e.nonce === null || e.nonce.toLowerCase() === nonce),
    'gpu_nonce',
    'GPU evidence answers our nonce',
    'nvidia_payload and every GPU entry name our client nonce.',
    'nvidia_payload names a different nonce: GPU evidence is stale or replayed.',
  );
  if (!nonceOk) return out;

  // (1) Raw device evidence, verified locally.
  const serials: string[] = [];
  let deviceError: string | null = null;
  for (const [i, e] of payload.entries.entries()) {
    try {
      serials.push(verifyDeviceEvidence(e, nonce, nowSecs));
    } catch (err) {
      deviceError = `GPU entry ${i}: ${(err as Error).message}`;
      break;
    }
  }
  c.expect(
    deviceError === null,
    'gpu_device_reports',
    'Raw GPU reports signed by genuine NVIDIA GPUs',
    `All ${payload.entries.length} reports: device certificate chains to the pinned NVIDIA Device Identity CA, the SPDM measurement report is signed by the device key, and the signed request carries our nonce.`,
    deviceError ?? '',
  );

  // (2) NVIDIA's platform verdict.
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
    typeof claims.eat_nonce === 'string' && claims.eat_nonce.toLowerCase() === nonce,
    'nras_nonce',
    'NRAS verdict bound to our nonce',
    'Signed eat_nonce equals our client nonce.',
    'Signed eat_nonce differs from our nonce.',
  );
  c.expect(
    claims['x-nvidia-overall-att-result'] === true,
    'nras_verdict',
    'NVIDIA NRAS verdict',
    'x-nvidia-overall-att-result = true (NVIDIA-signed overall platform appraisal).',
    `x-nvidia-overall-att-result = ${JSON.stringify(claims['x-nvidia-overall-att-result'])}.`,
  );

  // (3) Per-GPU detached claims, authenticated through the platform token's signed digests.
  const submods = isRecord(claims.submods) ? claims.submods : null;
  const digests = new Map<string, string>();
  for (const [k, v] of Object.entries(submods ?? {})) {
    const d = Array.isArray(v) && v[0] === 'DIGEST' && Array.isArray(v[1]) && v[1][0] === 'SHA-256' && typeof v[1][1] === 'string' ? v[1][1].toLowerCase() : null;
    if (d) digests.set(k, d);
  }
  const detached = Array.isArray(body) && isRecord(body[1]) ? body[1] : null;
  const gpus: AuthenticatedGpu[] = [];
  let claimError: string | null = null;
  let claimsUnavailable = false;
  if (!submods || digests.size === 0 || digests.size !== Object.keys(submods).length) {
    claimError = 'The signed platform token does not list per-GPU claim digests (submods).';
  } else if (!detached || Object.keys(detached).length === 0) {
    claimsUnavailable = true;
    claimError = 'NRAS response has no per-GPU detached tokens; per-GPU claims cannot be authenticated.';
  } else if (Object.keys(detached).length !== digests.size || !Object.keys(detached).every((k) => digests.has(k))) {
    claimError = 'Per-GPU detached tokens do not correspond one-to-one to the signed submods.';
  } else {
    for (const [k, digest] of [...digests.entries()].sort(([a], [b]) => a.localeCompare(b, 'en', { numeric: true }))) {
      const t = detached[k];
      if (typeof t !== 'string' || createHash('sha256').update(t, 'utf8').digest('hex') !== digest) {
        claimError = `${k}: detached token does not match the digest signed in the platform token.`;
        break;
      }
      let g: Record<string, unknown>;
      try {
        g = verifyNrasJwt(t, nras.jwks, nowSecs);
      } catch (e) {
        claimError = `${k}: ${(e as Error).message}`;
        break;
      }
      if (typeof g.eat_nonce !== 'string' || g.eat_nonce.toLowerCase() !== nonce) {
        claimError = `${k}: signed eat_nonce differs from our nonce.`;
        break;
      }
      const bad = REQUIRED_GPU_CLAIMS.find(([name, want]) => g[name] !== want);
      if (bad) {
        claimError = `${k}: ${bad[0]} = ${JSON.stringify(g[bad[0]])} (required: ${bad[2]}).`;
        break;
      }
      if (typeof g.ueid !== 'string' || !/^[0-9]{1,60}$/.test(g.ueid)) {
        claimError = `${k}: no signed device id (ueid).`;
        break;
      }
      gpus.push({
        key: k,
        ueid: g.ueid,
        hwmodel: typeof g.hwmodel === 'string' ? g.hwmodel : null,
        driver_version: typeof g['x-nvidia-gpu-driver-version'] === 'string' ? (g['x-nvidia-gpu-driver-version'] as string) : null,
        vbios_version: typeof g['x-nvidia-gpu-vbios-version'] === 'string' ? (g['x-nvidia-gpu-vbios-version'] as string) : null,
      });
    }
  }
  if (claimError && claimsUnavailable) c.unavailable('gpu_claims', 'Per-GPU NVIDIA claims authenticated', claimError);
  else
    c.expect(
      claimError === null,
      'gpu_claims',
      'Per-GPU NVIDIA claims authenticated',
      `${gpus.length} per-GPU tokens match the digests signed in the platform token, verify under the pinned NVIDIA key policy and answer our nonce; each reports ${REQUIRED_GPU_CLAIMS.map(([, , d]) => d).join(', ')}.`,
      claimError ?? '',
    );

  // (4) Inventory: the appraised GPUs are exactly the reported devices.
  if (claimError === null) {
    const signed = gpus.map((g) => g.ueid).sort();
    const reported = [...serials].sort();
    const same = deviceError === null && new Set(signed).size === signed.length && signed.length === reported.length && signed.every((u, i) => u === reported[i]);
    c.expect(
      same,
      'gpu_inventory',
      'Appraised GPUs are the reported GPUs',
      `The ${gpus.length} NVIDIA-signed device ids equal the serial numbers of the ${reported.length} reported GPU device certificates, one to one.`,
      deviceError !== null
        ? 'Raw GPU reports did not verify, so the appraised GPUs cannot be matched to them.'
        : `NVIDIA appraised ${signed.length} device(s) that do not match the ${reported.length} reported GPU certificate(s).`,
    );
  } else {
    c.unavailable('gpu_inventory', 'Appraised GPUs are the reported GPUs', 'Per-GPU claims were not authenticated, so no GPU inventory is asserted.');
  }
  if (c.checks.every((x) => x.status === 'pass')) out.gpus = gpus;
  return out;
}
