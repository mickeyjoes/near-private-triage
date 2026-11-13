// Adversarial transformations of a GENUINE evidence bundle. Each scenario models
// a concrete attack or failure, and states the verdict the verifier must reach.
// Used by the negative test suite and by the UI's Tamper Lab (precomputed by
// scripts/build-demo.ts with this same code). Pure functions: no network.
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { ethers } from 'ethers';
import { isRecord, sha256Hex } from './bytes.ts';
import { type EvidenceBundle, quoteKey } from './evidence.ts';
import type { PropertyId, Verdict } from './types.ts';

export interface TamperScenario {
  id: string;
  title: string;
  attack: string;
  expect: Exclude<Verdict, 'VERIFIED'>;
  /** Property expected to catch it, and the check that must not pass. */
  property: PropertyId;
  check: string;
  apply: (b: EvidenceBundle, ctx: TamperContext) => EvidenceBundle;
}

export interface TamperContext {
  /** A second, independent genuine bundle (for replay scenarios). */
  other: EvidenceBundle;
}

const clone = (b: EvidenceBundle): EvidenceBundle => structuredClone(b);

function flipHex(hex: string, at = 10): string {
  const ch = hex[at]!;
  return hex.slice(0, at) + (ch === '0' ? '1' : '0') + hex.slice(at + 1);
}

function att(b: EvidenceBundle): Record<string, unknown> {
  return JSON.parse(b.attestation!.body) as Record<string, unknown>;
}

function setAtt(b: EvidenceBundle, a: Record<string, unknown>) {
  b.attestation!.body = JSON.stringify(a);
}

function sig(b: EvidenceBundle): Record<string, unknown> {
  return JSON.parse(b.signature!.body) as Record<string, unknown>;
}

function setSig(b: EvidenceBundle, s: Record<string, unknown>) {
  b.signature!.body = JSON.stringify(s);
}

function editResponse(b: EvidenceBundle, edit: (text: string) => string, rehash: boolean) {
  const c = b.completion!;
  const text = edit(Buffer.from(c.response_b64!, 'base64').toString('utf8'));
  const bytes = Buffer.from(text, 'utf8');
  c.response_b64 = bytes.toString('base64');
  if (rehash) c.response_sha256 = sha256Hex(bytes);
}

/** Change the model's verdict inside the signed response: the attack a judge cares about. */
function downgradeSeverity(text: string): string {
  for (const [from, to] of [
    ['\\"severity\\": \\"critical\\"', '\\"severity\\": \\"low\\"'],
    ['\\"severity\\":\\"critical\\"', '\\"severity\\":\\"low\\"'],
    ['\\"validity\\": \\"likely_valid\\"', '\\"validity\\": \\"likely_invalid\\"'],
  ] as const) {
    if (text.includes(from)) return text.replace(from, to);
  }
  const i = text.indexOf('"content":"');
  if (i < 0) return text + ' ';
  const j = i + 30;
  return text.slice(0, j) + (text[j] === 'X' ? 'Y' : 'X') + text.slice(j + 1);
}

export const SCENARIOS: TamperScenario[] = [
  {
    id: 'response_edited_rehashed',
    title: 'Analysis edited after signing',
    attack: 'An intermediary rewrites the verdict in the response (e.g. “critical” → “low”) and recomputes the SHA-256 so the hash matches the new bytes.',
    expect: 'FAILED',
    property: 'response_signature',
    check: 'signed_text',
    apply: (b) => {
      const t = clone(b);
      editResponse(t, downgradeSeverity, true);
      return t;
    },
  },
  {
    id: 'response_bytes_swapped',
    title: 'Response bytes swapped, hash kept',
    attack: 'The response shown to the user is altered but the original (signed) hash is left in place.',
    expect: 'FAILED',
    property: 'response_signature',
    check: 'response_bytes',
    apply: (b) => {
      const t = clone(b);
      editResponse(t, downgradeSeverity, false);
      return t;
    },
  },
  {
    id: 'request_hash_altered',
    title: 'Different report substituted',
    attack: 'The receipt claims a different request (report) than the one the enclave signed.',
    expect: 'FAILED',
    property: 'response_signature',
    check: 'signed_text',
    apply: (b) => {
      const t = clone(b);
      t.completion!.request_sha256 = flipHex(t.completion!.request_sha256);
      delete t.completion!.request_b64;
      return t;
    },
  },
  {
    id: 'forged_signer',
    title: 'Signature by an unattested key',
    attack: 'An attacker signs the exact correct text with their own key. The signature is valid — but the key is not bound to any attested enclave.',
    expect: 'FAILED',
    property: 'response_signature',
    check: 'signer_attested',
    apply: (b) => {
      const t = clone(b);
      const s = sig(t);
      const w = new ethers.Wallet('0x' + sha256Hex('privatetriage tamper-lab attacker key'));
      s.signature = w.signMessageSync(String(s.text));
      s.signing_address = w.address;
      setSig(t, s);
      return t;
    },
  },
  {
    id: 'gateway_signed',
    title: 'Gateway-signed instead of model-signed',
    attack: 'The response is presented with a gateway signature (as for streamed or aliased requests). PrivateTriage requires the model TEE itself to sign.',
    expect: 'FAILED',
    property: 'response_signature',
    check: 'signature_kind',
    apply: (b) => {
      const t = clone(b);
      const s = sig(t);
      s.signature_kind = 'gateway';
      setSig(t, s);
      return t;
    },
  },
  {
    id: 'unknown_signature_kind',
    title: 'Unknown signature kind',
    attack: 'The service returns a signature kind this verifier does not understand.',
    expect: 'UNVERIFIED',
    property: 'response_signature',
    check: 'signature_kind',
    apply: (b) => {
      const t = clone(b);
      const s = sig(t);
      s.signature_kind = 'experimental_v2';
      setSig(t, s);
      return t;
    },
  },
  {
    id: 'signature_missing',
    title: 'Signature unavailable',
    attack: 'The signature endpoint fails or the signature was never produced.',
    expect: 'UNVERIFIED',
    property: 'response_signature',
    check: 'signature_present',
    apply: (b) => {
      const t = clone(b);
      t.signature = { ...t.signature!, status: 404, body: '{"error":{"message":"not found"}}' };
      return t;
    },
  },
  {
    id: 'replayed_attestation',
    title: 'Replayed attestation from another session',
    attack: 'Genuine, valid attestation evidence captured earlier is replayed instead of a fresh answer to our challenge.',
    expect: 'FAILED',
    property: 'gateway_tee',
    check: 'nonce_bound',
    apply: (b, ctx) => {
      const t = clone(b);
      t.attestation = { ...ctx.other.attestation!, socket_id: b.attestation!.socket_id };
      t.collateral = { ...ctx.other.collateral };
      t.nras = { ...ctx.other.nras };
      return t;
    },
  },
  {
    id: 'challenge_not_from_request',
    title: 'Challenge not derived from this report',
    attack: 'The nonce salt is swapped, so the attestation challenge no longer commits to this request.',
    expect: 'FAILED',
    property: 'response_signature',
    check: 'nonce_derivation',
    apply: (b) => {
      const t = clone(b);
      t.nonce.salt = flipHex(t.nonce.salt);
      return t;
    },
  },
  {
    id: 'quote_corrupted',
    title: 'Corrupted Intel TDX quote',
    attack: 'One bit of the gateway’s signed TD report (MRSEAM measurement) is flipped, collateral re-attached. Intel’s quote signature no longer verifies.',
    expect: 'FAILED',
    property: 'gateway_tee',
    check: 'quote_verified',
    apply: (b) => {
      const t = clone(b);
      const a = att(t);
      const g = a.gateway_attestation as Record<string, unknown>;
      const q = String(g.intel_quote);
      const col = t.collateral[quoteKey(q)];
      const bad = flipHex(q, 2 * 100); // byte 100: inside the signed TD report body
      g.intel_quote = bad;
      t.collateral[quoteKey(bad)] = col ?? null;
      setAtt(t, a);
      return t;
    },
  },
  {
    id: 'model_signer_swapped',
    title: 'Model report claims a different key',
    attack: 'The model attestation advertises a signing key that its hardware quote does not commit to.',
    expect: 'FAILED',
    property: 'model_tee',
    check: 'signer_bound',
    apply: (b) => {
      const t = clone(b);
      const a = att(t);
      const m = (a.model_attestations as Record<string, unknown>[])[0]!;
      m.signing_address = '0x' + sha256Hex('not the enclave key').slice(0, 40);
      setAtt(t, a);
      return t;
    },
  },
  {
    id: 'tls_intercepted',
    title: 'TLS terminated by an intermediary',
    attack: 'The certificate seen on the connection is not the one bound into the gateway quote (e.g. a TLS-inspecting proxy).',
    expect: 'FAILED',
    property: 'tls_binding',
    check: 'tls_spki',
    apply: (b) => {
      const t = clone(b);
      t.attestation!.peer_spki_sha256 = flipHex(t.attestation!.peer_spki_sha256!);
      return t;
    },
  },
  {
    id: 'different_connection',
    title: 'Report sent on a different connection',
    attack: 'Attestation is checked on one connection, but the report travels over another, unverified one.',
    expect: 'FAILED',
    property: 'tls_binding',
    check: 'same_connection',
    apply: (b) => {
      const t = clone(b);
      t.completion!.socket_id = t.completion!.socket_id + 1;
      return t;
    },
  },
  {
    id: 'nras_token_forged',
    title: 'Forged NVIDIA GPU verdict',
    attack: 'The NVIDIA attestation token’s claims are edited; its ES384 signature no longer verifies.',
    expect: 'FAILED',
    property: 'gpu_tee',
    check: 'nras_signature',
    apply: (b) => {
      const t = clone(b);
      const n = t.nras['0']!;
      const arr = JSON.parse(n.nrasResponse) as unknown[];
      const pair = arr[0] as [string, string];
      const [h, p, s] = pair[1].split('.') as [string, string, string];
      const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) as Record<string, unknown>;
      claims.iat = Number(claims.iat) + 1;
      pair[1] = `${h}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${s}`;
      t.nras['0'] = { ...n, nrasResponse: JSON.stringify(arr) };
      return t;
    },
  },
  {
    id: 'nras_self_certified',
    title: 'NVIDIA verdict re-signed with an attacker key',
    attack: 'The attacker forges a passing GPU verdict, signs it with their own P-384 key, and ships a key set that reuses NVIDIA’s genuine certificate chain under the same key id. The key does not match NVIDIA’s certificate.',
    expect: 'FAILED',
    property: 'gpu_tee',
    check: 'nras_signature',
    apply: (b) => {
      const t = clone(b);
      const n = t.nras['0']!;
      const arr = JSON.parse(n.nrasResponse) as unknown[];
      const pair = arr[0] as [string, string];
      const [h, p] = pair[1].split('.') as [string, string, string];
      const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8')) as { kid: string };
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
      const sig = cryptoSign('sha384', Buffer.from(`${h}.${p}`), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
      pair[1] = `${h}.${p}.${sig}`;
      const jwks = JSON.parse(n.jwks) as { keys: Record<string, unknown>[] };
      const genuine = jwks.keys.find((k) => k.kid === header.kid)!;
      const forged = { ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>), kid: header.kid, x5c: genuine.x5c };
      t.nras['0'] = { nrasResponse: JSON.stringify(arr), jwks: JSON.stringify({ keys: [forged] }) };
      return t;
    },
  },
  {
    id: 'event_log_rewritten',
    title: 'Event log rewritten to claim another app',
    attack: 'The model report’s event log is edited to claim a different app identity than the one the hardware measured.',
    expect: 'FAILED',
    property: 'model_tee',
    check: 'rtmr3',
    apply: (b) => {
      const t = clone(b);
      const a = att(t);
      const m = (a.model_attestations as Record<string, unknown>[])[0]!;
      const info = m.info as Record<string, unknown>;
      const tcbRaw = info.tcb_info;
      const tcb = (typeof tcbRaw === 'string' ? JSON.parse(tcbRaw) : tcbRaw) as Record<string, unknown>;
      const raw = m.event_log ?? tcb.event_log;
      const log = (typeof raw === 'string' ? JSON.parse(raw) : raw) as { event: string; event_payload: string; digest?: string }[];
      const ev = log.find((e) => e.event === 'app-id')!;
      ev.event_payload = flipHex(ev.event_payload, 2);
      delete ev.digest;
      m.event_log = typeof raw === 'string' ? JSON.stringify(log) : log;
      setAtt(t, a);
      return t;
    },
  },
  {
    id: 'gpu_evidence_missing',
    title: 'GPU attestation unavailable',
    attack: 'NVIDIA’s attestation service is unreachable, so GPU confidential-computing mode cannot be confirmed.',
    expect: 'UNVERIFIED',
    property: 'gpu_tee',
    check: 'nras_verdict',
    apply: (b) => {
      const t = clone(b);
      t.nras = {};
      return t;
    },
  },
  {
    id: 'attestation_missing',
    title: 'No attestation at all',
    attack: 'The attestation endpoint returns nothing usable.',
    expect: 'UNVERIFIED',
    property: 'gateway_tee',
    check: 'report_present',
    apply: (b) => {
      const t = clone(b);
      t.attestation = { ...t.attestation!, status: 503, body: '{"error":{"message":"unavailable"}}' };
      return t;
    },
  },
  {
    id: 'model_swapped',
    title: 'Different model claimed',
    attack: 'The receipt claims a different model than the one whose enclave produced the evidence and signature.',
    expect: 'FAILED',
    property: 'model_tee',
    check: 'model_name',
    apply: (b) => {
      const t = clone(b);
      t.model = 'openai/gpt-5.4';
      return t;
    },
  },
  {
    id: 'inference_failed',
    title: 'Malformed / failed inference',
    attack: 'The model call fails (HTTP 500), so there is nothing signed to verify.',
    expect: 'UNVERIFIED',
    property: 'response_signature',
    check: 'signature_present',
    apply: (b) => {
      const t = clone(b);
      t.completion!.status = 500;
      return t;
    },
  },
  {
    id: 'bundle_policy_relaxed',
    title: 'Bundle tries to relax the policy',
    attack: 'The evidence file rewrites its own policy to accept out-of-date or revoked platform firmware — and ships an edited verdict. The verifier ignores bundle-supplied policy and still catches the edit.',
    expect: 'FAILED',
    property: 'response_signature',
    check: 'signed_text',
    apply: (b) => {
      const t = clone(b);
      t.policy = {
        acceptedTcbStatuses: ['UpToDate', 'OutOfDate', 'ConfigurationNeeded', 'Revoked'],
        measurements: { os: [], apps: [], mr_kms: [], key_providers: [] },
      };
      // ...combined with an edited response, to show the relaxed policy buys nothing.
      editResponse(t, downgradeSeverity, true);
      return t;
    },
  },
];

export function isTamperable(b: EvidenceBundle): boolean {
  return Boolean(
    b.attestation && b.completion?.response_b64 && b.signature && isRecord(JSON.parse(b.signature.body)) && b.nras['0'] && b.attestation.peer_spki_sha256,
  );
}
