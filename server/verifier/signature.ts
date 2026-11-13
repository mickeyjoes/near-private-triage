// Response-signature verification over exact request/response bytes, following
// https://docs.near.ai/cloud/verification/cloud-api/response-signatures and the
// reference helpers in .../reference/response-signature-verification.
import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import { EvidenceError, hexToBytes, isRecord, sameBytes } from './bytes.ts';
import { CheckList, type SignerIdentity } from './types.ts';

export type SignatureKind = 'provider_tee' | 'gateway';

export interface SignatureCheckInput {
  /** Parsed JSON from GET /v1/signature/{id}, or null if unavailable. */
  signature: unknown;
  /** SHA-256 (hex) of the exact request/response bytes, computed by the caller from bytes it holds. */
  requestSha256: string;
  responseSha256: string;
  /** Canonical model ID sent in the original request (with x-no-aliasing). */
  model: string;
  /** Which signer our policy requires. PrivateTriage requires provider_tee. */
  requiredKind: SignatureKind;
  /** Verified preflight identities. */
  verifiedModelSigners: SignerIdentity[];
  verifiedGatewaySigner: SignerIdentity | null;
}

export interface SignatureCheckResult {
  checks: CheckList;
  kind: string | null;
  signer: SignerIdentity | null;
  expectedText: string;
  requestSha256: string;
  responseSha256: string;
}

export function expectedSignatureText(kind: SignatureKind, model: string, requestSha256: string, responseSha256: string): string {
  const hashes = `${requestSha256.toLowerCase()}:${responseSha256.toLowerCase()}`;
  return kind === 'provider_tee' ? `${model}:${hashes}` : hashes;
}

function identityBytes(id: SignerIdentity): Buffer {
  return hexToBytes(id.signing_address, 'signing_address', id.signing_algo === 'ecdsa' ? 20 : 32);
}

function sameIdentity(a: SignerIdentity, b: SignerIdentity): boolean {
  return a.signing_algo === b.signing_algo && sameBytes(identityBytes(a), identityBytes(b));
}

export function checkResponseSignature(input: SignatureCheckInput): SignatureCheckResult {
  const c = new CheckList();
  const { requestSha256, responseSha256 } = input;
  const out: SignatureCheckResult = {
    checks: c,
    kind: null,
    signer: null,
    expectedText: expectedSignatureText(input.requiredKind, input.model, requestSha256, responseSha256),
    requestSha256,
    responseSha256,
  };
  const s = input.signature;
  if (!isRecord(s)) {
    c.unavailable('signature_present', 'Response signature available', 'No signature was returned for this completion.');
    return out;
  }
  if ('error_code' in s || typeof s.signature !== 'string' || typeof s.text !== 'string') {
    c.unavailable('signature_present', 'Response signature available', 'Signature endpoint returned an unavailable result.');
    return out;
  }
  c.pass('signature_present', 'Response signature available', 'Signature retrieved for this completion ID.');

  // Signer classification must come from signature_kind; never inferred from text shape.
  const kind = typeof s.signature_kind === 'string' ? s.signature_kind : null;
  out.kind = kind;
  if (kind !== 'provider_tee' && kind !== 'gateway') {
    c.unavailable('signature_kind', 'Signer kind is the model TEE', `signature_kind ${JSON.stringify(s.signature_kind)} is absent or unknown; signer cannot be classified.`);
    return out;
  }
  c.expect(
    kind === input.requiredKind,
    'signature_kind',
    'Signer kind is the model TEE',
    kind === 'provider_tee' ? 'signature_kind = provider_tee: signed inside the model-serving TEE.' : 'signature_kind = gateway.',
    `signature_kind = ${kind}, but policy requires ${input.requiredKind}. A gateway signature does not prove the model TEE produced the response.`,
  );

  // Exact-bytes binding: text must equal the expected payload for THIS request/response/model.
  const expected = expectedSignatureText(kind, input.model, requestSha256, responseSha256);
  out.expectedText = expected;
  c.expect(
    s.text === expected,
    'signed_text',
    'Signature covers these exact bytes',
    kind === 'provider_tee'
      ? `Signed text = model ‖ SHA-256(request) ‖ SHA-256(response) for ${input.model}.`
      : 'Signed text = SHA-256(request) ‖ SHA-256(response).',
    'Signed text does not match the hashes of the bytes we sent and received (tampered request/response or wrong model).',
  );

  // Cryptographic signature check.
  let signer: SignerIdentity;
  try {
    const algo = s.signing_algo;
    if (algo !== 'ecdsa' && algo !== 'ed25519') throw new EvidenceError('unsupported', `unsupported signing_algo ${JSON.stringify(algo)}`);
    signer = { signing_algo: algo, signing_address: String(s.signing_address) };
    const addr = identityBytes(signer);
    const sig = hexToBytes(s.signature, 'signature', algo === 'ecdsa' ? 65 : 64);
    let valid: boolean;
    if (algo === 'ecdsa') {
      const recovered = ethers.verifyMessage(Buffer.from(s.text, 'utf8'), ethers.hexlify(sig));
      valid = sameBytes(hexToBytes(recovered, 'recovered', 20), addr);
    } else {
      valid = nacl.sign.detached.verify(Buffer.from(s.text, 'utf8'), sig, addr);
    }
    out.signer = signer;
    if (!c.expect(valid, 'signature_valid', 'Signature is cryptographically valid',
      algo === 'ecdsa' ? `EIP-191 signature recovers ${signer.signing_address}.` : 'Ed25519 signature verifies.',
      'Signature does not verify for the claimed signing_address.')) return out;
  } catch (e) {
    const code = (e as EvidenceError).code;
    if (code === 'unsupported') c.unavailable('signature_valid', 'Signature is cryptographically valid', (e as Error).message);
    else c.fail('signature_valid', 'Signature is cryptographically valid', (e as Error).message);
    return out;
  }

  // Signer must match exactly one VERIFIED preflight report of the right kind.
  if (kind === 'provider_tee') {
    const matches = input.verifiedModelSigners.filter((m) => sameIdentity(m, signer));
    c.expect(
      matches.length === 1,
      'signer_attested',
      'Signer key is bound to attested hardware',
      `Signer matches exactly one model report verified before the request (${signer.signing_algo} ${signer.signing_address}).`,
      matches.length === 0
        ? 'Signer does not match any model report verified before the request.'
        : 'Signer matches more than one verified report (ambiguous).',
    );
  } else {
    const g = input.verifiedGatewaySigner;
    c.expect(
      g !== null && sameIdentity(g, signer),
      'signer_attested',
      'Signer key is bound to attested hardware',
      'Signer matches the gateway report verified before the request.',
      'Signer does not match the verified gateway report.',
    );
  }
  return out;
}
