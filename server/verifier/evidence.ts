// Evidence bundle + pure evaluation.
//
// Live runs, negative tests and offline re-verification all use the SAME
// evaluation code: the live pipeline captures raw evidence into an
// EvidenceBundle, and evaluate*() turns a bundle into a Receipt. Nothing in the
// evaluation path performs network I/O, so a recorded bundle can be tampered
// with in tests or re-checked by a third party without an API key.
import { createHash } from 'node:crypto';
import { isRecord, sha256Hex } from './bytes.ts';
import { checkGpuEvidence, type GpuCheckResult, type NrasEvidence } from './gpu.ts';
import { checkNearReport, DEFAULT_POLICY, type ReportCheckResult, type ReportPolicy } from './nearReport.ts';
import { checkResponseSignature, type SignatureCheckResult } from './signature.ts';
import type { Collateral } from './tdx.ts';
import { quoteFactsSummary } from './tdx.ts';
import {
  type Check,
  CheckList,
  combineVerdicts,
  type Property,
  type SignerIdentity,
  type Verdict,
  verdictOf,
} from './types.ts';

export const NONCE_DOMAIN = 'privatetriage/attestation-nonce/v1';

/** nonce = SHA-256(domain ‖ salt ‖ SHA-256(request bytes)). Uniformly random given a random salt,
 * and lets anyone holding the receipt confirm the attestation challenge was derived from THIS request. */
export function deriveNonce(saltHex: string, requestSha256: string): string {
  return createHash('sha256')
    .update(NONCE_DOMAIN)
    .update(Buffer.from(saltHex, 'hex'))
    .update(Buffer.from(requestSha256, 'hex'))
    .digest('hex');
}

export interface ExchangeRecord {
  status: number;
  /** Raw response body as UTF-8 text (attestation/signature JSON are public evidence). */
  body: string;
  socket_id: number;
  peer_spki_sha256: string | null;
}

export interface EvidenceBundle {
  schema: 'privatetriage.evidence/v1';
  captured_at: string;
  captured_at_secs: number;
  endpoint: string;
  model: string;
  nonce: { salt: string; request_sha256: string; value: string };
  attestation: ExchangeRecord | null;
  /** Intel collateral per quote, keyed by SHA-256 of the quote hex string. */
  collateral: Record<string, Collateral | null>;
  /** NRAS result per model candidate index. */
  nras: Record<string, NrasEvidence | null>;
  completion: {
    status: number;
    request_sha256: string;
    response_sha256: string;
    chat_id: string | null;
    socket_id: number;
    peer_spki_sha256: string | null;
    /** Present only when the request content is non-confidential (fixtures) or the user exports it. */
    request_b64?: string;
    response_b64?: string;
  } | null;
  /** Why the completion was not sent, if preflight blocked disclosure. */
  blocked_reason?: string;
  signature: ExchangeRecord | null;
  policy: ReportPolicy;
}

export interface CandidateResult {
  index: number;
  report: ReportCheckResult;
  gpu: GpuCheckResult;
  verdict: Verdict;
  identity: SignerIdentity | null;
}

export interface PreflightResult {
  gateway: ReportCheckResult | null;
  gatewayVerdict: Verdict;
  candidates: CandidateResult[];
  verifiedModelSigners: SignerIdentity[];
  ok: boolean;
  reason: string;
  attestationError: Check | null;
}

export const quoteKey = (quoteHex: string): string => sha256Hex(quoteHex);

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function evaluatePreflight(b: EvidenceBundle): PreflightResult {
  const empty: PreflightResult = {
    gateway: null,
    gatewayVerdict: 'UNVERIFIED',
    candidates: [],
    verifiedModelSigners: [],
    ok: false,
    reason: '',
    attestationError: null,
  };
  if (!b.attestation || b.attestation.status !== 200) {
    empty.reason = `Attestation report unavailable (HTTP ${b.attestation?.status ?? 'n/a'}).`;
    empty.attestationError = { id: 'report_present', label: 'Attestation report present', status: 'unavailable', detail: empty.reason };
    return empty;
  }
  const att = parseJson(b.attestation.body);
  if (!isRecord(att)) {
    empty.reason = 'Attestation response is not a JSON object.';
    empty.attestationError = { id: 'report_present', label: 'Attestation report present', status: 'fail', detail: empty.reason };
    return empty;
  }
  const collateralFor = (rep: unknown): Collateral | null =>
    isRecord(rep) && typeof rep.intel_quote === 'string' ? b.collateral[quoteKey(rep.intel_quote)] ?? null : null;

  const gateway = checkNearReport({
    report: att.gateway_attestation,
    nonceHex: b.nonce.value,
    collateral: collateralFor(att.gateway_attestation),
    nowSecs: b.captured_at_secs,
    policy: b.policy,
    peerSpkiSha256: b.attestation.peer_spki_sha256 ?? undefined,
  });
  // tls_spki is evaluated as part of the TLS-binding property, not the gateway TEE property.
  const gatewayCore = gateway.checks.checks.filter((c) => c.id !== 'tls_spki');
  const gatewayVerdict = verdictOf(gatewayCore);

  const candidates: CandidateResult[] = [];
  const list = Array.isArray(att.model_attestations) ? att.model_attestations : [];
  list.forEach((rep, index) => {
    const report = checkNearReport({
      report: rep,
      nonceHex: b.nonce.value,
      collateral: collateralFor(rep),
      nowSecs: b.captured_at_secs,
      policy: b.policy,
    });
    if (isRecord(rep) && typeof rep.model_name === 'string' && rep.model_name !== b.model) {
      report.checks.fail('model_name', 'Report is for the requested model', `Report is for ${rep.model_name}, not ${b.model}.`);
    }
    const gpu = checkGpuEvidence(isRecord(rep) ? rep.nvidia_payload : undefined, b.nonce.value, b.nras[String(index)] ?? null, b.captured_at_secs);
    const verdict = verdictOf([...report.checks.checks, ...gpu.checks.checks]);
    candidates.push({ index, report, gpu, verdict, identity: report.identity });
  });
  const verifiedModelSigners = candidates.filter((c) => c.verdict === 'VERIFIED' && c.identity).map((c) => c.identity!);

  let reason = '';
  if (gatewayVerdict !== 'VERIFIED') reason = 'Gateway TEE evidence did not verify.';
  else if (list.length === 0) reason = 'No model-TEE attestation was returned for this model (not a confidential TEE model, or evidence unavailable).';
  else if (verifiedModelSigners.length === 0) reason = 'No model-TEE attestation candidate verified.';
  const tls = gateway.checks.checks.find((c) => c.id === 'tls_spki');
  if (!reason && (!tls || tls.status !== 'pass')) reason = 'Gateway TLS key is not proven to live inside the attested gateway.';
  return { gateway, gatewayVerdict, candidates, verifiedModelSigners, ok: reason === '', reason, attestationError: null };
}

export interface Receipt {
  schema: 'privatetriage.receipt/v1';
  verdict: Verdict;
  headline: string;
  captured_at: string;
  endpoint: string;
  model: string;
  nonce: EvidenceBundle['nonce'] & { derivation: string };
  request_sha256: string | null;
  response_sha256: string | null;
  chat_id: string | null;
  disclosed: boolean;
  signer: { kind: string | null; algo: string | null; address: string | null } | null;
  properties: Property[];
  gateway: Record<string, unknown> | null;
  model_tee: Record<string, unknown> | null;
  not_proven: string[];
  trust_assumptions: string[];
}

const NOT_PROVEN = [
  'That the model’s security analysis is correct. AI triage is a recommendation; attestation proves how it ran, not what it concluded.',
  'That NEAR AI Cloud does not retain prompts. Attestation identifies measured software; it does not audit retention behaviour of that software.',
  'End-to-end encryption to the model. TLS terminates in the attested gateway TEE; the gateway then forwards to the model TEE over a channel this receipt does not verify.',
  'Image provenance. Container digests are measured and displayed, but not checked against a source-build allowlist.',
  'That the verified model report and the completion came from the same serving instance (instances of one model share a signing key).',
  'Confidentiality between the user’s browser and the PrivateTriage backend beyond standard HTTPS/localhost.',
];

const TRUST_ASSUMPTIONS = [
  'Intel TDX hardware and Intel’s attestation signing root (DCAP / PCS).',
  'NVIDIA H100/H200 confidential-computing hardware and NVIDIA NRAS signing keys (JWKS fetched over WebPKI TLS).',
  'The measured NEAR AI Cloud software stack (dstack, gateway, model server) behaves as its published source describes.',
  'The PrivateTriage backend you run: it holds the API key, sees your report in plaintext, and performs these checks.',
  'WebPKI for the TLS connections to Intel PCS, NVIDIA NRAS and NEAR AI Cloud.',
];

function prop(id: Property['id'], title: string, statement: string, checks: Check[]): Property {
  return { id, title, statement, checks, verdict: verdictOf(checks) };
}

export interface CompletionFacts {
  chatId: string | null;
}

export function evaluateBundle(b: EvidenceBundle): { receipt: Receipt; preflight: PreflightResult; signature: SignatureCheckResult | null } {
  const pre = evaluatePreflight(b);
  const properties: Property[] = [];

  // Gateway TEE
  const gwChecks = pre.gateway ? pre.gateway.checks.checks.filter((c) => c.id !== 'tls_spki') : pre.attestationError ? [pre.attestationError] : [];
  properties.push(prop('gateway_tee', 'Gateway runs in a genuine Intel TDX enclave',
    'The NEAR AI Cloud gateway that received the request runs measured software inside an Intel TDX confidential VM, and produced this evidence after our challenge.', gwChecks));

  // TLS binding: quote-bound SPKI == peer SPKI on the attestation connection, and inference on that same connection.
  const tlsChecks = new CheckList();
  const spki = pre.gateway?.checks.checks.find((c) => c.id === 'tls_spki');
  if (spki) tlsChecks.checks.push(spki);
  else tlsChecks.unavailable('tls_spki', 'TLS key is inside the attested TEE', 'Gateway TLS fingerprint evidence unavailable.');
  if (b.completion && b.attestation) {
    tlsChecks.expect(
      b.completion.socket_id === b.attestation.socket_id,
      'same_connection',
      'Report sent over the attested connection',
      'The inference request used the same TLS connection whose certificate was matched to the gateway quote.',
      'The inference request used a different TLS connection than the attested one.',
    );
  } else {
    tlsChecks.unavailable('same_connection', 'Report sent over the attested connection', 'No inference request was sent.');
  }
  properties.push(prop('tls_binding', 'Your report was encrypted to the attested gateway',
    'The TLS session carrying the report terminated inside the attested gateway enclave, not at an intermediary.', tlsChecks.checks));

  // Signature
  let sig: SignatureCheckResult | null = null;
  const chatId = b.completion?.chat_id ?? null;
  if (b.completion && b.completion.status === 200) {
    const sigBody = b.signature && b.signature.status === 200 ? parseJson(b.signature.body) : null;
    sig = checkResponseSignature({
      signature: sigBody,
      requestSha256: b.completion.request_sha256,
      responseSha256: b.completion.response_sha256,
      model: b.model,
      requiredKind: 'provider_tee',
      verifiedModelSigners: pre.verifiedModelSigners,
      verifiedGatewaySigner: pre.gateway?.identity ?? null,
    });
  }

  // Model TEE + GPU: report on the candidate the signer matched; otherwise all candidates.
  let chosen: CandidateResult[] = pre.candidates;
  if (sig?.signer) {
    const s = sig.signer;
    const m = pre.candidates.filter(
      (c) => c.identity && c.identity.signing_algo === s.signing_algo && c.identity.signing_address.toLowerCase() === s.signing_address.toLowerCase(),
    );
    if (m.length > 0) chosen = m;
  }
  const modelChecks: Check[] = chosen.length ? chosen.flatMap((c) => c.report.checks.checks) : [
    { id: 'model_report', label: 'Model attestation present', status: 'unavailable', detail: 'No model-TEE attestation candidates were returned.' },
  ];
  const gpuChecks: Check[] = chosen.length ? chosen.flatMap((c) => c.gpu.checks.checks) : [
    { id: 'gpu_evidence', label: 'GPU evidence present', status: 'unavailable', detail: 'No model-TEE attestation candidates were returned.' },
  ];
  properties.push(prop('model_tee', 'Model runs in a genuine Intel TDX enclave',
    'The model-serving environment runs measured software in an Intel TDX confidential VM, bound to the signing key, and answered our fresh challenge.', modelChecks));
  properties.push(prop('gpu_tee', 'Model GPUs are in confidential-computing mode',
    'NVIDIA attested — and signed a verdict bound to our nonce — that the GPUs serving the model are genuine and running in confidential-computing mode with expected firmware.', gpuChecks));

  const sigChecks: Check[] = sig ? sig.checks.checks : [
    { id: 'signature_present', label: 'Response signature available', status: 'unavailable', detail: b.blocked_reason ? `Not requested: ${b.blocked_reason}` : `Completion unavailable (HTTP ${b.completion?.status ?? 'n/a'}).` },
  ];
  properties.push(prop('response_signature', 'Analysis was signed inside the model enclave',
    'The model TEE signed SHA-256 hashes of the exact request we sent and the exact response we received, with a key that the attested hardware vouches for.', sigChecks));

  const verdict = combineVerdicts(properties.map((p) => p.verdict));
  const failed = properties.filter((p) => p.verdict === 'FAILED').map((p) => p.title);
  const unverified = properties.filter((p) => p.verdict === 'UNVERIFIED').map((p) => p.title);
  const headline =
    verdict === 'VERIFIED'
      ? 'Confidential execution verified: attested gateway and GPU-backed model TEE, response signed in the model enclave.'
      : verdict === 'FAILED'
        ? `Verification FAILED: ${failed.join('; ')}.`
        : `Not verified: ${unverified.join('; ')}.`;

  const chosenOne = chosen.length === 1 ? chosen[0]! : null;
  return {
    preflight: pre,
    signature: sig,
    receipt: {
      schema: 'privatetriage.receipt/v1',
      verdict,
      headline,
      captured_at: b.captured_at,
      endpoint: b.endpoint,
      model: b.model,
      nonce: { ...b.nonce, derivation: `SHA-256("${NONCE_DOMAIN}" ‖ salt ‖ request_sha256)` },
      request_sha256: b.completion?.request_sha256 ?? b.nonce.request_sha256,
      response_sha256: b.completion?.response_sha256 ?? null,
      chat_id: chatId,
      disclosed: b.completion !== null,
      signer: sig ? { kind: sig.kind, algo: sig.signer?.signing_algo ?? null, address: sig.signer?.signing_address ?? null } : null,
      properties,
      gateway: pre.gateway
        ? {
            signing_address: pre.gateway.identity?.signing_address ?? null,
            signing_algo: pre.gateway.identity?.signing_algo ?? null,
            tls_spki_sha256: pre.gateway.tlsCertFingerprint,
            compose_hash: pre.gateway.composeHash,
            image_digests: pre.gateway.imageDigests,
            quote: pre.gateway.quote ? quoteFactsSummary(pre.gateway.quote) : null,
          }
        : null,
      model_tee: chosenOne
        ? {
            candidate_index: chosenOne.index,
            candidates_returned: pre.candidates.length,
            candidates_verified: pre.verifiedModelSigners.length,
            signing_address: chosenOne.identity?.signing_address ?? null,
            signing_algo: chosenOne.identity?.signing_algo ?? null,
            compose_hash: chosenOne.report.composeHash,
            image_digests: chosenOne.report.imageDigests,
            quote: chosenOne.report.quote ? quoteFactsSummary(chosenOne.report.quote) : null,
            gpu: {
              count: chosenOne.gpu.gpuCount,
              arch: chosenOne.gpu.arch,
              nras_iat: chosenOne.gpu.claims?.iat ?? null,
              nras_jti: chosenOne.gpu.claims?.jti ?? null,
              nras_eat_nonce: chosenOne.gpu.claims?.eat_nonce ?? null,
            },
          }
        : { candidates_returned: pre.candidates.length, candidates_verified: pre.verifiedModelSigners.length },
      not_proven: NOT_PROVEN,
      trust_assumptions: TRUST_ASSUMPTIONS,
    },
  };
}

export { DEFAULT_POLICY };
