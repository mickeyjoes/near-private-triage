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
export const VERIFIER_ID = 'privatetriage-verifier/2 (policy: TCB UpToDate only, provider_tee signer, Intel PCS, NVIDIA NRAS + per-GPU claims + device reports)';
/** The only gateway PrivateTriage talks to. A bundle naming another endpoint does not verify. */
export const EXPECTED_ENDPOINT = 'https://cloud-api.near.ai';

/** See server/near/connection.ts. Recorded by the backend; `sent` is implied by a recorded response. */
export type TransmissionState = 'not_sent' | 'may_have_been_sent' | 'sent';

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
  /** Why NRAS evidence is missing for a candidate (diagnostic only). */
  nras_errors?: Record<string, string>;
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
  /** Why no verified completion exists (preflight block, pin refusal, transport failure). */
  blocked_reason?: string;
  /** Whether the report left the backend (absent in bundles recorded before 2026-11-14). */
  transmission?: { state: TransmissionState; detail: string };
  /** Why the signature could not be fetched (e.g. the attested connection closed). */
  signature_error?: string;
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

/** Upper bound on model candidates evaluated (each costs a quote verification). */
export const MAX_CANDIDATES = 8;

/** A short, sanitized provider error message (public attestation endpoint; no secrets). */
function providerMessage(body: string | undefined): string {
  if (!body) return '';
  const j = parseJson(body);
  const msg = isRecord(j) && isRecord(j.error) && typeof j.error.message === 'string' ? j.error.message : isRecord(j) && typeof j.detail === 'string' ? j.detail : '';
  const clean = msg.replace(/[^\x20-\x7e]/g, '').slice(0, 160);
  return clean ? `: “${clean}”` : '';
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** `policy` is the VERIFIER's policy. A bundle's own recorded policy is informational only and is never trusted. */
export function evaluatePreflight(b: EvidenceBundle, policy: ReportPolicy = DEFAULT_POLICY): PreflightResult {
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
    empty.reason = `Attestation report unavailable (HTTP ${b.attestation?.status ?? 'n/a'})${providerMessage(b.attestation?.body)}.`;
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
    policy,
    role: 'gateway',
    peerSpkiSha256: b.attestation.peer_spki_sha256 ?? undefined,
  });
  // tls_spki is evaluated as part of the TLS-binding property, not the gateway TEE property.
  const gatewayCore = gateway.checks.checks.filter((c) => c.id !== 'tls_spki');
  const gatewayVerdict = verdictOf(gatewayCore);

  const candidates: CandidateResult[] = [];
  const list = Array.isArray(att.model_attestations) ? att.model_attestations : [];
  if (list.length > MAX_CANDIDATES) {
    empty.reason = `Attestation lists ${list.length} model candidates (limit ${MAX_CANDIDATES}).`;
    empty.attestationError = { id: 'report_present', label: 'Attestation report present', status: 'fail', detail: empty.reason };
    return empty;
  }
  list.forEach((rep, index) => {
    const report = checkNearReport({
      report: rep,
      nonceHex: b.nonce.value,
      collateral: collateralFor(rep),
      nowSecs: b.captured_at_secs,
      policy,
      role: 'model',
    });
    // NEAR policy: every candidate must be a report for exactly the requested model.
    const name = isRecord(rep) ? rep.model_name : undefined;
    report.checks.expect(
      name === b.model,
      'model_name',
      'Report is for the requested model',
      `Report is for ${b.model}.`,
      typeof name === 'string' ? `Report is for "${name}", not ${b.model}.` : `Report does not name its model (expected ${b.model}).`,
    );
    const gpu = checkGpuEvidence(isRecord(rep) ? rep.nvidia_payload : undefined, b.nonce.value, b.nras[String(index)] ?? null, b.captured_at_secs, b.nras_errors?.[String(index)]);
    const verdict = verdictOf([...report.checks.checks, ...gpu.checks.checks]);
    candidates.push({ index, report, gpu, verdict, identity: report.identity });
  });
  const verifiedModelSigners = candidates.filter((c) => c.verdict === 'VERIFIED' && c.identity).map((c) => c.identity!);

  let reason = '';
  const unverified = candidates.filter((c) => c.verdict !== 'VERIFIED');
  if (gatewayVerdict !== 'VERIFIED') reason = 'Gateway TEE evidence did not verify.';
  else if (list.length === 0) reason = 'No model-TEE attestation was returned for this model (not a confidential TEE model, or evidence unavailable).';
  else if (verifiedModelSigners.length === 0) reason = 'No model-TEE attestation candidate verified.';
  // Any candidate could serve the request, so every candidate must verify before disclosure.
  else if (unverified.length > 0) reason = `Model candidate${unverified.length > 1 ? 's' : ''} ${unverified.map((c) => `#${c.index}`).join(', ')} did not verify; every candidate must verify before the report is sent.`;
  const tls = gateway.checks.checks.find((c) => c.id === 'tls_spki');
  if (!reason && (!tls || tls.status !== 'pass')) reason = 'Gateway TLS key is not proven to live inside the attested gateway.';
  return { gateway, gatewayVerdict, candidates, verifiedModelSigners, ok: reason === '', reason, attestationError: null };
}

export interface Receipt {
  schema: 'privatetriage.receipt/v1';
  verifier: string;
  verdict: Verdict;
  headline: string;
  captured_at: string;
  endpoint: string;
  model: string;
  nonce: EvidenceBundle['nonce'] & { derivation: string };
  request_sha256: string | null;
  response_sha256: string | null;
  chat_id: string | null;
  /** not_sent | may_have_been_sent | sent — never "withheld" after a transmission that may have occurred. */
  transmission: TransmissionState;
  transmission_detail: string;
  /** True unless the report provably never left the backend (transmission === 'not_sent'). */
  disclosed: boolean;
  signer: { kind: string | null; algo: string | null; address: string | null } | null;
  properties: Property[];
  gateway: Record<string, unknown> | null;
  model_tee: Record<string, unknown> | null;
  not_proven: string[];
  trust_assumptions: string[];
}

const NOT_PROVEN = [
  'That the model’s security analysis is correct. AI triage is a recommendation; attestation describes how it ran, not whether its conclusions are right.',
  'That NEAR AI Cloud does not retain prompts. Attestation identifies measured software; it does not audit retention behaviour of that software.',
  'End-to-end encryption to the model. TLS terminates in the attested gateway TEE; the gateway then forwards to the model TEE over a channel this receipt does not verify.',
  'Which serving instance answered. Instances of one model share a signing key and may run different measured configurations, so the signature identifies the model deployment’s key, not the attested instance.',
  'Image or model-weight provenance. Container digests and an app compose are measured and displayed, but not checked against a source-build or model-weight allowlist; any compose of the pinned NEAR app is accepted.',
  'That NEAR’s pinned software is free of vulnerabilities or behaves as published. Measurements identify which dstack OS image and NEAR app ran (pinned on first observation, 2026-11-13); they are not an audit of that software.',
  'Freshness today. A recorded receipt is a historical appraisal against archived Intel/NVIDIA collateral at capture time, not a current revocation check.',
  'Confidentiality between the user’s browser and the PrivateTriage backend beyond standard HTTPS/localhost.',
];

const TRUST_ASSUMPTIONS = [
  'Intel TDX hardware and Intel’s attestation signing root (DCAP / PCS).',
  'NVIDIA confidential-computing GPUs, NVIDIA’s Device Identity CA (pinned to NVIDIA’s published root) and NRAS signing keys (intermediates pinned on first observation; no full NVIDIA certificate-revocation policy).',
  'NEAR AI Cloud as operator: its measured software (dstack, gateway, model server, management components), its deployment and key-provisioning governance, and its gateway-to-model channel.',
  'The PrivateTriage backend you run: it holds the API key, sees your report in plaintext, performs these checks, and records the connection observations (socket ids, peer certificates, timings) that offline verification cannot re-observe.',
  'WebPKI for the TLS connections to Intel PCS, NVIDIA NRAS and NEAR AI Cloud.',
];

/** What the report's journey was, from the recorded evidence (conservative for older bundles). */
export function transmissionOf(b: EvidenceBundle, preflightOk: boolean): { state: TransmissionState; detail: string } {
  if (b.completion) return { state: 'sent', detail: b.transmission?.detail ?? `Report delivered to the gateway; HTTP ${b.completion.status} response recorded.` };
  if (b.transmission && ['not_sent', 'may_have_been_sent', 'sent'].includes(b.transmission.state)) {
    return { state: b.transmission.state, detail: String(b.transmission.detail ?? '') };
  }
  // Bundles recorded before transmission tracking: the pipeline only ever attempted
  // to send after a passing preflight, so a failed preflight proves nothing was sent.
  if (!preflightOk) return { state: 'not_sent', detail: 'Preflight attestation did not verify; the report was not sent.' };
  if ((b.blocked_reason ?? '').startsWith('Preflight only')) return { state: 'not_sent', detail: b.blocked_reason! };
  return { state: 'may_have_been_sent', detail: 'Preflight passed but no response was recorded; the report may have been sent.' };
}

function prop(id: Property['id'], title: string, statement: string, checks: Check[]): Property {
  return { id, title, statement, checks, verdict: verdictOf(checks) };
}

export interface CompletionFacts {
  chatId: string | null;
}

function b64Bytes(v: unknown): Buffer | null {
  if (typeof v !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(v)) return null;
  return Buffer.from(v, 'base64');
}

/** Checks that tie the attestation challenge and any embedded content to the signed hashes. */
function bindingChecks(b: EvidenceBundle): Check[] {
  const c = new CheckList();
  const n = b.nonce;
  c.expect(
    Number.isInteger(b.captured_at_secs) && Math.floor(Date.parse(b.captured_at) / 1000) === b.captured_at_secs,
    'capture_time',
    'Displayed capture time is the evaluated time',
    `Captured ${b.captured_at}.`,
    'The displayed capture time differs from the time the evidence was evaluated at.',
  );
  let derived = '';
  try {
    derived = deriveNonce(n.salt, n.request_sha256);
  } catch {
    derived = '';
  }
  c.expect(
    /^[0-9a-f]{64}$/.test(n.salt ?? '') && /^[0-9a-f]{64}$/.test(n.request_sha256 ?? '') && derived === n.value,
    'nonce_derivation',
    'Challenge was derived from this request',
    `nonce = SHA-256(domain ‖ salt ‖ request hash) recomputes to ${n.value.slice(0, 16)}…`,
    'The attestation nonce does not recompute from the recorded salt and request hash.',
  );
  if (b.completion) {
    c.expect(
      b.completion.request_sha256 === n.request_sha256,
      'request_bound',
      'Signed request is the challenged request',
      'The request hash covered by the signature is the one the attestation challenge was derived from.',
      'The signed request hash differs from the request the attestation challenge was derived from.',
    );
    for (const [field, hash, label] of [
      ['request_b64', b.completion.request_sha256, 'request'],
      ['response_b64', b.completion.response_sha256, 'response'],
    ] as const) {
      const raw = b.completion[field];
      if (raw === undefined) continue;
      const bytes = b64Bytes(raw);
      const ok = c.expect(
        bytes !== null && sha256Hex(bytes) === hash,
        `${label}_bytes`,
        `Included ${label} bytes match the signed hash`,
        `SHA-256 of the included ${label} bytes equals the signed ${label} hash.`,
        `The included ${label} bytes do not hash to the signed ${label} hash (content was altered).`,
      );
      if (label === 'response' && ok) {
        // The completion id is recorder metadata unless it is checked against the signed bytes.
        const j = parseJson(bytes!.toString('utf8'));
        const signedId = isRecord(j) && typeof j.id === 'string' ? j.id : null;
        c.expect(
          signedId !== null && signedId === b.completion.chat_id,
          'chat_id_bound',
          'Completion id comes from the signed response',
          `Completion id ${String(b.completion.chat_id).slice(0, 24)} is the id inside the signed response bytes.`,
          'The recorded completion id differs from the id inside the signed response bytes.',
        );
      }
    }
  }
  return c.checks;
}

export interface EvaluateOptions {
  policy?: ReportPolicy;
}

export function evaluateBundle(
  b: EvidenceBundle,
  opts: EvaluateOptions = {},
): { receipt: Receipt; preflight: PreflightResult; signature: SignatureCheckResult | null } {
  const pre = evaluatePreflight(b, opts.policy ?? DEFAULT_POLICY);
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
  tlsChecks.expect(
    b.endpoint === EXPECTED_ENDPOINT,
    'endpoint',
    'Recorded endpoint is NEAR AI Cloud',
    `Endpoint ${EXPECTED_ENDPOINT} (recorded by the backend).`,
    `The bundle names endpoint ${JSON.stringify(b.endpoint)}, not ${EXPECTED_ENDPOINT}.`,
  );
  if (b.completion && b.attestation) {
    tlsChecks.expect(
      b.completion.socket_id === b.attestation.socket_id && b.completion.peer_spki_sha256 === b.attestation.peer_spki_sha256,
      'same_connection',
      'Report sent over the attested connection',
      'The inference request used the same TLS connection (same socket, same peer certificate key) that was matched to the gateway quote.',
      'The inference request used a different TLS connection or peer certificate than the attested one.',
    );
  } else {
    tlsChecks.unavailable('same_connection', 'Report sent over the attested connection', 'No inference response was recorded.');
  }
  properties.push(prop('tls_binding', 'Your report was encrypted to the attested gateway',
    'The TLS session carrying the report terminated inside the attested gateway enclave, not at an intermediary. The peer certificate and socket identity are observed live by the backend that captured this evidence (a recorder assertion); offline re-verification checks them against the quote but cannot re-observe the connection.', tlsChecks.checks));

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
      modelEvidenceAvailable: pre.candidates.length > 0,
      pendingModelSigners: pre.candidates.filter((c) => c.verdict === 'UNVERIFIED' && c.identity).map((c) => c.identity!),
      verifiedGatewaySigner: pre.gateway?.identity ?? null,
    });
  }

  // Model TEE + GPU: EVERY candidate's checks count (any could have served the request).
  // The summary below describes the candidate whose key signed the response.
  let chosen: CandidateResult[] = pre.candidates;
  if (sig?.signer) {
    const s = sig.signer;
    const m = pre.candidates.filter(
      (c) => c.identity && c.identity.signing_algo === s.signing_algo && c.identity.signing_address.toLowerCase() === s.signing_address.toLowerCase(),
    );
    if (m.length > 0) chosen = m;
  }
  const multi = pre.candidates.length > 1;
  const tagged = (c: CandidateResult, xs: Check[]) => (multi ? xs.map((x) => ({ ...x, label: `[candidate ${c.index}] ${x.label}` })) : xs);
  const modelChecks: Check[] = pre.candidates.length ? pre.candidates.flatMap((c) => tagged(c, c.report.checks.checks)) : [
    { id: 'model_report', label: 'Model attestation present', status: 'unavailable', detail: 'No model-TEE attestation candidates were returned.' },
  ];
  const gpuChecks: Check[] = pre.candidates.length ? pre.candidates.flatMap((c) => tagged(c, c.gpu.checks.checks)) : [
    { id: 'gpu_evidence', label: 'GPU evidence present', status: 'unavailable', detail: 'No model-TEE attestation candidates were returned.' },
  ];
  properties.push(prop('model_tee', 'Model runs in a genuine Intel TDX enclave',
    'Every model-serving environment NEAR returned for this model runs pinned, measured software in an Intel TDX confidential VM, is bound to its signing key, and answered our fresh challenge.', modelChecks));
  properties.push(prop('gpu_tee', 'Model GPUs are in confidential-computing mode',
    'Each GPU report reported by the model enclave is signed by a genuine NVIDIA GPU and answers our nonce; NVIDIA’s signed appraisal of exactly those GPUs (per-GPU claims bound into the platform token) reports confidential-computing measurements that match, secure boot and no debug.', gpuChecks));

  const sigChecks: Check[] = sig ? [...bindingChecks(b), ...sig.checks.checks] : [
    { id: 'signature_present', label: 'Response signature available', status: 'unavailable', detail: b.blocked_reason ? `Not requested: ${b.blocked_reason}` : `Completion unavailable (HTTP ${b.completion?.status ?? 'n/a'}).` },
  ];
  if (sig && b.signature_error) {
    const i = sigChecks.findIndex((c) => c.id === 'signature_present' && c.status !== 'pass');
    if (i >= 0) sigChecks[i] = { ...sigChecks[i]!, detail: b.signature_error };
  }
  properties.push(prop('response_signature', 'Response signed by the model deployment’s enclave key',
    'A key that the attested model enclave vouches for signed SHA-256 hashes of the exact serialized API request (system prompt, report, model and parameters) and the exact response bytes; the attestation challenge was derived from that same request. Checked after the response, so it cannot gate disclosure.', sigChecks));

  const verdict = combineVerdicts(properties.map((p) => p.verdict));
  const failed = properties.filter((p) => p.verdict === 'FAILED').map((p) => p.title);
  const unverified = properties.filter((p) => p.verdict === 'UNVERIFIED').map((p) => p.title);
  const headline =
    verdict === 'VERIFIED'
      ? 'Confidential execution verified: attested gateway and GPU-backed model TEE; response signed by the model deployment’s enclave key.'
      : verdict === 'FAILED'
        ? `Verification FAILED — property failed: ${failed.map((t) => `“${t}”`).join('; ')}.`
        : `Not verified — evidence missing for: ${unverified.map((t) => `“${t}”`).join('; ')}.`;

  const chosenOne = chosen.length === 1 ? chosen[0]! : null;
  const tx = transmissionOf(b, pre.ok);
  const gpus = chosenOne?.gpu.gpus ?? null;
  const models = gpus ? [...new Set(gpus.map((g) => g.hwmodel ?? 'unknown'))] : [];
  return {
    preflight: pre,
    signature: sig,
    receipt: {
      schema: 'privatetriage.receipt/v1',
      verifier: VERIFIER_ID,
      verdict,
      headline,
      captured_at: b.captured_at,
      endpoint: b.endpoint,
      model: b.model,
      nonce: { ...b.nonce, derivation: `SHA-256("${NONCE_DOMAIN}" ‖ salt ‖ request_sha256)` },
      request_sha256: b.completion?.request_sha256 ?? b.nonce.request_sha256,
      response_sha256: b.completion?.response_sha256 ?? null,
      chat_id: chatId,
      transmission: tx.state,
      transmission_detail: tx.detail,
      disclosed: tx.state !== 'not_sent',
      signer: sig ? { kind: sig.kind, algo: sig.signer?.signing_algo ?? null, address: sig.signer?.signing_address ?? null } : null,
      properties,
      gateway: pre.gateway
        ? {
            signing_address: pre.gateway.identity?.signing_address ?? null,
            signing_algo: pre.gateway.identity?.signing_algo ?? null,
            app_id: pre.gateway.app?.app_id ?? null,
            os_image_hash: pre.gateway.app?.os_image_hash ?? null,
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
            app_id: chosenOne.report.app?.app_id ?? null,
            os_image_hash: chosenOne.report.app?.os_image_hash ?? null,
            compose_hash: chosenOne.report.composeHash,
            image_digests: chosenOne.report.imageDigests,
            quote: chosenOne.report.quote ? quoteFactsSummary(chosenOne.report.quote) : null,
            // Only NVIDIA-signed, inventory-reconciled facts; null unless every GPU check passed.
            gpu: gpus
              ? {
                  count: gpus.length,
                  arch: models.join(' + '),
                  source: 'NVIDIA-signed per-GPU claims, matched to the reported device certificates',
                  driver_versions: [...new Set(gpus.map((g) => g.driver_version).filter((x): x is string => x !== null))],
                  nras_iat: chosenOne.gpu.claims?.iat ?? null,
                  nras_jti: chosenOne.gpu.claims?.jti ?? null,
                  nras_eat_nonce: chosenOne.gpu.claims?.eat_nonce ?? null,
                }
              : null,
          }
        : { candidates_returned: pre.candidates.length, candidates_verified: pre.verifiedModelSigners.length },
      not_proven: NOT_PROVEN,
      trust_assumptions: TRUST_ASSUMPTIONS,
    },
  };
}

export { DEFAULT_POLICY };
