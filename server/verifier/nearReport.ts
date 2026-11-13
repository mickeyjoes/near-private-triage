// Checks for one NEAR-operated dstack attestation report (gateway or model),
// implementing https://docs.near.ai/cloud/verification/reference/quote-nonce-signer
// as a list of explicit, individually reported checks. The verified quote is the
// source of truth; HTTP fields are only compared against it.
import { EvidenceError, hexToBytes, isRecord, jsonOrValue, sameBytes, sha256, sha384, toHex } from './bytes.ts';
import { type Collateral, type QuoteFacts, verifyQuote } from './tdx.ts';
import { type MeasurementPolicy, PINNED_MEASUREMENTS, type Role } from './measurements.ts';
import { CheckList, type SignerIdentity } from './types.ts';

export interface ReportPolicy {
  acceptedTcbStatuses: string[];
  measurements: MeasurementPolicy;
}

export const DEFAULT_POLICY: ReportPolicy = { acceptedTcbStatuses: ['UpToDate'], measurements: PINNED_MEASUREMENTS };

export interface ReportCheckInput {
  report: unknown;
  nonceHex: string;
  collateral: Collateral | null;
  nowSecs: number;
  policy?: ReportPolicy;
  /** Which NEAR workload this report must be (gateway or model server). */
  role: Role;
  /** SHA-256 of the peer certificate SPKI observed on the SAME TLS connection (gateway only). */
  peerSpkiSha256?: string;
}

export interface ReportCheckResult {
  checks: CheckList;
  identity: SignerIdentity | null;
  quote: QuoteFacts | null;
  composeHash: string | null;
  appCompose: string | null;
  imageDigests: string[];
  tlsCertFingerprint: string | null;
  /** Authenticated (RTMR3-replayed) dstack app events. */
  app: { app_id: string | null; os_image_hash: string | null } | null;
}

const IDENTITY_BYTES = { ecdsa: 20, ed25519: 32 } as const;

/** Replays IMR-3 events; returns the register value and the event payloads by name. */
export function replayRtmr3(eventLog: unknown): { rtmr3: Buffer; events: Map<string, string> } {
  const events = jsonOrValue(eventLog, 'event_log');
  if (!Array.isArray(events)) throw new EvidenceError('malformed', 'event_log is not a list');
  const named = new Map<string, string>();
  let rtmr3: Buffer = Buffer.alloc(48);
  for (const ev of events) {
    if (!isRecord(ev)) throw new EvidenceError('malformed', 'event_log entry is not an object');
    if (ev.imr !== 3) continue;
    if (typeof ev.event_type !== 'number' || typeof ev.event !== 'string') {
      throw new EvidenceError('malformed', 'event_log entry lacks event_type/event');
    }
    const et = Buffer.alloc(4);
    et.writeUInt32LE(ev.event_type >>> 0);
    const payload = hexToBytes(ev.event_payload ?? '', `event_payload(${ev.event})`);
    const digest = sha384(et, ':', Buffer.from(ev.event, 'utf8'), ':', payload);
    if (typeof ev.digest === 'string' && ev.digest !== '') {
      if (!sameBytes(hexToBytes(ev.digest, 'event digest'), digest)) {
        throw new EvidenceError('mismatch', `event_log digest mismatch for event "${ev.event}"`);
      }
    }
    rtmr3 = sha384(rtmr3, digest);
    if (named.has(ev.event)) named.set(ev.event, '\u0000duplicate');
    else named.set(ev.event, toHex(payload));
  }
  return { rtmr3, events: named };
}

export function extractImageDigests(appCompose: string): string[] {
  const out = new Set<string>();
  for (const m of appCompose.matchAll(/@sha256:([0-9a-f]{64})/g)) out.add(`sha256:${m[1]}`);
  return [...out];
}

function parseIdentity(report: Record<string, unknown>): SignerIdentity {
  const algo = report.signing_algo;
  if (algo !== 'ecdsa' && algo !== 'ed25519') {
    throw new EvidenceError('unsupported', `unsupported signing_algo ${JSON.stringify(algo)}`);
  }
  const bytes = hexToBytes(report.signing_address, 'signing_address', IDENTITY_BYTES[algo]);
  return { signing_algo: algo, signing_address: (algo === 'ecdsa' ? '0x' : '') + toHex(bytes) };
}

export function checkNearReport(input: ReportCheckInput): ReportCheckResult {
  const policy = input.policy ?? DEFAULT_POLICY;
  const c = new CheckList();
  const result: ReportCheckResult = {
    checks: c,
    identity: null,
    quote: null,
    composeHash: null,
    appCompose: null,
    imageDigests: [],
    tlsCertFingerprint: null,
    app: null,
  };
  const r = input.report;
  if (!isRecord(r)) {
    c.unavailable('report_present', 'Attestation report present', 'No attestation report was returned.');
    return result;
  }

  // 1. Nonce format (client-side sanity; a non-32-byte nonce can never be fresh evidence).
  let nonce: Buffer;
  try {
    nonce = hexToBytes(input.nonceHex, 'client nonce', 32);
  } catch (e) {
    c.fail('nonce_format', 'Client nonce is 32 random bytes', (e as Error).message);
    return result;
  }

  // 2. Quote verification (Intel DCAP chain, signatures, TCB).
  if (typeof r.intel_quote !== 'string' || r.intel_quote.length === 0) {
    c.unavailable('quote_verified', 'Intel TDX quote verifies', 'Report has no intel_quote.');
    return result;
  }
  if (!input.collateral) {
    c.unavailable('quote_verified', 'Intel TDX quote verifies', 'Intel collateral unavailable; quote not checked.');
    return result;
  }
  let q: QuoteFacts;
  try {
    q = verifyQuote(r.intel_quote, input.collateral, input.nowSecs);
  } catch (e) {
    c.fail('quote_verified', 'Intel TDX quote verifies', (e as Error).message);
    return result;
  }
  result.quote = q;
  c.pass('quote_verified', 'Intel TDX quote verifies', `DCAP signature chain to Intel root verified (${q.reportType}).`);
  c.expect(
    policy.acceptedTcbStatuses.includes(q.tcbStatus),
    'tcb_status',
    'Platform TCB status accepted by policy',
    `TCB status ${q.tcbStatus}${q.advisoryIds.length ? `; advisories ${q.advisoryIds.join(', ')}` : '; no advisories'}.`,
    `TCB status ${q.tcbStatus} is not in the accepted set [${policy.acceptedTcbStatuses.join(', ')}]; advisories: ${q.advisoryIds.join(', ') || 'none'}.`,
  );
  c.expect(!q.debug, 'not_debug', 'TD is not in debug mode', 'TD_ATTRIBUTES debug bit is 0.', 'TD_ATTRIBUTES debug bit is set: memory is inspectable by the host.');

  // 3. Signer identity + nonce binding in report_data (read from the verified quote).
  let identity: SignerIdentity;
  try {
    identity = parseIdentity(r);
  } catch (e) {
    const code = e instanceof EvidenceError ? e.code : 'malformed';
    if (code === 'unsupported') c.unavailable('signer_identity', 'Signer identity well-formed', (e as Error).message);
    else c.fail('signer_identity', 'Signer identity well-formed', (e as Error).message);
    return result;
  }
  const idBytes = hexToBytes(identity.signing_address, 'signing_address');
  let bound: Buffer;
  let fp: Buffer | null = null;
  try {
    if (r.tls_cert_fingerprint !== undefined && r.tls_cert_fingerprint !== null && r.tls_cert_fingerprint !== '') {
      fp = hexToBytes(r.tls_cert_fingerprint, 'tls_cert_fingerprint', 32);
      result.tlsCertFingerprint = toHex(fp);
      bound = sha256(idBytes, fp);
    } else {
      bound = Buffer.concat([idBytes, Buffer.alloc(32 - idBytes.length)]);
    }
  } catch (e) {
    c.fail('report_data_binding', 'Quote binds signer and nonce', (e as Error).message);
    return result;
  }
  const expectedRd = Buffer.concat([bound, nonce]);
  const signerBound = sameBytes(q.reportData.subarray(0, 32), bound);
  const nonceBound = sameBytes(q.reportData.subarray(32, 64), nonce);
  c.expect(
    signerBound,
    'signer_bound',
    'Quote binds the signing key',
    fp
      ? `report_data[0:32] = SHA-256(signer ‖ TLS SPKI fingerprint) for ${identity.signing_address}.`
      : `report_data[0:32] = ${identity.signing_address} (zero-padded).`,
    `report_data[0:32] does not commit to signer ${identity.signing_address}.`,
  );
  c.expect(
    nonceBound,
    'nonce_bound',
    'Quote embeds our fresh nonce',
    'report_data[32:64] equals the client-generated nonce: the quote was produced after our challenge.',
    'report_data[32:64] is not our nonce: evidence is stale, replayed, or for another request.',
  );
  c.expect(
    typeof r.request_nonce === 'string' && r.request_nonce.toLowerCase() === input.nonceHex.toLowerCase(),
    'nonce_echo',
    'Echoed request_nonce matches',
    'HTTP request_nonce equals our nonce.',
    'HTTP request_nonce is missing or differs from our nonce.',
  );
  if (r.report_data !== undefined) {
    let echoed: Buffer | null = null;
    try {
      echoed = hexToBytes(r.report_data, 'report_data');
    } catch {
      echoed = null;
    }
    c.expect(
      echoed !== null && sameBytes(echoed, q.reportData) && sameBytes(q.reportData, expectedRd),
      'report_data_echo',
      'Echoed report_data matches quote',
      'HTTP report_data equals the quote report_data.',
      'HTTP report_data differs from the verified quote.',
    );
  }
  result.identity = identity;

  // 4. Configuration measurement: MRCONFIGID = 01 ‖ SHA-256(app_compose) ‖ 0^15.
  try {
    if (!isRecord(r.info)) throw new EvidenceError('malformed', 'info missing');
    const tcb = jsonOrValue(r.info.tcb_info, 'tcb_info');
    if (!isRecord(tcb) || typeof tcb.app_compose !== 'string') throw new EvidenceError('malformed', 'tcb_info.app_compose missing');
    const compose = tcb.app_compose;
    const h = sha256(Buffer.from(compose, 'utf8'));
    const expected = Buffer.concat([Buffer.from([1]), h, Buffer.alloc(15)]);
    result.composeHash = toHex(h);
    result.appCompose = compose;
    result.imageDigests = extractImageDigests(compose);
    c.expect(
      sameBytes(q.mrConfigId, expected),
      'mrconfig',
      'Measured config matches app_compose',
      `MRCONFIGID = 01 ‖ SHA-256(app_compose) = ${toHex(h).slice(0, 16)}…`,
      'MRCONFIGID does not commit to the returned app_compose.',
    );
  } catch (e) {
    c.fail('mrconfig', 'Measured config matches app_compose', (e as Error).message);
  }

  // 5. RTMR3 event-log replay: authenticates the logged app events.
  let events: Map<string, string> | null = null;
  try {
    const replay = replayRtmr3(r.event_log);
    if (
      c.expect(
        sameBytes(replay.rtmr3, q.rtMr3),
        'rtmr3',
        'Event log replays to RTMR3',
        'Replaying the IMR-3 event log reproduces the quote’s RTMR3, so the logged app events are the measured ones.',
        'Replayed event log does not match quote RTMR3.',
      )
    ) {
      events = replay.events;
    }
  } catch (e) {
    c.fail('rtmr3', 'Event log replays to RTMR3', (e as Error).message);
  }
  if (events) result.app = { app_id: events.get('app-id') ?? null, os_image_hash: events.get('os-image-hash') ?? null };
  if (events && result.composeHash) {
    c.expect(
      events.get('compose-hash') === result.composeHash,
      'compose_event',
      'Measured compose-hash event matches app_compose',
      'RTMR3 compose-hash event = SHA-256(app_compose) = MRCONFIGID payload.',
      'RTMR3 compose-hash event differs from SHA-256(app_compose).',
    );
  }

  // 6. Workload policy: NEAR's pinned dstack OS image and app identity.
  const pol = policy.measurements;
  const hex = (b: Buffer) => toHex(b);
  const os = pol.os.find(
    (p) => p.role === input.role && p.mrtd === hex(q.mrTd) && p.rtmr1 === hex(q.rtMr1) && p.rtmr2 === hex(q.rtMr2) && (events === null || events.get('os-image-hash') === p.os_image_hash),
  );
  if (os) c.pass('os_image', 'Pinned NEAR dstack OS image', `${os.name}: MRTD, RTMR1, RTMR2 and os-image-hash match.`);
  else
    c.unavailable(
      'os_image',
      'Pinned NEAR dstack OS image',
      `Unrecognized ${input.role} OS measurements (MRTD ${hex(q.mrTd).slice(0, 16)}…, RTMR2 ${hex(q.rtMr2).slice(0, 16)}…). Not in the pinned list; review with \`npm run pin\`.`,
    );
  if (events) {
    const appId = events.get('app-id') ?? '';
    const app = pol.apps.find((a) => a.role === input.role && a.app_id === appId);
    const kms = pol.mr_kms.includes(events.get('mr-kms') ?? '');
    let provider = '';
    try {
      provider = Buffer.from(events.get('key-provider') ?? '', 'hex').toString('utf8');
    } catch {
      provider = '';
    }
    const kp = pol.key_providers.includes(provider);
    if (app && kms && kp) c.pass('app_identity', 'Pinned NEAR app identity', `${app.name}: app-id ${appId.slice(0, 12)}…, KMS and key provider match.`);
    else
      c.unavailable(
        'app_identity',
        'Pinned NEAR app identity',
        `${!app ? `Unrecognized ${input.role} app-id ${appId.slice(0, 12) || '(none)'}…. ` : ''}${!kms ? 'Unrecognized KMS measurement. ' : ''}${!kp ? 'Unrecognized key provider. ' : ''}Review with \`npm run pin\`.`,
      );
  } else {
    c.unavailable('app_identity', 'Pinned NEAR app identity', 'App events not authenticated (event log did not replay).');
  }

  // 7. Optional same-connection TLS binding (gateway).
  if (input.peerSpkiSha256 !== undefined) {
    const ok = fp !== null && signerBound && fp.toString('hex') === input.peerSpkiSha256.toLowerCase();
    if (fp === null) {
      c.unavailable('tls_spki', 'TLS key is inside the attested TEE', 'Report has no tls_cert_fingerprint.');
    } else {
      c.expect(
        ok,
        'tls_spki',
        'TLS key is inside the attested TEE',
        'SPKI of the certificate on this very connection equals the quote-bound fingerprint.',
        'Peer certificate SPKI differs from the quote-bound fingerprint.',
      );
    }
  }
  return result;
}
