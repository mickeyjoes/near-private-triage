// Derive what the guided demo displays for a RECORDED run from authenticated
// bytes only (audit finding F4).
//
// The displayed analysis is parsed from the response bytes whose SHA-256 the model
// enclave signed; the request bytes must be byte-identical to the triage request
// for the named fictional sample. Saved derived data (run.json) is treated as
// untrusted: if it disagrees with the authenticated bytes, the build fails.
// Stage timings in run.json are backend-recorded display metadata, never signed.
import { type AnalystNote, notesFor } from '../../shared/annotations.ts';
import { type HygieneFinding, scanReport } from '../../shared/hygiene.ts';
import type { SampleReport } from '../../shared/samples.ts';
import { sha256Hex } from '../verifier/bytes.ts';
import { evaluateBundle, type EvidenceBundle, type Receipt } from '../verifier/evidence.ts';
import type { StageEvent } from './run.ts';
import { interpretResponse, triageRequestBytes, type TriageOutcome } from './triage.ts';

export class ReplayIntegrityError extends Error {}

/** run.json as saved by scripts/record-samples.ts. Untrusted. */
export interface SavedRun {
  sample_id?: string;
  model?: string;
  marker?: string;
  hygiene?: unknown;
  stages?: StageEvent[];
  outcome?: unknown;
  duration_ms?: number;
}

export interface Provenance {
  kind: 'recorded' | 'live';
  captured_at: string;
  request_sha256: string | null;
  response_sha256: string | null;
  analysis: string;
  request: string;
  timings: string;
}

export interface RecordedRun {
  model: string;
  marker: string;
  hygiene: HygieneFinding[];
  stages: StageEvent[];
  duration_ms: number;
  outcome: TriageOutcome;
  receipt: Receipt;
  analyst_notes: AnalystNote[];
  provenance: Provenance;
}

const MARKER = /^Triage the following vulnerability report\.\n\n<<<REPORT ([0-9a-f]{12})>>>\n/;

function stringsIn(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.flatMap(stringsIn);
  if (v && typeof v === 'object') return Object.values(v).flatMap(stringsIn);
  return [];
}

export function deriveRecordedRun(sample: SampleReport, bundle: EvidenceBundle, saved: SavedRun): RecordedRun {
  const fail = (m: string): never => {
    throw new ReplayIntegrityError(`${sample.id}: ${m}`);
  };
  const c = bundle.completion;
  if (!c?.request_b64 || !c.response_b64) return fail('recorded evidence lacks the exact request/response bytes');
  const req = Buffer.from(c.request_b64, 'base64');
  const resp = Buffer.from(c.response_b64, 'base64');
  if (sha256Hex(req) !== c.request_sha256 || c.request_sha256 !== bundle.nonce.request_sha256) fail('request bytes do not hash to the signed, challenged request hash');
  if (sha256Hex(resp) !== c.response_sha256) fail('response bytes do not hash to the signed response hash');
  const { receipt } = evaluateBundle(bundle);
  if (receipt.verdict !== 'VERIFIED') fail(`receipt is ${receipt.verdict}, not VERIFIED: ${receipt.headline}`);

  // Association: the signed request is exactly the triage request for this sample.
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(req.toString('utf8'));
  } catch {
    fail('request bytes are not JSON');
  }
  const messages = (parsed as { messages?: { content?: unknown }[] })?.messages;
  const user = Array.isArray(messages) ? messages[1]?.content : undefined;
  const m = typeof user === 'string' ? MARKER.exec(user) : null;
  if (!m) return fail('request does not carry a report marker');
  const marker = m[1]!;
  if (!req.equals(triageRequestBytes(marker, sample.title, sample.body, bundle.model))) {
    fail(`signed request is not the triage request for sample "${sample.id}"`);
  }

  // The analysis comes from the signed bytes; saved derived data must agree.
  const outcome = interpretResponse(c.status, resp);
  if (JSON.stringify(outcome) !== JSON.stringify(saved.outcome)) fail('saved analysis (run.json) differs from the analysis parsed from the signed response bytes');
  if (saved.marker !== marker) fail('saved marker differs from the marker in the signed request');
  if (saved.model !== bundle.model) fail('saved model differs from the evidence');
  if (saved.sample_id !== undefined && saved.sample_id !== sample.id) fail('saved sample id differs');
  const hygiene = scanReport(`${sample.title}\n${sample.body}`);
  if (JSON.stringify(hygiene) !== JSON.stringify(saved.hygiene)) fail('saved hygiene findings differ from a fresh local scan of the sample');

  // Human corrections must quote text that really is in the signed output.
  const notes = notesFor(c.response_sha256);
  const said = stringsIn(outcome.triage);
  for (const n of notes) if (!said.some((x) => x.includes(n.quote))) fail(`analyst note ${n.id} quotes text that is not in the signed output`);

  return {
    model: bundle.model,
    marker,
    hygiene,
    stages: Array.isArray(saved.stages) ? saved.stages : [],
    duration_ms: typeof saved.duration_ms === 'number' ? saved.duration_ms : 0,
    outcome,
    receipt,
    analyst_notes: notes,
    provenance: {
      kind: 'recorded',
      captured_at: bundle.captured_at,
      request_sha256: c.request_sha256,
      response_sha256: c.response_sha256,
      analysis: 'Parsed from the signed response bytes when this site was built; the build fails if saved data disagrees.',
      request: `Byte-identical to the triage request for the fictional sample "${sample.id}" (report marker ${marker}).`,
      timings: 'Stage timings are backend-recorded display data, not signed.',
    },
  };
}
