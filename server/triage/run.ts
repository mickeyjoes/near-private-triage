// One confidential triage: hygiene scan → attest → (gated) disclose → verify → interpret.
import type { AnalystNote } from '../../shared/annotations.ts';
import { type HygieneFinding, scanReport } from '../../shared/hygiene.ts';
import { runConfidentialCompletion, type Stage } from '../near/confidentialCompletion.ts';
import { evaluateBundle, type EvidenceBundle, type Receipt } from '../verifier/evidence.ts';
import type { Provenance } from './replay.ts';
import { buildTriageRequest, DEFAULT_MODEL, interpretResponse, type TriageOutcome } from './triage.ts';

export interface StageEvent {
  stage: Stage;
  detail: string;
  t_ms: number;
}

export interface TriageRun {
  model: string;
  marker: string;
  hygiene: HygieneFinding[];
  stages: StageEvent[];
  receipt: Receipt;
  outcome: TriageOutcome | null;
  analyst_notes: AnalystNote[];
  provenance: Provenance;
  /** Full evidence INCLUDING the exact request/response bytes (contains the report). Never persisted server-side. */
  evidence: EvidenceBundle;
  duration_ms: number;
}

export async function runTriage(opts: {
  apiKey: string;
  title: string;
  body: string;
  model?: string;
  onStage?: (e: StageEvent) => void;
}): Promise<TriageRun> {
  const model = opts.model ?? DEFAULT_MODEL;
  const hygiene = scanReport(`${opts.title}\n${opts.body}`);
  const req = buildTriageRequest(opts.title, opts.body, model);
  const t0 = Date.now();
  const stages: StageEvent[] = [];
  const result = await runConfidentialCompletion({
    apiKey: opts.apiKey,
    model,
    requestBody: req.bytes,
    onStage: (stage, detail) => {
      const e = { stage, detail, t_ms: Date.now() - t0 };
      stages.push(e);
      opts.onStage?.(e);
    },
  });
  const c = result.bundle.completion;
  if (c) {
    c.request_b64 = result.requestBytes.toString('base64');
    if (result.responseBytes) c.response_b64 = result.responseBytes.toString('base64');
  }
  const outcome = c ? interpretResponse(c.status, result.responseBytes) : null;
  // Re-evaluate with the exact bytes attached, so the returned receipt is exactly
  // what offline re-verification of this evidence bundle will reproduce.
  const { receipt } = evaluateBundle(result.bundle);
  return {
    model,
    marker: req.marker,
    hygiene,
    stages,
    receipt,
    outcome,
    analyst_notes: [],
    provenance: {
      kind: 'live',
      captured_at: result.bundle.captured_at,
      request_sha256: c?.request_sha256 ?? null,
      response_sha256: c?.response_sha256 ?? null,
      analysis: c ? 'Parsed from the response bytes received in this run (the bytes whose hash the receipt checks).' : 'No response was received.',
      request: 'Built by this backend from the title and body you submitted, plus the system prompt, a random report marker, the model and parameters.',
      timings: 'Measured by this backend.',
    },
    evidence: result.bundle,
    duration_ms: Date.now() - t0,
  };
}
