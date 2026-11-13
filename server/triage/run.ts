// One confidential triage: hygiene scan → attest → (gated) disclose → verify → interpret.
import { type HygieneFinding, scanReport } from '../../shared/hygiene.ts';
import { runConfidentialCompletion, type Stage } from '../near/confidentialCompletion.ts';
import type { EvidenceBundle, Receipt } from '../verifier/evidence.ts';
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
  return {
    model,
    marker: req.marker,
    hygiene,
    stages,
    receipt: result.receipt,
    outcome,
    evidence: result.bundle,
    duration_ms: Date.now() - t0,
  };
}
