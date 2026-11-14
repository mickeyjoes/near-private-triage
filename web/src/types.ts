import type { AnalystNote } from '../../shared/annotations.ts';
import type { HygieneFinding } from '../../shared/hygiene.ts';
import type { SampleReport } from '../../shared/samples.ts';
import type { Triage, TriageCheck } from '../../shared/triage.ts';

export type Verdict = 'VERIFIED' | 'FAILED' | 'UNVERIFIED';
export type CheckStatus = 'pass' | 'fail' | 'unavailable';

export interface Check {
  id: string;
  label: string;
  status: CheckStatus;
  detail: string;
}

export interface Property {
  id: string;
  title: string;
  verdict: Verdict;
  statement: string;
  checks: Check[];
}

export interface QuoteSummary {
  tcb_status?: string;
  advisory_ids?: string[];
  mr_td?: string;
  rtmr3?: string;
  report_data?: string;
}

export interface Receipt {
  schema: string;
  verifier: string;
  verdict: Verdict;
  headline: string;
  captured_at: string;
  endpoint: string;
  model: string;
  nonce: { salt: string; request_sha256: string; value: string; derivation: string };
  request_sha256: string | null;
  response_sha256: string | null;
  chat_id: string | null;
  transmission: 'not_sent' | 'may_have_been_sent' | 'sent';
  transmission_detail: string;
  disclosed: boolean;
  signer: { kind: string | null; algo: string | null; address: string | null } | null;
  properties: Property[];
  gateway: {
    signing_address?: string | null;
    app_id?: string | null;
    os_image_hash?: string | null;
    tls_spki_sha256?: string | null;
    compose_hash?: string | null;
    image_digests?: string[];
    quote?: QuoteSummary | null;
  } | null;
  model_tee: {
    signing_address?: string | null;
    app_id?: string | null;
    os_image_hash?: string | null;
    compose_hash?: string | null;
    image_digests?: string[];
    candidates_returned?: number;
    candidates_verified?: number;
    quote?: QuoteSummary | null;
    gpu?: { count: number; arch: string; source: string; driver_versions: string[]; nras_iat: number | null; nras_jti: string | null; nras_eat_nonce: string | null } | null;
  } | null;
  not_proven: string[];
  trust_assumptions: string[];
}

export interface StageEvent {
  stage: string;
  detail: string;
  t_ms: number;
}

export interface TriageOutcome {
  status: 'ok' | 'malformed' | 'error';
  triage: Triage | null;
  reasoning: string | null;
  finishReason: string | null;
  usage: { prompt_tokens: number; completion_tokens: number; reasoning_tokens: number } | null;
  errors: string[];
  consistency: TriageCheck[];
}

export interface EvidenceBundle {
  schema: string;
  captured_at: string;
  model: string;
  completion: { request_b64?: string; response_b64?: string; [k: string]: unknown } | null;
  [k: string]: unknown;
}

export interface TriageRun {
  model: string;
  marker: string;
  hygiene: HygieneFinding[];
  stages: StageEvent[];
  receipt: Receipt;
  outcome: TriageOutcome | null;
  analyst_notes?: AnalystNote[];
  provenance?: {
    kind: 'recorded' | 'live';
    captured_at: string;
    request_sha256: string | null;
    response_sha256: string | null;
    analysis: string;
    request: string;
    timings: string;
  };
  evidence?: EvidenceBundle;
  evidence_file?: string;
  duration_ms: number;
}

export interface TamperResult {
  id: string;
  title: string;
  attack: string;
  expect: Verdict;
  property: string;
  check: string;
  verdict: Verdict;
  headline: string;
  properties: { id: string; title: string; verdict: Verdict; checks: Check[] }[];
}

export interface DemoData {
  schema: string;
  note: string;
  samples: SampleReport[];
  runs: Record<string, TriageRun>;
  gate1: { receipt: Receipt; evidence_file: string };
  refusals: { model: string; captured_at: string; blocked_reason: string | null; receipt: Receipt }[];
  outages: { id: string; model: string; captured_at: string; blocked_reason: string | null; transmission: Receipt['transmission']; disclosed: boolean; verdict: Verdict }[];
  tamper: { base: string; results: TamperResult[] };
}

export interface BackendStatus {
  live: boolean;
  key_configured: boolean;
  default_model: string;
  models: string[];
  runs_remaining: number;
  busy: boolean;
}

export type { AnalystNote, HygieneFinding, SampleReport, Triage, TriageCheck };
