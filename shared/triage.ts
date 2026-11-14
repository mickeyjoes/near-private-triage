// Triage output contract shared by backend (validation) and frontend (rendering).
// The model is asked for exactly this JSON shape (structured outputs), and the
// backend re-validates it: model output is never trusted to match the schema.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'undetermined';
export type Validity = 'likely_valid' | 'needs_more_information' | 'likely_invalid';
export type Confidence = 'high' | 'medium' | 'low';
export type EvidenceQuality = 'strong' | 'partial' | 'weak';
export type Priority = 'immediate' | 'short_term' | 'long_term';

export interface Triage {
  title: string;
  summary: string;
  vulnerability_class: string;
  cwe: string[];
  validity: Validity;
  severity: Severity;
  cvss_v31_vector: string | null;
  cvss_v31_score: number | null;
  confidence: Confidence;
  confidence_rationale: string;
  affected_components: string[];
  attack_preconditions: string[];
  impact: string;
  evidence_quality: EvidenceQuality;
  reproduction_assessment: string;
  missing_information: string[];
  questions_for_reporter: string[];
  recommended_actions: { priority: Priority; action: string }[];
  injection_detected: boolean;
  injection_notes: string;
}

const str = { type: 'string' } as const;
const strList = { type: 'array', items: { type: 'string' } } as const;

export const TRIAGE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: [
    'title',
    'summary',
    'vulnerability_class',
    'cwe',
    'validity',
    'severity',
    'cvss_v31_vector',
    'cvss_v31_score',
    'confidence',
    'confidence_rationale',
    'affected_components',
    'attack_preconditions',
    'impact',
    'evidence_quality',
    'reproduction_assessment',
    'missing_information',
    'questions_for_reporter',
    'recommended_actions',
    'injection_detected',
    'injection_notes',
  ],
  properties: {
    title: str,
    summary: str,
    vulnerability_class: str,
    cwe: strList,
    validity: { type: 'string', enum: ['likely_valid', 'needs_more_information', 'likely_invalid'] },
    severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'informational', 'undetermined'] },
    cvss_v31_vector: { type: ['string', 'null'] },
    cvss_v31_score: { type: ['number', 'null'] },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    confidence_rationale: str,
    affected_components: strList,
    attack_preconditions: strList,
    impact: str,
    evidence_quality: { type: 'string', enum: ['strong', 'partial', 'weak'] },
    reproduction_assessment: str,
    missing_information: strList,
    questions_for_reporter: strList,
    recommended_actions: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['priority', 'action'],
        properties: { priority: { type: 'string', enum: ['immediate', 'short_term', 'long_term'] }, action: str },
      },
    },
    injection_detected: { type: 'boolean' },
    injection_notes: str,
  },
} as const;

export interface ValidationResult {
  ok: boolean;
  triage: Triage | null;
  errors: string[];
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Strict structural validation of model output against TRIAGE_SCHEMA (no coercion). */
export function validateTriage(value: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isObj(value)) return { ok: false, triage: null, errors: ['output is not a JSON object'] };
  const props = TRIAGE_SCHEMA.properties as Record<string, Record<string, unknown>>;
  for (const key of TRIAGE_SCHEMA.required) {
    if (!(key in value)) errors.push(`missing field "${key}"`);
  }
  for (const key of Object.keys(value)) {
    if (!(key in props)) errors.push(`unexpected field "${key}"`);
  }
  for (const [key, spec] of Object.entries(props)) {
    if (!(key in value)) continue;
    const v = value[key];
    const t = spec.type;
    const types = Array.isArray(t) ? t : [t];
    const typeOk = types.some((ty) =>
      ty === 'null' ? v === null : ty === 'array' ? Array.isArray(v) : ty === 'number' ? typeof v === 'number' && Number.isFinite(v) : typeof v === ty,
    );
    if (!typeOk) {
      errors.push(`field "${key}" has wrong type`);
      continue;
    }
    if (Array.isArray(spec.enum) && !spec.enum.includes(v)) errors.push(`field "${key}" has invalid value ${JSON.stringify(v)}`);
    if (Array.isArray(v)) {
      const items = spec.items as Record<string, unknown>;
      v.forEach((item, i) => {
        if (items.type === 'string' && typeof item !== 'string') errors.push(`${key}[${i}] is not a string`);
        if (items.type === 'object') {
          // Nested objects are as strict as the top level (additionalProperties: false).
          const allowed = Object.keys((items.properties as Record<string, unknown>) ?? {});
          if (
            !isObj(item) ||
            typeof item.action !== 'string' ||
            !['immediate', 'short_term', 'long_term'].includes(item.priority as string) ||
            Object.keys(item).some((k) => !allowed.includes(k))
          ) {
            errors.push(`${key}[${i}] is malformed`);
          }
        }
      });
    }
  }
  return errors.length ? { ok: false, triage: null, errors } : { ok: true, triage: value as unknown as Triage, errors };
}

// ---------------------------------------------------------------------------
// CVSS v3.1 base score (FIRST specification, section 7.1 + Appendix A roundup).
// Used to check the model's stated score against its own vector deterministically.

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

function roundup(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export interface CvssResult {
  score: number;
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
}

export function cvss31(vector: string): CvssResult | null {
  const m = /^CVSS:3\.[01]\/AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([HLN])\/I:([HLN])\/A:([HLN])$/.exec(vector.trim());
  if (!m) return null;
  const [, av, ac, pr, ui, s, c, i, a] = m as unknown as [string, 'N' | 'A' | 'L' | 'P', 'L' | 'H', 'N' | 'L' | 'H', 'N' | 'R', 'U' | 'C', 'H' | 'L' | 'N', 'H' | 'L' | 'N', 'H' | 'L' | 'N'];
  const changed = s === 'C';
  const prW = pr === 'N' ? 0.85 : pr === 'L' ? (changed ? 0.68 : 0.62) : changed ? 0.5 : 0.27;
  const iss = 1 - (1 - W.CIA[c]) * (1 - W.CIA[i]) * (1 - W.CIA[a]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * W.AV[av] * W.AC[ac] * prW * W.UI[ui];
  let score = 0;
  if (impact > 0) score = changed ? roundup(Math.min(1.08 * (impact + exploitability), 10)) : roundup(Math.min(impact + exploitability, 10));
  const severity = score === 0 ? 'none' : score < 4 ? 'low' : score < 7 ? 'medium' : score < 9 ? 'high' : 'critical';
  return { score, severity };
}

export interface TriageCheck {
  id: string;
  status: 'ok' | 'warn';
  detail: string;
}

/** Deterministic consistency checks on the model's assessment (not a correctness proof). */
export function consistencyChecks(t: Triage): TriageCheck[] {
  const out: TriageCheck[] = [];
  if (t.cvss_v31_vector) {
    const r = cvss31(t.cvss_v31_vector);
    if (!r) out.push({ id: 'cvss_vector', status: 'warn', detail: `CVSS vector "${t.cvss_v31_vector}" is not a valid CVSS 3.1 base vector.` });
    else {
      out.push(
        t.cvss_v31_score !== null && Math.abs(r.score - t.cvss_v31_score) < 0.05
          ? { id: 'cvss_score', status: 'ok', detail: `Stated score ${t.cvss_v31_score.toFixed(1)} matches the score computed from the vector.` }
          : { id: 'cvss_score', status: 'warn', detail: `Model stated ${t.cvss_v31_score ?? 'no score'}, but the vector computes to ${r.score.toFixed(1)}. Computed value shown.` },
      );
      const sev = t.severity;
      const match = sev === r.severity || (sev === 'informational' && r.severity === 'none');
      out.push(
        match
          ? { id: 'cvss_severity', status: 'ok', detail: `Severity "${sev}" agrees with the CVSS rating (${r.severity}).` }
          : { id: 'cvss_severity', status: 'warn', detail: `Severity "${sev}" differs from the CVSS rating of its own vector (${r.severity}).` },
      );
    }
  } else if (t.severity !== 'undetermined' && t.severity !== 'informational') {
    out.push({ id: 'cvss_vector', status: 'warn', detail: 'Severity given without a CVSS vector to justify it.' });
  }
  if (t.validity === 'needs_more_information' && t.questions_for_reporter.length === 0) {
    out.push({ id: 'questions', status: 'warn', detail: 'Marked as needing more information but asks the reporter nothing.' });
  }
  if (t.confidence === 'high' && t.evidence_quality === 'weak') {
    out.push({ id: 'confidence', status: 'warn', detail: 'High confidence despite weak evidence.' });
  }
  return out;
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'informational', 'undetermined'];
