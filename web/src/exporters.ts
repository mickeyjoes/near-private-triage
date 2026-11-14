// Client-side exports. Everything is generated in the browser from data already
// returned to the submitter; nothing is uploaded anywhere.
import { cvss31 } from '../../shared/triage.ts';
import { attribution } from './attribution.ts';
import type { EvidenceBundle, Receipt, TriageRun } from './types.ts';

export function download(name: string, content: string, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48) || 'report';

export function verdictPhrase(r: Receipt): string {
  if (r.verdict === 'VERIFIED') return 'Confidential execution verified (execution only — the analysis itself is AI-generated and may be wrong)';
  if (r.verdict === 'FAILED') return 'Verification FAILED — do not trust this output';
  if (r.transmission === 'not_sent') return 'Not verified — the report was not sent';
  if (r.transmission === 'may_have_been_sent') return 'Not verified — the report MAY HAVE BEEN SENT, but no response was received';
  return 'Not verified — the report was sent, but the evidence is incomplete';
}

/** Model output is untrusted: neutralise HTML and Markdown images/links so a viewer cannot be made to fetch anything. */
export function untrusted(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/!\[/g, '!\\[').replace(/\]\(/g, ']\\(');
}

/** Evidence without the report/response bytes: still verifies (signature is over hashes). */
export function shareableEvidence(b: EvidenceBundle): EvidenceBundle {
  const copy = structuredClone(b);
  if (copy.completion) {
    delete copy.completion.request_b64;
    delete copy.completion.response_b64;
  }
  return copy;
}

export function triageMarkdown(run: TriageRun, title: string): string {
  const r = run.receipt;
  const raw = run.outcome?.triage;
  // Every model-provided string is untrusted Markdown: escape it before export.
  const t = raw ? (JSON.parse(JSON.stringify(raw), (_k, v) => (typeof v === 'string' ? untrusted(v) : v)) as typeof raw) : null;
  const p = run.provenance;
  const a = attribution(r);
  const L: string[] = [];
  L.push(`# Triage: ${t?.title ?? untrusted(title)}`, '');
  L.push(`> **Execution:** ${verdictPhrase(r)}`);
  L.push(`> **Source:** ${p?.kind === 'recorded' ? `recorded run (historical receipt; not a fresh inference) — ${p.analysis}` : p?.kind === 'live' ? `live run — ${p.analysis}` : 'unknown'}`);
  L.push(`> Model \`${r.model}\` · captured ${r.captured_at} · completion \`${r.chat_id ?? 'n/a'}\` · report transmission: ${r.transmission.replace(/_/g, ' ')}`);
  // Signer fields come from the provider's signature response: untrusted until verified.
  const code = (s: string | null) => untrusted(s ?? '?').replace(/`/g, "'");
  if (r.signer?.address) {
    L.push(
      a.ok
        ? `> Signed by the model deployment’s enclave key \`${code(r.signer.address)}\` (${code(r.signer.kind)}, ${code(r.signer.algo)})`
        : `> Claimed signer \`${code(r.signer.address)}\` — UNVERIFIED: not authenticated as the attested model enclave’s key`,
    );
  }
  L.push(`> request SHA-256 \`${r.request_sha256}\` (the complete serialized API request: system prompt, report marker, model, parameters and report) · response SHA-256 \`${r.response_sha256}\``, '');
  L.push('_Model-generated text below is untrusted; HTML and Markdown links/images in it are escaped._', '');
  if (!t) {
    L.push(r.transmission === 'sent' ? '**No valid analysis was produced.**' : `**No analysis:** ${r.transmission_detail}`, '', ...(run.outcome?.errors ?? []).map((e) => `- ${untrusted(e)}`));
    return L.join('\n');
  }
  L.push(
    a.ok
      ? '_The analysis below is parsed from the response bytes signed by the attested model enclave’s key._'
      : '**⚠ Authenticity NOT verified:** the analysis below is parsed from a received response that no valid signature from an attested model enclave covers. Do not rely on it.',
    '',
  );
  const computed = t.cvss_v31_vector ? cvss31(t.cvss_v31_vector) : null;
  L.push('| | |', '|---|---|');
  const band = computed ? (computed.severity === 'none' ? 'informational' : computed.severity) : t.severity;
  L.push(`| Severity | **${band}**${computed && band !== t.severity ? ` (recomputed from the vector; model said ${t.severity})` : ''} |`);
  L.push(`| CVSS 3.1 | ${t.cvss_v31_vector ? `\`${t.cvss_v31_vector}\` — ${computed ? computed.score.toFixed(1) : 'invalid vector'} (computed)${t.cvss_v31_score !== null && computed && Math.abs(computed.score - t.cvss_v31_score) >= 0.05 ? `; model stated ${t.cvss_v31_score}` : ''}` : 'not scored'} |`);
  L.push(`| Validity | ${t.validity.replace(/_/g, ' ')} |`);
  L.push(`| Confidence | ${t.confidence} — ${t.confidence_rationale} |`);
  L.push(`| Class | ${t.vulnerability_class} (${t.cwe.join(', ') || 'no CWE'}) |`);
  L.push(`| Evidence quality | ${t.evidence_quality} |`, '');
  L.push('## Summary', '', t.summary, '');
  L.push('## Impact', '', t.impact, '');
  const list = (h: string, xs: string[]) => {
    if (xs.length) L.push(`## ${h}`, '', ...xs.map((x) => `- ${x}`), '');
  };
  list('Affected components', t.affected_components);
  list('Attack preconditions', t.attack_preconditions);
  L.push('## Reproduction assessment', '', t.reproduction_assessment, '');
  L.push('## Recommended actions', '');
  for (const p of ['immediate', 'short_term', 'long_term'] as const) {
    const xs = t.recommended_actions.filter((a) => a.priority === p);
    if (xs.length) L.push(`**${p.replace('_', ' ')}**`, ...xs.map((a) => `- ${a.action}`), '');
  }
  for (const n of run.analyst_notes ?? []) {
    L.push(`## Analyst correction (human commentary — not part of the signed model output)`, '');
    L.push(`Corrects: “${n.quote}”`, '', `**${n.title}**`, '', ...n.body.flatMap((x) => [x, '']));
    L.push(`— ${n.author}, ${n.date}. References: ${n.references.map((x) => `${x.label} <${x.url}>`).join('; ')}. The signed response is unchanged; this note is bound to its SHA-256.`, '');
  }
  list('Missing information', t.missing_information);
  list('Questions for the reporter', t.questions_for_reporter);
  if (t.injection_detected || run.hygiene.some((h) => h.kind === 'injection')) {
    L.push('## ⚠ Instructions aimed at the AI detected — check the analysis for their influence', '', t.injection_notes || 'Flagged by the local hygiene scan.', '');
    for (const h of run.hygiene.filter((x) => x.kind === 'injection')) L.push(`- local scan: ${h.label}`);
    L.push('');
  }
  const warns = run.outcome?.consistency.filter((c) => c.status === 'warn') ?? [];
  list('Deterministic consistency warnings', warns.map((w) => w.detail));
  L.push('---', '');
  L.push(`**${r.verdict === 'VERIFIED' ? 'What the verification proves' : `What a VERIFIED receipt would prove — this receipt is ${r.verdict}, so none of it is established for this run`}:** before the report was sent, NEAR AI Cloud’s gateway and every model enclave it returned produced Intel TDX evidence for NEAR’s pinned software, and NVIDIA GPU evidence and per-GPU appraisals for confidential-computing mode, all answering a challenge derived from the exact request; afterwards, a key held by the attested model deployment signed the request/response hashes above, and this analysis is parsed from those response bytes.`, '');
  L.push('**What it does not prove:**', ...r.not_proven.map((x) => `- ${x}`), '');
  L.push(`_Generated by PrivateTriage (${r.verifier}). Re-verify offline: \`npm run verify -- evidence.json\`._`);
  return L.join('\n');
}
