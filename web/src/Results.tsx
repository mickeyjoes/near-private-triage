import { useState } from 'react';
import { cvss31, type Triage } from '../../shared/triage.ts';
import { download, shareableEvidence, slug, triageMarkdown } from './exporters.ts';
import * as I from './icons.tsx';
import type { EvidenceBundle, Receipt, TriageRun } from './types.ts';
import { CopyHash, Disclosure, Pill, short, StatusGlyph, VerdictBadge, VerdictIcon } from './ui.tsx';

const SEV_TONE: Record<string, string> = { critical: 'crit', high: 'high', medium: 'med', low: 'low', informational: 'info', undetermined: 'undet' };

export function VerdictBanner({ run }: { run: TriageRun }) {
  const r = run.receipt;
  const ok = r.verdict === 'VERIFIED';
  const modelOk = run.outcome?.status === 'ok';
  return (
    <div className={`banner banner-${r.verdict.toLowerCase()}`}>
      <div className="banner-icon">
        <VerdictIcon v={r.verdict} size={30} />
      </div>
      <div className="banner-main">
        <div className="banner-title">
          {ok ? 'Confidential execution verified' : r.verdict === 'FAILED' ? 'Verification failed — do not trust this output' : r.disclosed ? 'Not verified — evidence incomplete' : 'Report withheld — attestation did not verify'}
        </div>
        <div className="banner-sub">
          {ok
            ? 'Hardware-attested gateway and GPU-backed model enclave; the model enclave signed the exact bytes below. This proves where and how the analysis ran — not that it is correct.'
            : r.headline}
        </div>
        <div className="banner-props">
          {r.properties.map((p) => (
            <span key={p.id} className={`mini mini-${p.verdict.toLowerCase()}`} title={`${p.title}: ${p.verdict}`}>
              <VerdictIcon v={p.verdict} size={13} />
              {PROP_SHORT[p.id] ?? p.id}
            </span>
          ))}
        </div>
      </div>
      <div className="banner-side">
        {ok && !modelOk ? <Pill tone="warn">Output rejected by schema</Pill> : null}
        <div className="banner-stat">
          <span>{(run.duration_ms / 1000).toFixed(1)}s</span>
          <small>end to end</small>
        </div>
      </div>
    </div>
  );
}

const PROP_SHORT: Record<string, string> = {
  gateway_tee: 'Gateway TEE',
  tls_binding: 'TLS bound',
  model_tee: 'Model TEE',
  gpu_tee: 'GPU CC',
  response_signature: 'Enclave signature',
};

function CvssBlock({ t }: { t: Triage }) {
  const c = t.cvss_v31_vector ? cvss31(t.cvss_v31_vector) : null;
  const mismatch = c && t.cvss_v31_score !== null && Math.abs(c.score - t.cvss_v31_score) >= 0.05;
  return (
    <div className={`cvss sev-${SEV_TONE[t.severity]}`}>
      <div className="cvss-score">{c ? c.score.toFixed(1) : '—'}</div>
      <div className="cvss-meta">
        <div className="cvss-sev">{t.severity}</div>
        <div className="cvss-vec">{t.cvss_v31_vector ?? 'Not scored — insufficient evidence'}</div>
        {mismatch ? (
          <div className="cvss-note">
            <I.Alert size={12} /> model stated {t.cvss_v31_score?.toFixed(1)}; computed from its vector
          </div>
        ) : c ? (
          <div className="cvss-note ok">
            <I.Check size={12} /> score recomputed from vector
          </div>
        ) : null}
      </div>
    </div>
  );
}

const isNothing = (s: string) => /^(none|n\/a|nothing|not applicable)\.?$/i.test(s.trim());

function List({ title, items: raw, empty }: { title: string; items: string[]; empty?: string }) {
  const items = raw.filter((x) => !isNothing(x));
  return (
    <div className="block">
      <h4>{title}</h4>
      {items.length ? (
        <ul className="bullets">
          {items.map((x, i) => (
            <li key={i}>{x}</li>
          ))}
        </ul>
      ) : (
        <p className="muted small">{empty ?? 'None.'}</p>
      )}
    </div>
  );
}

export function AnalysisView({ run }: { run: TriageRun }) {
  const o = run.outcome;
  const t = o?.triage;
  if (!t) {
    return (
      <div className="empty-analysis">
        <I.Alert size={22} />
        <div>
          <strong>{run.receipt.disclosed ? 'No valid analysis was produced.' : 'The report was never sent, so there is no analysis.'}</strong>
          <p>{run.receipt.disclosed ? (o?.errors.join(' ') ?? 'Unknown error.') : run.receipt.headline}</p>
          {run.receipt.disclosed ? <p className="muted small">PrivateTriage never repairs or guesses model output: malformed answers are rejected.</p> : null}
        </div>
      </div>
    );
  }
  const injected = t.injection_detected || run.hygiene.some((h) => h.kind === 'injection');
  const warns = o!.consistency.filter((c) => c.status === 'warn');
  const groups = (['immediate', 'short_term', 'long_term'] as const).map((p) => ({ p, xs: t.recommended_actions.filter((a) => a.priority === p) }));
  return (
    <div className="analysis">
      <div className="ai-note">
        <I.Spark size={15} />
        AI-generated triage recommendation. Treat as a second opinion for a human analyst — the cryptographic checks cover execution, not judgement.
      </div>
      <div className="analysis-top">
        <CvssBlock t={t} />
        <div className="analysis-headline">
          <h3>{t.title}</h3>
          <div className="chips">
            <Pill tone={t.validity === 'likely_valid' ? 'good' : t.validity === 'likely_invalid' ? 'bad' : 'warn'}>{t.validity.replace(/_/g, ' ')}</Pill>
            <Pill tone="neutral">confidence: {t.confidence}</Pill>
            <Pill tone="neutral">evidence: {t.evidence_quality}</Pill>
            <Pill tone="neutral">{t.vulnerability_class}</Pill>
            {t.cwe.map((c) => (
              <Pill key={c} tone="ghost">
                {c}
              </Pill>
            ))}
          </div>
          <p className="summary">{t.summary}</p>
          <p className="muted small">
            <strong>Confidence rationale:</strong> {t.confidence_rationale}
          </p>
        </div>
      </div>

      {injected ? (
        <div className="injection">
          <div className="injection-head">
            <I.Alert size={17} /> Prompt-injection attempt detected — and ignored
          </div>
          <p>{t.injection_notes || 'The local scan flagged instructions aimed at the AI triage system.'}</p>
          <div className="injection-sources">
            <span>
              Model: <strong>{t.injection_detected ? 'flagged' : 'not flagged'}</strong>
            </span>
            <span>
              Local scan: <strong>{run.hygiene.filter((h) => h.kind === 'injection').length} pattern(s)</strong>
            </span>
            <span>
              Report fenced by random marker <code>{run.marker}</code>
            </span>
          </div>
        </div>
      ) : null}

      <div className="grid-2">
        <div className="block">
          <h4>Impact</h4>
          <p>{t.impact}</p>
        </div>
        <div className="block">
          <h4>Reproduction assessment</h4>
          <p>{t.reproduction_assessment}</p>
        </div>
        <List title="Affected components" items={t.affected_components} />
        <List title="Attack preconditions" items={t.attack_preconditions} />
      </div>

      <div className="block actions">
        <h4>Recommended actions</h4>
        <div className="action-groups">
          {groups.map(({ p, xs }) =>
            xs.length ? (
              <div key={p} className={`action-group ag-${p}`}>
                <div className="ag-label">{p.replace('_', ' ')}</div>
                <ol>
                  {xs.map((a, i) => (
                    <li key={i}>{a.action}</li>
                  ))}
                </ol>
              </div>
            ) : null,
          )}
        </div>
      </div>

      <div className="grid-2">
        <List title="Missing information" items={t.missing_information} empty="Nothing essential missing." />
        <List title="Questions for the reporter" items={t.questions_for_reporter} empty="No follow-up questions needed." />
      </div>

      <div className="block">
        <h4>Deterministic consistency checks</h4>
        <ul className="consistency">
          {o!.consistency.length === 0 ? <li className="muted small">No CVSS vector to check (severity undetermined).</li> : null}
          {o!.consistency.map((c) => (
            <li key={c.id} className={c.status}>
              {c.status === 'ok' ? <I.Check size={14} /> : <I.Alert size={14} />} {c.detail}
            </li>
          ))}
        </ul>
        {warns.length ? <p className="muted small">Arithmetic is recomputed locally; the computed CVSS score is the one displayed.</p> : null}
      </div>

      {o!.reasoning ? (
        <Disclosure
          summary={
            <span>
              Model reasoning <span className="muted">· {o!.usage?.reasoning_tokens.toLocaleString() ?? '?'} tokens · part of the signed response</span>
            </span>
          }
        >
          <pre className="reasoning">{o!.reasoning}</pre>
        </Disclosure>
      ) : null}
    </div>
  );
}

function Fact({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div className="fact">
      <dt>{k}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export function VerificationView({ receipt: r }: { receipt: Receipt }) {
  const g = r.gateway;
  const m = r.model_tee;
  return (
    <div className="verification">
      <div className="props">
        {r.properties.map((p) => {
          const bad = p.checks.filter((c) => c.status !== 'pass');
          return (
            <div key={p.id} className={`prop prop-${p.verdict.toLowerCase()}`}>
              <div className="prop-head">
                <div className="prop-title">{p.title}</div>
                <VerdictBadge v={p.verdict} compact />
              </div>
              <p className="prop-stmt">{p.statement}</p>
              <Disclosure
                defaultOpen={bad.length > 0}
                summary={
                  <span>
                    {p.checks.length} checks · {p.checks.filter((c) => c.status === 'pass').length} passed
                    {bad.length ? <span className="muted"> · {bad.length} not passed</span> : null}
                  </span>
                }
              >
                <ul className="checks">
                  {p.checks.map((c, i) => (
                    <li key={c.id + i} className={`chk chk-${c.status}`}>
                      <StatusGlyph s={c.status} />
                      <div>
                        <div className="chk-label">{c.label}</div>
                        <div className="chk-detail">{c.detail}</div>
                      </div>
                    </li>
                  ))}
                </ul>
              </Disclosure>
            </div>
          );
        })}
      </div>

      <div className="grid-2 proves">
        <div className="block proves-yes">
          <h4>
            <I.ShieldCheck size={16} /> What a VERIFIED receipt proves
          </h4>
          <ul className="bullets">
            <li>The NEAR AI Cloud gateway that terminated your TLS session runs NEAR’s pinned dstack OS image and app identity in a genuine, non-debug Intel TDX enclave with up-to-date platform firmware.</li>
            <li>The model was served from a separate Intel TDX enclave whose {m?.gpu?.count ?? ''} NVIDIA GPUs NVIDIA attests are in confidential-computing mode — both enclaves and the GPUs answered a challenge derived from your report.</li>
            <li>The model enclave’s attested key signed SHA-256 of the exact request and response, so the analysis you see is byte-for-byte what the enclave produced.</li>
            <li>Your report was released only after all of the above checked out.</li>
          </ul>
        </div>
        <div className="block proves-no">
          <h4>
            <I.Eye size={16} /> What it does not prove
          </h4>
          <ul className="bullets">
            {r.not_proven.map((x, i) => (
              <li key={i}>{x}</li>
            ))}
          </ul>
        </div>
      </div>

      <Disclosure summary={<span>Cryptographic facts</span>} defaultOpen>
        <dl className="facts">
          <Fact k="Model">
            <code>{r.model}</code>
          </Fact>
          <Fact k="Captured">{new Date(r.captured_at).toUTCString()}</Fact>
          <Fact k="Challenge nonce">
            <CopyHash value={r.nonce.value} label="nonce" />
          </Fact>
          <Fact k="Nonce derivation">
            <code className="small">{r.nonce.derivation}</code>
          </Fact>
          <Fact k="Request SHA-256">
            <CopyHash value={r.request_sha256} />
          </Fact>
          <Fact k="Response SHA-256">
            <CopyHash value={r.response_sha256} />
          </Fact>
          <Fact k="Completion ID">
            <code>{r.chat_id ?? '—'}</code>
          </Fact>
          <Fact k="Response signer">{r.signer?.address ? <span>{r.signer.kind} · {r.signer.algo} · <CopyHash value={r.signer.address} n={6} /></span> : '—'}</Fact>
          <Fact k="Model enclave key">
            <CopyHash value={m?.signing_address} n={6} />
          </Fact>
          <Fact k="Gateway enclave key">
            <CopyHash value={g?.signing_address} n={6} />
          </Fact>
          <Fact k="Gateway TLS SPKI">
            <CopyHash value={g?.tls_spki_sha256} />
          </Fact>
          <Fact k="TCB (gateway / model)">
            {g?.quote?.tcb_status ?? '—'} / {m?.quote?.tcb_status ?? '—'}
          </Fact>
          <Fact k="GPUs">{m?.gpu ? `${m.gpu.count} × ${m.gpu.arch ?? '?'} · NRAS token ${short(m.gpu.nras_jti, 6)}` : '—'}</Fact>
          <Fact k="App identity (gateway / model)">
            <CopyHash value={g?.app_id} n={6} /> <CopyHash value={m?.app_id} n={6} />
          </Fact>
          <Fact k="dstack OS image (gateway / model)">
            <CopyHash value={g?.os_image_hash} n={6} /> <CopyHash value={m?.os_image_hash} n={6} />
          </Fact>
          <Fact k="Model compose hash">
            <CopyHash value={m?.compose_hash} />
          </Fact>
          <Fact k="Gateway compose hash">
            <CopyHash value={g?.compose_hash} />
          </Fact>
          <Fact k="Model MRTD">
            <CopyHash value={m?.quote?.mr_td} />
          </Fact>
          <Fact k="Verifier">
            <span className="small">{r.verifier}</span>
          </Fact>
        </dl>
      </Disclosure>

      <Disclosure summary={<span>Trust assumptions</span>}>
        <ul className="bullets">
          {r.trust_assumptions.map((x, i) => (
            <li key={i}>{x}</li>
          ))}
        </ul>
      </Disclosure>
    </div>
  );
}

export function EvidenceView({ run, title, evidence, evidenceUrl }: { run: TriageRun; title: string; evidence: EvidenceBundle | null; evidenceUrl: string | null }) {
  const [busy, setBusy] = useState(false);
  const name = slug(run.outcome?.triage?.title ?? title);
  const getEvidence = async (): Promise<EvidenceBundle | null> => {
    if (evidence) return evidence;
    if (!evidenceUrl) return null;
    setBusy(true);
    try {
      return (await (await fetch(evidenceUrl)).json()) as EvidenceBundle;
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="evidence">
      <div className="exports">
        <button type="button" className="export" onClick={() => download(`${name}.triage.md`, triageMarkdown(run, title), 'text/markdown')}>
          <I.File size={20} />
          <div>
            <strong>Triage report</strong>
            <span>Markdown · analysis + verification summary + limits</span>
          </div>
          <I.Download size={16} />
        </button>
        <button type="button" className="export" onClick={() => download(`${name}.receipt.json`, JSON.stringify(run.receipt, null, 2) + '\n')}>
          <I.ShieldCheck size={20} />
          <div>
            <strong>Verification receipt</strong>
            <span>JSON · every check, hash, signer and limitation</span>
          </div>
          <I.Download size={16} />
        </button>
        <button
          type="button"
          className="export"
          disabled={busy}
          onClick={async () => {
            const e = await getEvidence();
            if (e) download(`${name}.evidence-shareable.json`, JSON.stringify(shareableEvidence(e), null, 1));
          }}
        >
          <I.Key size={20} />
          <div>
            <strong>Shareable evidence</strong>
            <span>No report content — hashes, quotes, GPU token, signature</span>
          </div>
          <I.Download size={16} />
        </button>
        <button
          type="button"
          className="export"
          disabled={busy}
          onClick={async () => {
            const e = await getEvidence();
            if (e) download(`${name}.evidence-full.json`, JSON.stringify(e, null, 1));
          }}
        >
          <I.Lock size={20} />
          <div>
            <strong>Full evidence</strong>
            <span>Includes exact request/response bytes — contains the report</span>
          </div>
          <I.Download size={16} />
        </button>
      </div>

      <div className="block repro">
        <h4>
          <I.Terminal size={16} /> Re-verify independently — no API key, no network
        </h4>
        <pre className="code">{`git clone <repo> && cd near-private-triage && npm ci
npm run verify -- ${name}.evidence-full.json
#  → re-checks Intel TDX quotes (archived Intel PCS collateral),
#    NVIDIA NRAS token (archived JWKS), TLS binding, nonce
#    derivation, and the enclave's ECDSA signature over the hashes.`}</pre>
        <p className="muted small">
          The shareable bundle verifies too: the enclave signed the <em>hashes</em>, so evidence can be published without revealing the report. Anyone holding the original report can confirm its SHA-256 matches <code>{short(run.receipt.request_sha256, 8)}</code>.
        </p>
      </div>
    </div>
  );
}
