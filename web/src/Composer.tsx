import { useMemo } from 'react';
import { scanReport } from '../../shared/hygiene.ts';
import * as I from './icons.tsx';
import type { SampleReport } from './types.ts';

export interface ComposerProps {
  samples: SampleReport[];
  selected: string;
  onSelect: (id: string) => void;
  title: string;
  body: string;
  onTitle: (s: string) => void;
  onBody: (s: string) => void;
  live: boolean;
  model: string;
  running: boolean;
  onRun: () => void;
  onReplay: () => void;
  canReplay: boolean;
}

const MODEL_LABEL: Record<string, string> = {
  'Qwen/Qwen3.6-35B-A3B-FP8': 'Qwen3.6 35B-A3B',
  'z-ai/glm-5.3-flash': 'GLM-5.3 Flash',
};

export function Composer(p: ComposerProps) {
  const findings = useMemo(() => scanReport(`${p.title}\n${p.body}`), [p.title, p.body]);
  const injections = findings.filter((f) => f.kind === 'injection');
  const secrets = findings.filter((f) => f.kind === 'secret');
  const editable = p.live && !p.running;
  const isSample = p.selected !== 'custom';
  const tokens = Math.round((p.title.length + p.body.length) / 3.6) + 900;

  return (
    <div className="composer card">
      <div className="card-head">
        <div>
          <div className="card-title">Confidential report</div>
          <div className="card-sub">
            {p.live ? 'Write or paste an unpublished report, or start from a fictional sample.' : 'Pick a fictional sample to replay its recorded, genuinely verified run.'}
          </div>
        </div>
      </div>

      <div className="samples" role="tablist" aria-label="Sample reports">
        {p.samples.map((s) => (
          <button key={s.id} type="button" role="tab" aria-selected={p.selected === s.id} className={`sample ${p.selected === s.id ? 'on' : ''}`} onClick={() => p.onSelect(s.id)} disabled={p.running}>
            <span className="sample-label">{s.label}</span>
            <span className="sample-hint">{s.hint}</span>
          </button>
        ))}
        {p.live ? (
          <button type="button" role="tab" aria-selected={p.selected === 'custom'} className={`sample ${p.selected === 'custom' ? 'on' : ''}`} onClick={() => p.onSelect('custom')} disabled={p.running}>
            <span className="sample-label">Your own report</span>
            <span className="sample-hint">Processed in memory, never stored</span>
          </button>
        ) : null}
      </div>

      <label className="field">
        <span className="field-label">Title</span>
        <input value={p.title} onChange={(e) => p.onTitle(e.target.value)} readOnly={!editable} maxLength={300} placeholder="Short description of the vulnerability" />
      </label>
      <label className="field grow">
        <span className="field-label">
          Report
          {isSample ? <span className="fiction">Fictional sample — invented product, accounts and data</span> : null}
        </span>
        <textarea value={p.body} onChange={(e) => p.onBody(e.target.value)} readOnly={!editable} spellCheck={false} placeholder="Steps to reproduce, affected component, impact, proof of concept…" />
      </label>

      <div className={`hygiene ${findings.length ? 'warn' : 'ok'}`}>
        <div className="hygiene-head">
          {findings.length ? <I.Alert size={16} /> : <I.ShieldCheck size={16} />}
          <span>
            {findings.length
              ? `Local pre-disclosure scan: ${injections.length ? `${injections.length} instruction${injections.length > 1 ? 's' : ''} aimed at the AI` : ''}${injections.length && secrets.length ? ' · ' : ''}${secrets.length ? `${secrets.length} possible live secret${secrets.length > 1 ? 's' : ''}` : ''}`
              : 'Local pre-disclosure scan: no injected instructions or live-looking secrets'}
          </span>
          <span className="hygiene-tag">runs in your browser · nothing sent</span>
        </div>
        {findings.length ? (
          <ul className="hygiene-list">
            {findings.slice(0, 5).map((f, i) => (
              <li key={i}>
                <span className={`hk hk-${f.kind}`}>{f.kind === 'injection' ? 'Injection' : 'Secret'}</span>
                <span className="hl">{f.label}</span>
                <span className="hx">{f.excerpt}</span>
              </li>
            ))}
          </ul>
        ) : null}
      </div>

      <div className="composer-foot">
        <div className="meta">
          <span className="meta-item" title={p.model}>
            <I.Gpu size={14} /> {MODEL_LABEL[p.model] ?? p.model} · GPU TEE
          </span>
          <span className="meta-item">≈ {tokens.toLocaleString()} input tokens</span>
          <span className="meta-item">≈ $0.006 / triage</span>
        </div>
        <div className="foot-actions">
        {p.live && p.canReplay ? (
          <button type="button" className="btn btn-ghost" onClick={p.onReplay} disabled={p.running} title="Replay the recorded genuine run of this sample (no inference cost)">
            <I.Play size={15} /> Replay recorded
          </button>
        ) : null}
        <button type="button" className="btn btn-primary" onClick={p.onRun} disabled={p.running || (!p.live && !p.canReplay) || (p.live && (p.body.trim().length < 40 || !p.title.trim()))}>
          {p.running ? <span className="spinner light" /> : p.live ? <I.Lock size={16} /> : <I.Play size={16} />}
          {p.running ? 'Verifying…' : p.live ? 'Attest & triage' : 'Replay verified run'}
        </button>
        </div>
      </div>
    </div>
  );
}
