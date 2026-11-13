// The disclosure gate: attestation must pass before the report leaves the backend.
import type { ReactElement } from 'react';
import * as I from './icons.tsx';
import type { Receipt, StageEvent } from './types.ts';
import { short } from './ui.tsx';

type StepState = 'pending' | 'active' | 'done' | 'failed' | 'skipped';

interface Step {
  key: string;
  title: string;
  sub: string;
  icon: ReactElement;
}

const STEPS: Step[] = [
  { key: 'challenge', title: 'Fresh challenge', sub: '256-bit nonce derived from your report’s hash', icon: <I.Dice size={17} /> },
  { key: 'gateway', title: 'Gateway attestation', sub: 'Intel TDX quote · TLS key bound to the enclave', icon: <I.Chip size={17} /> },
  { key: 'model', title: 'Model + GPU attestation', sub: 'Model TDX quote · NVIDIA confidential-computing verdict', icon: <I.Gpu size={17} /> },
  { key: 'gate', title: 'Disclosure gate', sub: 'Report released only if every check above passed', icon: <I.Gate size={17} /> },
  { key: 'inference', title: 'Confidential inference', sub: 'Sent over the same attested TLS session', icon: <I.Lock size={17} /> },
  { key: 'signature', title: 'Enclave signature', sub: 'Model TEE signs SHA-256 of request & response', icon: <I.Signature size={17} /> },
  { key: 'verdict', title: 'Independent verdict', sub: 'Every claim re-checked, fail-closed', icon: <I.ShieldCheck size={17} /> },
];

function deriveStates(stages: StageEvent[], receipt: Receipt | null, running: boolean): StepState[] {
  const seen = new Set(stages.map((s) => s.stage));
  const st: StepState[] = STEPS.map(() => 'pending');
  const prop = (id: string) => receipt?.properties.find((p) => p.id === id)?.verdict;
  if (seen.has('challenge')) st[0] = 'done';
  if (seen.has('attestation')) st[1] = 'active';
  if (seen.has('appraisal')) {
    const blocked = seen.has('blocked');
    st[1] = blocked && prop('gateway_tee') !== 'VERIFIED' ? 'failed' : 'done';
    st[2] = blocked && st[1] === 'done' ? 'failed' : blocked ? 'skipped' : 'done';
    if (blocked) {
      st[3] = 'failed';
      for (let i = 4; i < STEPS.length; i++) st[i] = 'skipped';
      return st;
    }
    st[3] = 'done';
  }
  if (seen.has('inference')) st[4] = 'active';
  if (seen.has('signature')) {
    st[4] = 'done';
    st[5] = 'active';
  }
  if (seen.has('verdict')) {
    if (st[4] === 'active') st[4] = receipt?.disclosed ? 'done' : 'failed';
    st[5] = prop('response_signature') === 'VERIFIED' ? 'done' : 'failed';
    st[6] = receipt?.verdict === 'VERIFIED' ? 'done' : 'failed';
  }
  if (!running && !seen.has('verdict') && stages.length > 0) {
    const i = st.indexOf('active');
    if (i >= 0) st[i] = 'failed';
  }
  if (running) {
    const firstPending = st.indexOf('pending');
    if (firstPending >= 0 && !st.includes('active')) st[firstPending] = 'active';
  }
  return st;
}

function stepDetail(key: string, stages: StageEvent[], r: Receipt | null): string | null {
  const ev = (s: string) => stages.find((x) => x.stage === s);
  if (!r) {
    if (key === 'challenge') return ev('challenge')?.detail ?? null;
    if (key === 'gate' && ev('blocked')) return 'Closed — report NOT sent';
    return null;
  }
  const q = r.gateway?.quote;
  switch (key) {
    case 'challenge':
      return `nonce ${short(r.nonce.value, 6)}`;
    case 'gateway':
      return r.gateway?.signing_address ? `TCB ${q?.tcb_status ?? '?'} · signer ${short(r.gateway.signing_address, 4)}` : null;
    case 'model': {
      const g = r.model_tee?.gpu;
      return r.model_tee?.signing_address ? `${g ? `${g.count}× ${g.arch ?? 'GPU'} · ` : ''}signer ${short(r.model_tee.signing_address, 4)}` : null;
    }
    case 'gate':
      return r.disclosed ? 'Open — attestation verified first' : 'Closed — report NOT sent';
    case 'inference':
      return r.disclosed ? r.model : null;
    case 'signature':
      return r.signer?.address ? `${r.signer.kind} · ${short(r.signer.address, 4)}` : null;
    case 'verdict':
      return r.verdict;
    default:
      return null;
  }
}

export function Pipeline({ stages, receipt, running, source }: { stages: StageEvent[]; receipt: Receipt | null; running: boolean; source: 'recorded' | 'live' | null }) {
  const states = deriveStates(stages, receipt, running);
  const t = (k: string) => {
    const map: Record<string, string[]> = {
      challenge: ['challenge'],
      gateway: ['attestation'],
      model: ['appraisal'],
      gate: ['inference', 'blocked'],
      inference: ['signature'],
      signature: ['verdict'],
      verdict: ['verdict'],
    };
    const e = stages.find((s) => map[k]?.includes(s.stage));
    return e ? `${(e.t_ms / 1000).toFixed(1)}s` : '';
  };
  return (
    <div className="pipeline card">
      <div className="card-head">
        <div>
          <div className="card-title">Disclosure gate</div>
          <div className="card-sub">Attest before you disclose — the report never leaves the backend unless the hardware proves itself first.</div>
        </div>
        {source ? <span className={`source source-${source}`}>{source === 'recorded' ? 'Recorded genuine run' : 'Live run'}</span> : null}
      </div>
      <ol className="steps">
        {STEPS.map((s, i) => {
          const state = states[i]!;
          const detail = stepDetail(s.key, stages, receipt);
          return (
            <li key={s.key} className={`step step-${state} ${s.key === 'gate' ? 'step-gate' : ''}`}>
              <div className="step-rail">
                <span className="step-dot">
                  {state === 'done' ? <I.Check size={14} /> : state === 'failed' ? <I.X size={14} /> : state === 'active' ? <span className="spinner" /> : s.icon}
                </span>
              </div>
              <div className="step-body">
                <div className="step-title">
                  {s.title}
                  <span className="step-time">{state !== 'pending' && state !== 'skipped' ? t(s.key) : ''}</span>
                </div>
                <div className="step-sub">{state === 'skipped' ? 'Not reached — fail-closed' : detail ?? s.sub}</div>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
