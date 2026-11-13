import { useEffect, useRef, useState } from 'react';
import * as I from './icons.tsx';
import type { TamperResult } from './types.ts';
import { SectionHead, StatusGlyph, VerdictBadge } from './ui.tsx';

const PROP_NAME: Record<string, string> = {
  gateway_tee: 'Gateway TEE',
  tls_binding: 'TLS binding',
  model_tee: 'Model TEE',
  gpu_tee: 'GPU attestation',
  response_signature: 'Enclave signature',
};

export function TamperLab({ results, baseLabel }: { results: TamperResult[]; baseLabel: string }) {
  const [sel, setSel] = useState<string>(results[0]?.id ?? '');
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [auto, setAuto] = useState(false);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    if (!auto) return;
    let i = 0;
    const tick = () => {
      const r = results[i];
      if (!r) {
        setAuto(false);
        return;
      }
      setSel(r.id);
      setRevealed((s) => new Set(s).add(r.id));
      document.getElementById(`lab-${r.id}`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      i++;
      timer.current = window.setTimeout(tick, 420);
    };
    tick();
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [auto, results]);

  const r = results.find((x) => x.id === sel);
  const caught = results.filter((x) => revealed.has(x.id) && x.verdict !== 'VERIFIED').length;
  const failed = results.filter((x) => revealed.has(x.id) && x.verdict === 'FAILED').length;
  const unver = results.filter((x) => revealed.has(x.id) && x.verdict === 'UNVERIFIED').length;
  const target = r?.properties.find((p) => p.id === r.property);
  const hit = target?.checks.find((c) => c.id === r?.check);

  return (
    <section id="tamper" className="section">
      <SectionHead eyebrow="Tamper lab" title="Attack the evidence. Watch it fail closed.">
        Each scenario modifies the <strong>genuine</strong> evidence of the recorded {baseLabel} run — editing the verdict, replaying old attestations, forging keys, intercepting TLS — and re-runs the same verifier. Nothing short of genuine evidence yields a verified result.
      </SectionHead>
      <div className="lab">
        <div className="lab-list card">
          <div className="lab-score">
            <div>
              <span className="big">
                {caught}/{results.length}
              </span>
              <span className="muted"> attacks caught</span>
            </div>
            <button type="button" className="btn btn-ghost" onClick={() => {
              setRevealed(new Set());
              setAuto(true);
            }} disabled={auto}>
              <I.Play size={14} /> Run all
            </button>
          </div>
          <div className="lab-legend">
            <span className="lg lg-failed">{failed} FAILED · hard cryptographic or binding failure</span>
            <span className="lg lg-unverified">{unver} UNVERIFIED · evidence missing, so no claim is made</span>
          </div>
          <ul>
            {results.map((x) => (
              <li key={x.id} id={`lab-${x.id}`}>
                <button
                  type="button"
                  className={`lab-item ${sel === x.id ? 'on' : ''}`}
                  onClick={() => {
                    setSel(x.id);
                    setRevealed((s) => new Set(s).add(x.id));
                  }}
                >
                  <span className="lab-title">{x.title}</span>
                  {revealed.has(x.id) ? <VerdictBadge v={x.verdict} compact /> : <span className="lab-pending">try it</span>}
                </button>
              </li>
            ))}
          </ul>
        </div>
        {r ? (
          <div className="lab-detail card">
            <div className="eyebrow">Attack</div>
            <h3>{r.title}</h3>
            <p className="lede">{r.attack}</p>
            {revealed.has(r.id) ? (
              <>
                <div className={`lab-outcome lo-${r.verdict.toLowerCase()}`}>
                  <VerdictBadge v={r.verdict} />
                  <span>
                    caught by <strong>{PROP_NAME[r.property] ?? r.property}</strong>
                  </span>
                </div>
                {hit ? (
                  <div className={`lab-check chk-${hit.status}`}>
                    <StatusGlyph s={hit.status} />
                    <div>
                      <div className="chk-label">{hit.label}</div>
                      <div className="chk-detail">{hit.detail}</div>
                    </div>
                  </div>
                ) : null}
                <div className="lab-props">
                  {r.properties.map((p) => (
                    <div key={p.id} className={`lab-prop lp-${p.verdict.toLowerCase()}`}>
                      <span>{PROP_NAME[p.id]}</span>
                      <VerdictBadge v={p.verdict} compact />
                    </div>
                  ))}
                </div>
                <p className="muted small">
                  Overall: <strong>{r.verdict}</strong> — {r.headline} Reproduce: <code>npm test</code>
                </p>
              </>
            ) : (
              <button type="button" className="btn btn-primary" onClick={() => setRevealed((s) => new Set(s).add(r.id))}>
                <I.Play size={15} /> Apply attack &amp; re-verify
              </button>
            )}
          </div>
        ) : null}
      </div>
    </section>
  );
}
