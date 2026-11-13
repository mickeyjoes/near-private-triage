import { useCallback, useEffect, useRef, useState } from 'react';
import { HowItWorks, Refusals } from './Boundary.tsx';
import { Composer } from './Composer.tsx';
import * as I from './icons.tsx';
import { Pipeline } from './Pipeline.tsx';
import { AnalysisView, EvidenceView, VerdictBanner, VerificationView } from './Results.tsx';
import { TamperLab } from './TamperLab.tsx';
import type { BackendStatus, DemoData, StageEvent, TriageRun } from './types.ts';
import { short } from './ui.tsx';

type Tab = 'analysis' | 'verification' | 'evidence';

export function App() {
  const [data, setData] = useState<DemoData | null>(null);
  const [status, setStatus] = useState<BackendStatus | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected, setSelected] = useState('lumora-staking');
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [stages, setStages] = useState<StageEvent[]>([]);
  const [run, setRun] = useState<TriageRun | null>(null);
  const [running, setRunning] = useState(false);
  const [source, setSource] = useState<'recorded' | 'live' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('analysis');
  const replayTimers = useRef<number[]>([]);
  const resultsRef = useRef<HTMLDivElement>(null);
  const live = Boolean(status?.live);

  useEffect(() => {
    fetch('demo/data.json')
      .then((r) => r.json() as Promise<DemoData>)
      .then((d) => {
        setData(d);
        const s = d.samples[0]!;
        setTitle(s.title);
        setBody(s.body);
      })
      .catch(() => setLoadError('Could not load the recorded demo data.'));
    fetch('api/status')
      .then((r) => (r.ok ? (r.json() as Promise<BackendStatus>) : null))
      .then((s) => setStatus(s))
      .catch(() => setStatus(null));
  }, []);

  const clearReplay = () => {
    replayTimers.current.forEach((t) => window.clearTimeout(t));
    replayTimers.current = [];
  };

  const select = (id: string) => {
    if (!data) return;
    clearReplay();
    setSelected(id);
    setRun(null);
    setStages([]);
    setError(null);
    setSource(null);
    if (id === 'custom') {
      setTitle('');
      setBody('');
      return;
    }
    const s = data.samples.find((x) => x.id === id)!;
    setTitle(s.title);
    setBody(s.body);
  };

  const showResult = useCallback((r: TriageRun, src: 'recorded' | 'live') => {
    setRun(r);
    setSource(src);
    setTab(r.outcome?.triage ? 'analysis' : 'verification');
    setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 120);
  }, []);

  const replay = () => {
    if (!data) return;
    const rec = data.runs[selected];
    if (!rec) return;
    clearReplay();
    setRun(null);
    setError(null);
    setStages([]);
    setRunning(true);
    setSource('recorded');
    const total = rec.stages.at(-1)?.t_ms ?? 1;
    const scale = Math.min(1, 6500 / total);
    rec.stages.forEach((s, i) => {
      const tm = window.setTimeout(() => {
        setStages((prev) => [...prev, s]);
        if (i === rec.stages.length - 1) {
          setRunning(false);
          showResult(rec, 'recorded');
        }
      }, 350 + s.t_ms * scale);
      replayTimers.current.push(tm);
    });
  };

  const runLive = async () => {
    clearReplay();
    setRun(null);
    setError(null);
    setStages([]);
    setRunning(true);
    setSource('live');
    try {
      const res = await fetch('api/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, body, model: status?.default_model }),
      });
      if (!res.ok || !res.body) {
        const j = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(j.error ?? `HTTP ${res.status}`);
      }
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl: number;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          if (!line.trim()) continue;
          const ev = JSON.parse(line) as { type: string } & Record<string, unknown>;
          if (ev.type === 'stage') setStages((p) => [...p, ev as unknown as StageEvent]);
          else if (ev.type === 'result') showResult(ev.run as TriageRun, 'live');
          else if (ev.type === 'error') throw new Error(String(ev.error));
        }
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
      fetch('api/status')
        .then((r) => (r.ok ? (r.json() as Promise<BackendStatus>) : null))
        .then(setStatus)
        .catch(() => {});
    }
  };

  const isRecordedSample = selected !== 'custom' && Boolean(data?.runs[selected]);
  const onRun = () => (live ? runLive() : replay());

  if (loadError) return <div className="fatal">{loadError}</div>;
  if (!data) return <div className="loading"><span className="spinner" /> Loading verified evidence…</div>;

  const g1 = data.gate1.receipt;

  return (
    <>
      <header className="topbar">
        <a className="brand" href="#top">
          <span className="logo">
            <I.ShieldCheck size={20} />
          </span>
          PrivateTriage
        </a>
        <nav>
          <a href="#triage">Triage</a>
          <a href="#tamper">Tamper lab</a>
          <a href="#refusals">Fail closed</a>
          <a href="#how">Trust model</a>
        </nav>
        <span className={`mode ${live ? 'mode-live' : 'mode-demo'}`} title={live ? 'This backend holds a NEAR AI Cloud key; reports are triaged live.' : 'Static guided demo: recorded genuine runs, re-verified by this build.'}>
          <span className="dot" />
          {live ? 'Live · NEAR AI Cloud' : 'Guided demo'}
          <span className="long">{live ? ` · ${status?.runs_remaining} runs left` : ' · recorded genuine evidence'}</span>
        </span>
      </header>

      <main id="top">
        <section className="hero">
          <div className="hero-glow" aria-hidden="true" />
          <div className="eyebrow">Confidential AI triage on NEAR AI Cloud</div>
          <h1>
            Attest before
            <br />
            you disclose.
          </h1>
          <p className="hero-lede">
            An unpublished vulnerability report is the most sensitive document a security team handles. PrivateTriage sends it to an AI analyst <strong>only after</strong> Intel TDX and NVIDIA confidential-computing hardware prove where the model runs — then proves the model enclave signed the exact analysis you read.
          </p>
          <div className="hero-cta">
            <a className="btn btn-primary" href="#triage">
              <I.Play size={16} /> {live ? 'Triage a report' : 'Replay a verified run'}
            </a>
            <a className="btn btn-ghost" href="#tamper">
              Try to break it <I.Arrow size={15} />
            </a>
          </div>
          <div className="hero-proof">
            <div className="hp">
              <span className="hp-k">Gate 1 · recorded real run, {new Date(g1.captured_at).toUTCString().slice(5, 22)} UTC</span>
              <span className="hp-v">
                <I.ShieldCheck size={15} /> 5 / 5 properties verified · {g1.properties.reduce((n, p) => n + p.checks.length, 0)} checks
              </span>
            </div>
            <div className="hp">
              <span className="hp-k">Model enclave signer</span>
              <span className="hp-v mono">{short(g1.signer?.address, 6)}</span>
            </div>
            <div className="hp">
              <span className="hp-k">GPU attestation</span>
              <span className="hp-v">
                {g1.model_tee?.gpu?.count}× NVIDIA {g1.model_tee?.gpu?.arch} · NRAS signed
              </span>
            </div>
            <div className="hp">
              <span className="hp-k">Reports stored server-side</span>
              <span className="hp-v">0</span>
            </div>
          </div>
        </section>

        <section id="triage" className="section workspace-section">
          <div className="workspace">
            <Composer
              samples={data.samples}
              selected={selected}
              onSelect={select}
              title={title}
              body={body}
              onTitle={setTitle}
              onBody={setBody}
              live={live}
              model={status?.default_model ?? data.runs[selected]?.model ?? 'Qwen/Qwen3.6-35B-A3B-FP8'}
              running={running}
              onRun={onRun}
              onReplay={replay}
              canReplay={isRecordedSample}
            />
            <Pipeline stages={stages} receipt={run?.receipt ?? null} running={running} source={source} />
          </div>
          {error ? (
            <div className="error card">
              <I.Alert size={18} /> {error} <span className="muted">Nothing was marked as verified.</span>
            </div>
          ) : null}

          {run ? (
            <div className="results" ref={resultsRef}>
              <VerdictBanner run={run} />
              <div className="tabs" role="tablist">
                {(
                  [
                    ['analysis', 'AI analysis'],
                    ['verification', 'Verification'],
                    ['evidence', 'Evidence & export'],
                  ] as const
                ).map(([k, label]) => (
                  <button key={k} type="button" role="tab" aria-selected={tab === k} className={`tab ${tab === k ? 'on' : ''}`} onClick={() => setTab(k)}>
                    {label}
                  </button>
                ))}
              </div>
              <div className="tab-panel card">
                {tab === 'analysis' ? <AnalysisView run={run} /> : null}
                {tab === 'verification' ? <VerificationView receipt={run.receipt} /> : null}
                {tab === 'evidence' ? (
                  <EvidenceView run={run} title={title} evidence={run.evidence ?? null} evidenceUrl={run.evidence_file ?? null} />
                ) : null}
              </div>
            </div>
          ) : null}
        </section>

        <TamperLab results={data.tamper.results} baseLabel={data.samples.find((s) => s.id === data.tamper.base)?.label ?? data.tamper.base} />
        <Refusals data={data} live={live} />
        <HowItWorks />
      </main>

      <footer className="footer">
        <div>
          <strong>PrivateTriage</strong> — confidential vulnerability triage on NEAR AI Cloud. NEAR Hackathon 2026 · Privacy &amp; Private AI.
        </div>
        <div className="muted small">
          All sample reports, products, accounts and transactions are fictional. Recorded runs are genuine NEAR AI Cloud inferences; their receipts are recomputed from archived evidence by this build. AI triage is a recommendation, not a verdict.
        </div>
      </footer>
    </>
  );
}
