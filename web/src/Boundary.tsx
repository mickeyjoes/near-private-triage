// "Fail closed" evidence (genuine refusals/outages) + trust boundary diagram.
import { useState } from 'react';
import * as I from './icons.tsx';
import type { DemoData, Receipt } from './types.ts';
import { SectionHead, VerdictBadge } from './ui.tsx';

export function Refusals({ data, live }: { data: DemoData; live: boolean }) {
  const [model, setModel] = useState('openai/gpt-5.4');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ receipt: Receipt; blocked_reason: string | null } | { error: string } | null>(null);
  const check = async () => {
    setBusy(true);
    setResult(null);
    try {
      const res = await fetch('api/preflight', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model }) });
      setResult(await res.json());
    } catch {
      setResult({ error: 'Backend unreachable.' });
    } finally {
      setBusy(false);
    }
  };
  return (
    <section id="refusals" className="section">
      <SectionHead eyebrow="Fail closed" title="No proof, no disclosure.">
        Most models on NEAR AI Cloud are proxied to external providers that run outside a TEE. PrivateTriage asks for hardware evidence first — and holds the report back whenever it can’t get it. These are genuine recorded refusals.
      </SectionHead>
      <div className="refusal-grid">
        {data.refusals.map((r) => (
          <div key={r.model} className="card refusal">
            <div className="refusal-head">
              <I.Ban size={18} />
              <code>{r.model}</code>
              <VerdictBadge v={r.receipt.verdict} compact />
            </div>
            <p className="small">{r.blocked_reason}</p>
            <div className="refusal-foot">
              <span className="sent-no">Report sent: no</span>
              <span className="muted small">{new Date(r.captured_at).toUTCString()}</span>
            </div>
          </div>
        ))}
        <div className="card refusal">
          <div className="refusal-head">
            <I.Gpu size={18} />
            <span>NVIDIA attestation outage</span>
            <VerdictBadge v="UNVERIFIED" compact />
          </div>
          <p className="small">
            During development NVIDIA’s attestation service was unreachable or timed out {data.outages.length} times. Each time the GPU verdict could not be confirmed, so the (fictional) report was held back before any request was made — the pipeline never “falls back” to sending.
          </p>
          <div className="refusal-foot">
            <span className="sent-no">Reports sent: {data.outages.filter((o) => o.transmission !== 'not_sent').length} of {data.outages.length}</span>
          </div>
        </div>
      </div>
      {live ? (
        <div className="card preflight">
          <div className="preflight-row">
            <label className="field inline">
              <span className="field-label">Check any model (free · attestation request only · no report is sent)</span>
              <input value={model} onChange={(e) => setModel(e.target.value)} spellCheck={false} />
            </label>
            <button type="button" className="btn btn-ghost" onClick={check} disabled={busy}>
              {busy ? <span className="spinner" /> : <I.Shield size={15} />} Run preflight
            </button>
          </div>
          {result ? (
            'error' in result ? (
              <p className="small">{result.error}</p>
            ) : (
              <div className="preflight-result">
                <VerdictBadge v={result.receipt.properties.find((p) => p.id === 'model_tee')?.verdict ?? result.receipt.verdict} />
                <span className="small">{result.blocked_reason ?? result.receipt.headline}</span>
              </div>
            )
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

export function HowItWorks() {
  return (
    <section id="how" className="section">
      <SectionHead eyebrow="Trust model" title="Exactly what is verified — and what isn’t.">
        Confidential inference is only as strong as the hops you can check. PrivateTriage verifies the hardware boundary NEAR AI Cloud exposes, binds it to your report, and is explicit about the rest.
      </SectionHead>
      <div className="flow card">
        <div className="flow-node">
          <I.Browser size={22} />
          <strong>Your browser</strong>
          <span>Local hygiene scan · exports</span>
        </div>
        <div className="flow-edge plain">
          <span>HTTP (localhost)</span>
        </div>
        <div className="flow-node trust">
          <I.Server size={22} />
          <strong>PrivateTriage backend</strong>
          <span>Holds API key · sees plaintext · verifies · writes no reports to disk</span>
        </div>
        <div className="flow-edge verified">
          <span>TLS key ∈ attested enclave · same socket</span>
        </div>
        <div className="flow-node tee">
          <I.Chip size={22} />
          <strong>Gateway TEE</strong>
          <span>Intel TDX · measured config · fresh nonce</span>
        </div>
        <div className="flow-edge unverified">
          <span>internal hop · not independently verified</span>
        </div>
        <div className="flow-node tee">
          <I.Gpu size={22} />
          <strong>Model TEE + GPUs</strong>
          <span>Intel TDX · NVIDIA CC (NRAS) · signs hashes</span>
        </div>
      </div>
      <div className="grid-3 explain">
        <div className="block">
          <h4>
            <I.Dice size={16} /> Request-bound challenge
          </h4>
          <p>The attestation nonce is SHA-256(domain ‖ random salt ‖ SHA-256(request)). The enclaves’ quotes embed it, so the evidence is fresh and committed to <em>this</em> report — not replayed from yesterday.</p>
        </div>
        <div className="block">
          <h4>
            <I.Gate size={17} /> Attest, then disclose
          </h4>
          <p>Attestation is fetched without the API key over a pinned TLS connection. Only if the gateway, every model enclave and its GPU evidence verify is the report sent — over that same connection, whose certificate key the gateway quote commits to. The signature fetch reuses it too; any request carrying the key is refused on any other connection. If a send fails, the receipt says “may have been sent”, never “withheld”.</p>
        </div>
        <div className="block">
          <h4>
            <I.Signature size={16} /> Model-enclave signature
          </h4>
          <p>
            Non-streaming, canonical model ID, <code>x-no-aliasing</code> — so the <em>model</em> TEE (not the gateway) signs <code>model:sha256(req):sha256(resp)</code>, where <code>req</code> is the whole serialized API request. The signer must match a model report verified before the request; instances of a model share that key.
          </p>
        </div>
        <div className="block">
          <h4>
            <I.ShieldX size={16} /> Fail-closed verdicts
          </h4>
          <p>Every check is pass, fail or unavailable. Any failure → FAILED. Anything missing → UNVERIFIED. Only all-pass across five properties yields a verified receipt, and the UI always says what it covers.</p>
        </div>
        <div className="block">
          <h4>
            <I.Terminal size={16} /> Offline re-verification
          </h4>
          <p>Evidence bundles archive Intel collateral, the raw GPU reports, NVIDIA’s platform and per-GPU tokens with their JWKS, and the signature. <code>npm run verify</code> recomputes the receipt byte-for-byte with no key and no network — a historical appraisal, not a current revocation check.</p>
        </div>
        <div className="block">
          <h4>
            <I.Eye size={16} /> Honest limits
          </h4>
          <p>Not end-to-end encrypted to the model (TLS ends in the gateway enclave; the gateway-to-model hop is NEAR’s). Not a no-retention guarantee. Not proof of which model instance answered. Not a correctness guarantee for the AI’s judgement. The backend you run sees plaintext.</p>
        </div>
      </div>
    </section>
  );
}
