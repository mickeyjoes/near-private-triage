import { type ReactNode, useState } from 'react';
import * as I from './icons.tsx';
import type { CheckStatus, Verdict } from './types.ts';

export const short = (h: string | null | undefined, n = 6) => (h ? (h.length > 2 * n + 2 ? `${h.slice(0, n + (h.startsWith('0x') ? 2 : 0))}…${h.slice(-n)}` : h) : '—');

export function VerdictIcon({ v, size = 18 }: { v: Verdict; size?: number }) {
  if (v === 'VERIFIED') return <I.ShieldCheck size={size} />;
  if (v === 'FAILED') return <I.ShieldX size={size} />;
  return <I.ShieldQ size={size} />;
}

const VERDICT_TEXT: Record<Verdict, string> = { VERIFIED: 'Verified', FAILED: 'Failed', UNVERIFIED: 'Unverified' };

/** Property-level badge. Always rendered next to the specific claim it qualifies. */
export function VerdictBadge({ v, compact }: { v: Verdict; compact?: boolean }) {
  return (
    <span className={`badge badge-${v.toLowerCase()}`}>
      <VerdictIcon v={v} size={compact ? 14 : 15} />
      {VERDICT_TEXT[v]}
    </span>
  );
}

export function StatusGlyph({ s }: { s: CheckStatus }) {
  return (
    <span className={`glyph glyph-${s}`} aria-label={s}>
      {s === 'pass' ? <I.Check size={13} /> : s === 'fail' ? <I.X size={13} /> : <I.Question size={13} />}
    </span>
  );
}

export function Pill({ children, tone = 'neutral', title }: { children: ReactNode; tone?: string; title?: string }) {
  return (
    <span className={`pill pill-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <code className="mono" title={title}>
      {children}
    </code>
  );
}

export function CopyHash({ value, n = 8, label }: { value: string | null | undefined; n?: number; label?: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="muted">—</span>;
  return (
    <button
      type="button"
      className="hash"
      title={`${label ? label + ': ' : ''}${value} (click to copy)`}
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
    >
      <span>{short(value, n)}</span>
      {copied ? <I.Check size={12} /> : <I.Copy size={12} />}
    </button>
  );
}

export function SectionHead({ eyebrow, title, children }: { eyebrow: string; title: string; children?: ReactNode }) {
  return (
    <div className="section-head">
      <div className="eyebrow">{eyebrow}</div>
      <h2>{title}</h2>
      {children ? <p className="lede">{children}</p> : null}
    </div>
  );
}

export function Disclosure({ summary, children, defaultOpen }: { summary: ReactNode; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(Boolean(defaultOpen));
  return (
    <div className={`disclosure ${open ? 'open' : ''}`}>
      <button type="button" className="disclosure-summary" aria-expanded={open} onClick={() => setOpen(!open)}>
        <I.Chevron size={15} className="chev" />
        {summary}
      </button>
      {open ? <div className="disclosure-body">{children}</div> : null}
    </div>
  );
}
