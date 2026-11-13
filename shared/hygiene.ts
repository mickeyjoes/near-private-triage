// Local pre-disclosure hygiene scan. Runs in the browser BEFORE anything is
// sent, and again on the backend. Deterministic and independent of the model:
// it flags (1) instructions aimed at an AI triage system and (2) material that
// looks like live credentials that should be redacted before disclosure.

export interface HygieneFinding {
  kind: 'injection' | 'secret';
  label: string;
  excerpt: string;
}

const INJECTION: [RegExp, string][] = [
  [/\bignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|prompts?|rules)\b/i, 'Asks the model to ignore its instructions'],
  [/\b(?:note|message|instructions?) (?:to|for) (?:the )?(?:ai|llm|model|assistant|triage (?:system|bot|model))\b/i, 'Addresses the AI triage system directly'],
  [/\b(?:classify|rate|score|mark|label) (?:this|it|the report) as\b/i, 'Dictates its own classification'],
  [/\bcvss(?: score)? (?:of )?10(?:\.0)?\b/i, 'Demands a maximum CVSS score'],
  [/\b(?:maximum|max|highest|full) (?:bounty|payout|reward)\b/i, 'Demands a payout outcome'],
  [/\b(?:you are now|act as|pretend to be|new role)\b/i, 'Attempts to change the model’s role'],
  [/\b(?:system prompt|reveal your (?:instructions|prompt))\b/i, 'References the system prompt'],
  [/\bdo not (?:mention|reveal|disclose) this (?:note|message|instruction)\b/i, 'Asks the model to hide an instruction'],
  [/<<<\s*END REPORT/i, 'Contains a fake report delimiter'],
];

const SECRETS: [RegExp, string][] = [
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, 'AWS access key ID'],
  [/-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, 'Private key block'],
  [/\bgh[pousr]_[A-Za-z0-9]{36,}\b/, 'GitHub token'],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}\b/, 'Slack token'],
  [/\bsk-[A-Za-z0-9_-]{24,}\b/, 'API secret key (sk-…)'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, 'JSON Web Token'],
  [/\bed25519:[1-9A-HJ-NP-Za-km-z]{60,}\b/, 'NEAR ed25519 private key'],
  [/\b(?:seed phrase|mnemonic)\s*[:=]/i, 'Wallet seed phrase'],
];

function excerpt(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 24);
  const end = Math.min(text.length, index + length + 24);
  return (start > 0 ? '…' : '') + text.slice(start, end).replace(/\s+/g, ' ') + (end < text.length ? '…' : '');
}

function redactExcerpt(text: string, index: number, length: number): string {
  const hit = text.slice(index, index + length);
  const masked = hit.length > 8 ? `${hit.slice(0, 4)}${'•'.repeat(Math.min(12, hit.length - 4))}` : '••••';
  return excerpt(text.slice(0, index) + masked + text.slice(index + length), index, masked.length);
}

export function scanReport(text: string): HygieneFinding[] {
  const out: HygieneFinding[] = [];
  for (const [re, label] of INJECTION) {
    const m = re.exec(text);
    if (m) out.push({ kind: 'injection', label, excerpt: excerpt(text, m.index, m[0].length) });
  }
  for (const [re, label] of SECRETS) {
    const m = re.exec(text);
    if (m) out.push({ kind: 'secret', label, excerpt: redactExcerpt(text, m.index, m[0].length) });
  }
  return out;
}
