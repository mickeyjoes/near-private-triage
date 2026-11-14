// Who produced the analysis? The UI and exports attribute content to the attested
// model enclave ONLY when the receipt proves it (delta review D1, 2026-11-14).
// A response that was received but not authenticated is labelled as such, and a
// signer address that did not verify is a "claimed" signer, never "the enclave key".
// Pure functions, so the wording is regression-tested without a browser.
import type { Receipt } from './types.ts';

/**
 * True only if the response signature verified AND the whole receipt verified:
 * a key is "the attested model enclave's key" only if that attestation passed.
 */
export function responseAuthenticated(r: Receipt): boolean {
  return r.verdict === 'VERIFIED' && r.properties.some((p) => p.id === 'response_signature' && p.verdict === 'VERIFIED');
}

export interface Attribution {
  ok: boolean;
  /** One-line note above the analysis. */
  analysis: string;
  /** Suffix on the model-reasoning disclosure. */
  reasoning: string;
  /** Prefix for any displayed signer address. */
  signerPrefix: string;
}

export function attribution(r: Receipt): Attribution {
  const ok = responseAuthenticated(r);
  return ok
    ? {
        ok,
        analysis: 'AI-generated triage recommendation, parsed from the signed response. Treat as a second opinion for a human analyst — the cryptographic checks cover execution, not judgement.',
        reasoning: 'part of the signed response',
        signerPrefix: '',
      }
    : {
        ok,
        analysis: 'AI-generated text from a received response whose authenticity is NOT verified — no valid signature from an attested model enclave covers it. Do not rely on it.',
        reasoning: 'part of the received response · authenticity not verified',
        signerPrefix: 'claimed, unverified · ',
      };
}
