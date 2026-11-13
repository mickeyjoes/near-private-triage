// Shared verification result types.
//
// Status semantics (fail-closed):
//   pass  – the check ran and the evidence satisfied it
//   fail  – the check ran and the evidence contradicted it (tamper, mismatch, bad signature)
//   unavailable – the check could not run (missing evidence, network/timeout, unsupported kind)
// A property is VERIFIED only when every required check passed. Any `fail` makes it FAILED;
// otherwise any `unavailable` makes it UNVERIFIED. There is no partial "verified".

export type CheckStatus = 'pass' | 'fail' | 'unavailable';
export type Verdict = 'VERIFIED' | 'FAILED' | 'UNVERIFIED';

export interface Check {
  id: string;
  label: string;
  status: CheckStatus;
  detail: string;
}

export interface Property {
  id: PropertyId;
  title: string;
  verdict: Verdict;
  /** What a VERIFIED result of this property means — and only that. */
  statement: string;
  checks: Check[];
}

export type PropertyId =
  | 'gateway_tee'
  | 'model_tee'
  | 'gpu_tee'
  | 'tls_binding'
  | 'response_signature';

export function verdictOf(checks: Check[]): Verdict {
  if (checks.length === 0) return 'UNVERIFIED';
  if (checks.some((c) => c.status === 'fail')) return 'FAILED';
  if (checks.some((c) => c.status !== 'pass')) return 'UNVERIFIED';
  return 'VERIFIED';
}

export function combineVerdicts(verdicts: Verdict[]): Verdict {
  if (verdicts.length === 0) return 'UNVERIFIED';
  if (verdicts.includes('FAILED')) return 'FAILED';
  if (verdicts.includes('UNVERIFIED')) return 'UNVERIFIED';
  return 'VERIFIED';
}

export class CheckList {
  readonly checks: Check[] = [];
  pass(id: string, label: string, detail: string): void {
    this.checks.push({ id, label, status: 'pass', detail });
  }
  fail(id: string, label: string, detail: string): void {
    this.checks.push({ id, label, status: 'fail', detail });
  }
  unavailable(id: string, label: string, detail: string): void {
    this.checks.push({ id, label, status: 'unavailable', detail });
  }
  expect(cond: boolean, id: string, label: string, okDetail: string, badDetail: string): boolean {
    if (cond) this.pass(id, label, okDetail);
    else this.fail(id, label, badDetail);
    return cond;
  }
  get verdict(): Verdict {
    return verdictOf(this.checks);
  }
}

/** Signing identity: always compared together with its algorithm. */
export interface SignerIdentity {
  signing_algo: 'ecdsa' | 'ed25519';
  signing_address: string;
}
