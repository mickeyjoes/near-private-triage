// Intel TDX quote verification via Phala's dcap-qvl (Apache-2.0).
// Collateral is fetched from Intel's own PCS (not a third-party cache) and is
// returned so it can be archived for later offline re-verification.
import dcap from '@phala/dcap-qvl';
import { EvidenceError, hexToBytes, toHex } from './bytes.ts';

export const INTEL_PCS_URL: string = dcap.INTEL_PCS_URL;

export interface QuoteFacts {
  reportType: string;
  tcbStatus: string;
  advisoryIds: string[];
  reportData: Buffer; // 64 bytes, read from the verified quote
  mrConfigId: Buffer; // 48 bytes
  mrTd: Buffer;
  rtMr0: Buffer;
  rtMr1: Buffer;
  rtMr2: Buffer;
  rtMr3: Buffer;
  tdAttributes: Buffer;
  debug: boolean;
}

export type Collateral = Record<string, unknown>;

export async function fetchCollateral(quoteHex: string, pcsUrl = INTEL_PCS_URL): Promise<Collateral> {
  const quote = hexToBytes(quoteHex, 'intel_quote');
  return (await dcap.getCollateral(pcsUrl, quote)) as unknown as Collateral;
}

/**
 * Cryptographically verify a TDX quote against collateral at `nowSecs`.
 * Throws EvidenceError('quote_invalid') when the quote does not verify.
 */
export function verifyQuote(quoteHex: string, collateral: Collateral, nowSecs: number): QuoteFacts {
  const quote = hexToBytes(quoteHex, 'intel_quote');
  let verified;
  try {
    verified = dcap.verify(quote, collateral as unknown as Parameters<typeof dcap.verify>[1], nowSecs);
  } catch (err) {
    throw new EvidenceError('quote_invalid', `TDX quote failed verification: ${(err as Error).message}`);
  }
  const report = verified.report;
  const td = report.asTd10() ?? report.asTd15()?.base ?? report.asTd15Ex()?.base.base ?? null;
  if (!td) throw new EvidenceError('quote_invalid', `expected a TDX quote, got ${report.type}`);
  const b = (u: Uint8Array) => Buffer.from(u);
  return {
    reportType: report.type,
    tcbStatus: String(verified.status),
    advisoryIds: [...(verified.advisory_ids ?? [])],
    reportData: b(td.reportData),
    mrConfigId: b(td.mrConfigId),
    mrTd: b(td.mrTd),
    rtMr0: b(td.rtMr0),
    rtMr1: b(td.rtMr1),
    rtMr2: b(td.rtMr2),
    rtMr3: b(td.rtMr3),
    tdAttributes: b(td.tdAttributes),
    debug: (td.tdAttributes[0]! & 1) === 1,
  };
}

export function quoteFactsSummary(f: QuoteFacts): Record<string, string | string[]> {
  return {
    report_type: f.reportType,
    tcb_status: f.tcbStatus,
    advisory_ids: f.advisoryIds,
    mr_td: toHex(f.mrTd),
    rtmr0: toHex(f.rtMr0),
    rtmr1: toHex(f.rtMr1),
    rtmr2: toHex(f.rtMr2),
    rtmr3: toHex(f.rtMr3),
    mr_config_id: toHex(f.mrConfigId),
    report_data: toHex(f.reportData),
    td_attributes: toHex(f.tdAttributes),
  };
}
