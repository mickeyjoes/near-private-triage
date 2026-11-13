// Byte/hex helpers. Every decoder is strict: malformed input throws instead of
// being silently coerced, so a garbled field can never compare "equal".
import { createHash, timingSafeEqual } from 'node:crypto';

export class EvidenceError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = 'EvidenceError';
  }
}

const HEX_RE = /^[0-9a-fA-F]*$/;

/** Decode hex (optional 0x prefix). Throws on odd length / non-hex / wrong size. */
export function hexToBytes(value: unknown, label: string, expectedBytes?: number): Buffer {
  if (typeof value !== 'string') throw new EvidenceError('malformed', `${label} must be a hex string`);
  const hex = value.replace(/^0x/i, '');
  if (!HEX_RE.test(hex) || hex.length % 2 !== 0) {
    throw new EvidenceError('malformed', `${label} is not valid hexadecimal`);
  }
  const bytes = Buffer.from(hex, 'hex');
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    throw new EvidenceError('malformed', `${label} must be ${expectedBytes} bytes, got ${bytes.length}`);
  }
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function sha256(...parts: Array<Uint8Array | string>): Buffer {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

export function sha384(...parts: Array<Uint8Array | string>): Buffer {
  const h = createHash('sha384');
  for (const p of parts) h.update(p);
  return h.digest();
}

export function sha256Hex(data: Uint8Array | string): string {
  return sha256(data).toString('hex');
}

/** Constant-time equality that is false (not throwing) on length mismatch. */
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Parse a value that may be JSON text or an already-decoded object. */
export function jsonOrValue(value: unknown, label: string): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    throw new EvidenceError('malformed', `${label} is not valid JSON`);
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
