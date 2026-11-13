// Minimal .env loader (no dependency). Reads NEARAI_CLOUD_API_KEY from the
// process environment first, then from ./.env. Never prints the value.
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export function loadApiKey(root = process.cwd()): string | null {
  const fromEnv = process.env.NEARAI_CLOUD_API_KEY;
  if (fromEnv && fromEnv.trim()) return fromEnv.trim();
  const p = resolve(root, '.env');
  if (!existsSync(p)) return null;
  for (const line of readFileSync(p, 'utf8').split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?NEARAI_CLOUD_API_KEY\s*=\s*(.*)\s*$/.exec(line);
    if (m) {
      const v = m[1]!.replace(/^(['"])(.*)\1$/, '$2').trim();
      if (v) return v;
    }
  }
  return null;
}
