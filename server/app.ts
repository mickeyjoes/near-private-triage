// PrivateTriage local backend (no framework, no dependencies beyond the verifier).
//
// Security posture:
// - Binds to 127.0.0.1 by default. Host-header allowlist defeats DNS rebinding;
//   POSTs require JSON + same-origin, so other sites cannot drive the API.
// - The NEAR AI Cloud API key never leaves this process (never sent to the browser).
// - Reports are processed in memory and returned to the submitter only. Nothing is
//   persisted, and report/response content is never logged.
// - Spend guard: one triage at a time and a per-process run cap.
//
// Usage: node server/app.ts   (PORT, HOST, PRIVATETRIAGE_MAX_RUNS, PRIVATETRIAGE_ALLOWED_HOSTS)
import { createReadStream, existsSync, statSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { MAX_REPORT_CHARS, MAX_TITLE_CHARS, TRIAGE_MODELS, DEFAULT_MODEL } from './triage/triage.ts';
import { runTriage } from './triage/run.ts';
import { loadApiKey } from './env.ts';
import { runConfidentialCompletion } from './near/confidentialCompletion.ts';
import { evaluateBundle, type EvidenceBundle } from './verifier/evidence.ts';
import { SCENARIOS } from './verifier/tamper.ts';

const ROOT = resolve(import.meta.dirname, '..');
const WEB = join(ROOT, 'web', 'dist');
const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? '127.0.0.1';
const MAX_RUNS = Number(process.env.PRIVATETRIAGE_MAX_RUNS ?? 40);
// PRIVATETRIAGE_DEMO_ONLY=1 serves the read-only guided demo even if a key exists.
const apiKey = process.env.PRIVATETRIAGE_DEMO_ONLY === '1' ? null : loadApiKey(ROOT);
const allowedHosts = new Set([
  `localhost:${PORT}`,
  `127.0.0.1:${PORT}`,
  `[::1]:${PORT}`,
  ...(process.env.PRIVATETRIAGE_ALLOWED_HOSTS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
]);

let runsStarted = 0;
let inFlight = false;

const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
};

function send(res: ServerResponse, status: number, body: unknown) {
  const data = JSON.stringify(body);
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(data);
}

async function readJson(req: IncomingMessage, limit: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw Object.assign(new Error('Request body too large'), { status: 413 });
    chunks.push(chunk as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw Object.assign(new Error('Body is not valid JSON'), { status: 400 });
  }
}

function guard(req: IncomingMessage): string | null {
  const host = req.headers.host ?? '';
  if (!allowedHosts.has(host)) return 'Host not allowed';
  if (req.method === 'POST') {
    if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) return 'Content-Type must be application/json';
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== `http://${host}` && origin !== `https://${host}`) return 'Cross-origin request refused';
  }
  return null;
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
};

function serveStatic(req: IncomingMessage, res: ServerResponse) {
  if (!existsSync(WEB)) {
    res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain' });
    res.end('Frontend not built. Run: npm run build');
    return;
  }
  const url = new URL(req.url ?? '/', 'http://x');
  let rel = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, '');
  let file = join(WEB, rel);
  if (!file.startsWith(WEB)) file = join(WEB, 'index.html');
  if (!existsSync(file) || statSync(file).isDirectory()) {
    rel = 'index.html';
    file = join(WEB, rel);
  }
  const immutable = file.includes(`${join(WEB, 'assets')}`);
  res.writeHead(200, {
    ...SECURITY_HEADERS,
    'Content-Type': MIME[extname(file)] ?? 'application/octet-stream',
    'Cache-Control': immutable ? 'public, max-age=31536000, immutable' : 'no-cache',
  });
  createReadStream(file).pipe(res);
}

const isBundle = (v: unknown): v is EvidenceBundle =>
  typeof v === 'object' && v !== null && (v as { schema?: unknown }).schema === 'privatetriage.evidence/v1';

async function handle(req: IncomingMessage, res: ServerResponse) {
  const refusal = guard(req);
  if (refusal) return send(res, 403, { error: refusal });
  const path = new URL(req.url ?? '/', 'http://x').pathname;

  if (req.method === 'GET' && path === '/api/status') {
    return send(res, 200, {
      live: Boolean(apiKey) && runsStarted < MAX_RUNS,
      key_configured: Boolean(apiKey),
      default_model: DEFAULT_MODEL,
      models: TRIAGE_MODELS,
      runs_remaining: Math.max(0, MAX_RUNS - runsStarted),
      busy: inFlight,
      persistence: 'none',
    });
  }

  if (req.method === 'POST' && path === '/api/triage') {
    if (!apiKey) return send(res, 503, { error: 'No NEAR AI Cloud API key is configured on this backend. Guided demo only.' });
    if (runsStarted >= MAX_RUNS) return send(res, 429, { error: 'Run limit for this backend process reached (spend guard).' });
    if (inFlight) return send(res, 429, { error: 'Another triage is in progress. Try again in a few seconds.' });
    const body = (await readJson(req, 128 * 1024)) as Record<string, unknown>;
    const title = typeof body.title === 'string' ? body.title.trim() : '';
    const report = typeof body.body === 'string' ? body.body : '';
    const model = typeof body.model === 'string' ? body.model : DEFAULT_MODEL;
    if (!title || title.length > MAX_TITLE_CHARS) return send(res, 400, { error: `Title is required (max ${MAX_TITLE_CHARS} characters).` });
    if (report.trim().length < 40 || report.length > MAX_REPORT_CHARS)
      return send(res, 400, { error: `Report must be 40–${MAX_REPORT_CHARS} characters.` });
    if (!TRIAGE_MODELS.includes(model)) return send(res, 400, { error: 'Model is not on the confidential triage allowlist.' });

    inFlight = true;
    runsStarted++;
    res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
    const emit = (o: unknown) => res.write(JSON.stringify(o) + '\n');
    const t0 = Date.now();
    try {
      const run = await runTriage({ apiKey, title, body: report, model, onStage: (e) => emit({ type: 'stage', ...e }) });
      emit({ type: 'result', run });
      // Metadata only: never the report, the response, or the key.
      console.log(`[triage] ${new Date().toISOString()} model=${model} verdict=${run.receipt.verdict} disclosed=${run.receipt.disclosed} output=${run.outcome?.status ?? 'none'} ${Date.now() - t0}ms`);
    } catch (e) {
      emit({ type: 'error', error: 'Triage pipeline error. Nothing was verified.' });
      console.log(`[triage] ${new Date().toISOString()} pipeline error: ${(e as Error).name}`);
    } finally {
      inFlight = false;
      res.end();
    }
    return;
  }

  if (req.method === 'POST' && path === '/api/preflight') {
    // Attestation only. No API key is used and no report is sent; free to run.
    const body = (await readJson(req, 4 * 1024)) as Record<string, unknown>;
    const model = typeof body.model === 'string' ? body.model : '';
    if (!/^[A-Za-z0-9._/-]{1,100}$/.test(model)) return send(res, 400, { error: 'Invalid model id.' });
    const r = await runConfidentialCompletion({
      apiKey: '',
      model,
      requestBody: Buffer.from(JSON.stringify({ model, messages: [{ role: 'user', content: 'preflight (never sent)' }] })),
      preflightOnly: true,
    });
    return send(res, 200, { receipt: r.receipt, blocked_reason: r.bundle.blocked_reason ?? null });
  }

  if (req.method === 'POST' && path === '/api/verify') {
    const body = await readJson(req, 16 * 1024 * 1024);
    if (!isBundle(body)) return send(res, 400, { error: 'Not a privatetriage.evidence/v1 bundle.' });
    try {
      return send(res, 200, { receipt: evaluateBundle(body).receipt });
    } catch {
      return send(res, 200, { error: 'Bundle is malformed; nothing verified.' });
    }
  }

  if (req.method === 'POST' && path === '/api/tamper') {
    const body = (await readJson(req, 16 * 1024 * 1024)) as Record<string, unknown>;
    const s = SCENARIOS.find((x) => x.id === body.scenario);
    if (!s || !isBundle(body.evidence) || !isBundle(body.other)) return send(res, 400, { error: 'Unknown scenario or invalid bundles.' });
    try {
      return send(res, 200, { receipt: evaluateBundle(s.apply(body.evidence, { other: body.other })).receipt });
    } catch {
      return send(res, 200, { error: 'Scenario could not be applied to this bundle.' });
    }
  }

  if (path.startsWith('/api/')) return send(res, 404, { error: 'Not found' });
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Method not allowed' });
  serveStatic(req, res);
}

const server = createServer((req, res) => {
  handle(req, res).catch((e: Error & { status?: number }) => {
    if (!res.headersSent) send(res, e.status ?? 500, { error: e.status ? e.message : 'Internal error' });
    else res.end();
  });
});
server.requestTimeout = 300_000;
server.listen(PORT, HOST, () => {
  console.log(`PrivateTriage on http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}  ·  live inference: ${apiKey ? 'enabled' : 'disabled (no key; guided demo only)'}  ·  run cap ${MAX_RUNS}`);
});
