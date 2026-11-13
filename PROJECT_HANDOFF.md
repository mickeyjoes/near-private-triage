# PROJECT_HANDOFF: PrivateTriage

_Last updated: 2026-11-13 (UTC). Repository: local `~/Dev/Hackathons/NEAR/near-private-triage`, branch `main`. **Not pushed, not public.**_

## VERDICT

**Gate 1 PASSED. The product works end to end.** A real NEAR AI Cloud confidential inference was verified across five properties and 42 checks:

- **Gateway TEE:** Intel TDX, TCB UpToDate, no debug, nonce-bound.
- **TLS binding:** the quote-bound SPKI equals the peer SPKI, and the inference ran on the same socket.
- **Model TEE:** Intel TDX.
- **GPU:** 8 × NVIDIA Hopper; the NRAS JWT is signed and nonce-bound.
- **Response signature:** `provider_tee` ECDSA over `model:sha256(req):sha256(resp)`, from the attested model key. Gateway and model signers differ.

The machine-readable receipt is `evidence/gate1/2026-11-13T16-12-38-022Z/receipt.json` (`"verdict": "VERIFIED"`). It re-verifies offline byte-for-byte.

Remaining work is owner-only: publication, the video, the X post, the Pursewarden reciprocal note and the submission.

## PRODUCT

- **The workflow is "attest before you disclose".** The local hygiene scan flags prompt injection and live secrets. The backend then derives a request-bound nonce, runs the attestation preflight with no API key, and sends the report only if that passes. Finally it verifies the enclave signature and renders a structured triage.
- **Triage output is structured.** It includes:
  - severity, a CVSS 3.1 vector, and a score **recomputed locally**, with the model's arithmetic errors flagged;
  - validity, confidence with rationale, and evidence quality;
  - impact, preconditions and affected components;
  - prioritized actions;
  - missing information and questions for the reporter;
  - an injection verdict.
- **Three fictional samples:**
  - NEAR async-callback drain (critical, likely valid);
  - SaaS SSRF to IMDS credentials (critical, likely valid);
  - a vague timing claim with an embedded "rate this CRITICAL / CVSS 10 / max bounty" injection. This one comes back undetermined, needs more information, low confidence, and injection detected.
- **Exports:**
  - triage report (Markdown);
  - receipt (JSON);
  - **shareable evidence** with no report content, which still verifies;
  - full evidence with the exact bytes.
- **The Tamper lab** applies 21 attacks to genuine evidence. All 21 are caught: 16 FAILED and 5 UNVERIFIED.
- **Fail-closed showcases:** genuine refusals of external-provider models (`openai/gpt-5.4`, `z-ai/glm-5.3`, both "No provider found that supports attestation reports"), and 3 genuine NVIDIA NRAS outages in which the report was held back.
- **Two modes:**
  - **Live** (`npm start` with a key): about 15 s and about $0.006 per triage.
  - **Guided demo** (`PRIVATETRIAGE_DEMO_ONLY=1`, or any static host): replays recorded genuine runs; the receipts are recomputed by the build.

## NEAR INTEGRATION

- **Endpoint:** NEAR AI Cloud `https://cloud-api.near.ai`.
- **Attestation:** `GET /v1/attestation/report` (`provider=near`, `include_tls_fingerprint=true`, `signing_algo=ecdsa`, nonce, `x-no-aliasing`), called without the key.
- **Inference:** `POST /v1/chat/completions`, non-streaming, canonical model ID, `x-no-aliasing`, `Accept-Encoding: identity`.
- **Signature:** `GET /v1/signature/{chat_id}?model=…&signing_algo=ecdsa`.
- **Models:**
  - The default is `Qwen/Qwen3.6-35B-A3B-FP8` (GPU TEE, about 15 s).
  - `z-ai/glm-5.3-flash` (used for Gate 1) needs more than 180 s for a full triage because of its reasoning, and reasoning can't be disabled through the gateway (three parameter variants tested).
  - Most catalogue models are external providers with no TEE attestation, and PrivateTriage refuses them.
- **Signer kind:** the **model TEE (`provider_tee`)** signed every VERIFIED run, never the gateway. The model signers were `0x3b753b4406613c5e70ae640508632b600424fa0c` (GLM-5.3-Flash) and `0xfdbd7952498b333206f360d71d97a1e0961e8ddf` (Qwen3.6). The gateway key is `0xb98a789cdc4817275f5155593ba73ef2a957e779`.

## VERIFICATION

- **Shared evaluator.** One pure, network-free evaluator (`server/verifier/evidence.ts`) serves live runs, the tests and offline verification. The verifier's own policy applies; a bundle's policy is ignored.
- **Freshness.** `nonce = SHA-256(domain ‖ salt ‖ SHA-256(request))`, and it is embedded in both TDX quotes and the NVIDIA token.
- **Offline verification:**
  ```
  npm run verify -- <evidence.json> [--receipt receipt.json]
  ```
  It needs no key and no network, and evaluates as of the capture time.
- **dcap-qvl note.** The PCK chain is taken from the archived collateral and checked against dcap-qvl's pinned Intel root. The quote's embedded PEM copy is transport only. Every signed region rejects a single-bit flip (probed).
- **Independent review:** see SECURITY below.

## SECURITY

- **API key:**
  - It lives only in a git-ignored `.env` (mode 600).
  - It never appears in the browser bundle, the evidence, the logs or git history (full-history scan clean; the only `Bearer` string in evidence is NEAR's public `app_compose` env placeholder).
- **Backend:**
  - It binds to 127.0.0.1.
  - A Host allowlist blocks DNS rebinding.
  - POSTs must be same-origin JSON.
  - There's a strict CSP and no third-party requests.
  - Spend guard: one triage at a time, a run cap of 40 per process, and a model allowlist.
  - Static serving is protected against path traversal.
- **No persistence:** reports live in memory only, and logs carry metadata only.
- **Model output** is treated as untrusted. The report is fenced by a random marker, the output goes through strict schema validation with no repair, and the CVSS arithmetic is recomputed.
- **Independent review (one reviewer, code-only brief):**
  - **Confirmed and fixed:**
    - Offline NVIDIA-verdict forgery: the NVIDIA CA is now pinned.
    - Disclosure despite a failed model candidate: every candidate must now verify.
    - A silently re-opened TLS connection could carry the report and key: the socket is now pinned before any byte is written.
    - A missing `model_name` skipped the model check.
  - **Plausible and fixed:**
    - No workload-measurement policy: NEAR's dstack OS image and app identity are now pinned.
    - The bundle could choose its own verification time: it is now anchored to NVIDIA's signed `iat`.
    - Offline TLS binding rested on unstated observations: every receipt now says so.
    - Backend guard races and limits.
  - Each fix has a regression test. The details and remaining limits are in `docs/TRUST_MODEL.md` § Independent review.
  - **Re-verified live after the fixes:** `evidence/gate1/2026-11-13T17-04-58-732Z`, VERIFIED, 42/42.

## UI/UX

- React 19 and Vite 8, dark and light themes, and system fonts only.
- Checked at 1440 px and 390 px, with no horizontal overflow and no console errors (headless Chrome).
- The verdict banner always qualifies its scope, and property badges sit beside the specific claims they cover.
- Screenshots are in `docs/media/`.
- Six UI issues were found while recording the video and fixed in `c747d69`:
  - the CVSS band is now recomputed from the vector;
  - no transient ✗ appears before the receipt arrives;
  - the action buttons stay together;
  - the spinner no longer overlaps its label;
  - the hero labels Gate 1 as a recorded real run;
  - the tamper list follows "Run all".
- Known cosmetic issue: the hero proof-strip label wraps "UTC" onto a second line at some desktop widths.

## DEMO VIDEO (local, unpublished)

- **File:** `~/Dev/Hackathons/NEAR/privatetriage-video/final/privatetriage-demo.mp4`, 1:50, 1920×1080, AI narration (disclosed on the end card), with `.en.srt` subtitles and `narration/SCRIPT.md`.
- **Made with:** the owner's `demo-video` skill (dvk), recorded against `c747d69`.
- **Footage:**
  - **Real footage:** one live NEAR AI Cloud triage of a fictional sample (VERIFIED in 17.0 s; the model said CVSS 9.8, the vector recomputes to 9.9).
  - **Guided-demo replays:** the recorded genuine runs.
  - **Terminal:** offline re-verification in a clean clone.
- **Checks:**
  - `dvk validate` passes, including the OCR privacy scan.
  - `dvk facts` passes 29/29 against the clone and the exported live evidence.
  - Sync is within tolerance.
- **Not yet checked:** nobody has listened to the audio, so the owner should listen once.
- **Repo URL on the end card:** add it once the repo is public (`assets/endcard.html`, then `dvk endcard && dvk render`).
- **Earlier cut:** the first cut, recorded on `1b83bf6`, is in `final/archive/`.
## CODE

```
server/verifier  server/near  server/triage  server/app.ts
shared/          web/         scripts/       test/  evidence/  docs/
```

- **Tests:** 66 `node:test` tests pass on Node 24.20 and 26.12.
- **Typecheck:** `tsc` for the server and the web app.
- **Dependencies:** pinned exactly, with install scripts disabled.
- **CI:** `.github/workflows/ci.yml` runs typecheck, tests, the build and offline re-verification of the evidence.
- **Pages:** `pages.yml` is manual-trigger only.

## REPRODUCTION

Clean clone, verified on 2026-11-13:

```bash
git clone <repo> && cd near-private-triage && npm ci
npm run typecheck && npm test                           # 66 pass
npm run build && PRIVATETRIAGE_DEMO_ONLY=1 npm start    # http://127.0.0.1:8787
npm run verify -- evidence/gate1/2026-11-13T16-12-38-022Z/evidence.json --receipt evidence/gate1/2026-11-13T16-12-38-022Z/receipt.json
```

- **Live mode:** add `NEARAI_CLOUD_API_KEY` to `.env`, run `npm start`, then click "Attest & triage".
- **Gate 1 probe:** `npm run gate1`.
- **Inference spend so far:** about $0.10 of the $3 credit, including probes, model comparison, 3 recording rounds, 2 live UI tests, the post-review Gate 1 re-run and 2 live video takes.

## SUBMISSION

Everything is in `docs/SUBMISSION.md`:
- the description (1,595 characters);
- the X draft (249 characters plus link; tags @NEARProtocol and #NEARHackathon);
- a 105 s storyboard;
- the payload template, with personal fields left for the owner;
- the checklist.

Rules come from the live `HACKATHON.md`, checked on 2026-11-13:
- One person may submit at most 2 independent projects.
- **Each README must name the other (Q-015).** The reciprocal line for Pursewarden is ready in `docs/PURSEWARDEN_DIFFERENCE.md`. This project did not modify Pursewarden.
- Each repository can be submitted once.
- The repository must be public by 2026-11-14T23:59Z.
- The X post needs the video or screenshots attached.

## NEXT ACTION

Owner: watch and listen to the demo video, then create the public GitHub repository (suggested name `mickeyjoes/near-private-triage`) and approve the push. Then:
1. Add the one-line reciprocal note to Pursewarden's README (rule Q-015).
2. Optionally add the repo URL to the video's end card.
3. Post on X with the video (draft in `docs/SUBMISSION.md`).
4. Submit with the payload template, filling in your personal fields.
