# Submission kit

Everything below is a draft. **Nothing has been published, posted or submitted.** Each outward step needs the owner's explicit approval (see the checklist).

Live rules checked on 2026-11-13: https://nearhackathon.com/HACKATHON.md.
- One person may submit **up to 2 independent, disclosed projects**, and each README must name the other (Q-015).
- Each repository can be submitted once.
- The repository must be public by **2026-11-14T23:59:00Z**.
- The X post must say it was built at NEAR HACKATHON, tag **@NEARProtocol** and **#NEARHackathon**, and attach a video or screenshots.
- A local-only demo is acceptable with a video (Q-012). A hosted demo is a plus; keep it up until at least 2026-11-18.

## 1. "What they built" (20–2000 characters; this text is 1,866)

```
PrivateTriage: attest before you disclose.

Problem: an unpublished vulnerability report is the most sensitive document a security team handles, yet teams increasingly paste reports into hosted LLMs on trust.

Product (research prototype): PrivateTriage sends a report to an AI model on NEAR AI Cloud only after the gateway and model enclaves' evidence verifies. Per report it derives a fresh nonce from the request hash, fetches attestation over a pinned TLS connection, and verifies the gateway's Intel TDX quote (DCAP, TCB, NEAR's pinned OS image and app, RTMR3), that the TLS key lives inside that enclave, every model enclave's TDX quote, and the GPUs: device-signed reports plus NVIDIA's signed platform and per-GPU appraisals, all bound to the nonce. Only then is the report sent, on the same attested connection; the API key never travels on any other. The model enclave's provider_tee signature over SHA-256 of the exact request and response must come from a verified key, and the analysis shown is parsed from those signed bytes. The UI shows a structured triage (CVSS recomputed from the vector, injection attempts flagged) beside a fail-closed receipt that separates what is proven from what is not (AI correctness, retention, end-to-end encryption, serving instance).

Evidence: genuine recorded runs (Gate 1 plus three fictional reports) re-verify offline byte-for-byte with no API key. 26 tested attacks on genuine evidence (edited verdict, replayed attestation, forged signer, TLS interception, forged NVIDIA tokens, invented GPUs...) are all caught. External-provider models are refused before disclosure. 107 tests. Findings from an independent audit were fixed before release.

NEAR: NEAR AI Cloud private inference, TEE attestation and response-signature APIs (Privacy & Private AI track). Independent second project by the author of Pursewarden.
```

## 2. X post draft (270 of 280 characters as X counts them, since links count as 23; attach the video)

```
Built at NEAR HACKATHON: PrivateTriage, AI triage for unpublished vuln reports. It won't send a report until @NEARProtocol AI Cloud's Intel TDX + NVIDIA GPU attestation checks out, then verifies the model enclave signed the answer. #NEARHackathon https://github.com/mickeyjoes/near-private-triage
```

Optional tags per the rules: @NearLegion and @NearBuilders.

## 3. Demo video

`~/Dev/Hackathons/NEAR/privatetriage-video/final/privatetriage-demo.mp4` (local, unpublished; made with the dvk kit / `demo-video` skill).

- **First cut** (1:50, recorded at `c747d69`) is archived as `final/archive/privatetriage-demo-c747d69.*`. After the 2026-11-14 audit it is **no longer accurate**: it says "42 checks" and "21 attacks … each re-verified" (the Tamper lab reveals build-time results), shows the old "detected — and ignored" card, says the hardware "proves where the model runs", and its terminal scene mixes up two commits.
- **Corrected cut — produced 2026-11-14** (bounded correction, no new inference): 1:54.97, 1920×1080, H.264/AAC, `.en.srt` subtitles. The live NEAR AI Cloud segment (s01–s03) is kept as recorded, with corrected narration and lower thirds disclosing "RECORDED AT c747d69 (UI WORDING SINCE CORRECTED)" — that footage still shows the old banner wording and "42 checks" in the hero, which is not spoken. The guided-demo scenes (injection, Verification, Tamper lab, Fail closed) and the clean-clone terminal (`9a74df7`: 47 ✓, VERDICT: VERIFIED, receipt: MATCHES) are re-captured from the fixed build; the narration says 47 checks and 26 tested attacks (21 fail, 5 unverified) "computed when the site was built"; the end card says "Research prototype · not production-ready". Validation: codec, loudness (−16.1 LUFS), OCR privacy scan, on-screen facts, `dvk facts` and A/V sync all pass. Narration is AI voice (disclosed); **the owner should listen once** before posting. Script: `narration/SCRIPT.md` in the video project.

## 4. Hosted read-only demo (optional, owner decision)

The guided demo is a static site. `npm run build` produces `web/dist` with recorded evidence and no backend. With no `/api`, the app falls back to demo mode, so it can be hosted anywhere static, such as GitHub Pages. `.github/workflows/pages.yml` is prepared with **manual trigger only** (`workflow_dispatch`). Nothing is deployed until the owner enables Pages for the repo and runs it. Never deploy the live backend publicly with a key: it is designed for localhost. The strict CSP and other security headers come from `server/app.ts`; GitHub Pages does not apply them, so do not claim the static host inherits them, keep unrelated sensitive apps off the same origin, and inspect the built `web/dist` before deploying.

## 5. Submission payload (owner fills the placeholders; never guessed)

```json
{
  "requestId": "<uuid generated once; reuse on retry>",
  "projectName": "PrivateTriage",
  "leadName": "<owner>",
  "email": "<owner contact email>",
  "size": "1",
  "tracks": ["privacy"],
  "nearAddress": "<owner mainnet account>",
  "projectUrl": "https://github.com/mickeyjoes/near-private-triage",
  "demoUrl": "<X post URL>",
  "idea": "<section 1 text>",
  "consent": true
}
```

- `size` assumes a solo entry; the owner should confirm it.
- `tracks`: `privacy` is primary. `security` also arguably fits (vulnerability triage); the owner decides, since Pursewarden already uses `security`.
- Read the consent notice to the owner verbatim before sending: *"I agree that the organizers may use these details to review our submission and contact us about this hackathon."*

## 6. Release checklist

| Item | Status |
|---|---|
| Gate 1: real inference, fresh nonce, attestation, signature bound to the request, response and model; machine-readable VERIFIED | ✅ `evidence/gate1/2026-11-13T16-12-38-022Z` |
| Product: 3 fictional samples (one uncertain plus injection), structured triage, exports | ✅ |
| Negative tests: tampering, signer mismatch, invalid quote, stale challenge, unavailable evidence, corrupted response, non-TEE model, malformed output, prompt injection, forged/invented GPU evidence, credential on a replacement connection, failed-send state, altered demo analysis | ✅ 107/107 |
| Final independent audit (2026-11-14): F1–F4 fixed with regression tests, F5 annotated, wording corrected | ✅ branch `fix/final-audit` (CI green); ⏳ owner merges into `main` |
| Offline receipt reproduction (byte-identical) | ✅ `npm run verify` |
| UI checked at desktop (1440) and mobile (390); no horizontal overflow; no console errors | ✅ |
| Clean-checkout build (`git clone` → `npm ci` → typecheck → test → build) | ✅ (see PROJECT_HANDOFF) |
| Secret scan: tree, full git history, built bundle, evidence | ✅ no key material |
| README names Pursewarden (Q-015) | ✅ |
| **Pursewarden README names PrivateTriage (Q-015)** | ⏳ owner: add the line in docs/PURSEWARDEN_DIFFERENCE.md |
| Create the GitHub repository and push | ✅ https://github.com/mickeyjoes/near-private-triage (pushed 2026-11-14) |
| **Make the repository public** (required by 2026-11-14T23:59Z) | ⏳ owner |
| Demo video | ✅ corrected cut produced and validated (see §3); ⏳ owner listens and approves |
| Publish the X post | ⏳ owner |
| Optional: enable Pages and run the manual Pages workflow | ⏳ owner |
| Submit (one attempt per repo) | ⏳ owner confirms the exact payload |
