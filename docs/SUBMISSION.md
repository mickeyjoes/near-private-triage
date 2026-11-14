# Submission kit

Everything below is a draft. **Nothing has been published, posted or submitted.** Each outward step needs the owner's explicit approval (see the checklist).

Live rules checked on 2026-11-13: https://nearhackathon.com/HACKATHON.md.
- One person may submit **up to 2 independent, disclosed projects**, and each README must name the other (Q-015).
- Each repository can be submitted once.
- The repository must be public by **2026-11-14T23:59:00Z**.
- The X post must say it was built at NEAR HACKATHON, tag **@NEARProtocol** and **#NEARHackathon**, and attach a video or screenshots.
- A local-only demo is acceptable with a video (Q-012). A hosted demo is a plus; keep it up until at least 2026-11-18.

## 1. "What they built" (20–2000 characters; this text is 1,595)

```
PrivateTriage: attest before you disclose.

Problem: an unpublished vulnerability report is the most sensitive document a security team handles, yet teams increasingly paste reports into hosted LLMs on trust.

Product: PrivateTriage triages a report with an AI model on NEAR AI Cloud only after cryptographic proof of where that model runs. Per report it derives a fresh nonce from the request hash, fetches NEAR AI Cloud attestation over a pinned TLS connection, and verifies: the gateway's Intel TDX quote (DCAP, TCB, measured config, RTMR3); that the TLS key lives inside that enclave; the model's TDX quote; and NVIDIA's signed GPU confidential-computing verdict, all bound to the nonce. Only then is the report sent, on the same attested connection. The model enclave's provider_tee signature over SHA-256(request) and SHA-256(response) must come from the verified key. The UI shows a structured triage (CVSS recomputed from the vector, prompt injection flagged) beside a fail-closed receipt that separates what is proven from what is not (AI correctness, retention, end-to-end encryption).

Evidence: genuine recorded runs (Gate 1 plus three fictional reports) re-verify offline byte-for-byte with no API key. 21 attacks on genuine evidence (edited verdict, replayed attestation, forged signer, TLS interception, forged NVIDIA token...) are all caught. External-provider models are refused before disclosure. 66 tests.

NEAR: NEAR AI Cloud private inference, TEE attestation and response-signature APIs (Privacy & Private AI track). Independent second project by the author of Pursewarden.
```

## 2. X post draft (273 of 280 characters as X counts them, since links count as 23; attach the video)

```
Built at NEAR HACKATHON: PrivateTriage, AI triage for unpublished vuln reports. It sends nothing until @NEARProtocol AI Cloud proves where the model runs (Intel TDX + NVIDIA GPU attestation), then checks the enclave signed the answer. #NEARHackathon https://github.com/mickeyjoes/near-private-triage
```

Optional tags per the rules: @NearLegion and @NearBuilders.

## 3. Demo video

**Produced** (local, unpublished): `~/Dev/Hackathons/NEAR/privatetriage-video/final/privatetriage-demo.mp4`, 1:50, recorded against `c747d69`. It includes one real live triage, the guided-demo replays and the offline re-verification terminal. Validation, facts and sync checks pass. The original storyboard it was built from is kept below for reference.

### Storyboard (about 105 s, screen recording of the guided demo plus one live run)

Record at 1440×900 with the system in dark mode. Run `npm run build && npm start` with a key, for scene 5. Everything else works in demo mode.

| t | Screen | Action | Voice-over (suggested) |
|---|---|---|---|
| 0–10 s | Hero | Slow scroll over "Attest before you disclose." and the Gate 1 proof strip | "Unpublished vulnerability reports are the last thing you want leaking from an AI tool. PrivateTriage won't send one until the hardware proves itself." |
| 10–25 s | Workspace | Select the **NEAR contract** sample. Point at the local scan: "runs in your browser · nothing sent". Click **Replay verified run**. | "Each report gets a fresh challenge derived from its own hash. NEAR AI Cloud must answer with Intel TDX quotes for the gateway and model, and an NVIDIA-signed GPU verdict." |
| 25–40 s | Disclosure gate | Steps tick green. Pause on "Disclosure gate · Open — attestation verified first". | "Only when every check passes does the report leave, over the same TLS connection whose key sits inside the attested gateway." |
| 40–55 s | AI analysis | Banner, then CVSS 9.6 critical. Hover "model stated 9.1; computed from its vector". | "The model enclave signs the exact request and response. The UI is honest: this proves where it ran, not that the AI is right. It even recomputes the CVSS the model got wrong." |
| 55–65 s | Injection sample | Replay **Vague claim + prompt injection** and show the yellow injection card. | "This report tries to order the AI to rate it critical. It's flagged locally and by the model, and ignored." |
| 65–80 s | Verification tab | Expand one property, then show "What it does not prove". | "Five properties, forty-two checks, and an explicit list of what isn't proven: no retention claim, no end-to-end claim." |
| 80–92 s | Tamper lab | Click **Run all**; 21/21 caught. Click "Analysis edited after signing", then **FAILED**. | "Edit the verdict, replay old attestation, forge a key, intercept TLS: every attack on genuine evidence fails closed." |
| 92–100 s | Fail closed | Show the refusal cards (gpt-5.4: "Report sent: no"). | "Models outside a TEE are refused before anything is sent." |
| 100–105 s | Terminal | `npm run verify -- evidence/gate1/…/evidence.json --receipt …`, then `VERIFIED`, `receipt: MATCHES` | "And anyone can re-verify the evidence offline. PrivateTriage, on NEAR AI Cloud." |

Optional live insert (replacing 25–40 s): on the live server, type a short fictional report, click **Attest & triage**, and show it streaming to VERIFIED in about 15 s.

## 4. Hosted read-only demo (optional, owner decision)

The guided demo is a static site. `npm run build` produces `web/dist` with recorded evidence and no backend. With no `/api`, the app falls back to demo mode, so it can be hosted anywhere static, such as GitHub Pages. `.github/workflows/pages.yml` is prepared with **manual trigger only** (`workflow_dispatch`). Nothing is deployed until the owner enables Pages for the repo and runs it. Never deploy the live backend publicly with a key: it is designed for localhost.

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
| Negative tests: tampering, signer mismatch, invalid quote, stale challenge, unavailable evidence, corrupted response, non-TEE model, malformed output, prompt injection | ✅ 66/66 |
| Offline receipt reproduction (byte-identical) | ✅ `npm run verify` |
| UI checked at desktop (1440) and mobile (390); no horizontal overflow; no console errors | ✅ |
| Clean-checkout build (`git clone` → `npm ci` → typecheck → test → build) | ✅ (see PROJECT_HANDOFF) |
| Secret scan: tree, full git history, built bundle, evidence | ✅ no key material |
| README names Pursewarden (Q-015) | ✅ |
| **Pursewarden README names PrivateTriage (Q-015)** | ⏳ owner: add the line in docs/PURSEWARDEN_DIFFERENCE.md |
| Create the GitHub repository and push | ✅ https://github.com/mickeyjoes/near-private-triage (pushed 2026-11-14) |
| **Make the repository public** (required by 2026-11-14T23:59Z) | ⏳ owner |
| Record the demo video | ✅ produced (1:50, validated); ⏳ owner listens and approves |
| Publish the X post | ⏳ owner |
| Optional: enable Pages and run the manual Pages workflow | ⏳ owner |
| Submit (one attempt per repo) | ⏳ owner confirms the exact payload |
