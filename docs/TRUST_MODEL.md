# PrivateTriage trust model

This document states exactly what PrivateTriage verifies, how it verifies it, what it assumes, and what it does not claim. It separates **attestation**, **TLS binding**, **authenticity** (response signature), **confidentiality**, and **end-to-end encryption**, which are often conflated.

## Parties and hops

| Hop | Protection | Verified by PrivateTriage? |
|---|---|---|
| Browser → PrivateTriage backend | localhost HTTP (or HTTPS if you deploy it) | **No.** You run the backend; it sees plaintext and holds the API key. |
| Backend → NEAR AI Cloud gateway | TLS 1.3, whose server key is committed to in the gateway's Intel TDX quote | **Yes.** The quote-bound SPKI equals the peer certificate's SPKI on the same socket that carries the report. |
| Gateway → model server | NEAR-internal; per NEAR docs, inside the platform | **No.** This hop is not independently verifiable from the outside, so **this is not end-to-end encryption to the model**. |
| Model server (CPU) | Intel TDX confidential VM | **Yes.** Quote, TCB, debug bit, measured config, RTMR3 and fresh nonce are checked. |
| Model GPUs | NVIDIA Hopper (GH100) confidential-computing mode | **Yes, as reported by the model enclave.** Raw GPU reports are verified locally (NVIDIA Device Identity CA chain, SPDM signature, our nonce); NVIDIA's NRAS platform token and every per-GPU token are authenticated and nonce-bound; NVIDIA's signed device ids must equal the reported GPUs. That these GPUs serve this model instance is trusted to NEAR's measured software. |
| Response authenticity | ECDSA signature by the model enclave key | **Yes.** `provider_tee` signature over the exact request/response hashes, by a key bound into a verified quote. Instances of a model share that key, so it identifies the deployment, not the instance. |

## The five properties (all must pass for VERIFIED)

1. **`gateway_tee`: the gateway runs in a genuine Intel TDX enclave.** Checks: `quote_verified` (DCAP chain to dcap-qvl's pinned Intel root, using Intel PCS collateral), `tcb_status` (only `UpToDate` accepted), `not_debug`, `signer_identity`, `signer_bound` (report_data[0:32] = SHA-256(signing address ‖ TLS SPKI fingerprint)), `nonce_bound` (report_data[32:64] = our nonce), `nonce_echo`, `report_data_echo`, `mrconfig` (MRCONFIGID = 01 ‖ SHA-256(app_compose)), `rtmr3` (event-log replay), `compose_event` (the measured compose-hash event equals SHA-256(app_compose)), `os_image` (MRTD, RTMR1, RTMR2 and os-image-hash equal NEAR's pinned dstack OS image), and `app_identity` (app-id, KMS measurement and key provider equal NEAR's pinned app). See "Workload pinning" below.
2. **`tls_binding`: the report was encrypted to the attested gateway.** Checks: `tls_spki` (peer certificate SPKI on the attestation socket = quote-bound fingerprint), `endpoint` (the recorded endpoint is `https://cloud-api.near.ai`) and `same_connection` (the completion used that same socket *and* peer certificate key).
   - Live, **every request carrying the API key** — the report POST and the signature GET — is **pinned** to that socket: nothing is written (not even the Authorization header) unless Node assigns exactly the attested socket with the attested certificate key. The transport refuses any credentialed request without a pin. If the gateway closed the idle connection, the report is not sent (during appraisal) or the signature is not fetched (after the response); the run then ends UNVERIFIED and the key is never sent on a replacement connection. A fresh attestation on a new connection is not attempted.
   - The transport records the report's **transmission state**: `not_sent` (refused before any byte was written), `may_have_been_sent` (written, no response: reset, timeout) or `sent` (the gateway answered, even if the response was then truncated, oversized or rejected). Receipts carry it, and the UI never says "withheld" unless it is `not_sent`. Bundles recorded before 2026-11-14 lack the field: a failed preflight proves `not_sent`; a recorded response proves `sent`; anything else is treated as `may_have_been_sent`.
   - Offline, these observations are as recorded by the capturing backend. They are checked against the quote, but cannot be re-observed. Every receipt states this.
3. **`model_tee`: the model runs in a genuine Intel TDX enclave.** The same quote and workload checks as the gateway, plus `model_name` (the report must name exactly the requested model; a missing name fails). **Every** candidate the gateway returns must verify before anything is sent, because any of them could serve the request. All candidates' checks appear in the receipt.
4. **`gpu_tee`: the model GPUs are in confidential-computing mode.** Checks:
   - `gpu_evidence`: 1–16 well-formed `{evidence, certificate}` GPU entries.
   - `gpu_nonce`: the NVIDIA payload and every entry name our nonce.
   - `gpu_device_reports`: **verified locally, offline.** Each device certificate chain must verify up to NVIDIA's self-signed **Device Identity CA**, pinned by SHA-256 `102bf659…7b48` (identical to `verifier_device_root.pem` published in NVIDIA's `nvtrust` repository); the SPDM 1.1 GET_MEASUREMENTS transcript must be signed (ECDSA P-384/SHA-384) by the device key; and the signed request must carry our nonce.
   - `nras_signature`: the NRAS platform token is an ES384 JWT whose P-384 key must be certified (x5c leaf signed by, and valid under) one of two **pinned NVIDIA attestation intermediate CAs**, and must equal that certificate's key. The `kid`, issuer, `exp`, `iat` and `nbf` are also checked.
   - `time_anchor`: the evaluation time is within 10 minutes of NVIDIA's signed `iat`.
   - `nras_nonce`: the signed `eat_nonce` equals our nonce.
   - `nras_verdict`: `x-nvidia-overall-att-result = true`.
   - `gpu_claims`: the platform token signs a SHA-256 digest of each per-GPU (“detached”) token in `submods`. Each detached token must match its digest, verify under the same pinned-key policy, answer our nonce, and report `measres = success`, `secboot = true`, `dbgstat = disabled`, and passing architecture, report-signature, certificate-chain and nonce checks. Missing detached tokens → UNVERIFIED; mismatched or forged → FAILED.
   - `gpu_inventory`: NVIDIA's signed device ids (`ueid`) must equal the reported GPUs' device-certificate serial numbers, one to one.
   - The receipt's GPU count and model (e.g. `8 × GH100`) are taken **only** from these authenticated claims, and only when every GPU check passed; otherwise no GPU inventory is asserted.
5. **`response_signature`: the response was signed by the model deployment's enclave key.** Checks:
   - `capture_time`: the displayed capture time is the evaluated time.
   - `nonce_derivation`: nonce = SHA-256(domain ‖ salt ‖ request hash).
   - `request_bound`: the signed request is the challenged request.
   - `request_bytes` and `response_bytes`: any included bytes hash to the signed hashes.
   - `chat_id_bound`: when the response bytes are included, the recorded completion id is the id inside them (it is otherwise recorder metadata).
   - `signature_present` (if the attested connection closed before the fetch, this is UNVERIFIED with that reason).
   - `signature_kind`: must be `provider_tee`. `gateway` → FAIL; unknown → UNVERIFIED.
   - `signed_text`: equals `model:sha256(req):sha256(resp)`.
   - `signature_valid`: EIP-191 recovery.
   - `signer_attested`: matches a model report verified before the request.
   - The signed `req` hash covers the **whole serialized API request** — system prompt, random report marker, model, parameters and the report — so checking it requires the exact request bytes (in the full evidence export), not just the report text.
   - This property is necessarily evaluated after the response; it cannot gate disclosure.

## Verdict semantics (fail closed)

- Each check is `pass`, `fail` or `unavailable`.
- Any `fail` → property **FAILED**. Otherwise any `unavailable` → property **UNVERIFIED**. All pass → **VERIFIED**. The overall verdict follows the same rule over the five properties.
- Missing evidence (NRAS unreachable, attestation endpoint error, missing signature, unknown signature kind) yields **UNVERIFIED**, never VERIFIED. Contradicting evidence yields **FAILED**.
- **The live pipeline will not send the report unless the preflight (properties 1–4) passes.** Three genuine NVIDIA NRAS outages during development produced blocked runs with no completion request at all; see `evidence/attempts/*blocked*`.
- The UI never shows a bare "Verified". The overall banner reads "Confidential execution verified", and its subtitle says it covers the attested hardware and NEAR's pinned software and that a key of that model deployment signed the exact bytes — not which instance served it, and not whether the analysis is right. Property badges always sit next to the specific claim they qualify. Recorded runs are labelled with their capture time as historical receipts.
- The guided demo shows only analyses **re-parsed from the signed response bytes at build time** (`server/triage/replay.ts`), with the signed request matched byte-for-byte to the fictional sample's triage request; the build fails if saved `run.json` data disagrees. Stage timings are backend-recorded display data, not signed.
- Human corrections to recorded model output (`shared/annotations.ts`) never alter the signed response: each is bound to the response's SHA-256, must quote text that is in the signed output, and is displayed and exported as separately labelled commentary.

## Freshness and request binding

- The nonce is `SHA-256("privatetriage/attestation-nonce/v1" ‖ 32-byte random salt ‖ SHA-256(request bytes))`. It is uniformly random given the salt, and it commits the hardware evidence to this specific request.
- The gateway quote, model quote and NVIDIA token all embed or sign this nonce. Replaying attestation from another session fails `nonce_bound`; this is tested with genuine bundles.
- The request bytes are built once, then hashed, sent and signed. Nothing is re-serialized, and `Accept-Encoding: identity` keeps the response bytes exact.

## Signer kind: model TEE vs gateway

NEAR AI Cloud returns `signature_kind = provider_tee` when the model-serving TEE signed `model:sha256(req):sha256(resp)`. It returns `gateway` when the gateway signed `sha256(req):sha256(resp)`, for example for streaming, alias resolution or the Responses API. PrivateTriage sends non-streaming requests with the canonical model ID and `x-no-aliasing: true`, and **requires `provider_tee`**. Every recorded VERIFIED run was signed by a model enclave key (`0x3b75…fa0c` for GLM-5.3-Flash, `0xfdbd…8ddf` for Qwen3.6), and never by the gateway key `0xb98a…e779`.

## Offline re-verification

`npm run verify -- <evidence.json>` runs the **same** pure evaluation code as the live pipeline, with no network access. Bundles carry:
- the raw attestation response;
- the Intel collateral per quote, including the PCK chain extracted at capture time;
- the raw GPU reports (inside the attestation response), the NVIDIA NRAS platform and per-GPU tokens, and the JWKS;
- the signature response;
- the socket identity and peer SPKI;
- the nonce inputs;
- optionally, the exact request and response bytes.

Notes:
- Evaluation happens *as of* `captured_at_secs`, because collateral and tokens expire. An offline verifier therefore checks internal consistency and cryptographic validity of a **historical** record; freshness is meaningful to whoever chose the salt at capture time. Replaying an entire genuine bundle intentionally reproduces the same historical receipt; it is never a new inference or a current revocation check.
- The verifier **ignores the policy recorded in a bundle** and applies its own (TCB `UpToDate` only, `provider_tee` signer). This is tested: a bundle that relaxes its own policy still fails.
- `@phala/dcap-qvl` verifies the PCK chain archived in the collateral against its **pinned Intel root**. The quote's embedded PEM chain is transport only, so flipping bytes in that embedded copy does not change the result. Every signed region (header, TD report body, report_data, quote signature, QE report) rejects a single-bit flip. This was checked with a byte-flip probe during development.

## Workload pinning (which software, not just which hardware)

A genuine, up-to-date TDX quote only proves that *some* TDX guest produced it. PrivateTriage additionally requires NEAR AI Cloud's own workload. The pins are in `server/verifier/measurements.ts`.

- **OS image:** MRTD (TD firmware), RTMR1 (kernel) and RTMR2 (kernel command line + initrd). These are measured by the TDX module and firmware, not by the guest. One profile is pinned for gateway nodes and one for GPU model nodes. RTMR0 (virtual hardware shape) is shown but not pinned.
- **App identity:** the dstack `app-id`, the KMS measurement `mr-kms` and the KMS key provider. All are authenticated by the RTMR3 replay. The app-id stayed constant when NEAR redeployed the gateway compose during 2026-11-13 (`988522…` → `b73eed…`), so routine NEAR releases keep verifying, while a foreign guest or foreign app does not. One model-serving app-id covers both models used.
- The values were **pinned on first observation** (2026-11-13) and cross-checked across 22 genuine reports.
- An unknown value yields **UNVERIFIED and blocks disclosure**. `npm run pin` (free; attestation only) shows the current values next to the pinned ones, so a human can review a new NEAR release before adding it.
- Compose hashes and container image digests are displayed but are not an allowlist. App-id governance (which composes NEAR's KMS will serve) is NEAR's responsibility.

## Independent review (2026-11-13)

A separate reviewer audited the verifier and backend with the code only (no conclusions supplied). Findings and fixes:

| # | Finding | Fix | Regression test |
|---|---|---|---|
| 1 | Offline GPU-verdict forgery: the NVIDIA JWKS came from the bundle and was not tied to NVIDIA. An empty GPU evidence list was also accepted. | The key must be certified by a pinned NVIDIA intermediate CA and equal its certificate; P-384, `kid`, `exp` and `iat` are required; an empty evidence list fails. | tamper `nras_self_certified` |
| 2 | The report could be sent when one model candidate failed, and that candidate was hidden from the receipt. | Every candidate must verify before disclosure; all candidates' checks are shown. | "a second model candidate that fails blocks disclosure" |
| 3 | The report and API key could go out on a silently re-opened TLS connection. | Socket pinning before any byte is written. | `test/connection.test.ts` (local TLS server drops the idle socket) |
| 4 | A missing `model_name` skipped the model check. | A missing name fails. | "a model report that does not name its model fails" |
| 5 | No workload-measurement policy, so any TDX guest passed. | OS image and app identity are pinned (above). | "a genuine TDX guest that is not NEAR's pinned OS image or app is UNVERIFIED" |
| 6 | The bundle chose its own verification time. | Time is anchored to the NVIDIA-signed `iat` (±10 min), and the displayed time must equal the evaluated time. Collateral itself is still the archived copy (see limits). | "a bundle that moves its own capture time…" |
| 7 | Offline TLS binding rests on recorded observations. | Stated in every receipt's TLS property. | n/a (disclosure) |
| — | Backend: a spend-guard race, unthrottled preflight, and CPU cost on `/api/verify`. | Slots are claimed before reading the body; preflight is serialized and capped; body limits apply; at most 8 model candidates per bundle. | — |

**Remaining limits from the review:**
- Offline verification uses the collateral archived in the bundle, so revocation is checked as of capture time.
- The TLS-binding observations are backend-recorded.
- Measurements are pinned on first use rather than derived from reproducible builds.

## Final independent audit (2026-11-14)

A second, independent audit (security, functional and product) reviewed commit `cff3b6c`. Verdict: fix before publication. It confirmed four medium-severity defects and one low-severity analysis error; it did **not** demonstrate disclosure before preflight, Intel-quote forgery, NVIDIA platform-token forgery, or substitution of different bytes under a valid model signature. Fixes are on branch `fix/final-audit`; each audit proof of concept is a regression test, and the original PoC scripts, re-run unchanged against the fixed code, no longer reproduce.

| # | Finding | Fix | Regression |
|---|---|---|---|
| F1 | The signature GET carried the API key without `requireSocket`; after the attested socket closed, a replacement TLS connection (certificate trusted by the client, e.g. corporate interception) received the key. | Signature fetch pinned like the POST; the transport refuses any credentialed request without a pin; a closed connection ends the run UNVERIFIED with the key unsent. | `test/connection.test.ts` (the audit's two-certificate replacement PoC; structural refusal); `test/pipeline.test.ts` (signature fetch on a closed connection) |
| F2 | After a passing preflight, a peer that received the report and then reset (or a truncated/oversized response) produced `disclosed = false` and "Report withheld — attestation did not verify". | Transport-recorded `not_sent` / `may_have_been_sent` / `sent`; receipts, banners, pipeline and exports use it; truncated responses are rejected; no response hash is invented. | reset-after-body (real TLS fixture, pipeline-level port of the audit probe), truncated, oversized, pin-refused |
| F3 | Null GPU reports, a forged per-GPU token, or 99 invented GPUs with an invented architecture stayed VERIFIED — the latter with a receipt showing 99 GPUs. | Raw device reports, per-GPU tokens and inventory authenticated (property 4 above); GPU facts only from authenticated claims. | tamper `gpu_reports_nulled`, `gpu_detached_token_forged`, `gpu_inventory_invented`, `gpu_device_substituted`; five receipt-level tests |
| F4 | `scripts/build-demo.ts` paired `run.json`'s saved analysis with a genuine receipt without comparing it to the signed response; a forged title/summary was shown under "Confidential execution verified" and exported as verified Markdown. | Analyses re-derived from signed bytes; request matched byte-for-byte to the sample; mismatches fail the build. | `test/replay.test.ts` (the audit's altered-analysis PoC, a one-action edit, swapped evidence, edited sample, marker/hygiene tampering) |
| F5 | The recorded Quillmark analysis recommends blocking 169.254.169.254 with the renderer's security group; security groups do not filter instance-metadata traffic. | Signed response preserved; visible analyst correction bound to its hash (IMDSv2 + hop limit or disabling IMDS, host/container egress rules, URL validation after DNS/redirects, least privilege, re-test; C/I/A impact assumptions flagged). | `test/replay.test.ts` (correction attached, quotes signed text, exported) |

Also from the audit: the recorded endpoint, completion id and completion peer SPKI were unauthenticated metadata (a rewritten bundle stayed VERIFIED) → now cross-checked (`endpoint`, `chat_id_bound`, `same_connection`; tamper `completion_metadata_forged`). Nested `recommended_actions` objects accepted extra properties → rejected. Markdown exports emitted model-provided Markdown/HTML verbatim → escaped. "Replay recorded" could replay a sample after its text was edited → disabled once edited. Wording corrected: "exact analysis you read", "detected — and ignored", click-time "re-verify" in the Tamper lab (results are computed at build time), the request-hash scope, historical freshness, shared model keys, provider trust, and "nothing persisted".

All 14 recorded receipts were regenerated by the corrected verifier: **no verdict changed** (VERIFIED runs stay VERIFIED with all 47 checks passing; refusals and outages stay UNVERIFIED and `not_sent`), and no `evidence.json` or `run.json` file was modified.

**Remaining limitations (not fixed; stated, not hidden):**
- Intel/NVIDIA hardware, roots and signing services are trusted; physical, firmware, side-channel and supply-chain attacks are out of scope.
- NEAR OS/app pins and the NVIDIA NRAS intermediates were pinned on first observation, not from reproducible builds or an independent provisioning source. NVIDIA signing-certificate revocation policy is not implemented.
- Provider governance is trusted: app-id is not a model-weight measurement, any compose of the pinned app is accepted (the measured model compose is NEAR's `dstack-nvidia` management stack), shared signing keys may span instances with different configurations, and the gateway-to-model channel is NEAR's.
- GPU evidence is not cryptographically tied to the specific serving instance; the measured software is trusted to report the devices it uses.
- Socket ids, peer certificates, endpoint and stage timings are recorder assertions offline.
- A dropped connection before the signature fetch is not recovered by re-attesting a new connection; the run ends UNVERIFIED.
- Prompt injection: the random marker and instructions reduce, but do not prevent, influence; one recorded case is not a robustness result. The hygiene scan warns; it does not redact or block.
- The backend is a localhost prototype: external-call budgets and malformed-bundle cost are bounded but not exhaustively hardened; do not expose it publicly.
- Triage quality is not evaluated beyond three fictional samples.

## Trust assumptions

1. Intel TDX hardware and Intel's attestation root (DCAP/PCS).
2. NVIDIA confidential-computing GPUs, NVIDIA's Device Identity CA (pinned to NVIDIA's published root) and NRAS signing keys (intermediates pinned on first observation; the JWKS is fetched over WebPKI TLS).
3. NEAR AI Cloud as operator: its measured software (dstack, gateway, model server and management components) does what its published source says, and its deployment, key-provisioning and gateway-to-model channel are sound. PrivateTriage displays the compose hash and image digests but **does not** check them against a source-build allowlist.
4. The PrivateTriage backend you run: it holds the API key, sees plaintext, and performs the checks.
5. WebPKI for TLS to Intel PCS, NVIDIA NRAS and NEAR AI Cloud.

## What is explicitly NOT claimed

- **Correctness of the AI's triage.** The model can be wrong. PrivateTriage recomputes CVSS arithmetic and flags inconsistencies, but a human decides.
- **No retention by NEAR AI Cloud or anyone else.** Attestation identifies measured software; it is not an audit of retention behaviour.
- **End-to-end encryption to the model.** TLS ends in the gateway enclave.
- **Same-instance binding.** The verified model report and the serving instance share a signing key, but they are not proven to be the same machine, and NEAR documents that shared keys may span instances with different measured configurations.
- **Current freshness.** A recorded receipt is a historical appraisal against archived collateral.
- **Image provenance.** Digests are measured, not matched against reproducible builds.
- **Confidentiality from the backend operator.** Whoever runs `server/app.ts` sees the report.

## Prompt-injection posture

- The report is untrusted input. It is fenced by `<<<REPORT {random 48-bit id}>>>` markers that the reporter cannot predict, and it is never placed in the system prompt.
- A deterministic local scan, run in the browser before anything is sent and again on the backend, flags instructions aimed at the AI and live-looking secrets.
- The model is instructed to flag (not follow) embedded instructions. In the one recorded injection case the signed analysis flagged it and did not adopt the demanded "CRITICAL / CVSS 10.0". That is one case, not a robustness claim: the marker prevents a guessed-delimiter collision, it does not isolate the model from the report's semantics. The UI therefore says "detected — check the analysis for their influence", never "ignored".
- Output must match a strict schema, and is never repaired. CVSS severity and score are recomputed from the model's own vector.
