# PrivateTriage trust model

This document states exactly what PrivateTriage verifies, how it verifies it, what it assumes, and what it does not claim. It separates **attestation**, **TLS binding**, **authenticity** (response signature), **confidentiality**, and **end-to-end encryption**, which are often conflated.

## Parties and hops

| Hop | Protection | Verified by PrivateTriage? |
|---|---|---|
| Browser → PrivateTriage backend | localhost HTTP (or HTTPS if you deploy it) | **No.** You run the backend; it sees plaintext and holds the API key. |
| Backend → NEAR AI Cloud gateway | TLS 1.3, whose server key is committed to in the gateway's Intel TDX quote | **Yes.** The quote-bound SPKI equals the peer certificate's SPKI on the same socket that carries the report. |
| Gateway → model server | NEAR-internal; per NEAR docs, inside the platform | **No.** This hop is not independently verifiable from the outside, so **this is not end-to-end encryption to the model**. |
| Model server (CPU) | Intel TDX confidential VM | **Yes.** Quote, TCB, debug bit, measured config, RTMR3 and fresh nonce are checked. |
| Model GPUs | NVIDIA Hopper confidential-computing mode | **Yes.** The NVIDIA NRAS-signed verdict is bound to our nonce. |
| Response authenticity | ECDSA signature by the model enclave key | **Yes.** `provider_tee` signature over the exact request/response hashes, by a key bound into a verified quote. |

## The five properties (all must pass for VERIFIED)

1. **`gateway_tee`: the gateway runs in a genuine Intel TDX enclave.** Checks: `quote_verified` (DCAP chain to dcap-qvl's pinned Intel root, using Intel PCS collateral), `tcb_status` (only `UpToDate` accepted), `not_debug`, `signer_identity`, `signer_bound` (report_data[0:32] = SHA-256(signing address ‖ TLS SPKI fingerprint)), `nonce_bound` (report_data[32:64] = our nonce), `nonce_echo`, `report_data_echo`, `mrconfig` (MRCONFIGID = 01 ‖ SHA-256(app_compose)), and `rtmr3` (event-log replay).
2. **`tls_binding`: the report was encrypted to the attested gateway.** Checks: `tls_spki` (peer certificate SPKI on the attestation socket = quote-bound fingerprint) and `same_connection` (the completion used that same socket; the HTTP agent is pinned to one socket).
3. **`model_tee`: the model runs in a genuine Intel TDX enclave.** The same quote checks as the gateway, plus `model_name` (the report is for exactly the requested model).
4. **`gpu_tee`: the model GPUs are in confidential-computing mode.** Checks: `gpu_evidence`, `gpu_nonce` (the NVIDIA payload answers our nonce), `nras_signature` (ES384 JWT verified with the NVIDIA JWKS, `kid` match, issuer, exp/nbf), `nras_nonce` (signed `eat_nonce` = our nonce) and `nras_verdict` (`x-nvidia-overall-att-result = true`).
5. **`response_signature`: the analysis was signed inside the model enclave.** Checks:
   - `nonce_derivation`: nonce = SHA-256(domain ‖ salt ‖ request hash).
   - `request_bound`: the signed request is the challenged request.
   - `request_bytes` and `response_bytes`: any included bytes hash to the signed hashes.
   - `signature_present`.
   - `signature_kind`: must be `provider_tee`. `gateway` → FAIL; unknown → UNVERIFIED.
   - `signed_text`: equals `model:sha256(req):sha256(resp)`.
   - `signature_valid`: EIP-191 recovery.
   - `signer_attested`: matches exactly one model report verified before the request.

## Verdict semantics (fail closed)

- Each check is `pass`, `fail` or `unavailable`.
- Any `fail` → property **FAILED**. Otherwise any `unavailable` → property **UNVERIFIED**. All pass → **VERIFIED**. The overall verdict follows the same rule over the five properties.
- Missing evidence (NRAS unreachable, attestation endpoint error, missing signature, unknown signature kind) yields **UNVERIFIED**, never VERIFIED. Contradicting evidence yields **FAILED**.
- **The live pipeline will not send the report unless the preflight (properties 1–4) passes.** Three genuine NVIDIA NRAS outages during development produced blocked runs with no completion request at all; see `evidence/attempts/*blocked*`.
- The UI never shows a bare "Verified". The overall banner reads "Confidential execution verified", and its subtitle says it covers where and how the analysis ran, not whether it is right. Property badges always sit next to the specific claim they qualify.

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
- the NVIDIA NRAS response and JWKS;
- the signature response;
- the socket identity and peer SPKI;
- the nonce inputs;
- optionally, the exact request and response bytes.

Notes:
- Evaluation happens *as of* `captured_at_secs`, because collateral and tokens expire. An offline verifier therefore checks internal consistency and cryptographic validity; freshness is meaningful to whoever chose the salt at capture time.
- The verifier **ignores the policy recorded in a bundle** and applies its own (TCB `UpToDate` only, `provider_tee` signer). This is tested: a bundle that relaxes its own policy still fails.
- `@phala/dcap-qvl` verifies the PCK chain archived in the collateral against its **pinned Intel root**. The quote's embedded PEM chain is transport only, so flipping bytes in that embedded copy does not change the result. Every signed region (header, TD report body, report_data, quote signature, QE report) rejects a single-bit flip. This was checked with a byte-flip probe during development.

## Trust assumptions

1. Intel TDX hardware and Intel's attestation root (DCAP/PCS).
2. NVIDIA Hopper confidential-computing hardware and NVIDIA's NRAS signing keys. The JWKS is fetched over WebPKI TLS.
3. The measured NEAR AI Cloud software (dstack, gateway, model server) does what its published source says. PrivateTriage displays the compose hash and image digests but **does not** check them against a source-build allowlist.
4. The PrivateTriage backend you run: it holds the API key, sees plaintext, and performs the checks.
5. WebPKI for TLS to Intel PCS, NVIDIA NRAS and NEAR AI Cloud.

## What is explicitly NOT claimed

- **Correctness of the AI's triage.** The model can be wrong. PrivateTriage recomputes CVSS arithmetic and flags inconsistencies, but a human decides.
- **No retention by NEAR AI Cloud or anyone else.** Attestation identifies measured software; it is not an audit of retention behaviour.
- **End-to-end encryption to the model.** TLS ends in the gateway enclave.
- **Same-instance binding.** The verified model report and the serving instance share a signing key, but they are not proven to be the same machine.
- **Image provenance.** Digests are measured, not matched against reproducible builds.
- **Confidentiality from the backend operator.** Whoever runs `server/app.ts` sees the report.

## Prompt-injection posture

- The report is untrusted input. It is fenced by `<<<REPORT {random 48-bit id}>>>` markers that the reporter cannot predict, and it is never placed in the system prompt.
- A deterministic local scan, run in the browser before anything is sent and again on the backend, flags instructions aimed at the AI and live-looking secrets.
- The model is instructed to flag (not follow) embedded instructions. The genuine recorded run on the injection sample flagged it and refused the demanded "CRITICAL / CVSS 10.0".
- Output must match a strict schema, and is never repaired. CVSS severity and score are recomputed from the model's own vector.
