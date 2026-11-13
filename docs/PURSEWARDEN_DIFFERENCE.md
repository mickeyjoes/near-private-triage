# PrivateTriage vs Pursewarden: two independent projects

NEAR HACKATHON rule Q-015 allows one person to submit at most two different projects, if they are independent and each README names the other. This page documents the independence.

| | **PrivateTriage** (this repo) | **Pursewarden** ([github.com/mickeyjoes/pursewarden](https://github.com/mickeyjoes/pursewarden), [pursewarden.com](https://pursewarden.com)) |
|---|---|---|
| Problem | Getting AI help to triage **confidential, unpublished vulnerability reports** without trusting an LLM provider on faith | Letting **AI agents spend** on NEAR without being able to exceed a fixed budget |
| Primary track | `privacy` (Privacy & Private AI) | `security`, `agents` |
| NEAR technology | **NEAR AI Cloud**: TEE inference, attestation reports, `provider_tee` response signatures | **NEAR protocol**: a Rust smart-contract vault, access keys, cross-contract budget enforcement on testnet and sandbox |
| Trust mechanism | Hardware attestation (Intel TDX + NVIDIA CC) checked before disclosure, plus model-enclave signatures | On-chain contract invariants and witnessed spending limits |
| Code | TypeScript verifier, Node backend, React UI | Rust contract, tooling, web viewer |
| Keys and credentials | A NEAR AI Cloud API key (owner's, kept in `.env`, never committed) | NEAR testnet accounts and keys |
| Evidence | NEAR AI Cloud attestation, signature and NRAS bundles in `evidence/` | Sandbox and testnet transaction evidence |
| Infrastructure | None deployed. Local backend; the read-only demo is a static site | pursewarden.com (GitHub Pages) and a testnet contract |

**Shared:** the author, and nothing else. PrivateTriage was built in a separate local workspace and Git repository (`near-private-triage`), from scratch, during the hackathon window. It does not import, copy, call, or reuse any Pursewarden code, contract, signing credential, evidence, domain or deployment.

## Reciprocal README note for Pursewarden (owner to add; not applied by this project)

Rule Q-015 requires Pursewarden's README to name this project as well. Suggested one-line note for Pursewarden's README, near its status block:

```markdown
> **Independent second project (rule Q-015):** the same author also submitted [PrivateTriage](https://github.com/mickeyjoes/near-private-triage), confidential AI triage of vulnerability reports on NEAR AI Cloud (track `privacy`). The two projects share no code, keys, evidence or infrastructure.
```

Adjust the URL if the PrivateTriage repository is published under a different name.
