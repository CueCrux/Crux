# crux-enterprise-shim — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Enterprise customer-hosted RCX capability-token validation contract. The production
enterprise distribution binds this contract to a customer KMS/HSM verifier; this crate
keeps the deterministic policy surface pure: trust-root selection, airgap enforcement,
backend/capability matching, and egress refusal reasons. Single-file crate (`src/lib.rs`).

## Key symbols
- `EnterpriseTrustRoot` + `validate_enterprise_trust_root` — static config contract
  (customer id, `customer:`-prefixed backend, trusted issuer kids, airgap flag)
- `EnterpriseShim::validate` — token + `EnterpriseShimCall` → `EnterpriseShimDecision`
  (`CustomerHosted` or `Refused` with a refusal code + `TokenValidationIssue`s)
- `EnterpriseShimCall::encrypted_blob_mirror` — the canonical call shape
- `enterprise_encrypted_blob_backend` — builds the customer backend with
  encrypted-blob/receipt-hash egress and the required attestations

## Invariants
- None of I1–I6. Enforcement here is scope-matching and fail-closed refusal codes;
  signature verification is the KMS/HSM binder's job in the enterprise distribution.

## Test & verify
- `cargo test -p crux-enterprise-shim`

## Local rules
- This is a compatibility contract, not internal plumbing: refusal codes
  (`token_invalid`, `capability_not_permitted`, `tenant_mismatch`,
  `backend_not_permitted`, `trust_root_mismatch`, `issuer_not_trusted`,
  `egress_not_permitted`) and issue codes are consumed by customer-hosted validators —
  renaming or re-meaning them is a breaking change. Ask first.
- Airgap is absolute: a trust root with `airgap: true` refuses any call to the hosted
  backend AND any token that merely *includes* a hosted backend entry (pinned by
  `refuses_airgap_tokens_that_include_hosted_backend`).
- Keep the crate pure — no IO, no clock ownership (caller passes `now_unix_seconds`),
  no serde. New checks go into `validate_scope` as deterministic matching.
