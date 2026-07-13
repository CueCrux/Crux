# M2 report — cloud witness mode for `crux-llm-shim`

Date: 2026-07-13  
ExecPlan: `tier-packaging-and-site-reframe-2026-07-13`, M2

## What was built

- Added a cloud-witness operating mode selected with `--cloud-witness
  --cloud-upstream anthropic|openai` and independently gated by
  `CRUX_CLOUD_WITNESS=1`. Local injection remains independently gated by
  `CRUX_LLM_SHIM=1`; the same binary can run separate instances on distinct
  loopback ports.
- Added the closed `CloudUpstream` enum. Production origins are exactly
  `https://api.anthropic.com` and `https://api.openai.com`; redirects are
  disabled, request targets must be origin-form paths, and the listener
  remains loopback-only. The existing local HTTP/RFC1918 allowlist is
  unchanged.
- Added exact request-body forwarding with end-to-end/auth header forwarding,
  RFC hop-by-hop filtering (including names nominated by `Connection`), TLS
  through `ureq`/rustls, response streaming, incremental SHA-256 output
  hashing, and bounded metadata-only response parsing. Workspace `ureq` keeps
  rustls but disables transparent gzip decoding, so explicitly requested
  compressed response bytes remain verbatim.
- Witnessed Anthropic `POST /v1/messages` and OpenAI
  `POST /v1/chat/completions` / `POST /v1/responses`. Other paths produce a
  signed `passthrough_unwitnessed` path/timestamp record.
- Added request metadata extraction for model, stream flag, names-only tools,
  and optional `x-crux-session-id`; added Anthropic/OpenAI JSON and SSE usage
  plus stop/finish metadata extraction. Request/response content and auth
  values never enter records, logs, or the JSONL spool.
- Added a dedicated Ed25519 witness key at
  `~/.local/state/crux/llm-shim/witness.key` by default. First creation is
  race-safe and `0600` on Unix; later starts reuse the same public identity.
  Symlink/non-regular keys, keys that are group/world-accessible when loaded,
  and writable parent custody are rejected into fail-soft degradation.
  The `wit_…` key id is the first 16 lowercase hex characters of SHA-256 over
  RFC 8410 Ed25519 SPKI DER.
- Added recursively sorted canonical-JSON signing and identity-pinned strict
  verification. The verifier rejects record alteration, stale signatures,
  key-id mismatch, and attacker re-signing with a different key.
- Extended the existing daemon-first `/v1/mediation/receipts` plus JSONL spool
  fallback. Cloud delivery uses a bounded, non-blocking ordered queue so
  daemon/filesystem stalls cannot create unbounded memory growth or delay
  provider calls; queue overflow is retained as one deferred degraded notice.
  Cross-process file locking preserves JSONL framing for concurrent local,
  Anthropic, and OpenAI instances. Key/signing/delivery failures attempt a
  content-free `witness_degraded` record and never stop forwarding.
- Witness receipt IDs include a random 128-bit process-instance component plus
  a monotonic counter, avoiding PID-reuse collisions across restarts.
- Added the loud `--insecure-test-upstream` path. It only honors
  `CRUX_CLOUD_WITNESS_TEST_UPSTREAM` when explicitly enabled (or in unit-test
  compilation), accepts loopback HTTP only, prints a warning in the CLI, and
  stamps every resulting record `test_upstream:true`.
- Documented what the witness proves, its limits, detectable absence on
  reconciled bypass, and Anthropic/OpenAI base-URL quickstarts.

## Files touched

- `Cargo.lock`
- `Cargo.toml`
- `crates/crux-claude-hooks/Cargo.toml`
- `crates/crux-claude-hooks/src/bin/crux_llm_shim.rs`
- `crates/crux-claude-hooks/src/llm_shim/allowlist.rs`
- `crates/crux-claude-hooks/src/llm_shim/cloud_witness.rs` (new)
- `crates/crux-claude-hooks/src/llm_shim/http.rs`
- `crates/crux-claude-hooks/src/llm_shim/mod.rs`
- `crates/crux-claude-hooks/src/llm_shim/receipts.rs`
- `crates/crux-claude-hooks/src/llm_shim/witness.rs` (new)
- `crates/crux-claude-hooks/tests/cloud_witness_e2e.rs` (new)
- `docs/llm-shim.md`
- `llms-full.txt` (regenerated to restore the repository freshness gate after
  pre-existing linked-doc edits)
- `M2-REPORT.md` (new)

`README.md` and `docs/assurance-coverage-matrix.md` were not edited.

## Receipt shapes

All normally witnessed records use this signed envelope:

```json
{
  "record": { "schema": "cuecrux.mediation.witness.v1", "kind": "..." },
  "witness": {
    "alg": "ed25519",
    "kid": "wit_<16 lowercase hex chars>",
    "public_key_b64": "<raw 32-byte Ed25519 public key, standard Base64>",
    "sig_b64": "<Ed25519 signature over sorted-key canonical JSON(record)>"
  }
}
```

`cloud_request_witnessed` carries `receipt_id`, provider, path, parsed model,
the `sha256:` digest of exact request body bytes, names-only `tool_names`,
`stream`, optional `session_hint`, `created_at`, and the test marker.

`cloud_response_witnessed` has its own `receipt_id` plus
`request_receipt_id`, provider/path, upstream status, the `sha256:` digest of
exact response bytes delivered, filtered numeric usage-token fields,
stop/finish reason, first-byte/end timestamps, `completed|aborted|upstream_error`,
and the test marker.

`passthrough_unwitnessed` contains schema/kind plus path, timestamp, and the
test marker. `witness_degraded` contains only operational metadata and no
request, response, or auth content. When the persistent key itself is
unavailable, the degraded record is necessarily unsigned and says
`persistent_key:false` rather than claiming the configured witness identity.

### Signed example captured from the forgery test run

Command:

```text
cargo test -p crux-claude-hooks --lib llm_shim::witness::tests::valid_envelope_verifies_and_forgery_paths_fail -- --nocapture
```

Output example (the same test verified this envelope before testing altered
record and different-key forgeries):

```json
{
  "record": {
    "kind": "cloud_request_witnessed",
    "request_digest": "sha256:001122",
    "schema": "cuecrux.mediation.witness.v1"
  },
  "witness": {
    "alg": "ed25519",
    "kid": "wit_7db89400a2058592",
    "public_key_b64": "IyobU7IDlPFFiJfmWZt800liOhrFlj0T7ouF1JujPiQ=",
    "sig_b64": "5N935umxJWlRxcoTg7dq1PRPKmAiOwonIhjGjqYdxojTadeEZIR/3lnNHknDvYNZK5tF8O122IfA6LDk9VHyBA=="
  }
}
```

## Test and quality summary

- `cargo fmt --all -- --check` — **PASS**.
- `cargo clippy -p crux-claude-hooks --all-targets -- -D warnings` — **PASS**.
- `cargo clippy --workspace --all-targets -- -D warnings` — **BLOCKED outside
  this change** in existing `corecrux-frame/src/v3.rs` tests: seven
  `clippy::unwrap_used` findings. The new crate target is clean.
- `cargo test -p crux-claude-hooks --lib llm_shim` — **PASS: 37 passed, 0
  failed** (allowlist, path matrix, parsers, hop headers, gates, canonical
  signing, forgery rejection, hardened key custody/reuse/unusable paths,
  authority-smuggling rejection, response end states, concurrent JSONL
  framing, and receipt delivery).
- Bind-free cloud CLI e2e — **PASS: 1 passed, 0 failed**.
- `cargo test -p crux-claude-hooks --no-fail-fast` — compiled every target;
  the sandbox then rejected all loopback `TcpListener` binds with
  `PermissionDenied`. Cloud target result after the final additions: **1
  bind-free help test plus 6 network tests requiring the outside-sandbox
  rerun**. The pre-existing hook/local-shim network targets and one existing
  lib test hit the same bind denial. No functional assertion ran and failed
  after a successful bind.
- `cargo doc --no-deps -p crux-claude-hooks` — **PASS**.
- `bash scripts/build-llms-full.sh --check` — **PASS** after regeneration.
- `bash scripts/check-agent-docs.sh` — **PASS**.
- CCL header check on every new Rust file — **PASS**.

## Deferred items and why

- The six cloud network e2e cases (Anthropic buffered, Anthropic gated SSE,
  OpenAI chat, OpenAI Responses API, gzip fidelity, and key-unavailable
  fail-soft) require the orchestrator's
  outside-sandbox rerun because this sandbox forbids loopback binds. They
  compile and their bind-free companion passes.
- The workspace-wide clippy gate needs the pre-existing
  `corecrux-frame/src/v3.rs` test unwrap warnings resolved by that crate's
  owner; editing unrelated trust-core tests was deliberately kept out of this
  M2 change.
- Daemon-side promotion of the new JSON drafts into other canonical CROWN
  receipt families was not added; this milestone owns the self-signed witness
  envelope and reuses the existing mediation delivery endpoint/spool.
