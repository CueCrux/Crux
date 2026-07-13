# M-P1B — legal-hold integrity report

`CORECRUXD_FEATURE_LEGAL_HOLD` remains default-off; no feature was enabled or default-flipped.

## B1 — fail closed on unparsable hold state

Files:

- `crates/corecrux-memory/src/legal_hold.rs`
- `crates/crux-mcp/src/tools/forget.rs` (end-to-end enforcement proof)

Changes:

- `legal_hold`, `active_hold_state`, and `legal_holds` now share one resolver over the complete state history, including superseded and tombstoned rows.
- Resolution selects the newest parsable state. Every malformed candidate emits `tracing::error!` with the hold id, fact id, and version.
- If no state version parses, the resolver constructs an active, tenant-wide fail-closed marker from the fact envelope and emits a second loud error.
- Tombstoning a hold-state fact no longer removes enforcement. Active hold-state tombstones are considered covered by their own hold, so ordinary hard compaction cannot erase the last recoverable state.

Invariant: any stored hold-state history remains visible to enforcement. Malformed, superseded, or tombstoned latest state cannot turn an active hold into an absent/released hold.

Tests:

- `malformed_newest_hold_state_falls_back_and_still_blocks_retention_and_hard_erasure` — passed.
- `only_unparsable_hold_state_synthesizes_tenant_wide_active_marker` — passed.
- `tombstoned_active_hold_state_still_enforces_and_blocks_compaction` — passed.
- `memory_forget_refuses_when_newest_legal_hold_state_is_malformed` — passed.

## B2 — daemon-owned prefix write guard

Files:

- `crates/corecrux-memory/src/fact_privacy.rs`
- `crates/crux-mcp/src/tools/facts.rs`
- `crates/corecruxd/src/http/facts.rs`
- `crates/corecruxd/src/http/tests.rs`

Changes:

- Added canonical `DAEMON_OWNED_ENTITY_PREFIXES` and `daemon_owned_entity_prefix` for `__legal_hold__::`, `__legal_hold_receipt__::`, and `__incident__::`.
- MCP `store_fact` rejects these namespaces before private-entity rewriting with `INVALID_PARAMS` and `error_code = RESERVED_ENTITY_PREFIX`.
- HTTP single and bulk fact writes reject them with a 403 problem response carrying `code = RESERVED_ENTITY_PREFIX`. Bulk validation completes before any store call.
- The guard remains at client boundaries; direct daemon `FactStore` legal-hold placement remains available.

Invariant: untrusted fact-write surfaces cannot create or supersede daemon governance state, while daemon-owned legal-hold and incident paths retain direct store access.

Tests:

- `daemon_owned_prefixes_are_write_protected_at_client_boundaries` — passed.
- `legal_hold_prefix_constants_match_the_client_write_guard` — passed.
- `daemon_internal_legal_hold_placement_remains_available` — passed.
- `store_fact_passport_rejects_daemon_owned_entity_prefixes` — passed.
- `put_fact_passport_rejects_daemon_owned_entity_prefix` — added; daemon test target could not be run locally (dependency download blocked, below).
- `put_facts_bulk_rejects_daemon_owned_entity_prefix_atomically` — added; daemon test target could not be run locally.

## B3 — forget TOCTOU and atomic release receipt

Files:

- `crates/crux-mcp/src/tools/forget.rs`
- `crates/corecrux-memory/src/legal_hold.rs`
- `crates/corecruxd/src/http/legal_holds.rs`
- `crates/corecruxd/src/http/observations.rs`

Changes:

- `memory_forget` now re-evaluates all covering holds under the same write lock used for deletion, before deleting any selected fact.
- The race test injects a hold after scope resolution and exercises the same handler implementation through the mutating phase.
- Release is now two-phase: `prepare_legal_hold_release` builds unsigned state/receipt material without mutation; the daemon signs, appends, and fsyncs the observation file and directory entries; `release_legal_hold` then revalidates current state and commits using the durable observation id.
- Observation singleton appends serialize chain-tip read plus append, preventing concurrent governance receipts from selecting the same chain position.
- Receipt append/sync failure leaves the hold active. A post-receipt state-write failure can only leave an orphan receipt, never an unreceipted release.

Invariant: no covering hold can appear between enforcement and deletion unnoticed, and no released hold state can commit before its signed receipt is crash-durable.

Tests:

- `hold_placed_between_scope_resolution_and_delete_is_refused` — passed.
- `place_release_are_private_receipted_and_survive_replay` — passed with the new prepare/durable-id/commit contract.
- `place_and_release_emit_ed25519_observation_receipts` — updated; daemon test target could not be run locally.
- `release_receipt_persist_failure_keeps_hold_active` — added; forces failure at the append step after chain resolution and receipt minting, but daemon test target could not be run locally.

## B4 — authenticated override attribution

Files:

- `crates/corecruxd/src/http/admin.rs`
- `crates/corecruxd/src/http/tests.rs` (call-site/fixture updates)

Changes:

- Admin action submission resolves the passport through `http_scope_context` and carries it in a non-serialized `AdminActionRecord` field.
- The GDPR legal-hold override ignores caller-supplied `actor` values for attribution. The bound passport becomes both the stored override material's actor and the signed observation principal.
- Caller-supplied actor fields remain ordinary request metadata only.

Invariant: a client cannot spoof the actor attributed by a `legal_hold_overridden` receipt.

Test:

- `held_hard_erasure_override_is_signed_and_bound_to_authenticated_passport` — added; daemon test target could not be run locally.

## Quality gates

- `cargo fmt --all -- --check` — passed.
- `cargo clippy --workspace -- -D warnings` — passed.
- `cargo doc --no-deps -p corecrux-memory -p crux-mcp -p corecruxd` — passed.
- Changed Rust files retain the CCL licence header — passed.
- `cargo check --offline -p corecruxd --bin corecruxd` — passed (production daemon code compiles).
- `cargo test -p corecrux-memory -p crux-mcp -p corecruxd` — could not start the combined target because the sandbox cannot download locked `wasm-encoder 0.253.0` for the daemon's `wat` dev-dependency (`static.crates.io` DNS resolution is unavailable).
- `cargo test --offline -p corecrux-memory` — all 207 unit tests passed. Five unrelated `sync_low_hanging` integration tests failed only because loopback `TcpListener::bind` returned `PermissionDenied`, as expected in this sandbox.
- `cargo test --offline -p crux-mcp` — 721 tests passed. Twelve unrelated coordination/GitHub/orchestrator/sync tests failed only because loopback listener binds returned `PermissionDenied`.
- Focused MCP regressions for reserved-prefix rejection, malformed-state forget enforcement, and the hold-placement race each passed independently.

## Deferred

No code item is deferred. The orchestrator must rerun the combined daemon test target outside this network/loopback-restricted sandbox; the local blocker is test infrastructure/dependency availability, not a compiled code failure.
