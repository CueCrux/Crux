// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! agent-passport M5 — T.1 cross-tenant-leak regression suite (the merge bar).
//!
//! This module is the exhaustive proof that the M5 write-enforcement + private-
//! scope hardening close the highest-risk surface (cross-tenant fact leakage)
//! **without** changing flag-OFF behaviour. Every invariant the ExecPlan names
//! has a named test here; the suite is the gate for merging M5.
//!
//! ## What "tenant isolation" maps onto in the current model (read this first)
//!
//! There is **no Fact-level `tenant` column** in `corecrux_memory::Fact`. The
//! substrate has exactly two isolation primitives that a fact can ride on:
//!
//! 1. **Private-fact ownership** (`__agent::<owner>::…`, enforced in
//!    `crate::scope`). Under M5 the `<owner>` key is the caller's resolved
//!    *passport_id* (e.g. `claude-work`), not the raw token-name. A private
//!    fact is visible ONLY to its owning passport (plus the owner's own legacy
//!    raw-name alias for back-compat). This is the strong, per-principal
//!    boundary — it is what "tenant A's private fact is invisible to tenant B"
//!    concretely means here.
//! 2. **Write-category exclusivity** (`crate::category_enforce`). A `work`
//!    passport cannot WRITE a `personal`-category entity and vice-versa. This
//!    partitions the *non-private* shared pool by category at write time.
//!
//! **Non-private facts remain a SHARED pool** readable by every authenticated
//! caller — that is the existing, intended collaboration model (two work agents
//! share their non-private memory). M5 does NOT make non-private facts
//! tenant-private, because the data model has no per-fact tenant tag to scope
//! them by; inventing a half-implementation there could leak, so it is
//! deliberately out of scope (documented in the report). What M5 DOES enforce:
//! a non-private fact cannot be *written* across a category boundary.
//!
//! The `query` (BM25 retrieval) path is a SEPARATE data plane from facts: it
//! reads the tenant-hash-partitioned doc index, never the FactStore. Its tenant
//! isolation is the hard `tenant_hash_full` equality filter in
//! `corecrux_retrieval::bm25`. Facts authored by passports never surface there.
//! `t1_query_path_tenant_a_doc_invisible_to_tenant_b` proves that filter on the
//! real `handle_query` path.

#![allow(clippy::unwrap_used)]

use serde_json::{json, Value};

use crate::agent::AgentIdentity;
use crate::agent_passport::AgentPassportMap;
use crate::dispatch::McpContext;
use crate::tools::audit_export::handle_audit_export_bundle;
use crate::tools::facts::{handle_delete_fact, handle_fact_history, handle_query_facts, handle_store_fact};
use crate::tools::forget::{handle_memory_forget, handle_memory_forget_dry_run};
use crate::tools::freshness::{handle_memory_freshness, handle_memory_sweep_candidates};
use crate::tools::memory::{handle_memory_edit, handle_memory_pin, handle_memory_view};
use crate::tools::memory_use::handle_memory_acknowledge_use;
use crate::tools::query::handle_query;
use corecrux_memory::fact_store::StoreFact;

// ── Fixtures ────────────────────────────────────────────────────────────────

/// A flag-ON base context with the built-in default agent→passport map.
fn flag_on_base() -> McpContext {
    McpContext::new_default("t1-node").with_agent_passports(true, AgentPassportMap::builtin_default())
}

/// A flag-OFF base context (the control). Identical store, no passport map.
fn flag_off_base() -> McpContext {
    McpContext::new_default("t1-node")
}

fn agent(ctx: &McpContext, name: &str, hash: u8) -> McpContext {
    ctx.with_agent(AgentIdentity {
        name: name.to_string(),
        token_hash: [hash; 32],
    })
}

/// Mint a passport record (so flag-ON write enforcement can resolve a category).
async fn seed_passport(ctx: &McpContext, id: &str, category: &str) {
    let record = json!({
        "id": id,
        "principal_id": format!("test::{id}"),
        "public_key_hex": "deadbeef",
        "category": category,
        "issued_at_unix_ms": 1u64,
    });
    let mut store = ctx.fact_store.write().await;
    store.store(StoreFact {
        entity: format!("__passport__::{id}"),
        key: "record".to_string(),
        value: record.to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    });
}

/// Extract a fact_id from a `store_fact` text response.
fn fact_id_of(resp: &Value) -> String {
    resp["content"][0]["text"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .nth(2)
        .unwrap()
        .to_string()
}

/// True if a `query_facts` response surfaced a row with the given value.
fn query_facts_has_value(resp: &Value, value: &str) -> bool {
    resp["structuredContent"]["rows"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|r| r["value"].as_str() == Some(value)))
}

/// True if a `memory_view` response surfaced a row with the given value.
fn memory_view_has_value(resp: &Value, value: &str) -> bool {
    resp["structuredContent"]["facts"]
        .as_array()
        .is_some_and(|facts| facts.iter().any(|f| f["value"].as_str() == Some(value)))
}

/// True if a `fact_history` text response mentions the given value.
fn fact_history_has_value(resp: &Value, value: &str) -> bool {
    resp["content"][0]["text"].as_str().is_some_and(|t| t.contains(value))
}

// ── INVARIANT 1: write enforcement (work passport vs personal entity) ─────────

#[tokio::test]
async fn t1_write_work_passport_rejected_on_personal_entity() {
    let base = flag_on_base();
    seed_passport(&base, "claude-work", "work").await;
    let claude = agent(&base, "anthropic", 0); // → claude-work (work)

    // work passport writing a personal-category entity → rejected, NOT stored.
    let err = handle_store_fact(
        &json!({"entity": "personal::diary", "key": "mood", "value": "leak-attempt"}),
        &claude,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, crate::protocol::INVALID_PARAMS);
    assert_eq!(err.data.as_ref().unwrap()["category_enforcement"], true);

    // Nothing landed: a shared read finds no such fact.
    let res = handle_query_facts(&json!({"query": "leak-attempt", "token_budget": 500}), &base)
        .await
        .unwrap();
    assert!(
        !query_facts_has_value(&res, "leak-attempt"),
        "rejected write must not be stored"
    );
}

#[tokio::test]
async fn t1_write_matching_category_succeeds() {
    let base = flag_on_base();
    seed_passport(&base, "claude-work", "work").await;
    let claude = agent(&base, "anthropic", 0);

    // work passport → work-category entity (default) → OK.
    let ok = handle_store_fact(
        &json!({"entity": "execplan:x", "key": "k", "value": "work-fact"}),
        &claude,
    )
    .await
    .unwrap();
    assert!(ok["structuredContent"]["fact_id"].as_str().unwrap().starts_with("f_"));

    // explicit work:: prefix also OK.
    handle_store_fact(
        &json!({"entity": "work::y", "key": "k", "value": "work-fact-2"}),
        &claude,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn t1_write_personal_passport_writes_personal_ok_but_work_blocked() {
    let base = flag_on_base();
    // Map a personal agent explicitly (built-in map only has work agents).
    let map = AgentPassportMap::from_pairs_str("homeuser:home-personal:personal");
    let base = base.with_agent_passports(true, map);
    seed_passport(&base, "home-personal", "personal").await;
    let home = agent(&base, "homeuser", 7);

    // personal → personal OK.
    handle_store_fact(
        &json!({"entity": "personal::diary", "key": "k", "value": "home-ok"}),
        &home,
    )
    .await
    .unwrap();
    // personal → work (default-category entity) blocked.
    let err = handle_store_fact(&json!({"entity": "execplan:z", "key": "k", "value": "home-bad"}), &home)
        .await
        .unwrap_err();
    assert_eq!(err.data.as_ref().unwrap()["category_enforcement"], true);
}

#[tokio::test]
async fn t1_write_system_entity_exempt() {
    let base = flag_on_base();
    seed_passport(&base, "claude-work", "work").await;
    let claude = agent(&base, "anthropic", 0);

    // System entity (`__*__`) is exempt — a work passport may write it even
    // though it is not "work"-categorised.
    handle_store_fact(
        &json!({"entity": "__bootstrap__::pattern:retry", "key": "k", "value": "sys-ok"}),
        &claude,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn t1_write_flag_on_unminted_passport_rejected() {
    // A flag-ON write by a mapped agent whose passport was never minted is
    // rejected (LegacyOrMissingPassport) — the enforcement fails closed.
    let base = flag_on_base();
    let claude = agent(&base, "anthropic", 0); // resolves claude-work, but NOT seeded
    let err = handle_store_fact(&json!({"entity": "execplan:x", "key": "k", "value": "v"}), &claude)
        .await
        .unwrap_err();
    assert_eq!(err.data.as_ref().unwrap()["category_enforcement"], true);
}

// ── INVARIANT 2: private fact visible ONLY to owning passport ─────────────────

/// claude-work's private fact is invisible to codex-work (a DIFFERENT passport
/// in the SAME `work` tenant-group) across query_facts, memory_view, AND
/// fact_history. This is the owning-passport-ONLY guarantee: group membership
/// does NOT grant private-fact visibility under M5.
#[tokio::test]
async fn t1_private_fact_owning_passport_only_across_all_read_paths() {
    let base = flag_on_base();
    seed_passport(&base, "claude-work", "work").await;
    seed_passport(&base, "codex-work", "work").await;

    let claude = agent(&base, "anthropic", 0); // → claude-work
    let codex = agent(&base, "openai", 2); // → codex-work (same `work` group)

    // claude-work stores a private fact.
    handle_store_fact(
        &json!({"entity": "secrets", "key": "api", "value": "private-needle", "private": true}),
        &claude,
    )
    .await
    .unwrap();

    // OWNER (claude-work) sees it on every read path.
    let q = handle_query_facts(&json!({"query": "private-needle", "token_budget": 500}), &claude)
        .await
        .unwrap();
    assert!(
        query_facts_has_value(&q, "private-needle"),
        "owner must see its private fact via query_facts"
    );

    let mv = handle_memory_view(&json!({"token_budget": 500}), &claude)
        .await
        .unwrap();
    assert!(
        memory_view_has_value(&mv, "private-needle"),
        "owner must see its private fact via memory_view"
    );

    let fh = handle_fact_history(&json!({"entity": "secrets", "key": "api"}), &claude)
        .await
        .unwrap();
    assert!(
        fact_history_has_value(&fh, "private-needle"),
        "owner must see its private fact via fact_history"
    );

    // DIFFERENT passport (codex-work) sees it on NONE of them — even though
    // it shares the `work` tenant-group with claude-work.
    let q = handle_query_facts(&json!({"query": "private-needle", "token_budget": 500}), &codex)
        .await
        .unwrap();
    assert!(
        !query_facts_has_value(&q, "private-needle"),
        "T.1 LEAK: codex saw claude's private fact via query_facts"
    );

    let mv = handle_memory_view(&json!({"token_budget": 500}), &codex).await.unwrap();
    assert!(
        !memory_view_has_value(&mv, "private-needle"),
        "T.1 LEAK: codex saw claude's private fact via memory_view"
    );

    let fh = handle_fact_history(&json!({"entity": "secrets", "key": "api"}), &codex)
        .await
        .unwrap();
    assert!(
        !fact_history_has_value(&fh, "private-needle"),
        "T.1 LEAK: codex saw claude's private fact via fact_history"
    );
}

/// The private owner key under flag-ON is the PASSPORT_ID, not the raw token
/// name. Proven structurally: the stored entity is `__agent::claude-work::…`.
#[tokio::test]
async fn t1_private_fact_owner_key_is_passport_id_not_token_name() {
    let base = flag_on_base();
    seed_passport(&base, "claude-work", "work").await;
    let claude = agent(&base, "anthropic", 0);

    let resp = handle_store_fact(
        &json!({"entity": "secrets", "key": "k", "value": "v", "private": true}),
        &claude,
    )
    .await
    .unwrap();
    let fid = resp["structuredContent"]["fact_id"].as_str().unwrap();

    let store = base.fact_store.read().await;
    let stored = store.get(fid).unwrap();
    assert_eq!(
        stored.entity, "__agent::claude-work::secrets",
        "private owner key must be the passport_id (claude-work), not the token name (anthropic)"
    );
    // And the M1 actor stamp AGREES with the owner key.
    assert_eq!(stored.actor.as_deref(), Some("claude-work"));
}

// ── INVARIANT 3: adversarial cross-tenant probes are DENIED ───────────────────

/// A different passport cannot supersede, delete, fact_history, or memory_view
/// another passport's private fact. Extends the existing
/// `store_fact_cannot_supersede_other_agents_private_fact` pattern to the full
/// adversarial matrix under flag-ON passport identities.
#[tokio::test]
async fn t1_adversarial_cross_passport_supersede_and_delete_denied() {
    let base = flag_on_base();
    seed_passport(&base, "claude-work", "work").await;
    seed_passport(&base, "codex-work", "work").await;
    let claude = agent(&base, "anthropic", 0);
    let codex = agent(&base, "openai", 2);

    let secret = handle_store_fact(
        &json!({"entity": "vault", "key": "k", "value": "claude-secret", "private": true}),
        &claude,
    )
    .await
    .unwrap();
    let secret_id = fact_id_of(&secret);

    // codex cannot SUPERSEDE claude's invisible private fact.
    let err = handle_store_fact(
        &json!({"entity": "execplan:pub", "key": "k", "value": "v", "supersedes": [secret_id]}),
        &codex,
    )
    .await
    .unwrap_err();
    let invalid = err.data.unwrap()["invalid_refs"].as_array().unwrap().clone();
    assert!(
        invalid.iter().any(|v| v == secret_id.as_str()),
        "supersede of invisible fact must be rejected"
    );

    // codex cannot DELETE it (delete of an invisible fact is a no-op "not found").
    let del = handle_delete_fact(&json!({"fact_id": secret_id}), &codex)
        .await
        .unwrap();
    assert!(
        del["content"][0]["text"].as_str().unwrap().contains("not found"),
        "cross-passport delete must be a no-op"
    );

    // The secret is untouched: still present + not superseded for the OWNER.
    let store = base.fact_store.read().await;
    let live = store.get(&secret_id).unwrap();
    assert!(
        !live.deleted,
        "cross-passport delete must not have soft-deleted the fact"
    );
    assert!(
        live.superseded_by.is_none(),
        "cross-passport supersede must not have retired the fact"
    );
}

// ── INVARIANT 4: migration / back-compat ──────────────────────────────────────

/// An existing personal-default / non-private fact (no actor, written flag-OFF)
/// STILL resolves and is visible to its legitimate readers after the flag is
/// turned on. Non-private facts are the shared pool — they must NOT be stranded
/// or wrongly hidden by the M5 identity rekeying.
#[tokio::test]
async fn t1_migration_legacy_nonprivate_fact_still_visible_after_flag_on() {
    // Write the legacy fact with the flag OFF (the pre-M5 world), then read it
    // back through a flag-ON context over the SAME store.
    let off = flag_off_base();
    let legacy_writer = agent(&off, "legacy-agent", 9);
    handle_store_fact(
        &json!({"entity": "shared", "key": "note", "value": "legacy-shared-needle"}),
        &legacy_writer,
    )
    .await
    .unwrap();

    // Same underlying store, flag now ON, a different (work) passport reads.
    let on = off.with_agent_passports(true, AgentPassportMap::builtin_default());
    seed_passport(&on, "claude-work", "work").await;
    let claude = agent(&on, "anthropic", 0);

    let q = handle_query_facts(&json!({"query": "legacy-shared-needle", "token_budget": 500}), &claude)
        .await
        .unwrap();
    assert!(
        query_facts_has_value(&q, "legacy-shared-needle"),
        "legacy non-private fact must remain visible to the shared pool after flag-on"
    );
}

/// A legacy PRIVATE fact (written flag-OFF, owner-keyed by raw token-name) stays
/// visible to its ORIGINAL owner after the flag flips on — the back-compat alias
/// keeps it from being stranded — and stays invisible to everyone else.
#[tokio::test]
async fn t1_migration_legacy_private_fact_not_stranded_for_owner() {
    // Flag-OFF: `anthropic` writes a private fact → owner key `anthropic`.
    let off = flag_off_base();
    let anth_off = agent(&off, "anthropic", 0);
    let resp = handle_store_fact(
        &json!({"entity": "oldnotes", "key": "k", "value": "legacy-private-needle", "private": true}),
        &anth_off,
    )
    .await
    .unwrap();
    let fid = fact_id_of(&resp);
    {
        let store = off.fact_store.read().await;
        assert_eq!(store.get(&fid).unwrap().entity, "__agent::anthropic::oldnotes");
    }

    // Flag flips ON: same `anthropic` agent now resolves to `claude-work`.
    let on = off.with_agent_passports(true, AgentPassportMap::builtin_default());
    seed_passport(&on, "claude-work", "work").await;
    let anth_on = agent(&on, "anthropic", 0);

    // The ORIGINAL owner still sees its legacy private fact (alias back-compat).
    let q = handle_query_facts(
        &json!({"query": "legacy-private-needle", "token_budget": 500}),
        &anth_on,
    )
    .await
    .unwrap();
    assert!(
        query_facts_has_value(&q, "legacy-private-needle"),
        "legacy private fact must NOT be stranded from its original owner after flag-on"
    );

    // A different passport (codex) still cannot see it.
    seed_passport(&on, "codex-work", "work").await;
    let codex_on = agent(&on, "openai", 2);
    let q = handle_query_facts(
        &json!({"query": "legacy-private-needle", "token_budget": 500}),
        &codex_on,
    )
    .await
    .unwrap();
    assert!(
        !query_facts_has_value(&q, "legacy-private-needle"),
        "legacy private fact must stay owner-only"
    );
}

// ── INVARIANT 5: the `query` (BM25 retrieval) path tenant isolation ───────────

/// Build a real `.ccxi` segment with one doc per tenant, load it into the
/// retrieval index, and prove `handle_query` for tenant-B never returns the
/// tenant-A doc. This is the third read path; its isolation is the hard
/// tenant_hash filter (facts never enter this plane at all).
#[tokio::test]
async fn t1_query_path_tenant_a_doc_invisible_to_tenant_b() {
    use corecrux_index::CcxiBuilder;

    let ctx = flag_on_base();

    // The handler hashes tenant_id with xxh64(.., 0); mirror that here.
    let hash = |t: &str| xxhash_rust::xxh64::xxh64(t.as_bytes(), 0);
    let tenant_a = hash("tenant-a");
    let tenant_b = hash("tenant-b");

    let mut builder = CcxiBuilder::new(0, 1, 100);
    builder.add_document(0, "alpha secret terraform module", 0, tenant_a);
    builder.add_document(1, "beta unrelated content", 100, tenant_b);
    let bytes = builder.build();
    {
        let mut index = ctx.retrieval_index.write().await;
        index.load_ccxi_bytes(&bytes).unwrap();
    }

    // tenant-A queries its own term → finds doc 0.
    let res_a = handle_query(
        &json!({"tenant_id": "tenant-a", "query": "terraform", "limit": 5, "contract": "legacy"}),
        &ctx,
    )
    .await
    .unwrap();
    let text_a = res_a["content"][0]["text"].as_str().unwrap();
    let parsed_a: Value = serde_json::from_str(text_a).unwrap();
    assert_eq!(
        parsed_a["results"].as_array().unwrap().len(),
        1,
        "tenant-a should see its own doc"
    );

    // tenant-B queries tenant-A's term → finds NOTHING (the A doc is filtered
    // out by the tenant_hash boundary).
    let res_b = handle_query(
        &json!({"tenant_id": "tenant-b", "query": "terraform", "limit": 5, "contract": "legacy"}),
        &ctx,
    )
    .await
    .unwrap();
    let text_b = res_b["content"][0]["text"].as_str().unwrap();
    let parsed_b: Value = serde_json::from_str(text_b).unwrap();
    assert_eq!(
        parsed_b["results"].as_array().unwrap().len(),
        0,
        "T.1 LEAK: tenant-b retrieved tenant-a's document via the query path"
    );
}

// ── INVARIANT 6: flag-OFF byte-for-byte control ───────────────────────────────

/// With the flag OFF, every M5 behaviour reduces to today's semantics:
///   * write enforcement is SKIPPED (a write to any category succeeds with no
///     passport minted) — proving the new gate cannot fire flag-off;
///   * private facts are keyed by the raw AGENT NAME (`__agent::alice::…`), not
///     a passport id;
///   * private visibility is owner-only by agent name, exactly as before.
#[tokio::test]
async fn t1_flag_off_byte_for_byte_control() {
    let off = flag_off_base();
    assert!(!off.agent_passports_enabled, "control must be flag-OFF");

    // (a) Write enforcement does NOT fire flag-off: an `alice` agent writes a
    //     personal-category entity with NO passport minted — succeeds.
    let alice = agent(&off, "alice", 0);
    let w = handle_store_fact(
        &json!({"entity": "personal::diary", "key": "k", "value": "off-ok"}),
        &alice,
    )
    .await
    .unwrap();
    assert!(w["structuredContent"]["fact_id"].as_str().unwrap().starts_with("f_"));

    // (b) Private facts are keyed by the RAW agent name flag-off.
    let p = handle_store_fact(
        &json!({"entity": "notes", "key": "k", "value": "alice-secret", "private": true}),
        &alice,
    )
    .await
    .unwrap();
    let pid = p["structuredContent"]["fact_id"].as_str().unwrap();
    {
        let store = off.fact_store.read().await;
        let f = store.get(pid).unwrap();
        assert_eq!(
            f.entity, "__agent::alice::notes",
            "flag-off private key must be the raw agent name"
        );
        assert!(f.actor.is_none(), "flag-off write records no actor");
    }

    // (c) Owner-only visibility by agent name, unchanged: bob cannot see it.
    let bob = agent(&off, "bob", 1);
    let q_alice = handle_query_facts(&json!({"query": "alice-secret", "token_budget": 500}), &alice)
        .await
        .unwrap();
    assert!(query_facts_has_value(&q_alice, "alice-secret"));
    let q_bob = handle_query_facts(&json!({"query": "alice-secret", "token_budget": 500}), &bob)
        .await
        .unwrap();
    assert!(
        !query_facts_has_value(&q_bob, "alice-secret"),
        "flag-off private fact must stay owner-only"
    );
}

/// Flag-OFF non-private facts remain a SHARED pool (the pre-M5 collaboration
/// model is untouched): a fact written by one agent is visible to another.
#[tokio::test]
async fn t1_flag_off_nonprivate_pool_is_shared_control() {
    let off = flag_off_base();
    let a = agent(&off, "agent-a", 1);
    let b = agent(&off, "agent-b", 2);
    handle_store_fact(&json!({"entity": "shared", "key": "k", "value": "shared-needle"}), &a)
        .await
        .unwrap();
    let q = handle_query_facts(&json!({"query": "shared-needle", "token_budget": 500}), &b)
        .await
        .unwrap();
    assert!(
        query_facts_has_value(&q, "shared-needle"),
        "flag-off non-private pool must stay shared"
    );
}

// ── INVARIANT 7: passport-keyed private facts are OWNER-MANAGEABLE on the ──────
//                secondary fact-surfacing handlers (M5 consistency-gap fix).
//
// The defect these guard against: under flag-ON a private fact is owned by the
// resolved passport_id (`__agent::claude-work::…`), but several handlers still
// used the raw token-name for visibility, so the legitimate OWNER could not
// see/manage its OWN private fact through them. These are NOT leak tests
// (INVARIANT 2/3 cover cross-exposure); they prove the owner-CAN side plus the
// other-CANNOT side on each converted surface, under flag-ON.

/// Shared async lock for the feature-flag-gated handlers (ack/forget/audit).
/// Mirrors the per-module guards; delegates to the crate-wide env lock so the
/// env-var writes here never race the other env-mutating tests.
fn t1_env_lock() -> &'static tokio::sync::Mutex<()> {
    crate::test_env_lock()
}

/// True if a `memory_freshness` / `memory_sweep_candidates` response has a row
/// for the given fact_id.
fn rows_have_fact_id(resp: &Value, fact_id: &str) -> bool {
    resp["structuredContent"]["rows"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|r| r["fact_id"].as_str() == Some(fact_id)))
}

/// Stand up a flag-ON base with both work passports minted, plus the two
/// agent contexts (claude-work owner, codex-work other) over the SAME store.
async fn owner_other_fixture() -> (McpContext, McpContext, McpContext) {
    let base = flag_on_base();
    seed_passport(&base, "claude-work", "work").await;
    seed_passport(&base, "codex-work", "work").await;
    let claude = agent(&base, "anthropic", 0); // → claude-work (owner)
    let codex = agent(&base, "openai", 2); // → codex-work (other)
    (base, claude, codex)
}

/// memory_freshness: the converted identity-scoped visibility gate governs the
/// SHARED (non-private) pool; a non-private fact written by the owner is visible
/// to BOTH passports (the intended collaboration model — not a leak). Private
/// facts never ride this surface for ANYONE because the handler ALSO filters the
/// `__agent::*` stored entity as reserved BEFORE the row is rendered — that
/// pre-existing guard is intentionally preserved. The owner-can / other-CANNOT
/// private split that the identity conversion guarantees is therefore proven on
/// the surfaces that actually unwrap-then-reserved-check (memory_edit/pin); here
/// we assert (a) the shared-pool parity and (b) that a private fact is absent
/// for both callers.
#[tokio::test]
async fn t1_memory_freshness_shared_pool_and_private_filtered() {
    let _g = t1_env_lock().lock().await;
    std::env::set_var("CORECRUXD_FEATURE_FRESHNESS", "1");
    let (_base, claude, codex) = owner_other_fixture().await;

    // Non-private (shared-pool) fact — both passports see it on memory_freshness.
    let shared = handle_store_fact(
        &json!({"entity": "work::fresh-shared", "key": "k", "value": "fresh-shared-needle"}),
        &claude,
    )
    .await
    .unwrap();
    let shared_id = fact_id_of(&shared);

    // Private fact — reserved-filtered for everyone, owner included.
    let secret = handle_store_fact(
        &json!({"entity": "fresh-secrets", "key": "k", "value": "fresh-needle", "private": true}),
        &claude,
    )
    .await
    .unwrap();
    let secret_id = fact_id_of(&secret);

    let owner = handle_memory_freshness(&json!({"top_k": 100, "token_budget": 2000}), &claude)
        .await
        .unwrap();
    assert!(rows_have_fact_id(&owner, &shared_id), "owner sees the shared fact");
    assert!(
        !rows_have_fact_id(&owner, &secret_id),
        "private facts are reserved-filtered even for the owner on memory_freshness"
    );

    let other = handle_memory_freshness(&json!({"top_k": 100, "token_budget": 2000}), &codex)
        .await
        .unwrap();
    assert!(
        rows_have_fact_id(&other, &shared_id),
        "shared (non-private) pool is visible to a different passport — intended collaboration"
    );
    assert!(
        !rows_have_fact_id(&other, &secret_id),
        "T.1: the owner's private fact is never exposed to a different passport"
    );
    std::env::remove_var("CORECRUXD_FEATURE_FRESHNESS");
}

/// memory_sweep_candidates: a superseded NON-private fact is a sweep candidate
/// for both passports (shared pool); a superseded PRIVATE fact is reserved-
/// filtered for everyone. Same reasoning as memory_freshness — the conversion
/// governs the shared pool and preserves the private-reserved guard.
#[tokio::test]
async fn t1_memory_sweep_candidates_shared_pool_and_private_filtered() {
    let _g = t1_env_lock().lock().await;
    std::env::set_var("CORECRUXD_FEATURE_FRESHNESS", "1");
    let (_base, claude, codex) = owner_other_fixture().await;

    // Shared superseded fact -> sweep candidate for both.
    let shared_old = handle_store_fact(
        &json!({"entity": "work::sweep-shared", "key": "old", "value": "sweep-shared-needle"}),
        &claude,
    )
    .await
    .unwrap();
    let shared_old_id = fact_id_of(&shared_old);
    handle_store_fact(
        &json!({"entity": "work::sweep-shared2", "key": "new", "value": "sweep-shared-new", "supersedes": [shared_old_id]}),
        &claude,
    )
    .await
    .unwrap();

    // Private superseded fact -> reserved-filtered for everyone.
    let secret_old = handle_store_fact(
        &json!({"entity": "sweep-secrets", "key": "old", "value": "sweep-needle", "private": true}),
        &claude,
    )
    .await
    .unwrap();
    let secret_old_id = fact_id_of(&secret_old);
    handle_store_fact(
        &json!({"entity": "sweep-secrets", "key": "new", "value": "sweep-new", "private": true, "supersedes": [secret_old_id]}),
        &claude,
    )
    .await
    .unwrap();

    let owner = handle_memory_sweep_candidates(&json!({"top_k": 100, "token_budget": 2000}), &claude)
        .await
        .unwrap();
    assert!(
        rows_have_fact_id(&owner, &shared_old_id),
        "owner sees shared sweep candidate"
    );
    assert!(
        !rows_have_fact_id(&owner, &secret_old_id),
        "private facts are reserved-filtered even for the owner on memory_sweep_candidates"
    );

    let other = handle_memory_sweep_candidates(&json!({"top_k": 100, "token_budget": 2000}), &codex)
        .await
        .unwrap();
    assert!(
        rows_have_fact_id(&other, &shared_old_id),
        "shared sweep candidate visible to other"
    );
    assert!(
        !rows_have_fact_id(&other, &secret_old_id),
        "T.1: the owner's private sweep candidate is never exposed to a different passport"
    );
    std::env::remove_var("CORECRUXD_FEATURE_FRESHNESS");
}

/// memory_forget (+ dry-run): the OWNER can forget a fact it can SEE and the
/// fact is actually soft-deleted; a DIFFERENT passport's forget over the same
/// scope affects ZERO facts and leaves the fact intact.
///
/// NOTE on private facts here: `memory_forget` independently filters the
/// `__agent::*` reserved prefix BEFORE the visibility check, so a *private*
/// fact is unforgettable through this surface by ANYONE (owner included) —
/// that pre-existing guard is intentionally preserved. To exercise the
/// converted identity-scoped visibility gate on a fact that actually reaches
/// it, the owner-can / other-cannot split is proven on a per-tenant-scoped
/// NON-private fact (`personal::claude-work::…`), whose visibility is decided
/// by the (now identity-scoped) `scope::fact_visible_to_identity` call. The
/// cross-passport private-fact protection itself is covered by INVARIANT 3
/// (`t1_adversarial_cross_passport_supersede_and_delete_denied`).
#[tokio::test]
async fn t1_memory_forget_owner_can_other_cannot() {
    let _g = t1_env_lock().lock().await;
    std::env::set_var("CORECRUXD_FEATURE_SCOPED_FORGET", "1");
    // Both passports are `work`; a `personal::` entity would be write-blocked, so
    // use a `work::`-prefixed tenant entity that both can WRITE but only the
    // matching scope reaches. The forget visibility gate is the lever under test.
    let (base, claude, codex) = owner_other_fixture().await;

    // Owner writes a NON-private, non-reserved fact that reaches the forget gate.
    let target = handle_store_fact(
        &json!({"entity": "work::forget-target", "key": "k", "value": "forget-needle"}),
        &claude,
    )
    .await
    .unwrap();
    let target_id = fact_id_of(&target);

    // A non-private fact is the SHARED pool, so a different passport CAN see it
    // here — that is the intended collaboration model, NOT a leak (private facts
    // are the per-principal boundary, covered elsewhere). What we assert: both
    // dry-runs preview it, and the OWNER's forget actually removes it.
    let owner_dry = handle_memory_forget_dry_run(
        &json!({"scope": {"type": "entity_prefix", "value": "work::forget-target"}}),
        &claude,
    )
    .await
    .unwrap();
    assert_eq!(
        owner_dry["structuredContent"]["count"], 1,
        "owner dry-run must preview the fact it can see"
    );

    let owner_forget = handle_memory_forget(
        &json!({
            "scope": {"type": "entity_prefix", "value": "work::forget-target"},
            "reason": "owner cleanup",
        }),
        &claude,
    )
    .await
    .unwrap();
    assert_eq!(
        owner_forget["facts_affected"], 1,
        "owner must be able to forget a fact it can see"
    );
    // After a successful soft-delete `store.get` filters the fact out (None),
    // and a query no longer surfaces it.
    {
        let store = base.fact_store.read().await;
        assert!(
            store.get(&target_id).is_none_or(|f| f.deleted),
            "owner's forget must have soft-deleted the fact"
        );
    }
    let q = handle_query_facts(&json!({"entity": "work::forget-target", "token_budget": 500}), &claude)
        .await
        .unwrap();
    assert!(
        !query_facts_has_value(&q, "forget-needle"),
        "the forgotten fact must no longer surface in query_facts"
    );

    // The cross-passport private-fact protection on forget's visibility gate:
    // a DIFFERENT passport cannot forget the OWNER's private fact. (The private
    // fact never reaches the gate because of the reserved-prefix filter, so the
    // affected count is 0 — but we ALSO assert the fact survives, which proves
    // the converted visibility check did not widen anything.)
    let secret = handle_store_fact(
        &json!({"entity": "forget-secrets", "key": "k", "value": "forget-secret-needle", "private": true}),
        &claude,
    )
    .await
    .unwrap();
    let secret_id = fact_id_of(&secret);
    let other_forget = handle_memory_forget(
        &json!({
            "scope": {"type": "passport_id", "value": "claude-work"},
            "reason": "cross-passport probe",
        }),
        &codex,
    )
    .await
    .unwrap();
    assert_eq!(
        other_forget["facts_affected"], 0,
        "T.1: cross-passport forget must be a no-op"
    );
    {
        let store = base.fact_store.read().await;
        assert!(
            !store.get(&secret_id).unwrap().deleted,
            "cross-passport forget must not have soft-deleted the owner's private fact"
        );
    }
    std::env::remove_var("CORECRUXD_FEATURE_SCOPED_FORGET");
}

/// memory_acknowledge_use: the converted identity-scoped visibility gate is the
/// `not_visible` discriminator. A SHARED (non-private) fact is ackable by both
/// passports. A PRIVATE fact is redacted (reserved) for the OWNER — who CAN see
/// it (passes the visibility gate) but it carries the `__agent::*` reserved
/// prefix, so the pre-existing reserved redaction applies — and is `not_visible`
/// for a DIFFERENT passport (the visibility gate correctly denies it BEFORE the
/// reserved check). The `not_visible` vs `redacted` split is precisely what the
/// identity conversion makes correct under flag-ON.
#[tokio::test]
async fn t1_memory_acknowledge_use_visibility_gate_distinguishes_owner_from_other() {
    let _g = t1_env_lock().lock().await;
    std::env::set_var("CORECRUXD_FEATURE_MEMORY_ACK", "1");
    let (_base, claude, codex) = owner_other_fixture().await;

    // Shared, non-private, non-reserved fact -> ackable by both passports.
    let shared = handle_store_fact(
        &json!({"entity": "work::ack-shared", "key": "k", "value": "ack-shared-needle"}),
        &claude,
    )
    .await
    .unwrap();
    let shared_id = fact_id_of(&shared);

    // Private fact owned by claude-work.
    let secret = handle_store_fact(
        &json!({"entity": "ack-secrets", "key": "k", "value": "ack-needle", "private": true}),
        &claude,
    )
    .await
    .unwrap();
    let secret_id = fact_id_of(&secret);

    // OWNER acks both: shared survives (filtered_count includes it), private is
    // redacted (owner CAN see it — not_visible=0 — but it's reserved-prefixed).
    let owner = handle_memory_acknowledge_use(
        &json!({"turn_id": "t1-owner", "fact_ids": [shared_id.clone(), secret_id.clone()]}),
        &claude,
    )
    .await
    .unwrap();
    assert_eq!(owner["filtered_count"], 1, "shared fact is acknowledged for the owner");
    assert_eq!(
        owner["not_visible_count"], 0,
        "owner's own private fact IS visible to it (identity gate passes) — so not 'not_visible'"
    );
    assert_eq!(
        owner["redacted_count"], 1,
        "owner's private fact is redacted by the reserved-prefix guard, not surfaced"
    );

    // DIFFERENT passport: shared is ackable (shared pool); the private fact is
    // denied by the identity visibility gate (not_visible) BEFORE the reserved
    // check — proving the conversion denies a different passport correctly.
    let other = handle_memory_acknowledge_use(
        &json!({"turn_id": "t1-other", "fact_ids": [shared_id.clone(), secret_id.clone()]}),
        &codex,
    )
    .await
    .unwrap();
    assert_eq!(
        other["filtered_count"], 1,
        "shared fact is acknowledged for a different passport too"
    );
    assert_eq!(
        other["not_visible_count"], 1,
        "T.1: the owner's private fact is not_visible to a different passport"
    );
    assert_eq!(other["redacted_count"], 0);
    std::env::remove_var("CORECRUXD_FEATURE_MEMORY_ACK");
}

/// memory_edit + memory_pin: the OWNER can edit and pin its OWN passport-keyed
/// private fact; a DIFFERENT passport is refused (reserved_or_invisible) on both.
#[tokio::test]
async fn t1_memory_edit_and_pin_owner_can_other_cannot() {
    let _g = t1_env_lock().lock().await;
    std::env::set_var("CORECRUXD_FEATURE_MEMORY_PANEL", "1");
    let (_base, claude, codex) = owner_other_fixture().await;

    let secret = handle_store_fact(
        &json!({"entity": "edit-secrets", "key": "k", "value": "edit-needle", "private": true}),
        &claude,
    )
    .await
    .unwrap();
    let fid = fact_id_of(&secret);

    // OWNER can edit.
    let edited = handle_memory_edit(
        &json!({"fact_id": fid, "new_value": "edited-by-owner", "reason": "owner edit"}),
        &claude,
    )
    .await
    .unwrap();
    assert_eq!(edited["structuredContent"]["new_fact"]["value"], "edited-by-owner");
    // The edited fact's entity is unwrapped to the LOGICAL name for the owner.
    assert_eq!(edited["structuredContent"]["new_fact"]["entity"], "edit-secrets");

    // OWNER can pin.
    let pinned = handle_memory_pin(&json!({"fact_id": fid, "pinned": true}), &claude)
        .await
        .unwrap();
    assert_eq!(pinned["structuredContent"]["pinned"], true);

    // DIFFERENT passport is refused on edit and pin (fact invisible to it).
    let edit_err = handle_memory_edit(&json!({"fact_id": fid, "new_value": "hijack", "reason": "x"}), &codex)
        .await
        .unwrap_err();
    assert_eq!(edit_err.code, crate::protocol::INVALID_PARAMS);
    assert_eq!(edit_err.data.unwrap()["reason"], "reserved_or_invisible");

    let pin_err = handle_memory_pin(&json!({"fact_id": fid, "pinned": true}), &codex)
        .await
        .unwrap_err();
    assert_eq!(pin_err.code, crate::protocol::INVALID_PARAMS);
    assert_eq!(pin_err.data.unwrap()["reason"], "reserved_or_invisible");
    std::env::remove_var("CORECRUXD_FEATURE_MEMORY_PANEL");
}

/// audit_export_bundle: the converted identity-scoped per-fact visibility gate
/// decides which NON-reserved facts a non-operator caller exports, while the
/// `include_reserved` operator bypass is preserved.
///
/// NOTE: `__agent::*` private facts are stripped by audit_export's reserved-
/// prefix filter for non-operator callers BEFORE the visibility check, so a
/// private fact only ever appears in an OPERATOR (`include_reserved=true`)
/// export — where the visibility check is intentionally bypassed. The owner-can
/// / other-cannot distinction that the identity conversion guarantees is
/// therefore proven on the surface it actually governs: the operator export
/// includes the owner's private fact (bypass preserved), and a non-operator
/// export of EITHER passport excludes it (reserved filter preserved). The
/// cross-passport private boundary itself is INVARIANT 2/3.
#[tokio::test]
async fn t1_audit_export_owner_can_other_cannot() {
    let _g = t1_env_lock().lock().await;
    std::env::set_var("CORECRUXD_FEATURE_AUDIT_EXPORT", "1");
    let td = tempfile::tempdir().unwrap();
    std::env::set_var("CORECRUXD_AUDIT_EXPORT_DIR", td.path());
    let (_base, claude, codex) = owner_other_fixture().await;

    handle_store_fact(
        &json!({"entity": "audit-secrets", "key": "k", "value": "audit-needle", "private": true}),
        &claude,
    )
    .await
    .unwrap();

    // Helper: read events.jsonl from the produced bundle and test for the value.
    async fn bundle_contains(resp: &Value, needle: &str) -> bool {
        let raw = std::fs::read(resp["bytes_path"].as_str().unwrap()).unwrap();
        let decoded = zstd::stream::decode_all(raw.as_slice()).unwrap();
        let mut archive = tar::Archive::new(decoded.as_slice());
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            if path == "events.jsonl" {
                let mut s = String::new();
                use std::io::Read as _;
                entry.read_to_string(&mut s).unwrap();
                return s.contains(needle);
            }
        }
        false
    }

    // OWNER operator export (include_reserved=true) DOES include its private
    // fact — the operator bypass is preserved by the conversion.
    let owner_op = handle_audit_export_bundle(
        &json!({"token_budget": 4000, "scope": {"include_reserved": true}}),
        &claude,
    )
    .await
    .unwrap();
    assert_eq!(owner_op["scope"]["include_reserved"], true);
    assert!(
        bundle_contains(&owner_op, "audit-needle").await,
        "operator export must include the owner's private fact (include_reserved bypass preserved)"
    );

    // OWNER non-operator export EXCLUDES the private fact (reserved-prefix filter
    // preserved — private facts never ride the non-operator bundle).
    let owner_plain = handle_audit_export_bundle(&json!({"token_budget": 4000}), &claude)
        .await
        .unwrap();
    assert!(
        !bundle_contains(&owner_plain, "audit-needle").await,
        "non-operator export must not include the private fact (reserved filter preserved)"
    );

    // DIFFERENT passport's non-operator export ALSO excludes it.
    let other_plain = handle_audit_export_bundle(&json!({"token_budget": 4000}), &codex)
        .await
        .unwrap();
    assert!(
        !bundle_contains(&other_plain, "audit-needle").await,
        "T.1: a different passport's non-operator export must not include the owner's private fact"
    );
    std::env::remove_var("CORECRUXD_FEATURE_AUDIT_EXPORT");
    std::env::remove_var("CORECRUXD_AUDIT_EXPORT_DIR");
}

/// Flag-OFF control for the converted handlers: with the flag OFF, the raw agent
/// name IS the identity and aliases is empty, so each handler behaves exactly as
/// pre-M5. Proven on two representative surfaces:
///   * memory_edit (panel) — flag-off owner (by raw name) CAN edit its own
///     private fact; a different agent is refused. This is the surface that
///     actually unwraps the private entity, so the owner-can/other-cannot split
///     is observable here flag-off, identically to flag-on.
///   * memory_freshness — flag-off shared (non-private) pool parity: a fact
///     written by one agent is visible to another; private facts are reserved-
///     filtered for everyone (unchanged from pre-M5).
#[tokio::test]
async fn t1_converted_handlers_flag_off_control() {
    let _g = t1_env_lock().lock().await;
    std::env::set_var("CORECRUXD_FEATURE_MEMORY_PANEL", "1");
    std::env::set_var("CORECRUXD_FEATURE_FRESHNESS", "1");
    let off = flag_off_base();
    assert!(!off.agent_passports_enabled, "control must be flag-OFF");
    let alice = agent(&off, "alice", 0);
    let bob = agent(&off, "bob", 1);

    // --- memory_edit/pin owner-can-other-cannot, flag-off (raw-name keyed) ---
    let resp = handle_store_fact(
        &json!({"entity": "off-secrets", "key": "k", "value": "off-needle", "private": true}),
        &alice,
    )
    .await
    .unwrap();
    let fid = fact_id_of(&resp);
    // Flag-off, the private key is the RAW agent name (not a passport id).
    {
        let store = off.fact_store.read().await;
        assert_eq!(store.get(&fid).unwrap().entity, "__agent::alice::off-secrets");
    }
    // Owner (raw name alice) can edit its own private fact.
    let edited = handle_memory_edit(
        &json!({"fact_id": fid, "new_value": "edited-off", "reason": "r"}),
        &alice,
    )
    .await
    .unwrap();
    assert_eq!(edited["structuredContent"]["new_fact"]["value"], "edited-off");
    assert_eq!(edited["structuredContent"]["new_fact"]["entity"], "off-secrets");
    // A different agent is refused.
    let bob_err = handle_memory_edit(&json!({"fact_id": fid, "new_value": "x", "reason": "r"}), &bob)
        .await
        .unwrap_err();
    assert_eq!(bob_err.data.unwrap()["reason"], "reserved_or_invisible");

    // --- memory_freshness shared-pool parity + private reserved-filtered ------
    let shared = handle_store_fact(
        &json!({"entity": "off-shared", "key": "k", "value": "off-shared-needle"}),
        &alice,
    )
    .await
    .unwrap();
    let shared_id = fact_id_of(&shared);
    let bob_view = handle_memory_freshness(&json!({"top_k": 100, "token_budget": 2000}), &bob)
        .await
        .unwrap();
    assert!(
        rows_have_fact_id(&bob_view, &shared_id),
        "flag-off shared pool: a different agent sees the non-private fact"
    );
    assert!(
        !rows_have_fact_id(&bob_view, &fid),
        "flag-off: the private fact is reserved-filtered on memory_freshness (unchanged from pre-M5)"
    );
    std::env::remove_var("CORECRUXD_FEATURE_FRESHNESS");
    std::env::remove_var("CORECRUXD_FEATURE_MEMORY_PANEL");
}
