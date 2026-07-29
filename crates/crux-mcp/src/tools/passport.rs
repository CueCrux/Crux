// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Agent Passport tools: `issue_passport`, `get_passport`.
//!
//! Passports are stored as facts under the `__passport__::{agent_name}` entity
//! prefix. They track identity, lineage (sponsor), and a reputation tier
//! derived from local receipt count. Sync operations require a minimum
//! passport tier before data can leave or enter the node.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::scope;
use corecrux_memory::fact_store::{FactQuery, StoreFact};

/// Entity prefix for all passports.
const PASSPORT_PREFIX: &str = "__passport__::";

/// Tier thresholds (matching CruxEngine passport service).
const TIER_ELITE_RECEIPTS: u64 = 2000;
const TIER_TRUSTED_RECEIPTS: u64 = 500;
const TIER_ESTABLISHED_RECEIPTS: u64 = 100;
const TIER_BASIC_RECEIPTS: u64 = 10;

/// Serialised passport record stored as a fact value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PassportRecord {
    pub principal_id: String,
    pub sponsor_id: Option<String>,
    pub reputation_tier: String,
    pub receipt_count: u64,
    pub issued_at: String,
    pub passport_hash: String,
    /// agent-passport M4: the tenant-group (collaboration boundary / shared
    /// pool) this passport belongs to, recorded at auto-issue/mint time from
    /// [`crate::agent_passport::AgentPassportMap`]. `None` for passports issued
    /// without a mapped tenant-group (flag-off, unmapped agents, or pre-M4
    /// records — `serde(default)` keeps those deserialising).
    ///
    /// This field is RECORDED ONLY. M4 does not consult it for any visibility
    /// decision; M5 (gated) is where group-visibility enforcement reads it.
    #[serde(default)]
    pub tenant_group: Option<String>,
    /// passport-revocation M1: when set (RFC3339), this passport is REVOKED and
    /// must be refused at the dispatch gate (M3). Terminal + supersede-don't-
    /// delete — the fact stays for audit; a revoked passport is never un-revoked
    /// (re-grant = a NEW passport). `serde(default)` keeps pre-revocation
    /// records deserialising (T.2 back-compat).
    #[serde(default)]
    pub revoked_at: Option<String>,
    /// passport-revocation M2: optional human-readable reason captured at revoke
    /// time, surfaced by `get_passport` (M4) so a revoked agent learns why.
    #[serde(default)]
    pub revoked_reason: Option<String>,
}

// ── Tier resolution ───────────────────────────────────────────────────────

/// Resolve a reputation tier from a receipt count.
fn resolve_tier(receipt_count: u64) -> &'static str {
    if receipt_count >= TIER_ELITE_RECEIPTS {
        "elite"
    } else if receipt_count >= TIER_TRUSTED_RECEIPTS {
        "trusted"
    } else if receipt_count >= TIER_ESTABLISHED_RECEIPTS {
        "established"
    } else if receipt_count >= TIER_BASIC_RECEIPTS {
        "basic"
    } else {
        "unverified"
    }
}

/// Map a tier name to a numeric rank (higher = more privileged).
fn tier_rank(tier: &str) -> u8 {
    match tier {
        "elite" => 4,
        "trusted" => 3,
        "established" => 2,
        "basic" => 1,
        _ => 0,
    }
}

/// passport-revocation M2: may `caller` revoke `target`?
///
/// Authorized iff one of:
/// - **self-revoke** — the caller's own passport key equals the target's;
/// - **operator** — the caller holds the top (`elite`) tier;
/// - **sponsor** — the caller is the principal that sponsored the target.
///
/// (Decision 2026-06-29: operator/admin-or-self, plus sponsor. No third-party
/// revoke. Configurable later via an OD row.)
fn can_revoke(caller_key: &str, caller: &PassportRecord, target_key: &str, target: &PassportRecord) -> bool {
    caller_key == target_key
        || caller.reputation_tier == "elite"
        || target.sponsor_id.as_deref() == Some(caller.principal_id.as_str())
}

// ── MCP-vs-daemon passport boundary ───────────────────────────────────────
//
// There are TWO passport stores keyed off the same `__passport__::` prefix:
//
//   * THIS module (crux-mcp) stores under `__passport__::{name}` key=`passport`
//     with the [`PassportRecord`] below (principal/sponsor/tier/receipt/hash).
//     `issue_passport`, `get_passport`, and the sync tier-gate
//     (`require_passport_tier`) read EXCLUSIVELY this store. It is the store
//     the reputation/tier ladder runs on.
//   * `corecruxd::passports` stores under `__passport__::{id}` key=`record`
//     with a richer record (category / agent_work_gate / public_key_hex) and
//     seeds `personal-default` / `work-default` / `public-default`.
//
// They share the entity prefix but use DIFFERENT keys, so they never collide
// in the FactStore. agent-passport M2 stays entirely within THIS (MCP) store
// to avoid a split-brain: the auto-issued passport is keyed to the resolved
// passport_id (e.g. `claude-work`) so it agrees with M1's `actor` attribution,
// but it does NOT touch or duplicate the daemon-seeded defaults.

// ── Shared helpers (used by sync gate) ────────────────────────────────────

/// Resolve the entity-name component used to key this agent's MCP passport.
///
/// Flag-OFF (or unmapped agent): the raw agent token-name — identical to the
/// pre-M2 behaviour, so `__passport__::anthropic`.
///
/// Flag-ON + mapped agent (agent-passport M2): the resolved passport_id from
/// [`McpContext::agent_passport_map`], e.g. `anthropic` → `claude-work`, so the
/// passport is keyed to the same id M1 stamps as the fact `actor`. This keeps
/// attribution and the passport in agreement.
pub(crate) fn passport_key_name(ctx: &McpContext) -> Option<String> {
    let agent_name = scope::agent_name(ctx.agent.as_ref())?;
    if ctx.agent_passports_enabled {
        if let Some(passport_id) = crate::agent_passport::resolve_agent_passport(agent_name, &ctx.agent_passport_map) {
            return Some(passport_id);
        }
    }
    Some(agent_name.to_string())
}

/// Look up the calling agent's passport from the fact store.
/// Returns `None` if no passport exists or the agent is anonymous.
pub(crate) async fn get_agent_passport(ctx: &McpContext) -> Option<PassportRecord> {
    let agent_name = passport_key_name(ctx)?;
    get_passport_by_name(ctx, &agent_name).await
}

/// Load a passport by its key-name (the entity component after `__passport__::`).
/// Used by `get_agent_passport` (the caller's own) and by `revoke_passport` (an
/// explicit target). `top_k` is >1 so a co-located `revocation` audit fact under
/// the same entity (M2) doesn't crowd out the `passport` fact.
pub(crate) async fn get_passport_by_name(ctx: &McpContext, name: &str) -> Option<PassportRecord> {
    let entity = format!("{PASSPORT_PREFIX}{name}");
    let q = FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(entity),
        entity_prefix: None,
        top_k: 16,
        token_budget: None,
    };

    let store = ctx.fact_store.read().await;
    let result = store.query(&q);
    result
        .facts
        .iter()
        .find(|f| !f.deleted && f.key == "passport")
        .and_then(|f| serde_json::from_str::<PassportRecord>(&f.value).ok())
}

/// Count facts with a non-null `source_receipt` in the store (proxy for
/// receipt-backed interactions).
async fn count_receipts(ctx: &McpContext) -> u64 {
    let store = ctx.fact_store.read().await;
    store
        .all_facts()
        .filter(|f| !f.deleted && f.source_receipt.is_some())
        .count() as u64
}

/// Check that the calling agent has a passport at or above the required tier.
/// Returns `Ok(())` if the check passes, or an MCP error-content `Value` if not.
pub(crate) async fn require_passport_tier(ctx: &McpContext, required_tier: &str) -> Result<(), Value> {
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    if agent_name.is_none() {
        return Err(json!({
            "content": [{
                "type": "text",
                "text": "sync requires an authenticated agent identity. Set CRUX_AGENT_TOKEN or CRUX_AGENT_TOKENS and pass the token as a Bearer header."
            }],
            "isError": true
        }));
    }

    let passport = get_agent_passport(ctx).await;

    match passport {
        None => Err(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "sync requires an agent passport. Call issue_passport() first to create one. Minimum tier for this operation: {required_tier}."
                )
            }],
            "isError": true
        })),
        Some(p) if tier_rank(&p.reputation_tier) < tier_rank(required_tier) => Err(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "sync requires {} tier or above. Your current tier is {} ({} receipts). \
                     Store more receipt-backed facts to increase your tier.",
                    required_tier, p.reputation_tier, p.receipt_count
                )
            }],
            "isError": true
        })),
        Some(_) => Ok(()),
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// `issue_passport` — create or return an agent passport.
///
/// Requires an authenticated agent identity. Creates the passport with
/// `unverified` tier on first call. Subsequent calls return the existing
/// passport (idempotent).
pub async fn handle_issue_passport(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let principal = passport_key_name(ctx).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "issue_passport requires an authenticated agent identity".to_string(),
        data: Some(json!({"requires_agent_identity": true})),
    })?;

    let sponsor_id = args.get("sponsor_id").and_then(|v| v.as_str()).map(String::from);

    // Check if passport already exists (idempotent).
    if let Some(existing) = get_agent_passport(ctx).await {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "passport already exists for {} (tier={}, receipts={}, sponsor={})",
                    existing.principal_id,
                    existing.reputation_tier,
                    existing.receipt_count,
                    existing.sponsor_id.as_deref().unwrap_or("none")
                )
            }]
        }));
    }

    let record = mint_passport(ctx, &principal, sponsor_id.clone(), agent_tenant_group(ctx)).await;

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "passport issued for {} (tier={}, receipts={}, sponsor={})",
                record.principal_id,
                record.reputation_tier,
                record.receipt_count,
                sponsor_id.as_deref().unwrap_or("none")
            )
        }]
    }))
}

/// Resolve the calling agent's tenant-group (agent-passport M4), recorded on
/// the minted passport so M5 can enforce on it and `get_passport` can surface
/// it. `None` when the flag is off, the agent is anonymous, or the agent is
/// not in the passport map — recording only, no visibility effect.
pub(crate) fn agent_tenant_group(ctx: &McpContext) -> Option<String> {
    if !ctx.agent_passports_enabled {
        return None;
    }
    let agent_name = scope::agent_name(ctx.agent.as_ref())?;
    crate::agent_passport::resolve_agent_group(agent_name, &ctx.agent_passport_map).map(|g| g.tenant)
}

/// Mint and persist a passport for `principal` (the resolved passport-key name)
/// and return the stored record.
///
/// Shared by `handle_issue_passport` and the agent-passport M2 auto-issue path
/// so both code paths produce byte-identical records. Callers MUST check
/// `get_agent_passport` first for idempotency — this function unconditionally
/// writes. `tenant_group` (agent-passport M4) is recorded on the record but
/// drives no visibility behaviour.
async fn mint_passport(
    ctx: &McpContext,
    principal: &str,
    sponsor_id: Option<String>,
    tenant_group: Option<String>,
) -> PassportRecord {
    let receipt_count = count_receipts(ctx).await;
    let tier = resolve_tier(receipt_count);

    // Build record (hash everything except passport_hash itself).
    let mut record = PassportRecord {
        principal_id: principal.to_string(),
        sponsor_id,
        reputation_tier: tier.to_string(),
        receipt_count,
        issued_at: chrono::Utc::now().to_rfc3339(),
        passport_hash: String::new(),
        tenant_group,
        revoked_at: None,
        revoked_reason: None,
    };
    let hash_input = serde_json::to_string(&record).unwrap_or_default();
    record.passport_hash = blake3::hash(hash_input.as_bytes()).to_hex().to_string();

    let canonical = serde_json::to_string(&record).unwrap_or_default();
    let entity = format!("{PASSPORT_PREFIX}{principal}");

    let req = StoreFact {
        tenant_hash: "default".to_string(),
        entity,
        key: "passport".to_string(),
        value: canonical,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };

    let mut store = ctx.fact_store.write().await;
    store.store(req);
    record
}

/// agent-passport M2 auto-issue: when the flag is on and the calling agent is
/// *mapped* to a passport_id, ensure a passport exists, minting one keyed to
/// the resolved id (e.g. `claude-work`) on first session. Idempotent — a second
/// call finds the existing passport and writes nothing.
///
/// No-op when the flag is off, the agent is anonymous, or the agent is not in
/// the passport map (those agents keep the pre-M2 "call issue_passport()"
/// flow). Returns the (possibly freshly minted) record when one exists.
pub(crate) async fn auto_issue_if_mapped(ctx: &McpContext) -> Option<PassportRecord> {
    if !ctx.agent_passports_enabled {
        return None;
    }
    let agent_name = scope::agent_name(ctx.agent.as_ref())?;
    // Only auto-issue for agents that resolve to a passport_id; unmapped agents
    // fall back to the explicit issue_passport() flow.
    let group = crate::agent_passport::resolve_agent_group(agent_name, &ctx.agent_passport_map)?;

    if let Some(existing) = get_agent_passport(ctx).await {
        return Some(existing);
    }
    // agent-passport M4: record the resolved tenant-group on the minted
    // passport (recording only — no visibility change).
    Some(mint_passport(ctx, &group.passport, None, Some(group.tenant)).await)
}

/// `get_passport` — return the calling agent's passport.
///
/// Recalculates the receipt count and upgrades the tier if thresholds are met.
pub async fn handle_get_passport(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let Some(agent_name) = passport_key_name(ctx) else {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": "no agent identity. Authenticate with a bearer token to access your passport."
            }]
        }));
    };

    // agent-passport M2: a mapped agent under the flag bootstraps its passport
    // on first access, so `get_passport` returns a tier instead of "none".
    // No-op when the flag is off or the agent is unmapped.
    auto_issue_if_mapped(ctx).await;

    let passport = get_agent_passport(ctx).await;

    match passport {
        None => Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("no passport for {agent_name}. Call issue_passport() to create one.")
            }]
        })),
        Some(mut record) => {
            // Recalculate receipt count and potentially upgrade tier.
            let receipt_count = count_receipts(ctx).await;
            let new_tier = resolve_tier(receipt_count);
            let tier_changed = new_tier != record.reputation_tier;

            if tier_changed || receipt_count != record.receipt_count {
                record.receipt_count = receipt_count;
                record.reputation_tier = new_tier.to_string();
                // Recompute hash.
                record.passport_hash = String::new();
                let hash_input = serde_json::to_string(&record).unwrap_or_default();
                record.passport_hash = blake3::hash(hash_input.as_bytes()).to_hex().to_string();

                // Update the stored passport.
                let canonical = serde_json::to_string(&record).unwrap_or_default();
                let entity = format!("{PASSPORT_PREFIX}{agent_name}");
                let req = StoreFact {
                    tenant_hash: "default".to_string(),
                    entity,
                    key: "passport".to_string(),
                    value: canonical,
                    source_receipt: None,
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                };
                let mut store = ctx.fact_store.write().await;
                store.store(req);
            }

            let upgrade_hint = if new_tier != "elite" {
                let next_tier = match new_tier {
                    "unverified" => ("basic", TIER_BASIC_RECEIPTS),
                    "basic" => ("established", TIER_ESTABLISHED_RECEIPTS),
                    "established" => ("trusted", TIER_TRUSTED_RECEIPTS),
                    "trusted" => ("elite", TIER_ELITE_RECEIPTS),
                    _ => ("basic", TIER_BASIC_RECEIPTS),
                };
                format!(
                    " Next tier: {} (need {} receipts, have {}).",
                    next_tier.0, next_tier.1, receipt_count
                )
            } else {
                String::new()
            };

            // passport-revocation M4: a revoked passport learns it was revoked
            // (and why) via get_passport — the one tool the M3 gate still allows.
            let revoked_note = match &record.revoked_at {
                Some(at) => format!(
                    " ⚠ REVOKED at {} (reason: {}).",
                    at,
                    record.revoked_reason.as_deref().unwrap_or("none")
                ),
                None => String::new(),
            };

            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "passport for {} (tier={}, receipts={}, sponsor={}, group={}, issued={}, hash={}).{}{}",
                        record.principal_id,
                        record.reputation_tier,
                        record.receipt_count,
                        record.sponsor_id.as_deref().unwrap_or("none"),
                        record.tenant_group.as_deref().unwrap_or("none"),
                        record.issued_at,
                        &record.passport_hash[..16],
                        upgrade_hint,
                        revoked_note
                    )
                }]
            }))
        }
    }
}

/// `revoke_passport` — revoke an agent passport (passport-revocation M2).
///
/// Terminal + supersede-don't-delete: the passport fact stays (revoked), and a
/// separate `revocation` audit fact records who/why/when (RCX
/// `AttestationRevokedReceipt` semantics). Enforcement (refusing a revoked
/// passport's calls) is M3, gated behind `CRUX_PASSPORT_REVOCATION=1`.
pub async fn handle_revoke_passport(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let Some(caller_key) = passport_key_name(ctx) else {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "revoke_passport requires an authenticated agent identity".to_string(),
            data: Some(json!({"requires_agent_identity": true})),
        });
    };

    let target_key = args
        .get("target_passport")
        .and_then(|v| v.as_str())
        .map_or_else(|| caller_key.clone(), String::from);
    let reason = args.get("reason").and_then(|v| v.as_str()).map(String::from);

    let err_content = |text: String| json!({"content": [{"type": "text", "text": text}], "isError": true});

    let Some(caller) = get_passport_by_name(ctx, &caller_key).await else {
        return Ok(err_content(format!(
            "revoke_passport: caller '{caller_key}' has no passport. Call issue_passport() first."
        )));
    };
    let Some(mut target) = get_passport_by_name(ctx, &target_key).await else {
        return Ok(err_content(format!(
            "revoke_passport: no passport found for '{target_key}'."
        )));
    };

    // Idempotent: a revoked passport is terminal — re-revoke is a no-op.
    if target.revoked_at.is_some() {
        return Ok(json!({"content": [{"type": "text", "text": format!(
            "passport '{}' is already revoked (at {}, reason={}).",
            target_key,
            target.revoked_at.as_deref().unwrap_or("?"),
            target.revoked_reason.as_deref().unwrap_or("none")
        )}]}));
    }

    if !can_revoke(&caller_key, &caller, &target_key, &target) {
        return Ok(err_content(format!(
            "revoke_passport: '{caller_key}' is not authorized to revoke '{target_key}'. \
             Allowed: self-revoke, the passport's sponsor, or an elite-tier operator."
        )));
    }

    // Stamp revocation (supersede-don't-delete) and recompute the integrity hash.
    let revoked_at = chrono::Utc::now().to_rfc3339();
    target.revoked_at = Some(revoked_at.clone());
    target.revoked_reason.clone_from(&reason);
    target.passport_hash = String::new();
    let hash_input = serde_json::to_string(&target).unwrap_or_default();
    target.passport_hash = blake3::hash(hash_input.as_bytes()).to_hex().to_string();

    let entity = format!("{PASSPORT_PREFIX}{target_key}");
    let canonical = serde_json::to_string(&target).unwrap_or_default();
    let event = json!({
        "revoker_passport": caller_key,
        "reason": reason,
        "revoked_at": revoked_at,
    });

    {
        let mut store = ctx.fact_store.write().await;
        // 1. Mark the passport record revoked.
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.clone(),
            key: "passport".to_string(),
            value: canonical,
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: Some(caller_key.clone()),
        });
        // 2. Receipted audit record of the revocation event (QC.3-attributed,
        //    T.4 audit trail via the store's append/receipt path).
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity,
            key: "revocation".to_string(),
            value: event.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: Some(caller_key.clone()),
        });
    }

    Ok(json!({"content": [{"type": "text", "text": format!(
        "passport '{}' revoked by '{}' (reason={}). Access is refused once revocation \
         enforcement (CRUX_PASSPORT_REVOCATION=1) is enabled.",
        target_key,
        caller_key,
        reason.as_deref().unwrap_or("none")
    )}]}))
}

// ── passport-revocation M3: enforcement helpers ────────────────────────────

/// Tools a REVOKED passport may still call, so it can discover *why* it was
/// revoked (M4). Everything else is refused by `call_tool` when
/// [`McpContext::revocation_enforced`] is on.
pub(crate) const REVOKED_AGENT_ALLOWLIST: &[&str] = &["get_passport", "get_agent_identity"];

/// If the calling agent's passport is revoked, return its reason (`Some`).
/// `None` when the agent is anonymous, has no passport, or the passport is
/// active — fail-open: only an explicit `revoked_at` blocks.
pub(crate) async fn caller_revocation_reason(ctx: &McpContext) -> Option<String> {
    let p = get_agent_passport(ctx).await?;
    p.revoked_at
        .is_some()
        .then(|| p.revoked_reason.unwrap_or_else(|| "(no reason recorded)".to_string()))
}

/// The error a revoked passport gets for a non-allowlisted tool.
pub(crate) fn revoked_call_error(tool: &str, reason: &str) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": format!(
                "passport revoked — '{tool}' refused (reason: {reason}). \
                 Call get_passport for your revocation status."
            )
        }],
        "isError": true
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;
    use corecrux_memory::fact_store::StoreFact;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    fn alice_ctx(ctx: &McpContext) -> McpContext {
        ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        })
    }

    // ── resolve_tier ───────────────────────────────────────────────

    #[test]
    fn tier_resolution() {
        assert_eq!(resolve_tier(0), "unverified");
        assert_eq!(resolve_tier(9), "unverified");
        assert_eq!(resolve_tier(10), "basic");
        assert_eq!(resolve_tier(99), "basic");
        assert_eq!(resolve_tier(100), "established");
        assert_eq!(resolve_tier(499), "established");
        assert_eq!(resolve_tier(500), "trusted");
        assert_eq!(resolve_tier(1999), "trusted");
        assert_eq!(resolve_tier(2000), "elite");
        assert_eq!(resolve_tier(10000), "elite");
    }

    #[test]
    fn tier_rank_ordering() {
        assert!(tier_rank("elite") > tier_rank("trusted"));
        assert!(tier_rank("trusted") > tier_rank("established"));
        assert!(tier_rank("established") > tier_rank("basic"));
        assert!(tier_rank("basic") > tier_rank("unverified"));
    }

    // ── issue_passport ─────────────────────────────────────────────

    #[tokio::test]
    async fn issue_passport_requires_agent() {
        let ctx = test_ctx(); // no agent
        let err = handle_issue_passport(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("authenticated agent"));
    }

    #[tokio::test]
    async fn issue_passport_creates_unverified() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        let result = handle_issue_passport(&json!({}), &alice).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("passport issued for alice"));
        assert!(text.contains("tier=unverified"));
    }

    #[tokio::test]
    async fn issue_passport_is_born_private() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);

        handle_issue_passport(&json!({}), &alice).await.unwrap();

        let store = alice.fact_store.read().await;
        let fact_id = store
            .all_facts()
            .find(|fact| fact.entity == "__passport__::alice" && fact.key == "passport")
            .map(|fact| fact.fact_id.clone())
            .expect("passport handler should persist a passport fact");
        let fact = store.get(&fact_id).expect("persisted passport fact should be readable");
        assert!(fact.private, "passport facts must be private from their first write");
    }

    #[tokio::test]
    async fn issue_passport_with_sponsor() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        let result = handle_issue_passport(&json!({"sponsor_id": "platform-admin"}), &alice)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("sponsor=platform-admin"));
    }

    #[tokio::test]
    async fn issue_passport_idempotent() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);

        // First call creates.
        let r1 = handle_issue_passport(&json!({}), &alice).await.unwrap();
        let t1 = r1["content"][0]["text"].as_str().unwrap();
        assert!(t1.contains("passport issued"));

        // Second call returns existing.
        let r2 = handle_issue_passport(&json!({}), &alice).await.unwrap();
        let t2 = r2["content"][0]["text"].as_str().unwrap();
        assert!(t2.contains("passport already exists"));
    }

    // ── get_passport ───────────────────────────────────────────────

    #[tokio::test]
    async fn get_passport_no_identity() {
        let ctx = test_ctx();
        let result = handle_get_passport(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no agent identity"));
    }

    #[tokio::test]
    async fn get_passport_not_issued() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        let result = handle_get_passport(&json!({}), &alice).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no passport for alice"));
    }

    #[tokio::test]
    async fn get_passport_returns_record() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);

        handle_issue_passport(&json!({}), &alice).await.unwrap();

        let result = handle_get_passport(&json!({}), &alice).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("passport for alice"));
        assert!(text.contains("tier=unverified"));
        assert!(text.contains("hash="));
    }

    #[tokio::test]
    async fn get_passport_upgrades_tier() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);

        handle_issue_passport(&json!({}), &alice).await.unwrap();

        // Add 10 receipt-backed facts to hit "basic" threshold.
        {
            let mut store = ctx.fact_store.write().await;
            for i in 0..10 {
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: format!("test-{i}"),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                });
            }
        }

        let result = handle_get_passport(&json!({}), &alice).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("tier=basic"));
        assert!(text.contains("receipts=10"));
    }

    // ── agent-passport M2: auto-issue + resolved key ───────────────

    use crate::agent_passport::AgentPassportMap;

    /// Context for `anthropic` with the flag ON and the built-in default map
    /// (`anthropic` → `claude-work`).
    fn anthropic_mapped_ctx(ctx: &McpContext) -> McpContext {
        ctx.with_agent(AgentIdentity {
            name: "anthropic".to_string(),
            token_hash: [0u8; 32],
        })
        .with_agent_passports(true, AgentPassportMap::builtin_default())
    }

    #[tokio::test]
    async fn flag_off_get_passport_still_none_for_anthropic() {
        // Flag-OFF: no auto-issue; get_passport reports "no passport" keyed to
        // the raw token-name — pre-M2 behaviour preserved.
        let ctx = test_ctx();
        let anthropic = ctx.with_agent(AgentIdentity {
            name: "anthropic".to_string(),
            token_hash: [0u8; 32],
        });
        let result = handle_get_passport(&json!({}), &anthropic).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no passport for anthropic"));
        assert!(text.contains("issue_passport()"));
    }

    #[tokio::test]
    async fn flag_on_get_passport_auto_issues_claude_work() {
        // Flag-ON + mapped: get_passport bootstraps the passport keyed to the
        // RESOLVED id (`claude-work`), not the raw token-name, and returns a
        // tier instead of "none".
        let base = test_ctx();
        let anthropic = anthropic_mapped_ctx(&base);

        let result = handle_get_passport(&json!({}), &anthropic).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("passport for claude-work"), "got: {text}");
        assert!(text.contains("tier=unverified"));

        // The fact is keyed to the resolved id, not the raw name.
        {
            let store = base.fact_store.read().await;
            assert!(store
                .all_facts()
                .any(|f| f.entity == "__passport__::claude-work" && f.key == "passport" && !f.deleted));
            assert!(!store
                .all_facts()
                .any(|f| f.entity == "__passport__::anthropic" && f.key == "passport"));
        }
    }

    #[tokio::test]
    async fn flag_on_cuecrux_session_first_contact_auto_issue_is_idempotent() {
        // Two auto-issue calls (simulating two sessions) must yield exactly one
        // passport — no duplicate on the second contact.
        let base = test_ctx();
        let anthropic = anthropic_mapped_ctx(&base);

        let r1 = super::auto_issue_if_mapped(&anthropic).await;
        assert!(r1.is_some());
        let r2 = super::auto_issue_if_mapped(&anthropic).await;
        assert!(r2.is_some());

        let store = base.fact_store.read().await;
        let count = store
            .all_facts()
            .filter(|f| f.entity == "__passport__::claude-work" && f.key == "passport" && !f.deleted)
            .count();
        assert_eq!(count, 1, "auto-issue must be idempotent (one passport)");
    }

    #[tokio::test]
    async fn flag_on_issue_passport_reachable_and_keys_resolved_id() {
        // Direct issue_passport call under the flag keys to the resolved id and
        // is idempotent with the auto-issue path.
        let base = test_ctx();
        let anthropic = anthropic_mapped_ctx(&base);

        let r1 = handle_issue_passport(&json!({}), &anthropic).await.unwrap();
        assert!(r1["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("passport issued for claude-work"));

        // Auto-issue afterwards must find the existing one, not duplicate.
        let r2 = handle_issue_passport(&json!({}), &anthropic).await.unwrap();
        assert!(r2["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("passport already exists for claude-work"));
    }

    #[tokio::test]
    async fn flag_on_unmapped_agent_does_not_auto_issue() {
        // Flag-ON but the agent is not in the map: no auto-issue; the explicit
        // issue_passport() flow still applies (keyed to the raw name).
        let base = test_ctx();
        let unmapped = base
            .with_agent(AgentIdentity {
                name: "windows-host".to_string(),
                token_hash: [0u8; 32],
            })
            .with_agent_passports(true, AgentPassportMap::builtin_default());

        assert!(super::auto_issue_if_mapped(&unmapped).await.is_none());
        let result = handle_get_passport(&json!({}), &unmapped).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no passport for windows-host"));
    }

    #[tokio::test]
    async fn flag_on_tier_ladder_engages_for_mapped_agent() {
        // After the auto-issued passport exists, adding receipts drives the
        // tier ladder via get_passport (resolve_tier mapping exercised).
        let base = test_ctx();
        let anthropic = anthropic_mapped_ctx(&base);

        handle_get_passport(&json!({}), &anthropic).await.unwrap(); // auto-issue

        {
            let mut store = base.fact_store.write().await;
            for i in 0..10 {
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: format!("rcpt-{i}"),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                });
            }
        }

        let result = handle_get_passport(&json!({}), &anthropic).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("passport for claude-work"));
        assert!(text.contains("tier=basic"), "got: {text}");
        assert!(text.contains("receipts=10"));
    }

    // ── agent-passport M4: tenant-group recording ──────────────────

    #[tokio::test]
    async fn flag_on_anthropic_records_tenant_group_work() {
        // Flag-ON + mapped: the auto-issued passport records tenant_group=work
        // and get_passport surfaces it (recording only — no visibility change).
        let base = test_ctx();
        let anthropic = anthropic_mapped_ctx(&base);

        let result = handle_get_passport(&json!({}), &anthropic).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("passport for claude-work"), "got: {text}");
        assert!(text.contains("group=work"), "got: {text}");

        // The recorded fact carries tenant_group on the PassportRecord.
        let rec = super::get_agent_passport(&anthropic).await.unwrap();
        assert_eq!(rec.tenant_group.as_deref(), Some("work"));
    }

    #[tokio::test]
    async fn flag_on_openai_records_tenant_group_work() {
        let base = test_ctx();
        let openai = base
            .with_agent(AgentIdentity {
                name: "openai".to_string(),
                token_hash: [0u8; 32],
            })
            .with_agent_passports(true, AgentPassportMap::builtin_default());

        let result = handle_get_passport(&json!({}), &openai).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("passport for codex-work"), "got: {text}");
        assert!(text.contains("group=work"), "got: {text}");

        let rec = super::get_agent_passport(&openai).await.unwrap();
        assert_eq!(rec.tenant_group.as_deref(), Some("work"));
    }

    #[tokio::test]
    async fn flag_on_custom_tenant_recorded_from_env_shape() {
        // A custom env map with an explicit `:tenant` segment is recorded.
        let map = AgentPassportMap::from_pairs_str("anthropic:claude-work:research");
        let base = test_ctx();
        let anthropic = base
            .with_agent(AgentIdentity {
                name: "anthropic".to_string(),
                token_hash: [0u8; 32],
            })
            .with_agent_passports(true, map);

        handle_get_passport(&json!({}), &anthropic).await.unwrap();
        let rec = super::get_agent_passport(&anthropic).await.unwrap();
        assert_eq!(rec.tenant_group.as_deref(), Some("research"));
    }

    #[tokio::test]
    async fn flag_off_records_no_tenant_group() {
        // Flag-OFF: explicit issue_passport keyed to the raw name records no
        // group; get_passport shows group=none.
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        handle_issue_passport(&json!({}), &alice).await.unwrap();

        let result = handle_get_passport(&json!({}), &alice).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("group=none"), "got: {text}");

        let rec = super::get_agent_passport(&alice).await.unwrap();
        assert_eq!(rec.tenant_group, None);
    }

    #[tokio::test]
    async fn pre_m4_passport_fact_without_group_still_loads() {
        // serde(default): a passport fact written before M4 (no tenant_group
        // field) must still deserialise into PassportRecord.
        let ctx = test_ctx();
        let legacy = r#"{"principal_id":"legacy","sponsor_id":null,"reputation_tier":"unverified","receipt_count":0,"issued_at":"2026-01-01T00:00:00Z","passport_hash":"abc"}"#;
        let rec: PassportRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(rec.principal_id, "legacy");
        assert_eq!(rec.tenant_group, None);
        let _ = ctx; // silence unused in case of future edits
    }

    #[tokio::test]
    async fn tenant_group_survives_tier_refresh() {
        // get_passport's tier-refresh re-stores the record; tenant_group must
        // survive the rewrite.
        let base = test_ctx();
        let anthropic = anthropic_mapped_ctx(&base);
        handle_get_passport(&json!({}), &anthropic).await.unwrap(); // auto-issue

        // Drive a tier change via receipts so the refresh path re-stores.
        {
            let mut store = base.fact_store.write().await;
            for i in 0..10 {
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: format!("rcpt-{i}"),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                });
            }
        }
        handle_get_passport(&json!({}), &anthropic).await.unwrap();

        let rec = super::get_agent_passport(&anthropic).await.unwrap();
        assert_eq!(rec.reputation_tier, "basic");
        assert_eq!(rec.tenant_group.as_deref(), Some("work"));
    }

    // ── passport-revocation M1: data model back-compat ─────────────

    #[test]
    fn pre_revocation_passport_fact_without_revoked_fields_still_loads() {
        // serde(default): a passport fact written before revocation (no
        // revoked_at / revoked_reason) must still deserialise (T.2 back-compat).
        let legacy = r#"{"principal_id":"legacy","sponsor_id":null,"reputation_tier":"unverified","receipt_count":0,"issued_at":"2026-01-01T00:00:00Z","passport_hash":"abc","tenant_group":"work"}"#;
        let rec: PassportRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(rec.tenant_group.as_deref(), Some("work"));
        assert_eq!(rec.revoked_at, None);
        assert_eq!(rec.revoked_reason, None);
    }

    #[tokio::test]
    async fn minted_passport_is_not_revoked() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        handle_issue_passport(&json!({}), &alice).await.unwrap();
        let rec = super::get_agent_passport(&alice).await.unwrap();
        assert_eq!(rec.revoked_at, None);
        assert_eq!(rec.revoked_reason, None);
    }

    // ── passport-revocation M2: revoke_passport ────────────────────

    #[test]
    fn can_revoke_matrix() {
        let mk = |principal: &str, tier: &str, sponsor: Option<&str>| PassportRecord {
            principal_id: principal.to_string(),
            sponsor_id: sponsor.map(String::from),
            reputation_tier: tier.to_string(),
            receipt_count: 0,
            issued_at: "t".to_string(),
            passport_hash: "h".to_string(),
            tenant_group: None,
            revoked_at: None,
            revoked_reason: None,
        };
        let caller = mk("alice", "basic", None);
        // self-revoke
        assert!(super::can_revoke("alice", &caller, "alice", &caller));
        // operator (elite) cross-revoke
        let elite = mk("op", "elite", None);
        let bob = mk("bob", "basic", None);
        assert!(super::can_revoke("op", &elite, "bob", &bob));
        // sponsor cross-revoke
        let sponsored = mk("bob", "basic", Some("alice"));
        assert!(super::can_revoke("alice", &caller, "bob", &sponsored));
        // unauthorized: not self, not elite, not sponsor
        assert!(!super::can_revoke("alice", &caller, "bob", &bob));
    }

    #[tokio::test]
    async fn revoke_requires_agent() {
        let ctx = test_ctx();
        let err = handle_revoke_passport(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn self_revoke_stamps_audits_and_is_idempotent() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        handle_issue_passport(&json!({}), &alice).await.unwrap();

        let r = handle_revoke_passport(&json!({"reason": "compromised"}), &alice)
            .await
            .unwrap();
        assert!(r.get("isError").is_none(), "got: {r}");
        assert!(r["content"][0]["text"].as_str().unwrap().contains("revoked"));

        let rec = super::get_agent_passport(&alice).await.unwrap();
        assert!(rec.revoked_at.is_some());
        assert_eq!(rec.revoked_reason.as_deref(), Some("compromised"));

        // A receipted revocation audit fact sits beside the passport.
        {
            let store = ctx.fact_store.read().await;
            assert!(store
                .all_facts()
                .any(|f| f.entity == "__passport__::alice" && f.key == "revocation" && !f.deleted));
        }

        // Second revoke is a terminal no-op.
        let r2 = handle_revoke_passport(&json!({}), &alice).await.unwrap();
        assert!(r2["content"][0]["text"].as_str().unwrap().contains("already revoked"));
    }

    #[tokio::test]
    async fn cross_revoke_unauthorized_is_denied() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        let bob = ctx.with_agent(AgentIdentity {
            name: "bob".to_string(),
            token_hash: [1u8; 32],
        });
        handle_issue_passport(&json!({}), &alice).await.unwrap();
        handle_issue_passport(&json!({}), &bob).await.unwrap();

        let r = handle_revoke_passport(&json!({"target_passport": "alice"}), &bob)
            .await
            .unwrap();
        assert_eq!(r["isError"], json!(true));
        assert!(r["content"][0]["text"].as_str().unwrap().contains("not authorized"));

        // alice's passport stays active.
        let rec = super::get_agent_passport(&alice).await.unwrap();
        assert!(rec.revoked_at.is_none());
    }

    #[tokio::test]
    async fn sponsor_can_revoke_sponsored_passport() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        let bob = ctx.with_agent(AgentIdentity {
            name: "bob".to_string(),
            token_hash: [1u8; 32],
        });
        handle_issue_passport(&json!({}), &alice).await.unwrap();
        handle_issue_passport(&json!({"sponsor_id": "alice"}), &bob)
            .await
            .unwrap();

        let r = handle_revoke_passport(&json!({"target_passport": "bob", "reason": "offboarded"}), &alice)
            .await
            .unwrap();
        assert!(r.get("isError").is_none(), "got: {r}");
        let rec = super::get_passport_by_name(&ctx, "bob").await.unwrap();
        assert_eq!(rec.revoked_reason.as_deref(), Some("offboarded"));
    }

    // ── passport-revocation M3: enforcement helper ─────────────────

    #[tokio::test]
    async fn caller_revocation_reason_none_when_active_some_when_revoked() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        handle_issue_passport(&json!({}), &alice).await.unwrap();
        assert!(super::caller_revocation_reason(&alice).await.is_none());

        handle_revoke_passport(&json!({"reason": "leak"}), &alice)
            .await
            .unwrap();
        assert_eq!(super::caller_revocation_reason(&alice).await.as_deref(), Some("leak"));
    }

    // ── passport-revocation M4: get_passport surfaces revoked state ─

    #[tokio::test]
    async fn get_passport_surfaces_revoked_state() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        handle_issue_passport(&json!({}), &alice).await.unwrap();
        handle_revoke_passport(&json!({"reason": "key leaked"}), &alice)
            .await
            .unwrap();

        let result = handle_get_passport(&json!({}), &alice).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("REVOKED"), "got: {text}");
        assert!(text.contains("key leaked"), "got: {text}");
    }

    // ── require_passport_tier ──────────────────────────────────────

    #[tokio::test]
    async fn require_tier_no_agent() {
        let ctx = test_ctx();
        let err = require_passport_tier(&ctx, "basic").await.unwrap_err();
        let text = err["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("authenticated agent identity"));
    }

    #[tokio::test]
    async fn require_tier_no_passport() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        let err = require_passport_tier(&alice, "basic").await.unwrap_err();
        let text = err["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("issue_passport()"));
    }

    #[tokio::test]
    async fn require_tier_insufficient() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        handle_issue_passport(&json!({}), &alice).await.unwrap();

        let err = require_passport_tier(&alice, "basic").await.unwrap_err();
        let text = err["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("basic tier or above"));
        assert!(text.contains("current tier is unverified"));
    }

    #[tokio::test]
    async fn require_tier_sufficient() {
        let ctx = test_ctx();
        let alice = alice_ctx(&ctx);
        handle_issue_passport(&json!({}), &alice).await.unwrap();

        // Add receipts to reach basic.
        {
            let mut store = ctx.fact_store.write().await;
            for i in 0..10 {
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: format!("r-{i}"),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                });
            }
        }

        // Refresh passport to pick up new receipts.
        handle_get_passport(&json!({}), &alice).await.unwrap();

        assert!(require_passport_tier(&alice, "basic").await.is_ok());
        assert!(require_passport_tier(&alice, "unverified").await.is_ok());
        assert!(require_passport_tier(&alice, "established").await.is_err());
    }
}
