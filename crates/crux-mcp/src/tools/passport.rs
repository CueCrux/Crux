// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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

// ── Shared helpers (used by sync gate) ────────────────────────────────────

/// Look up the calling agent's passport from the fact store.
/// Returns `None` if no passport exists or the agent is anonymous.
pub(crate) async fn get_agent_passport(ctx: &McpContext) -> Option<PassportRecord> {
    let agent_name = scope::agent_name(ctx.agent.as_ref())?;

    let entity = format!("{PASSPORT_PREFIX}{agent_name}");
    let q = FactQuery {
        query: None,
        entity: Some(entity),
        entity_prefix: None,
        top_k: 1,
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
    let agent_name = scope::agent_name(ctx.agent.as_ref()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "issue_passport requires an authenticated agent identity".to_string(),
        data: Some(json!({"requires_agent_identity": true})),
    })?;

    let sponsor_id = args.get("sponsor_id").and_then(|v| v.as_str()).map(String::from);

    // Check if passport already exists.
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

    let receipt_count = count_receipts(ctx).await;
    let tier = resolve_tier(receipt_count);

    // Build record (hash everything except passport_hash itself).
    let mut record = PassportRecord {
        principal_id: agent_name.to_string(),
        sponsor_id: sponsor_id.clone(),
        reputation_tier: tier.to_string(),
        receipt_count,
        issued_at: chrono::Utc::now().to_rfc3339(),
        passport_hash: String::new(),
    };
    let hash_input = serde_json::to_string(&record).unwrap_or_default();
    record.passport_hash = blake3::hash(hash_input.as_bytes()).to_hex().to_string();

    let canonical = serde_json::to_string(&record).unwrap_or_default();
    let entity = format!("{PASSPORT_PREFIX}{agent_name}");

    let req = StoreFact {
        entity,
        key: "passport".to_string(),
        value: canonical,
        source_receipt: None,
        confidence: 1.0,
        private: false,
    };

    let mut store = ctx.fact_store.write().await;
    store.store(req);

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "passport issued for {} (tier={}, receipts={}, sponsor={})",
                agent_name,
                tier,
                receipt_count,
                sponsor_id.as_deref().unwrap_or("none")
            )
        }]
    }))
}

/// `get_passport` — return the calling agent's passport.
///
/// Recalculates the receipt count and upgrades the tier if thresholds are met.
pub async fn handle_get_passport(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let Some(agent_name) = scope::agent_name(ctx.agent.as_ref()) else {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": "no agent identity. Authenticate with a bearer token to access your passport."
            }]
        }));
    };

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
                    entity,
                    key: "passport".to_string(),
                    value: canonical,
                    source_receipt: None,
                    confidence: 1.0,
                    private: false,
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

            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "passport for {} (tier={}, receipts={}, sponsor={}, issued={}, hash={}).{}",
                        record.principal_id,
                        record.reputation_tier,
                        record.receipt_count,
                        record.sponsor_id.as_deref().unwrap_or("none"),
                        record.issued_at,
                        &record.passport_hash[..16],
                        upgrade_hint
                    )
                }]
            }))
        }
    }
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
                    entity: format!("test-{i}"),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
                });
            }
        }

        let result = handle_get_passport(&json!({}), &alice).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("tier=basic"));
        assert!(text.contains("receipts=10"));
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
                    entity: format!("r-{i}"),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
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
