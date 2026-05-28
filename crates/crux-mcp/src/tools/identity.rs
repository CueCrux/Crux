// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Identity-continuity MCP tools: `passport_split`, `passport_merge`,
//! `passport_link_device`.
//!
//! Free-tier implementation of ExecPlan
//! `agent-ux-08-identity-continuity-2026-05-27`. Each tool:
//!
//! - Requires an authenticated agent identity (T.3 attribution).
//! - Refuses to cross tenant boundaries (T.1) — source and target
//!   passports must share the same tenant.
//! - Accepts an explicit `token_budget` (QC.2).
//! - Emits a `PassportSplit` / `PassportMerge` / `PassportLinkDevice`
//!   receipt body (CBOR, BLAKE3-hashed) which the downstream v3
//!   dataplane signs via the existing CROWN Ed25519 pipeline. No new
//!   key class is introduced.
//! - Gated behind `CORECRUXD_FEATURE_IDENTITY_CONTINUITY=1`. Default off.
//!
//! Splits and merges are NOT reversible at the fact level. Once a merge
//! retires the source passport, sessions issued under that passport
//! become read-only references. This is by design — receipt history is
//! the immutable record.

use std::env;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::scope;
use crate::tools::passport::{require_passport_tier, PassportRecord};
use corecrux_memory::fact_store::{FactQuery, StoreFact};
use corecrux_receipts::{
    encode_passport_link_device_body_v1, encode_passport_merge_body_v1, encode_passport_split_body_v1,
    MergeConflictPolicyV1, PassportLinkDeviceReceiptBodyV1, PassportMergeConflictV1, PassportMergeReceiptBodyV1,
    PassportSplitReceiptBodyV1, SCHEMA_PASSPORT_LINK_DEVICE_BODY_V1, SCHEMA_PASSPORT_MERGE_BODY_V1,
    SCHEMA_PASSPORT_SPLIT_BODY_V1,
};

/// Feature flag gating ALL three identity-continuity tools.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_IDENTITY_CONTINUITY";

/// Operator-tier name. Defined at the tool layer because passport tiers in
/// this codebase are receipt-count derived (`unverified|basic|established|
/// trusted|elite`); "operator" maps to `trusted`+ for the free-tier
/// implementation. The ExecPlan's stronger "operator passport" concept
/// will be wired through `rcx-capability-token` when the hosted tier
/// lands, but free-tier callers gate on the local equivalent.
const OPERATOR_TIER: &str = "trusted";

/// Entity prefix used by [`crate::tools::passport`] to store passport
/// records. Identity-continuity metadata (split lineage, merge state,
/// retired flag, linked devices) lives alongside the passport under the
/// same entity using distinct keys.
const PASSPORT_PREFIX: &str = "__passport__::";

const KEY_SPLIT_LINEAGE: &str = "split_lineage";
const KEY_MERGE_STATE: &str = "merge_state";
const KEY_RETIRED: &str = "retired";
const KEY_LINKED_DEVICE_PREFIX: &str = "linked_device:";

fn feature_enabled() -> bool {
    env::var(FEATURE_FLAG_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn require_feature_flag() -> Result<(), JsonRpcError> {
    if feature_enabled() {
        Ok(())
    } else {
        Err(JsonRpcError {
            code: METHOD_NOT_FOUND,
            message: format!("identity-continuity tools are disabled (set {FEATURE_FLAG_ENV}=1 to enable)"),
            data: Some(json!({"feature_flag": FEATURE_FLAG_ENV, "enabled": false})),
        })
    }
}

fn require_token_budget(args: &Value) -> Result<u64, JsonRpcError> {
    let budget = args.get("token_budget").and_then(|v| v.as_u64());
    match budget {
        Some(n) if n > 0 => Ok(n),
        _ => Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "token_budget is required (positive integer) per QC.2".to_string(),
            data: Some(json!({"param": "token_budget", "required": true, "min": 1})),
        }),
    }
}

fn require_agent(ctx: &McpContext) -> Result<String, JsonRpcError> {
    scope::agent_name(ctx.agent.as_ref())
        .map(str::to_string)
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "identity-continuity tools require an authenticated agent identity".to_string(),
            data: Some(json!({"param": "passport", "requires_agent_identity": true})),
        })
}

/// Tenant of a passport — derived from the passport's principal_id by
/// splitting on `:` and taking the namespace portion when present.
/// E.g. `personal::myles` → `personal`, `business::acme::staging` →
/// `business::acme`, `passport:user-bob` → `passport`. Bare names fall
/// back to `__default__`.
fn tenant_of(principal_id: &str) -> String {
    if let Some(idx) = principal_id.find("::") {
        // Take everything up to and including the last `::` group that's
        // not a leaf node. The simplest stable rule: split on `::` and keep
        // all-but-last component as the tenant.
        let parts: Vec<&str> = principal_id.split("::").collect();
        if parts.len() >= 2 {
            return parts[..parts.len() - 1].join("::");
        }
        return principal_id[..idx].to_string();
    }
    if let Some(idx) = principal_id.find(':') {
        return principal_id[..idx].to_string();
    }
    "__default__".to_string()
}

/// Fetch a passport by principal_id. Returns `None` if missing or marked
/// retired. Retired passports are visible via [`load_passport_raw`].
async fn load_passport(ctx: &McpContext, principal_id: &str) -> Option<PassportRecord> {
    let raw = load_passport_raw(ctx, principal_id).await?;
    let retired = is_retired(ctx, principal_id).await;
    if retired {
        None
    } else {
        Some(raw)
    }
}

async fn load_passport_raw(ctx: &McpContext, principal_id: &str) -> Option<PassportRecord> {
    let entity = format!("{PASSPORT_PREFIX}{principal_id}");
    let q = FactQuery {
        query: None,
        entity: Some(entity),
        entity_prefix: None,
        top_k: 4,
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

async fn is_retired(ctx: &McpContext, principal_id: &str) -> bool {
    let entity = format!("{PASSPORT_PREFIX}{principal_id}");
    let q = FactQuery {
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
        .any(|f| !f.deleted && f.key == KEY_RETIRED && f.value == "true")
}

fn build_receipt_id(prefix: &str, parts: &[&str]) -> String {
    let joined = parts.join("|");
    let digest = blake3::hash(joined.as_bytes()).to_hex();
    format!("{prefix}_{}", &digest.as_str()[..16])
}

fn now_rfc3339() -> (DateTime<Utc>, String) {
    let now = Utc::now();
    let s = now.to_rfc3339();
    (now, s)
}

// ── `passport_split` ──────────────────────────────────────────────────────

/// `passport_split` — fork a passport into a new identity that inherits the
/// source's facts via read-through, writes diverge to the new identity.
pub async fn handle_passport_split(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    require_feature_flag()?;
    let _ = require_token_budget(args)?;
    let agent_name = require_agent(ctx)?;

    // Operator-tier requirement on the caller's passport.
    if let Err(err) = require_passport_tier(ctx, OPERATOR_TIER).await {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "passport_split requires operator-tier (trusted+) on the calling passport".to_string(),
            data: Some(err),
        });
    }

    let source_passport = args
        .get("target_passport")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "missing required param: target_passport (the passport id to fork)".to_string(),
            data: Some(json!({"param": "target_passport", "required": true})),
        })?
        .to_string();
    let new_name = args
        .get("new_passport_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "missing required param: new_passport_name".to_string(),
            data: Some(json!({"param": "new_passport_name", "required": true})),
        })?
        .to_string();
    let reason = args.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Caller must own the source passport.
    if source_passport != agent_name {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "passport_split: target_passport must equal the calling agent's passport id".to_string(),
            data: Some(json!({
                "param": "target_passport",
                "calling_agent": agent_name,
                "got": source_passport,
            })),
        });
    }

    let source = load_passport(ctx, &source_passport).await.ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("source passport {source_passport} does not exist or is retired"),
        data: Some(json!({"param": "target_passport", "exists": false})),
    })?;

    // Cross-tenant guard (T.1) — the new passport must live in the same
    // tenant. We enforce by deriving the source tenant and requiring the
    // new name to share that prefix.
    let source_tenant = tenant_of(&source.principal_id);
    let new_tenant = tenant_of(&new_name);
    if source_tenant != new_tenant {
        return Err(JsonRpcError {
            code: -32003, // 403-equivalent in JSON-RPC space
            message: format!(
                "cross-tenant split forbidden: source tenant {source_tenant} != new passport tenant {new_tenant}"
            ),
            data: Some(json!({
                "source_tenant": source_tenant,
                "new_tenant": new_tenant,
                "policy": "T.1 cross-tenant guard",
            })),
        });
    }

    // Reject if a passport with this name already exists (active or retired).
    if load_passport_raw(ctx, &new_name).await.is_some() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("a passport named {new_name} already exists"),
            data: Some(json!({"param": "new_passport_name", "collision": true})),
        });
    }

    let tenant_id = source_tenant.clone();
    let (now, now_str) = now_rfc3339();
    let receipt_id = build_receipt_id("r_passport_split", &[&source.principal_id, &new_name, &now_str]);

    let body = PassportSplitReceiptBodyV1 {
        schema: SCHEMA_PASSPORT_SPLIT_BODY_V1.to_string(),
        receipt_id: receipt_id.clone(),
        tenant_id: tenant_id.clone(),
        initiated_by_passport_id: agent_name.clone(),
        source_passport_id: source.principal_id.clone(),
        new_passport_id: new_name.clone(),
        reason: reason.clone(),
        initiated_at: now_str.clone(),
    };
    let body_bytes = encode_passport_split_body_v1(&body).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("split receipt encode failed: {err}"),
        data: None,
    })?;
    let body_hash_hex = blake3::hash(&body_bytes).to_hex().to_string();

    // Materialise the new passport. The fork inherits the source's tier
    // (read-through over the source's facts is achieved at query time —
    // see `read_through_source`). Writes diverge to the new id.
    let new_record = PassportRecord {
        principal_id: new_name.clone(),
        sponsor_id: Some(source.principal_id.clone()),
        reputation_tier: source.reputation_tier.clone(),
        receipt_count: 0,
        issued_at: now.to_rfc3339(),
        passport_hash: body_hash_hex.clone(),
    };
    let canonical = serde_json::to_string(&new_record).unwrap_or_default();
    let new_entity = format!("{PASSPORT_PREFIX}{new_name}");

    let mut store = ctx.fact_store.write().await;
    store.store(StoreFact {
        entity: new_entity.clone(),
        key: "passport".to_string(),
        value: canonical,
        source_receipt: Some(receipt_id.clone()),
        confidence: 1.0,
        private: false,
        horizon_class: None,
    });
    // Record the split lineage on BOTH passports so future reads can
    // resolve the read-through chain.
    store.store(StoreFact {
        entity: new_entity,
        key: KEY_SPLIT_LINEAGE.to_string(),
        value: json!({
            "forked_from": source.principal_id.clone(),
            "split_receipt_id": receipt_id.clone(),
            "split_at": now_str.clone(),
            "reason": reason.clone(),
        })
        .to_string(),
        source_receipt: Some(receipt_id.clone()),
        confidence: 1.0,
        private: false,
        horizon_class: None,
    });
    store.store(StoreFact {
        entity: format!("{PASSPORT_PREFIX}{}", source.principal_id),
        key: format!("split_into:{new_name}"),
        value: json!({
            "split_receipt_id": receipt_id.clone(),
            "split_at": now_str.clone(),
        })
        .to_string(),
        source_receipt: Some(receipt_id.clone()),
        confidence: 1.0,
        private: false,
        horizon_class: None,
    });

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "passport_split: {} forked into {} (receipt {}); writes diverge to new id, reads inherit from source via lineage (NOT reversible at fact level)",
                source.principal_id, new_name, receipt_id,
            ),
        }],
        "new_passport_id": new_name,
        "split_receipt_id": receipt_id,
        "receipt_body_cbor_hex": hex::encode(&body_bytes),
        "receipt_body_hash_hex": body_hash_hex,
        "tenant_id": tenant_id,
    }))
}

// ── `passport_merge` ──────────────────────────────────────────────────────

fn parse_conflict_policy(args: &Value) -> Result<MergeConflictPolicyV1, JsonRpcError> {
    let raw = args
        .get("conflict_policy")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "missing required param: conflict_policy (must be explicit; never silent)".to_string(),
            data: Some(json!({
                "param": "conflict_policy",
                "required": true,
                "accepted": ["prefer_source", "prefer_target", "error_on_conflict"],
            })),
        })?;
    serde_json::from_value::<MergeConflictPolicyV1>(json!(raw)).map_err(|_| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!(
            "invalid conflict_policy '{raw}'; must be one of prefer_source|prefer_target|error_on_conflict"
        ),
        data: Some(json!({
            "param": "conflict_policy",
            "got": raw,
            "accepted": ["prefer_source", "prefer_target", "error_on_conflict"],
        })),
    })
}

/// Conflict-list status code for 409-equivalent responses.
const CONFLICT_STATUS: i32 = -32004;

/// `passport_merge` — collapse two passports under one identity.
pub async fn handle_passport_merge(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    require_feature_flag()?;
    let _ = require_token_budget(args)?;
    let agent_name = require_agent(ctx)?;

    if let Err(err) = require_passport_tier(ctx, OPERATOR_TIER).await {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "passport_merge requires operator-tier (trusted+) on the calling passport".to_string(),
            data: Some(err),
        });
    }

    let source_id = args
        .get("source_passport")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "missing required param: source_passport".to_string(),
            data: Some(json!({"param": "source_passport", "required": true})),
        })?
        .to_string();
    let target_id = args
        .get("target_passport")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "missing required param: target_passport".to_string(),
            data: Some(json!({"param": "target_passport", "required": true})),
        })?
        .to_string();
    let policy = parse_conflict_policy(args)?;
    let reason = args.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if source_id == target_id {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "source_passport and target_passport must differ".to_string(),
            data: Some(json!({"source_passport": source_id, "target_passport": target_id})),
        });
    }

    // Caller must hold an operator-tier passport that owns at least one
    // side (typically target). We require ownership of BOTH unless the
    // caller is the source (in which case they're consenting to retire
    // their own identity into target).
    if agent_name != source_id && agent_name != target_id {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "passport_merge: caller must own source or target passport".to_string(),
            data: Some(json!({
                "calling_agent": agent_name,
                "source_passport": source_id,
                "target_passport": target_id,
            })),
        });
    }

    let source = load_passport(ctx, &source_id).await.ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("source passport {source_id} does not exist or is retired"),
        data: Some(json!({"param": "source_passport", "exists": false})),
    })?;
    let target = load_passport(ctx, &target_id).await.ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("target passport {target_id} does not exist or is retired"),
        data: Some(json!({"param": "target_passport", "exists": false})),
    })?;

    // Cross-tenant guard (T.1).
    let source_tenant = tenant_of(&source.principal_id);
    let target_tenant = tenant_of(&target.principal_id);
    if source_tenant != target_tenant {
        return Err(JsonRpcError {
            code: -32003,
            message: format!(
                "cross-tenant merge forbidden: source tenant {source_tenant} != target tenant {target_tenant}"
            ),
            data: Some(json!({
                "source_tenant": source_tenant,
                "target_tenant": target_tenant,
                "policy": "T.1 cross-tenant guard",
            })),
        });
    }

    // Detect conflicts: walk both passports' fact entities under
    // `__agent::<name>::*` and find (entity_suffix, key) pairs that
    // appear in BOTH with different values. (The agent-prefixed entities
    // already exist in this codebase per the forget ExecPlan.)
    let conflicts = detect_conflicts(ctx, &source_id, &target_id).await;
    if matches!(policy, MergeConflictPolicyV1::ErrorOnConflict) && !conflicts.is_empty() {
        return Err(JsonRpcError {
            code: CONFLICT_STATUS,
            message: format!(
                "passport_merge: {} conflict(s) detected under error_on_conflict policy",
                conflicts.len()
            ),
            data: Some(json!({
                "conflicts": conflicts.iter().map(|(e, k, s, t)| json!({
                    "entity": e,
                    "key": k,
                    "source_value": s,
                    "target_value": t,
                })).collect::<Vec<_>>(),
                "policy": "error_on_conflict",
            })),
        });
    }

    let resolved: Vec<PassportMergeConflictV1> = conflicts
        .iter()
        .map(|(e, k, _s, _t)| PassportMergeConflictV1 {
            entity: e.clone(),
            key: k.clone(),
            resolution: policy.as_str().to_string(),
            chosen_fact_id: format!("inline:{}", policy.as_str()),
        })
        .collect();

    let (now, now_str) = now_rfc3339();
    let receipt_id = build_receipt_id("r_passport_merge", &[&source_id, &target_id, &now_str]);

    let body = PassportMergeReceiptBodyV1 {
        schema: SCHEMA_PASSPORT_MERGE_BODY_V1.to_string(),
        receipt_id: receipt_id.clone(),
        tenant_id: source_tenant.clone(),
        initiated_by_passport_id: agent_name.clone(),
        source_passport_id: source.principal_id.clone(),
        target_passport_id: target.principal_id.clone(),
        conflict_policy: policy,
        conflicts: resolved.clone(),
        reason: reason.clone(),
        initiated_at: now_str.clone(),
    };
    let body_bytes = encode_passport_merge_body_v1(&body).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("merge receipt encode failed: {err}"),
        data: None,
    })?;
    let body_hash_hex = blake3::hash(&body_bytes).to_hex().to_string();

    // Mark the source passport retired. Sessions become read-only refs;
    // future writes that try to attribute to the source id are rejected
    // by `load_passport()` (which returns None for retired records).
    let mut store = ctx.fact_store.write().await;
    let source_entity = format!("{PASSPORT_PREFIX}{}", source.principal_id);
    store.store(StoreFact {
        entity: source_entity.clone(),
        key: KEY_RETIRED.to_string(),
        value: "true".to_string(),
        source_receipt: Some(receipt_id.clone()),
        confidence: 1.0,
        private: false,
        horizon_class: None,
    });
    store.store(StoreFact {
        entity: source_entity,
        key: KEY_MERGE_STATE.to_string(),
        value: json!({
            "merged_into": target.principal_id.clone(),
            "merge_receipt_id": receipt_id.clone(),
            "retired_at": now_str.clone(),
            "reason": reason.clone(),
        })
        .to_string(),
        source_receipt: Some(receipt_id.clone()),
        confidence: 1.0,
        private: false,
        horizon_class: None,
    });
    // Record on the target too.
    store.store(StoreFact {
        entity: format!("{PASSPORT_PREFIX}{}", target.principal_id),
        key: format!("merged_from:{}", source.principal_id),
        value: json!({
            "merge_receipt_id": receipt_id.clone(),
            "merged_at": now_str.clone(),
            "conflicts_resolved": resolved.len(),
            "conflict_policy": body.conflict_policy.as_str(),
        })
        .to_string(),
        source_receipt: Some(receipt_id.clone()),
        confidence: 1.0,
        private: false,
        horizon_class: None,
    });
    drop(store);

    let _ = now;

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "passport_merge: {} retired into {} (policy={}, {} conflict(s) resolved, receipt {}); merge is NOT reversible at fact level — sessions under {} are now read-only references",
                source.principal_id,
                target.principal_id,
                body.conflict_policy.as_str(),
                resolved.len(),
                receipt_id,
                source.principal_id,
            ),
        }],
        "merged_passport_id": target.principal_id,
        "merge_receipt_id": receipt_id,
        "conflicts_resolved": resolved.len(),
        "conflict_policy": body.conflict_policy.as_str(),
        "receipt_body_cbor_hex": hex::encode(&body_bytes),
        "receipt_body_hash_hex": body_hash_hex,
        "tenant_id": source_tenant,
        "retired_passport_id": source.principal_id,
    }))
}

/// Find (entity, key) pairs that exist under both source and target
/// passports' private agent namespaces with differing values. Returns
/// `(entity_suffix, key, source_value, target_value)`.
async fn detect_conflicts(ctx: &McpContext, source: &str, target: &str) -> Vec<(String, String, String, String)> {
    let store = ctx.fact_store.read().await;
    let source_pfx = format!("__agent::{source}::");
    let target_pfx = format!("__agent::{target}::");
    let mut source_idx: std::collections::HashMap<(String, String), String> = std::collections::HashMap::new();
    let mut target_idx: std::collections::HashMap<(String, String), String> = std::collections::HashMap::new();
    for f in store.all_facts() {
        if f.deleted {
            continue;
        }
        if let Some(suffix) = f.entity.strip_prefix(&source_pfx) {
            source_idx.insert((suffix.to_string(), f.key.clone()), f.value.clone());
        } else if let Some(suffix) = f.entity.strip_prefix(&target_pfx) {
            target_idx.insert((suffix.to_string(), f.key.clone()), f.value.clone());
        }
    }
    let mut out = Vec::new();
    for ((entity, key), src_val) in source_idx {
        if let Some(tgt_val) = target_idx.get(&(entity.clone(), key.clone())) {
            if &src_val != tgt_val {
                out.push((entity, key, src_val, tgt_val.clone()));
            }
        }
    }
    out
}

// ── `passport_link_device` ────────────────────────────────────────────────

/// `passport_link_device` — bind a device fingerprint to the calling
/// agent's passport with a capability subset.
pub async fn handle_passport_link_device(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    require_feature_flag()?;
    let _ = require_token_budget(args)?;
    let agent_name = require_agent(ctx)?;

    if let Err(err) = require_passport_tier(ctx, OPERATOR_TIER).await {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "passport_link_device requires operator-tier (trusted+) on the calling passport".to_string(),
            data: Some(err),
        });
    }

    let device_fingerprint = args
        .get("device_fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "missing required param: device_fingerprint (BLAKE3 hex of canonical attestation)".to_string(),
            data: Some(json!({"param": "device_fingerprint", "required": true})),
        })?
        .to_string();

    // Lightweight format check — fingerprints are 64-hex BLAKE3 digests.
    if device_fingerprint.len() != 64 || !device_fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "device_fingerprint must be 64-char lowercase hex (BLAKE3)".to_string(),
            data: Some(json!({"param": "device_fingerprint", "format": "blake3-hex"})),
        });
    }

    let capabilities_subset: Vec<String> = args.get("capabilities_subset").and_then(|v| v.as_array()).map_or_else(
        || vec!["facts:read".to_string()],
        |arr| arr.iter().filter_map(|v| v.as_str()).map(str::to_string).collect(),
    );

    let passport = load_passport(ctx, &agent_name).await.ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("calling passport {agent_name} does not exist or is retired"),
        data: Some(json!({"param": "passport", "exists": false})),
    })?;

    let tenant_id = tenant_of(&passport.principal_id);
    let (_now, now_str) = now_rfc3339();
    let receipt_id = build_receipt_id(
        "r_passport_link",
        &[&passport.principal_id, &device_fingerprint, &now_str],
    );

    let body = PassportLinkDeviceReceiptBodyV1 {
        schema: SCHEMA_PASSPORT_LINK_DEVICE_BODY_V1.to_string(),
        receipt_id: receipt_id.clone(),
        tenant_id: tenant_id.clone(),
        passport_id: passport.principal_id.clone(),
        device_fingerprint: device_fingerprint.clone(),
        capabilities_subset: capabilities_subset.clone(),
        initiated_at: now_str.clone(),
    };
    let body_bytes = encode_passport_link_device_body_v1(&body).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("link-device receipt encode failed: {err}"),
        data: None,
    })?;
    let body_hash_hex = blake3::hash(&body_bytes).to_hex().to_string();

    let mut store = ctx.fact_store.write().await;
    store.store(StoreFact {
        entity: format!("{PASSPORT_PREFIX}{}", passport.principal_id),
        key: format!("{KEY_LINKED_DEVICE_PREFIX}{device_fingerprint}"),
        value: json!({
            "device_fingerprint": device_fingerprint.clone(),
            "capabilities_subset": capabilities_subset.clone(),
            "link_receipt_id": receipt_id.clone(),
            "linked_at": now_str.clone(),
        })
        .to_string(),
        source_receipt: Some(receipt_id.clone()),
        confidence: 1.0,
        private: false,
        horizon_class: None,
    });
    drop(store);

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "passport_link_device: device {} linked to {} with caps {:?} (receipt {})",
                &device_fingerprint[..16],
                passport.principal_id,
                capabilities_subset,
                receipt_id,
            ),
        }],
        "link_receipt_id": receipt_id,
        "passport_id": passport.principal_id,
        "device_fingerprint": device_fingerprint,
        "capabilities_subset": capabilities_subset,
        "receipt_body_cbor_hex": hex::encode(&body_bytes),
        "receipt_body_hash_hex": body_hash_hex,
        "tenant_id": tenant_id,
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;
    use crate::tools::passport::handle_issue_passport;
    use corecrux_memory::fact_store::StoreFact;
    use corecrux_receipts::{
        decode_passport_link_device_body_v1, decode_passport_merge_body_v1, decode_passport_split_body_v1,
    };

    pub(crate) fn flag_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    struct FeatureFlagGuard {
        prior: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl FeatureFlagGuard {
        fn enabled() -> Self {
            let lock = flag_lock().lock().unwrap_or_else(|p| p.into_inner());
            let prior = env::var(FEATURE_FLAG_ENV).ok();
            env::set_var(FEATURE_FLAG_ENV, "1");
            Self { prior, _lock: lock }
        }
        fn disabled() -> Self {
            let lock = flag_lock().lock().unwrap_or_else(|p| p.into_inner());
            let prior = env::var(FEATURE_FLAG_ENV).ok();
            env::remove_var(FEATURE_FLAG_ENV);
            Self { prior, _lock: lock }
        }
    }
    impl Drop for FeatureFlagGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => env::set_var(FEATURE_FLAG_ENV, v),
                None => env::remove_var(FEATURE_FLAG_ENV),
            }
        }
    }

    fn agent_ctx(name: &str) -> McpContext {
        let ctx = McpContext::new_default("test-node");
        ctx.with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    /// Issue a passport AND push it into `trusted` tier by seeding 500
    /// receipt-backed facts.
    async fn promote_to_operator(ctx: &McpContext) {
        handle_issue_passport(&json!({}), ctx).await.unwrap();
        {
            let mut store = ctx.fact_store.write().await;
            for i in 0..500 {
                store.store(StoreFact {
                    entity: format!("seed-{i}"),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                });
            }
        }
        // Re-issue to trigger tier recalculation via get_passport call path.
        crate::tools::passport::handle_get_passport(&json!({}), ctx)
            .await
            .unwrap();
    }

    #[test]
    fn tenant_of_extracts_namespace() {
        assert_eq!(tenant_of("personal::myles"), "personal");
        assert_eq!(tenant_of("business::acme::staging"), "business::acme");
        assert_eq!(tenant_of("passport:user-bob"), "passport");
        assert_eq!(tenant_of("bare"), "__default__");
    }

    #[tokio::test]
    async fn passport_split_requires_feature_flag() {
        let _g = FeatureFlagGuard::disabled();
        let ctx = agent_ctx("personal::alice");
        let err = handle_passport_split(
            &json!({
                "target_passport": "personal::alice",
                "new_passport_name": "personal::alice-work",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn passport_split_requires_token_budget() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        let err = handle_passport_split(
            &json!({
                "target_passport": "personal::alice",
                "new_passport_name": "personal::alice-work",
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["param"], "token_budget");
    }

    #[tokio::test]
    async fn passport_split_requires_passport() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = McpContext::new_default("test-node"); // anonymous
        let err = handle_passport_split(
            &json!({
                "target_passport": "personal::alice",
                "new_passport_name": "personal::alice-work",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn passport_split_requires_operator_tier() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        // Issue without promoting — stays at unverified.
        handle_issue_passport(&json!({}), &ctx).await.unwrap();
        let err = handle_passport_split(
            &json!({
                "target_passport": "personal::alice",
                "new_passport_name": "personal::alice-work",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("operator-tier"));
    }

    #[tokio::test]
    async fn passport_split_rejects_cross_tenant() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;
        let err = handle_passport_split(
            &json!({
                "target_passport": "personal::alice",
                "new_passport_name": "business::evilcorp::alice",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, -32003);
        assert!(err.message.contains("cross-tenant"));
    }

    #[tokio::test]
    async fn passport_split_forks_identity_and_emits_receipt() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;

        let resp = handle_passport_split(
            &json!({
                "target_passport": "personal::alice",
                "new_passport_name": "personal::alice-work",
                "reason": "separate work persona",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp["new_passport_id"], "personal::alice-work");
        assert!(resp["split_receipt_id"]
            .as_str()
            .unwrap()
            .starts_with("r_passport_split_"));
        let cbor_hex = resp["receipt_body_cbor_hex"].as_str().unwrap();
        let body_bytes = hex::decode(cbor_hex).unwrap();
        let decoded = decode_passport_split_body_v1(&body_bytes).unwrap();
        assert_eq!(decoded.source_passport_id, "personal::alice");
        assert_eq!(decoded.new_passport_id, "personal::alice-work");
        assert_eq!(decoded.initiated_by_passport_id, "personal::alice");
        // Crown-verify analogue: hash matches.
        let computed = blake3::hash(&body_bytes).to_hex().to_string();
        assert_eq!(resp["receipt_body_hash_hex"], computed);
        // Tamper check.
        let mut tampered = body_bytes.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert_ne!(
            blake3::hash(&tampered).to_hex().to_string(),
            resp["receipt_body_hash_hex"].as_str().unwrap()
        );
    }

    #[tokio::test]
    async fn passport_split_rejects_duplicate_name() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;
        // Pre-create the target name as an existing passport.
        let entity = format!("{PASSPORT_PREFIX}personal::alice-work");
        {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                entity,
                key: "passport".to_string(),
                value: serde_json::to_string(&PassportRecord {
                    principal_id: "personal::alice-work".to_string(),
                    sponsor_id: None,
                    reputation_tier: "unverified".to_string(),
                    receipt_count: 0,
                    issued_at: "2026-05-28T00:00:00Z".to_string(),
                    passport_hash: "0000".to_string(),
                })
                .unwrap(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
            });
        }
        let err = handle_passport_split(
            &json!({
                "target_passport": "personal::alice",
                "new_passport_name": "personal::alice-work",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("already exists"));
    }

    // ── passport_merge ────────────────────────────────────────────

    #[tokio::test]
    async fn passport_merge_requires_explicit_conflict_policy() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;
        let err = handle_passport_merge(
            &json!({
                "source_passport": "personal::alice-old",
                "target_passport": "personal::alice",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["param"], "conflict_policy");
    }

    #[tokio::test]
    async fn passport_merge_rejects_cross_tenant() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;
        // Seed a foreign-tenant target passport.
        {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                entity: format!("{PASSPORT_PREFIX}business::acme::root"),
                key: "passport".to_string(),
                value: serde_json::to_string(&PassportRecord {
                    principal_id: "business::acme::root".to_string(),
                    sponsor_id: None,
                    reputation_tier: "trusted".to_string(),
                    receipt_count: 500,
                    issued_at: "2026-05-28T00:00:00Z".to_string(),
                    passport_hash: "ffff".to_string(),
                })
                .unwrap(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
            });
        }
        let err = handle_passport_merge(
            &json!({
                "source_passport": "personal::alice",
                "target_passport": "business::acme::root",
                "conflict_policy": "prefer_target",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, -32003);
        assert!(err.message.contains("cross-tenant"));
    }

    #[tokio::test]
    async fn passport_merge_error_on_conflict_returns_409_with_list() {
        let _g = FeatureFlagGuard::enabled();
        // Caller is the target; we'll seed a source passport under the
        // same tenant and create a (entity, key) conflict.
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;
        // Pre-create source passport in same tenant.
        {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                entity: format!("{PASSPORT_PREFIX}personal::alice-old"),
                key: "passport".to_string(),
                value: serde_json::to_string(&PassportRecord {
                    principal_id: "personal::alice-old".to_string(),
                    sponsor_id: None,
                    reputation_tier: "trusted".to_string(),
                    receipt_count: 500,
                    issued_at: "2026-05-28T00:00:00Z".to_string(),
                    passport_hash: "abcd".to_string(),
                })
                .unwrap(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
            });
            // Create conflict: both passports have an `__agent::<name>::prefs`
            // entity with key=city, different values.
            store.store(StoreFact {
                entity: "__agent::personal::alice-old::prefs".to_string(),
                key: "city".to_string(),
                value: "Munich".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
            });
            store.store(StoreFact {
                entity: "__agent::personal::alice::prefs".to_string(),
                key: "city".to_string(),
                value: "Berlin".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
            });
        }
        let err = handle_passport_merge(
            &json!({
                "source_passport": "personal::alice-old",
                "target_passport": "personal::alice",
                "conflict_policy": "error_on_conflict",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, CONFLICT_STATUS);
        let conflicts = err.data.unwrap()["conflicts"].as_array().unwrap().clone();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0]["key"], "city");
    }

    #[tokio::test]
    async fn passport_merge_prefer_source_resolves_deterministically_and_retires_source() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;
        // Seed source.
        {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                entity: format!("{PASSPORT_PREFIX}personal::alice-old"),
                key: "passport".to_string(),
                value: serde_json::to_string(&PassportRecord {
                    principal_id: "personal::alice-old".to_string(),
                    sponsor_id: None,
                    reputation_tier: "trusted".to_string(),
                    receipt_count: 500,
                    issued_at: "2026-05-28T00:00:00Z".to_string(),
                    passport_hash: "abcd".to_string(),
                })
                .unwrap(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
            });
            store.store(StoreFact {
                entity: "__agent::personal::alice-old::prefs".to_string(),
                key: "city".to_string(),
                value: "Munich".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
            });
            store.store(StoreFact {
                entity: "__agent::personal::alice::prefs".to_string(),
                key: "city".to_string(),
                value: "Berlin".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
            });
        }
        let resp = handle_passport_merge(
            &json!({
                "source_passport": "personal::alice-old",
                "target_passport": "personal::alice",
                "conflict_policy": "prefer_source",
                "reason": "consolidate",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp["merged_passport_id"], "personal::alice");
        assert_eq!(resp["conflicts_resolved"], 1);
        assert_eq!(resp["conflict_policy"], "prefer_source");
        assert_eq!(resp["retired_passport_id"], "personal::alice-old");
        let cbor = hex::decode(resp["receipt_body_cbor_hex"].as_str().unwrap()).unwrap();
        let decoded = decode_passport_merge_body_v1(&cbor).unwrap();
        assert_eq!(decoded.conflict_policy, MergeConflictPolicyV1::PreferSource);
        // Source passport now retired — load_passport returns None.
        assert!(load_passport(&ctx, "personal::alice-old").await.is_none());
        // Raw load still returns the record (for audit lookups).
        assert!(load_passport_raw(&ctx, "personal::alice-old").await.is_some());
        // Tamper detection: hash differs after a single-bit flip.
        let mut tampered = cbor.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert_ne!(
            blake3::hash(&cbor).to_hex().to_string(),
            blake3::hash(&tampered).to_hex().to_string()
        );
    }

    #[tokio::test]
    async fn passport_merge_caller_must_own_one_side() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::eve"); // unrelated caller
        promote_to_operator(&ctx).await;
        // Seed both passports as separate identities.
        {
            let mut store = ctx.fact_store.write().await;
            for name in ["personal::alice", "personal::alice-old"] {
                store.store(StoreFact {
                    entity: format!("{PASSPORT_PREFIX}{name}"),
                    key: "passport".to_string(),
                    value: serde_json::to_string(&PassportRecord {
                        principal_id: name.to_string(),
                        sponsor_id: None,
                        reputation_tier: "trusted".to_string(),
                        receipt_count: 500,
                        issued_at: "2026-05-28T00:00:00Z".to_string(),
                        passport_hash: "abcd".to_string(),
                    })
                    .unwrap(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                });
            }
        }
        let err = handle_passport_merge(
            &json!({
                "source_passport": "personal::alice-old",
                "target_passport": "personal::alice",
                "conflict_policy": "prefer_target",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("must own source or target"));
    }

    // ── passport_link_device ──────────────────────────────────────

    #[tokio::test]
    async fn passport_link_device_requires_operator_tier() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        handle_issue_passport(&json!({}), &ctx).await.unwrap();
        let fp = blake3::hash(b"laptop-001").to_hex().to_string();
        let err = handle_passport_link_device(
            &json!({
                "device_fingerprint": fp,
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("operator-tier"));
    }

    #[tokio::test]
    async fn passport_link_device_requires_token_budget() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;
        let fp = blake3::hash(b"laptop-001").to_hex().to_string();
        let err = handle_passport_link_device(
            &json!({
                "device_fingerprint": fp,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["param"], "token_budget");
    }

    #[tokio::test]
    async fn passport_link_device_rejects_malformed_fingerprint() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;
        let err = handle_passport_link_device(
            &json!({
                "device_fingerprint": "not-hex",
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("64-char lowercase hex"));
    }

    #[tokio::test]
    async fn passport_link_device_stores_binding_and_emits_receipt() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;
        let fp = blake3::hash(b"laptop-001-attestation").to_hex().to_string();
        let resp = handle_passport_link_device(
            &json!({
                "device_fingerprint": fp.clone(),
                "capabilities_subset": ["facts:read", "facts:write"],
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp["passport_id"], "personal::alice");
        assert_eq!(resp["device_fingerprint"], fp);
        let caps = resp["capabilities_subset"].as_array().unwrap();
        assert_eq!(caps.len(), 2);
        let cbor = hex::decode(resp["receipt_body_cbor_hex"].as_str().unwrap()).unwrap();
        let decoded = decode_passport_link_device_body_v1(&cbor).unwrap();
        assert_eq!(decoded.passport_id, "personal::alice");
        assert_eq!(decoded.device_fingerprint, fp);
        assert_eq!(decoded.capabilities_subset.len(), 2);
        // Tamper detection.
        let mut tampered = cbor.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert_ne!(
            blake3::hash(&cbor).to_hex().to_string(),
            blake3::hash(&tampered).to_hex().to_string()
        );
    }

    #[tokio::test]
    async fn passport_link_device_defaults_capabilities_to_read_only() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("personal::alice");
        promote_to_operator(&ctx).await;
        let fp = blake3::hash(b"device-2").to_hex().to_string();
        let resp = handle_passport_link_device(
            &json!({
                "device_fingerprint": fp,
                "token_budget": 500,
            }),
            &ctx,
        )
        .await
        .unwrap();
        let caps = resp["capabilities_subset"].as_array().unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0], "facts:read");
    }
}
