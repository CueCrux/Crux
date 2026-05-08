// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Constraint tools: `declare_constraint`, `get_constraints`, `check_constraints`.
//!
//! Constraints are stored as facts under the `__constraints__::{id}` entity
//! prefix, reusing the existing fact store for persistence, versioning, and sync.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use corecrux_memory::action_enrichment::{enrich_action, ActionEnrichmentInput};
use corecrux_memory::fact_store::{FactQuery, StoreFact};

/// Entity prefix for all constraints.
const CONSTRAINT_PREFIX: &str = "__constraints__::";

/// Allowed constraint types.
const VALID_TYPES: &[&str] = &["boundary", "relationship", "policy", "context_flag"];

/// Allowed severity levels (ordered critical → low).
const VALID_SEVERITIES: &[&str] = &["critical", "high", "medium", "low"];

/// Serialised constraint record stored as a fact value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConstraintRecord {
    constraint_id: String,
    constraint_type: String,
    assertion: String,
    severity: String,
    status: String,
    created_at: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// `declare_constraint` — declare an organisational constraint.
pub async fn handle_declare_constraint(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let constraint_type = require_str(args, "constraint_type")?;
    let assertion = require_str(args, "assertion")?;
    let severity = args.get("severity").and_then(|v| v.as_str()).unwrap_or("medium");

    // Validate enum values.
    if !VALID_TYPES.contains(&constraint_type) {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!(
                "invalid constraint_type: '{constraint_type}'. Must be one of: {}",
                VALID_TYPES.join(", ")
            ),
            data: Some(json!({"param": "constraint_type", "allowed": VALID_TYPES})),
        });
    }
    if !VALID_SEVERITIES.contains(&severity) {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!(
                "invalid severity: '{severity}'. Must be one of: {}",
                VALID_SEVERITIES.join(", ")
            ),
            data: Some(json!({"param": "severity", "allowed": VALID_SEVERITIES})),
        });
    }

    let constraint_id = format!("c_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));

    let record = ConstraintRecord {
        constraint_id: constraint_id.clone(),
        constraint_type: constraint_type.to_string(),
        assertion: assertion.to_string(),
        severity: severity.to_string(),
        status: "active".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let canonical = serde_json::to_string(&record).unwrap_or_default();
    let constraint_hash = blake3::hash(canonical.as_bytes()).to_hex().to_string();

    let entity = format!("{CONSTRAINT_PREFIX}{constraint_id}");
    let req = StoreFact {
        entity,
        key: "constraint".to_string(),
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
                "constraint declared: {} (type={}, severity={}, hash={})",
                constraint_id, constraint_type, severity, &constraint_hash[..16]
            )
        }]
    }))
}

/// `get_constraints` — list active constraints, optionally filtered.
pub async fn handle_get_constraints(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let filter_type = args.get("constraint_type").and_then(|v| v.as_str());
    let filter_status = args.get("status").and_then(|v| v.as_str()).unwrap_or("active");

    let q = FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some(CONSTRAINT_PREFIX.to_string()),
        top_k: 200,
        token_budget: None,
    };

    let store = ctx.fact_store.read().await;
    let result = store.query(&q);

    let mut constraints: Vec<ConstraintRecord> = result
        .facts
        .iter()
        .filter(|f| !f.deleted && f.key == "constraint")
        .filter_map(|f| serde_json::from_str::<ConstraintRecord>(&f.value).ok())
        .filter(|r| r.status == filter_status)
        .filter(|r| filter_type.is_none_or(|t| r.constraint_type == t))
        .collect();

    // Sort by severity (critical first), then newest first.
    constraints.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then_with(|| b.created_at.cmp(&a.created_at))
    });

    if constraints.is_empty() {
        return Ok(json!({
            "content": [{ "type": "text", "text": "no constraints found" }]
        }));
    }

    let lines: Vec<String> = constraints
        .iter()
        .map(|c| {
            format!(
                "[{}] {} (type={}, severity={}, status={})",
                c.constraint_id, c.assertion, c.constraint_type, c.severity, c.status
            )
        })
        .collect();

    let text = format!("{} constraint(s):\n{}", constraints.len(), lines.join("\n"));

    Ok(json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

/// `check_constraints` — check a proposed action against active constraints.
pub async fn handle_check_constraints(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let (action, enrichment_receipt_id) = action_text_for_constraint_check(args)?;

    // Load all active constraints.
    let q = FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some(CONSTRAINT_PREFIX.to_string()),
        top_k: 200,
        token_budget: None,
    };

    let store = ctx.fact_store.read().await;
    let result = store.query(&q);

    let constraints: Vec<ConstraintRecord> = result
        .facts
        .iter()
        .filter(|f| !f.deleted && f.key == "constraint")
        .filter_map(|f| serde_json::from_str::<ConstraintRecord>(&f.value).ok())
        .filter(|r| r.status == "active")
        .collect();

    if constraints.is_empty() {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "{}verdict: pass (no constraints defined)",
                    enrichment_prefix(enrichment_receipt_id.as_deref())
                )
            }]
        }));
    }

    // Keyword match: tokenise action and each constraint assertion.
    let action_terms = tokenise(&action);
    let mut matches: Vec<(ConstraintRecord, f64)> = Vec::new();

    for constraint in &constraints {
        let assertion_terms = tokenise(&constraint.assertion);
        if assertion_terms.is_empty() {
            continue;
        }
        let overlap: usize = assertion_terms
            .iter()
            .filter(|term| action_terms.contains(term))
            .count();
        if overlap > 0 {
            let score = overlap as f64 / assertion_terms.len() as f64;
            matches.push((constraint.clone(), score));
        }
    }

    // Determine verdict from highest matched severity.
    let verdict = if matches.iter().any(|(c, _)| c.severity == "critical") {
        "block"
    } else if matches.iter().any(|(c, _)| c.severity == "high") {
        "warn"
    } else {
        "pass"
    };

    if matches.is_empty() {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "{}verdict: pass (0/{} constraints matched)",
                    enrichment_prefix(enrichment_receipt_id.as_deref()),
                    constraints.len()
                )
            }]
        }));
    }

    // Sort matches by score descending.
    matches.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let match_lines: Vec<String> = matches
        .iter()
        .map(|(c, score)| {
            format!(
                "  - [{}] {} (severity={}, match={:.0}%)",
                c.constraint_id,
                c.assertion,
                c.severity,
                score * 100.0
            )
        })
        .collect();

    let text = format!(
        "{}verdict: {} ({}/{} constraints matched)\n{}",
        enrichment_prefix(enrichment_receipt_id.as_deref()),
        verdict,
        matches.len(),
        constraints.len(),
        match_lines.join("\n")
    );

    Ok(json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn action_text_for_constraint_check(args: &Value) -> Result<(String, Option<String>), JsonRpcError> {
    if let Some(tool_name) = args.get("tool_name").and_then(|v| v.as_str()) {
        let proposal = enrich_action(
            None,
            ActionEnrichmentInput {
                tenant_id: args.get("tenant_id").and_then(|v| v.as_str()).map(str::to_string),
                tool_name: tool_name.to_string(),
                tool_parameters: args.get("tool_parameters").cloned().unwrap_or_else(|| json!({})),
                action_description: args
                    .get("action_description")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                include_first_party_enrichers: false,
            },
        );
        let receipt_id = proposal
            .enrichment_receipt
            .as_ref()
            .map(|receipt| receipt.receipt_id.clone());
        return Ok((proposal.narrative, receipt_id));
    }

    Ok((require_str(args, "action_description")?.to_string(), None))
}

fn enrichment_prefix(receipt_id: Option<&str>) -> String {
    receipt_id.map_or_else(String::new, |receipt_id| {
        format!("action_enrichment: basic receipt={receipt_id}\n")
    })
}

/// Map severity to a sort rank (lower = higher priority).
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// Tokenise a string into lowercase terms, filtering short stop-words.
fn tokenise(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|t| t.len() >= 3)
        .map(String::from)
        .collect()
}

/// Extract a required string parameter or return an INVALID_PARAMS error.
fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    // ── declare_constraint ─────────────────────────────────────────

    #[tokio::test]
    async fn declare_constraint_basic() {
        let ctx = test_ctx();
        let result = handle_declare_constraint(
            &json!({"constraint_type": "policy", "assertion": "All API keys must be rotated every 90 days"}),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("constraint declared: c_"));
        assert!(text.contains("type=policy"));
        assert!(text.contains("severity=medium")); // default
        assert!(text.contains("hash="));
    }

    #[tokio::test]
    async fn declare_constraint_with_severity() {
        let ctx = test_ctx();
        let result = handle_declare_constraint(
            &json!({"constraint_type": "boundary", "assertion": "No direct database access", "severity": "critical"}),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("type=boundary"));
        assert!(text.contains("severity=critical"));
    }

    #[tokio::test]
    async fn declare_constraint_missing_assertion() {
        let ctx = test_ctx();
        let err = handle_declare_constraint(&json!({"constraint_type": "policy"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("assertion"));
    }

    #[tokio::test]
    async fn declare_constraint_missing_type() {
        let ctx = test_ctx();
        let err = handle_declare_constraint(&json!({"assertion": "something"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("constraint_type"));
    }

    #[tokio::test]
    async fn declare_constraint_invalid_type() {
        let ctx = test_ctx();
        let err = handle_declare_constraint(&json!({"constraint_type": "nonsense", "assertion": "something"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("invalid constraint_type"));
    }

    #[tokio::test]
    async fn declare_constraint_invalid_severity() {
        let ctx = test_ctx();
        let err = handle_declare_constraint(
            &json!({"constraint_type": "policy", "assertion": "something", "severity": "extreme"}),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("invalid severity"));
    }

    // ── get_constraints ────────────────────────────────────────────

    #[tokio::test]
    async fn get_constraints_empty() {
        let ctx = test_ctx();
        let result = handle_get_constraints(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no constraints found");
    }

    #[tokio::test]
    async fn get_constraints_returns_declared() {
        let ctx = test_ctx();
        handle_declare_constraint(
            &json!({"constraint_type": "policy", "assertion": "Rotate keys every 90 days"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_declare_constraint(
            &json!({"constraint_type": "boundary", "assertion": "No direct DB access", "severity": "critical"}),
            &ctx,
        )
        .await
        .unwrap();

        let result = handle_get_constraints(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("2 constraint(s)"));
        assert!(text.contains("Rotate keys"));
        assert!(text.contains("No direct DB access"));
        // Critical should come first.
        let critical_pos = text.find("No direct DB access").unwrap();
        let medium_pos = text.find("Rotate keys").unwrap();
        assert!(critical_pos < medium_pos);
    }

    #[tokio::test]
    async fn get_constraints_filter_by_type() {
        let ctx = test_ctx();
        handle_declare_constraint(&json!({"constraint_type": "policy", "assertion": "Policy one"}), &ctx)
            .await
            .unwrap();
        handle_declare_constraint(
            &json!({"constraint_type": "boundary", "assertion": "Boundary one"}),
            &ctx,
        )
        .await
        .unwrap();

        let result = handle_get_constraints(&json!({"constraint_type": "boundary"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("1 constraint(s)"));
        assert!(text.contains("Boundary one"));
        assert!(!text.contains("Policy one"));
    }

    // ── check_constraints ──────────────────────────────────────────

    #[tokio::test]
    async fn check_constraints_no_constraints() {
        let ctx = test_ctx();
        let result = handle_check_constraints(&json!({"action_description": "Deploy the application"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("verdict: pass"));
        assert!(text.contains("no constraints defined"));
    }

    #[tokio::test]
    async fn check_constraints_missing_action() {
        let ctx = test_ctx();
        let err = handle_check_constraints(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("action_description"));
    }

    #[tokio::test]
    async fn check_constraints_critical_blocks() {
        let ctx = test_ctx();
        handle_declare_constraint(
            &json!({"constraint_type": "boundary", "assertion": "No direct database access allowed", "severity": "critical"}),
            &ctx,
        )
        .await
        .unwrap();

        let result = handle_check_constraints(
            &json!({"action_description": "Execute direct database query to delete users"}),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("verdict: block"));
    }

    #[tokio::test]
    async fn check_constraints_high_warns() {
        let ctx = test_ctx();
        handle_declare_constraint(
            &json!({"constraint_type": "policy", "assertion": "API keys must be encrypted at rest", "severity": "high"}),
            &ctx,
        )
        .await
        .unwrap();

        let result = handle_check_constraints(
            &json!({"action_description": "Store API keys in plaintext config file"}),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("verdict: warn"));
    }

    #[tokio::test]
    async fn check_constraints_no_match_passes() {
        let ctx = test_ctx();
        handle_declare_constraint(
            &json!({"constraint_type": "policy", "assertion": "All deployments require approval", "severity": "critical"}),
            &ctx,
        )
        .await
        .unwrap();

        let result = handle_check_constraints(&json!({"action_description": "Update the README documentation"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("verdict: pass"));
    }

    // ── tokenise helper ────────────────────────────────────────────

    #[test]
    fn tokenise_basic() {
        let tokens = tokenise("Hello, World! This is a test.");
        assert!(tokens.contains(&"hello".to_string()));
        assert!(tokens.contains(&"world".to_string()));
        assert!(tokens.contains(&"this".to_string()));
        assert!(tokens.contains(&"test".to_string()));
        // "is" and "a" are < 3 chars, filtered out.
        assert!(!tokens.contains(&"is".to_string()));
        assert!(!tokens.contains(&"a".to_string()));
    }

    #[test]
    fn tokenise_preserves_underscores() {
        let tokens = tokenise("context_flag and api_key");
        assert!(tokens.contains(&"context_flag".to_string()));
        assert!(tokens.contains(&"api_key".to_string()));
    }
}
