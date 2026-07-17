// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Action enrichment tools.

use corecrux_memory::action_enrichment::{
    enrich_action, ActionEnrichmentInput, EnrichedActionProposal, ACTION_ENRICHMENT_RECEIPT_ENTITY_PREFIX,
};
use corecrux_memory::fact_store::StoreFact;
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};

pub async fn handle_enrich_action(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let mut input: ActionEnrichmentInput = serde_json::from_value(args.clone()).map_err(|err| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("invalid enrich_action arguments: {err}"),
        data: Some(json!({
            "required": ["tool_name"],
            "note": "MCP enrich_action provides deterministic basic enrichment; Pro first-party enrichment is exposed on POST /v1/actions/enrich."
        })),
    })?;

    // The MCP tool is the Free/basic path. Pro first-party enrichment is
    // product-gated by the daemon HTTP route where product posture is known.
    input.include_first_party_enrichers = false;
    let proposal = enrich_action(None, input);
    store_enrichment_capsule(ctx, &proposal).await;

    let text = serde_json::to_string_pretty(&proposal).map_err(|err| JsonRpcError {
        code: crate::protocol::INTERNAL_ERROR,
        message: format!("failed to encode enriched action proposal: {err}"),
        data: None,
    })?;

    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": proposal,
    }))
}

async fn store_enrichment_capsule(ctx: &McpContext, proposal: &EnrichedActionProposal) {
    let Some(receipt) = proposal.enrichment_receipt.as_ref() else {
        return;
    };
    let value = match serde_json::to_string(proposal) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(?err, "mcp-action-enrichment-encode-failed");
            return;
        }
    };
    let fact = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!(
            "{ACTION_ENRICHMENT_RECEIPT_ENTITY_PREFIX}::{}::{}",
            proposal.tenant_id, receipt.receipt_id
        ),
        key: "proposal".to_string(),
        value,
        source_receipt: Some(receipt.receipt_id.clone()),
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    };
    ctx.fact_store.write().await.store(fact);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enrich_action_returns_basic_proposal_and_stores_capsule() {
        let ctx = McpContext::new_default("test-node");
        let result = handle_enrich_action(
            &json!({
                "tenant_id": "business::acme",
                "tool_name": "calendar.move_event",
                "tool_parameters": {
                    "event_id": "evt_1",
                    "attendees": ["customer@example.com"],
                    "new_time": "2026-05-08T16:00:00Z"
                },
                "action_description": "Move customer meeting"
            }),
            &ctx,
        )
        .await
        .unwrap();

        assert_eq!(
            result["structuredContent"]["schema"],
            corecrux_memory::action_enrichment::ACTION_ENRICHMENT_SCHEMA
        );
        assert_eq!(result["structuredContent"]["enrichment_mode"], "basic");

        let store = ctx.fact_store.read().await;
        let facts = store.query(&corecrux_memory::fact_store::FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            query: Some(ACTION_ENRICHMENT_RECEIPT_ENTITY_PREFIX.to_string()),
            entity: None,
            entity_prefix: Some(format!("{ACTION_ENRICHMENT_RECEIPT_ENTITY_PREFIX}::business::acme")),
            top_k: 10,
            token_budget: None,
        });
        assert_eq!(facts.facts.len(), 1);
        assert!(facts.facts[0].private);
    }
}
