// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Local action enrichment endpoint.

use super::*;
use corecrux_memory::action_enrichment::{
    enrich_action, ActionEnrichmentInput, EnrichedActionProposal, ACTION_ENRICHMENT_RECEIPT_ENTITY_PREFIX,
    ACTION_ENRICHMENT_SCHEMA,
};
use corecrux_memory::fact_store::StoreFact;
use serde_json::json;

const FIRST_PARTY_ENRICHERS_SERVICE: &str = "enrichers:first_party";

pub(super) fn action_enrichment_posture(state: &AppState) -> serde_json::Value {
    let product = crate::product::ProductPosture::new(state.operating_mode, &state.enabled_pro_services);
    json!({
        "schema": ACTION_ENRICHMENT_SCHEMA,
        "contract_path": "/v1/actions/enrich",
        "basic_available": true,
        "first_party_pro_gated": true,
        "first_party_service": FIRST_PARTY_ENRICHERS_SERVICE,
        "first_party_enabled": product
            .enabled_pro_services
            .iter()
            .any(|service| service == FIRST_PARTY_ENRICHERS_SERVICE),
        "receipt_entity_prefix": ACTION_ENRICHMENT_RECEIPT_ENTITY_PREFIX,
        "enricher_domains": ["code", "file", "email_calendar", "crm_customer"],
    })
}

pub(super) async fn post_action_enrich(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<ActionEnrichmentInput>,
) -> Response {
    if let Err(problem) = require_http_any_scope(
        &state.auth,
        &headers,
        &["query:read", "admin:read", FIRST_PARTY_ENRICHERS_SERVICE],
    ) {
        return problem.into_response();
    }

    if body.tool_name.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tool_name must not be empty");
    }

    if body.include_first_party_enrichers {
        if let Err(problem) =
            require_http_any_scope(&state.auth, &headers, &[FIRST_PARTY_ENRICHERS_SERVICE, "admin:write"])
        {
            return problem.into_response();
        }
        if !first_party_enabled(&state) {
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(json!({
                    "schema": ACTION_ENRICHMENT_SCHEMA,
                    "status": "pro_service_not_enabled",
                    "capability": FIRST_PARTY_ENRICHERS_SERVICE,
                    "fallback": {
                        "reason_code": "pro_service_not_enabled",
                        "detail": "basic action enrichment is available in Free; first-party enrichers require Pro and the enrichers:first_party service"
                    }
                })),
            )
                .into_response();
        }
        if body
            .tenant_id
            .as_deref()
            .map(str::trim)
            .filter(|tenant_id| !tenant_id.is_empty())
            .is_none()
        {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "tenant_id must be supplied when first-party enrichers are requested",
            );
        }
    }

    body.tool_name = body.tool_name.trim().to_string();
    let proposal = {
        let store = state.fact_store.read().await;
        enrich_action(Some(&store), body)
    };

    if let Err(err) = store_enrichment_capsule(&state, &proposal).await {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store action enrichment receipt: {err}"),
        );
    }

    Json(json!({
        "schema": ACTION_ENRICHMENT_SCHEMA,
        "status": "ok",
        "basic_available": true,
        "first_party_enrichers_used": proposal.enrichment_mode == "first_party",
        "proposal": proposal,
    }))
    .into_response()
}

fn first_party_enabled(state: &AppState) -> bool {
    crate::product::ProductPosture::new(state.operating_mode, &state.enabled_pro_services)
        .enabled_pro_services
        .iter()
        .any(|service| service == FIRST_PARTY_ENRICHERS_SERVICE)
}

async fn store_enrichment_capsule(state: &AppState, proposal: &EnrichedActionProposal) -> std::io::Result<()> {
    let Some(receipt) = proposal.enrichment_receipt.as_ref() else {
        return Ok(());
    };
    let mut fact = StoreFact {
        entity: format!(
            "{ACTION_ENRICHMENT_RECEIPT_ENTITY_PREFIX}::{}::{}",
            proposal.tenant_id, receipt.receipt_id
        ),
        key: "proposal".to_string(),
        value: serde_json::to_string(proposal).map_err(std::io::Error::other)?,
        source_receipt: Some(receipt.receipt_id.clone()),
        confidence: 1.0,
        private: true,
    horizon_class: None,
    };
    crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
    state.fact_store.write().await.try_store(fact)?;
    Ok(())
}
