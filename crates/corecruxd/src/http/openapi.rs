// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! OpenAPI document — `GET /v1/openapi.json` returns the utoipa-generated schema for the daemon's HTTP surface.

use axum::Json;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Crux Daemon API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Append-only event store with BM25 retrieval, CROWN receipts, and fact memory.",
        license(name = "CCL v1.0", url = "https://github.com/CueCrux/Crux/blob/main/LICENCE.md")
    ),
    paths(
        // Health
        super::health::healthz,
        super::health::readyz,
        super::health::metrics,
        super::health::get_version,
        // Facts
        super::facts::put_fact,
        super::facts::put_facts_bulk,
        super::facts::get_fact,
        super::facts::delete_fact,
        super::facts::get_facts_by_entity,
        super::facts::query_facts,
        super::facts::export_facts,
        // Sessions
        super::facts::put_session_state,
        super::facts::get_session_state,
        // Events
        super::events::event_stream,
        // Query
        super::query::post_query_text_search,
        super::query::post_query_text_search_expand,
        super::query::post_query_graph_expand,
        super::query::post_query_time_range,
        // Receipts
        super::receipts::get_receipt_body_v1,
        super::receipts::get_receipt_signature_v1,
        super::receipts::get_receipt_verification_v1,
    ),
    components(schemas(
        corecrux_memory::fact_store::Fact,
        corecrux_memory::fact_store::StoreFact,
        corecrux_memory::fact_store::FactQuery,
        corecrux_memory::fact_store::FactQueryResult,
        corecrux_memory::fact_store::FactExportResult,
        corecrux_memory::session_store::SessionState,
        super::query::GraphExpandBody,
        super::query::TimeRangeBody,
        super::query::TextSearchBody,
        super::query::TextSearchExpandBody,
        super::query::ExpandResultId,
    )),
    security(
        ("bearer_auth" = [])
    ),
    modifiers(&SecurityAddon)
)]
pub(super) struct ApiDoc;

struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

pub(super) async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}
