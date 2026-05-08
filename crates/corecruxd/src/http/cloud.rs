// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Product/cloud access posture for Pro cloud-only and hybrid deployments.

use super::{require_http_any_scope, AppState};
use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};

pub(super) async fn get_cloud_access_contract(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["admin:read", "query:read"]) {
        return problem.into_response();
    }
    let sync_status = super::health::sync_runtime_status();
    let cloud = crate::product::CloudPosture::from_sync(&sync_status);
    let contract = crate::product::CloudAccessContract::new(state.operating_mode, &state.enabled_pro_services, &cloud);
    Json(contract).into_response()
}
