// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Witness/TSA local smoke route.

use super::{AppState, IntoResponse, Json, State, StatusCode};

#[utoipa::path(
    get,
    path = "/v1/witness/smoke",
    tag = "Receipts",
    responses(
        (status = 200, description = "Witness/TSA local configuration smoke passed"),
        (status = 503, description = "Witness/TSA local configuration smoke failed"),
    )
)]
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_witness_smoke(State(state): State<AppState>) -> impl IntoResponse {
    let report = state.witness.smoke_report();
    let status = if report.ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(report))
}
