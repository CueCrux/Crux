// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use corecrux_types::ProblemDetails;

/// Newtype wrapper that implements `IntoResponse` for `ProblemDetails`.
///
/// `corecrux-types` is framework-agnostic (no axum dep), so the Axum
/// integration lives here in corecruxd.
#[derive(Debug)]
pub struct ProblemResponse(pub ProblemDetails);

impl IntoResponse for ProblemResponse {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = serde_json::to_string(&self.0).unwrap_or_else(|_| {
            r#"{"type":"https://errors.cuecrux.com/internal","title":"Serialization Error","status":500}"#.to_string()
        });
        let mut response = (status, body).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

impl From<ProblemDetails> for ProblemResponse {
    fn from(pd: ProblemDetails) -> Self {
        Self(pd)
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::response::IntoResponse;
    use corecrux_types::ProblemDetails;

    use super::ProblemResponse;

    #[tokio::test]
    async fn problem_response_sets_status_and_content_type() {
        let pd = ProblemDetails::new(404, "https://errors.cuecrux.com/not-found", "Not Found");
        let resp = ProblemResponse(pd).into_response();
        assert_eq!(resp.status().as_u16(), 404);
        assert_eq!(
            resp.headers().get("content-type").unwrap().to_str().unwrap(),
            "application/problem+json"
        );

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["type"], "https://errors.cuecrux.com/not-found");
        assert_eq!(json["title"], "Not Found");
        assert_eq!(json["status"], 404);
    }

    #[tokio::test]
    async fn problem_response_invalid_status_falls_back_to_500() {
        let pd = ProblemDetails {
            problem_type: "https://errors.cuecrux.com/internal".to_string(),
            title: "Bad Status".to_string(),
            status: 9999, // invalid HTTP status
            detail: None,
            instance: None,
            extensions: None,
        };
        let resp = ProblemResponse(pd).into_response();
        assert_eq!(resp.status().as_u16(), 500);
    }

    #[tokio::test]
    async fn problem_response_from_trait() {
        let pd = ProblemDetails::new(400, "https://errors.cuecrux.com/bad-request", "Bad Request");
        let pr: ProblemResponse = pd.into();
        let resp = pr.into_response();
        assert_eq!(resp.status().as_u16(), 400);
    }

    #[tokio::test]
    async fn problem_response_with_detail_and_instance() {
        let mut pd = ProblemDetails::new(422, "https://errors.cuecrux.com/validation", "Validation Error");
        pd.detail = Some("Field 'name' is required".to_string());
        pd.instance = Some("/streams/abc".to_string());

        let resp = ProblemResponse(pd).into_response();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["detail"], "Field 'name' is required");
        assert_eq!(json["instance"], "/streams/abc");
    }
}
