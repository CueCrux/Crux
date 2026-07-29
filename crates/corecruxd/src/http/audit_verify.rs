// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `POST /v1/audit/bundle/verify` — offline verification of a caller-supplied
//! BYO Audit Trail bundle (`tar.zst`).
//!
//! Stateless and side-effect-free: it decompresses the archive (bounded by the
//! receipts crate's decompression cap, so a decompression-bomb / over-large
//! archive is rejected rather than allocated), recomputes the `events.jsonl`
//! and `receipts.cbor` content hashes, and verifies the manifest's Ed25519
//! signature against the public key pinned *inside* the manifest. No daemon
//! state is read or written and no network / key fetch happens — the same
//! guarantees as the offline `corecruxctl audit-export --verify` CLI, exposed
//! over HTTP so a third party can verify a bundle they were handed.
//!
//! A *failed verification* is returned as `ok: false` in the `VerifyReportV1`
//! body at HTTP 200, so the caller sees every sub-check verdict (hash matches,
//! signature validity, witness endorsement). Only a structurally malformed or
//! over-cap archive is a 4xx.
//!
//! The route is `Read`-classified by the deny-by-default route-auth middleware
//! (`http::route_auth`): a caller needs a read scope, so this is not an open,
//! unauthenticated decompress-and-verify surface. The compressed upload is
//! additionally capped at [`AUDIT_BUNDLE_MAX_UPLOAD_BYTES`] at the route layer.

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use corecrux_receipts::{verify_bundle_v1, AuditBundleError};

use super::session::problem;

/// Maximum accepted *compressed* upload size (8 MiB). The *decompressed* size is
/// separately and independently capped inside the verifier
/// (`corecrux_receipts::MAX_DECOMPRESSED_BUNDLE_BYTES`), so this is the
/// first-line bound before any decompression work happens.
pub const AUDIT_BUNDLE_MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

pub async fn post_audit_bundle_verify(body: Bytes) -> Response {
    match verify_bundle_v1(&body) {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(AuditBundleError::DecompressedTooLarge) => problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "bundle_too_large",
            "audit bundle decompresses beyond the accepted size cap",
        ),
        Err(err) => problem(
            StatusCode::BAD_REQUEST,
            "malformed_bundle",
            format!("audit bundle could not be parsed: {err}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_receipts::{build_bundle_v1, AuditBundleKeyClassV1, AuditBundleScopeV1, BuildBundleInputV1};
    use ed25519_dalek::SigningKey;

    fn valid_bundle_bytes() -> Vec<u8> {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let built = build_bundle_v1(BuildBundleInputV1 {
            bundle_id: "http-verify-test".into(),
            since_rfc3339: "2026-05-27T00:00:00Z".into(),
            until_rfc3339: "2026-05-28T00:00:00Z".into(),
            generated_at_rfc3339: "2026-05-28T01:00:00Z".into(),
            scope: AuditBundleScopeV1::default(),
            events: vec![],
            receipt_refs: vec![],
            witness_proofs: vec![],
            signing_key: &sk,
            signer_key_id: "k1".into(),
            key_class: AuditBundleKeyClassV1::Ephemeral,
        })
        .expect("build bundle");
        let mut buf = Vec::new();
        built.write_tar_zst(&mut buf).expect("write tar.zst");
        buf
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn valid_bundle_verifies_ok() {
        let resp = post_audit_bundle_verify(Bytes::from(valid_bundle_bytes())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["ok"], serde_json::Value::Bool(true));
        assert_eq!(body["signature_valid"], serde_json::Value::Bool(true));
    }

    #[tokio::test]
    async fn tampered_bundle_reports_not_ok_at_200() {
        // Flip a byte in the compressed stream — still a decodable archive shape
        // only if it survives zstd framing; if not, we accept a 4xx. Either way
        // it must never report ok:true.
        let mut bytes = valid_bundle_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        let resp = post_audit_bundle_verify(Bytes::from(bytes)).await;
        if resp.status() == StatusCode::OK {
            let body = body_json(resp).await;
            assert_eq!(body["ok"], serde_json::Value::Bool(false));
        } else {
            assert!(resp.status().is_client_error());
        }
    }

    #[tokio::test]
    async fn garbage_body_is_client_error() {
        let resp = post_audit_bundle_verify(Bytes::from_static(b"definitely not a tar.zst")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_body_is_client_error() {
        let resp = post_audit_bundle_verify(Bytes::new()).await;
        assert!(resp.status().is_client_error());
    }
}
