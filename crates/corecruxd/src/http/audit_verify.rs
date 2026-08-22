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
//! **Identity pinning (play03 D2).** The manifest key proves the bundle is
//! internally consistent, not who produced it: re-signing an edited bundle with
//! a freshly generated key passes every check above. `?expect_pubkey_hex=` lets
//! a caller state which issuer the bundle should have come from, and a bundle
//! signed by anyone else comes back `ok: false` with
//! `signer_pin: "mismatch"`. Without it — and without the daemon-wide
//! `CRUX_EXPORT_VERIFY_PUBLIC_KEY_HEX` fallback — the report is unchanged but
//! carries `signer_pin: "unpinned"` and the `UNPINNED — trust unproven`
//! label, so a green verdict is not mistaken for proof of origin.
//!
//! The route is `Read`-classified by the deny-by-default route-auth middleware
//! (`http::route_auth`): a caller needs a read scope, so this is not an open,
//! unauthenticated decompress-and-verify surface. The compressed upload is
//! additionally capped at [`AUDIT_BUNDLE_MAX_UPLOAD_BYTES`] at the route layer.

use axum::body::Bytes;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use corecrux_receipts::{verify_bundle_pinned_v1, AuditBundleError, ExpectedSignerV1};

use super::session::problem;

/// Query parameters for `POST /v1/audit/bundle/verify`.
#[derive(Debug, Default, Deserialize)]
pub struct AuditBundleVerifyQuery {
    /// Expected Ed25519 signer public key, 64 hex chars. When present, a
    /// bundle signed by any other key verifies `ok: false`. Absent falls back
    /// to `CRUX_EXPORT_VERIFY_PUBLIC_KEY_HEX`, then to unpinned.
    pub expect_pubkey_hex: Option<String>,
}

/// Maximum accepted *compressed* upload size (8 MiB). The *decompressed* size is
/// separately and independently capped inside the verifier
/// (`corecrux_receipts::MAX_DECOMPRESSED_BUNDLE_BYTES`), so this is the
/// first-line bound before any decompression work happens.
pub const AUDIT_BUNDLE_MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

pub async fn post_audit_bundle_verify(Query(query): Query<AuditBundleVerifyQuery>, body: Bytes) -> Response {
    // A malformed pin is a 400, never a silent downgrade to unpinned: a caller
    // who asked for an identity check must not be told "verified" because the
    // key they typed was unusable.
    let expected = match query.expect_pubkey_hex.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(raw) => match ExpectedSignerV1::from_hex(raw) {
            Ok(pin) => Some(pin),
            Err(err) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "invalid_expect_pubkey_hex",
                    format!("expect_pubkey_hex is unusable: {err}"),
                )
            }
        },
        None => match ExpectedSignerV1::from_env() {
            Ok(pin) => pin,
            Err(err) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid_expected_signer_config",
                    format!("the daemon's configured expected signer is unusable: {err}"),
                )
            }
        },
    };

    match verify_bundle_pinned_v1(&body, None, expected.as_ref()) {
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

    const EXPORTER_SECRET: [u8; 32] = [0x42; 32];

    fn signing_key(secret: [u8; 32]) -> SigningKey {
        SigningKey::from_bytes(&secret)
    }

    fn pubkey_hex(secret: [u8; 32]) -> String {
        hex::encode(signing_key(secret).verifying_key().to_bytes())
    }

    fn bundle_bytes_signed_by(secret: [u8; 32]) -> Vec<u8> {
        let sk = signing_key(secret);
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
            key_class: AuditBundleKeyClassV1::Persistent,
        })
        .expect("build bundle");
        let mut buf = Vec::new();
        built.write_tar_zst(&mut buf).expect("write tar.zst");
        buf
    }

    fn valid_bundle_bytes() -> Vec<u8> {
        bundle_bytes_signed_by(EXPORTER_SECRET)
    }

    fn no_pin() -> Query<AuditBundleVerifyQuery> {
        Query(AuditBundleVerifyQuery::default())
    }

    fn pin(hex_key: &str) -> Query<AuditBundleVerifyQuery> {
        Query(AuditBundleVerifyQuery {
            expect_pubkey_hex: Some(hex_key.to_string()),
        })
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn valid_bundle_verifies_ok() {
        let resp = post_audit_bundle_verify(no_pin(), Bytes::from(valid_bundle_bytes())).await;
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
        let resp = post_audit_bundle_verify(no_pin(), Bytes::from(bytes)).await;
        if resp.status() == StatusCode::OK {
            let body = body_json(resp).await;
            assert_eq!(body["ok"], serde_json::Value::Bool(false));
        } else {
            assert!(resp.status().is_client_error());
        }
    }

    #[tokio::test]
    async fn garbage_body_is_client_error() {
        let resp = post_audit_bundle_verify(no_pin(), Bytes::from_static(b"definitely not a tar.zst")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_body_is_client_error() {
        let resp = post_audit_bundle_verify(no_pin(), Bytes::new()).await;
        assert!(resp.status().is_client_error());
    }

    /// play03 D2 — an unpinned pass must not read as proof of origin.
    #[tokio::test]
    async fn unpinned_export_verify_is_relabelled_trust_unproven() {
        let resp = post_audit_bundle_verify(no_pin(), Bytes::from(valid_bundle_bytes())).await;
        let body = body_json(resp).await;
        assert_eq!(body["ok"], serde_json::Value::Bool(true));
        assert_eq!(body["signer_pin"], serde_json::Value::String("unpinned".into()));
        assert_eq!(
            body["trust_label"],
            serde_json::Value::String(corecrux_receipts::EXPORT_TRUST_UNPINNED_LABEL.into())
        );
    }

    /// play03 D2 — the pinned issuer verifies green and says the identity was
    /// actually checked.
    #[tokio::test]
    async fn pinned_export_verify_reports_the_identity_was_checked() {
        let resp = post_audit_bundle_verify(pin(&pubkey_hex(EXPORTER_SECRET)), Bytes::from(valid_bundle_bytes())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["ok"], serde_json::Value::Bool(true));
        assert_eq!(body["signer_pin"], serde_json::Value::String("pinned".into()));
        assert!(body["signer_public_key_b64"].as_str().is_some());
    }

    /// play03 D2 — the attack: an export re-signed by someone else is
    /// internally consistent, so it passes unpinned. Pinned, it is refused.
    #[tokio::test]
    async fn export_verify_refuses_an_unexpected_issuer() {
        let attacker_bundle = bundle_bytes_signed_by([0x99; 32]);

        let unpinned = post_audit_bundle_verify(no_pin(), Bytes::from(attacker_bundle.clone())).await;
        assert_eq!(body_json(unpinned).await["ok"], serde_json::Value::Bool(true));

        let resp = post_audit_bundle_verify(pin(&pubkey_hex(EXPORTER_SECRET)), Bytes::from(attacker_bundle)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["ok"], serde_json::Value::Bool(false));
        assert_eq!(body["signer_pin"], serde_json::Value::String("mismatch".into()));
        assert!(body["failure_reason"]
            .as_str()
            .expect("failure_reason")
            .contains("expected signer"));
    }

    /// A pin the caller typed wrong is a 400, never a quiet fallback to an
    /// unpinned pass.
    #[tokio::test]
    async fn malformed_export_pin_is_rejected_not_ignored() {
        let resp = post_audit_bundle_verify(pin("not-a-key"), Bytes::from(valid_bundle_bytes())).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// play03 D2 red-before-green: an ephemeral signer is refused at build, so
    /// no such bundle can reach this route in the first place.
    #[tokio::test]
    async fn ephemeral_signed_export_cannot_be_built() {
        let sk = signing_key(EXPORTER_SECRET);
        let err = build_bundle_v1(BuildBundleInputV1 {
            bundle_id: "ephemeral-export".into(),
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
        });
        let Err(err) = err else {
            panic!("ephemeral-signed export must be refused");
        };
        assert!(matches!(err, AuditBundleError::EphemeralSigningKeyRefused));
    }
}
