// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 `UsagePing` receipt class — Phase T (opt-in adoption signal).
//!
//! ## What this is
//!
//! A deliberately **metadata-only** receipt class that lets a daemon emit a
//! signed "a thing happened" ping (a session opened, a query ran, the daemon
//! started) without disclosing *what* happened. It is the only adoption
//! signal the daemon's no-phone-home vow permits, and it is the third
//! production-cutover launch-gate number (≥25 distinct-passport pings — see
//! ExecPlan `phase-t-usage-receipts-2026-07-03`).
//!
//! ## Metadata-only invariant (this is the whole point)
//!
//! The canonical body carries ONLY: `schema`, `kind`, `receipt_id`,
//! `tenant_id`, `passport_fpr`, `event_class` (a closed, validated set),
//! an integer `count`, and `created_at`. **No fact ids, no query text, no
//! corpus identity, no entity content.** [`build_usage_ping_body_v1`] takes a
//! strongly-typed input that cannot express content, and
//! [`assert_usage_ping_kind_v1`] is a *strict* recognizer: it rejects any
//! body that carries an unexpected key, an unknown `event_class`, or a
//! reserved-prefix identity. That strictness is deliberate and is the
//! difference from [`crate::memory_use_v1::assert_memory_use_kind_v1`]
//! (which is kind-only): a usage ping must be *provably* metadata-only.
//!
//! ## Local-only in M0
//!
//! This module is the local signed primitive only. It is emitted + persisted
//! through the daemon's signed-observation path (`append_one`, never a raw
//! store write) behind the default-OFF `CORECRUXD_FEATURE_USAGE_RECEIPTS`
//! flag. The opt-in, consent-gated *outbound* submitter is a separate
//! milestone (M1) and adds no network code here — so the primitive keeps the
//! `assert-no-phone-home.sh` release gate green.

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::memory_use_v1::is_reserved_entity_prefix;
use crate::verify_v1::ReceiptSigV1;

/// Receipt schema string written into the canonical body for usage-ping
/// receipts. Mirrors the shared body-schema convention (`kind` is the class
/// discriminator, not the schema string).
pub const USAGE_PING_BODY_SCHEMA_V1: &str = "cuecrux.receipt.body.v1";

/// The `kind` discriminator value identifying a usage-ping receipt.
pub const USAGE_PING_KIND_V1: &str = "usage_ping";

/// The closed, validated set of `event_class` string values. Anything outside
/// this set is rejected — a usage ping is an adoption signal, not a general
/// telemetry channel, so the class vocabulary is fixed by code review.
pub const USAGE_EVENT_CLASSES_V1: &[&str] = &["session", "query", "daemon_start"];

/// The exact set of top-level keys a well-formed usage-ping body may carry.
/// [`assert_usage_ping_kind_v1`] rejects any body with a key outside this set
/// — that is what makes "content-bearing body" a rejectable condition.
pub const USAGE_PING_ALLOWED_KEYS_V1: &[&str] = &[
    "schema",
    "kind",
    "receipt_id",
    "tenant_id",
    "passport_fpr",
    "event_class",
    "count",
    "created_at",
];

/// The class of adoption event a ping records. Closed set on purpose — unknown
/// values do not round-trip and are rejected by [`UsageEventClassV1::parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageEventClassV1 {
    /// An agent session was opened against the daemon.
    Session,
    /// A retrieval / query was served.
    Query,
    /// The daemon process started.
    DaemonStart,
}

impl UsageEventClassV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Query => "query",
            Self::DaemonStart => "daemon_start",
        }
    }

    /// Parse a string into a [`UsageEventClassV1`]. Returns `None` for any
    /// value outside the closed set — usage pings do not accept an open-ended
    /// `Other(..)` variant (contrast [`crate::memory_use_v1::MemoryUseIntentV1`]).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "session" => Some(Self::Session),
            "query" => Some(Self::Query),
            "daemon_start" => Some(Self::DaemonStart),
            _ => None,
        }
    }
}

/// Input to [`build_usage_ping_body_v1`]. Every field is metadata; there is
/// no field through which fact content, query text, or corpus identity could
/// be expressed.
#[derive(Debug, Clone)]
pub struct UsagePingBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    /// The daemon's passport fingerprint — the adoption unit M2 tallies
    /// distinct instances by.
    pub passport_fpr: &'a str,
    pub event_class: UsageEventClassV1,
    /// A small integer count (e.g. sessions since the last ping). No content.
    pub count: u64,
    /// Caller-provided ISO-8601 timestamp for determinism in tests.
    pub created_at: &'a str,
}

/// Build the canonical CBOR bytes for a usage-ping receipt body.
///
/// Returns the encoded bytes and the BLAKE3 digest over those bytes; the
/// digest is what the signature binds to. The encoder produces a
/// deterministic key order so two calls with the same input emit
/// byte-identical output (verifier round-trips depend on this).
///
/// Defence in depth: if `tenant_id` or `passport_fpr` carries a reserved
/// entity prefix (`__agent::`, `__ops::`, `__bootstrap__::`) the body is
/// refused (empty bytes returned) so an internal namespace can never leak
/// into an adoption ping. An empty body fails the downstream hash-binding
/// cleanly rather than panicking.
pub fn build_usage_ping_body_v1(input: &UsagePingBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    if is_reserved_entity_prefix(input.tenant_id) || is_reserved_entity_prefix(input.passport_fpr) {
        let empty: Vec<u8> = Vec::new();
        let digest = blake3::hash(&empty);
        return (empty, *digest.as_bytes());
    }

    // CBOR map entries are emitted in the order they appear in the Vec, so a
    // deterministic key order is just a matter of building the list in a fixed
    // sequence.
    let top: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("schema".to_string()),
            CborValue::Text(USAGE_PING_BODY_SCHEMA_V1.to_string()),
        ),
        (
            CborValue::Text("kind".to_string()),
            CborValue::Text(USAGE_PING_KIND_V1.to_string()),
        ),
        (
            CborValue::Text("receipt_id".to_string()),
            CborValue::Text(input.receipt_id.to_string()),
        ),
        (
            CborValue::Text("tenant_id".to_string()),
            CborValue::Text(input.tenant_id.to_string()),
        ),
        (
            CborValue::Text("passport_fpr".to_string()),
            CborValue::Text(input.passport_fpr.to_string()),
        ),
        (
            CborValue::Text("event_class".to_string()),
            CborValue::Text(input.event_class.as_str().to_string()),
        ),
        (
            CborValue::Text("count".to_string()),
            CborValue::Integer(input.count.into()),
        ),
        (
            CborValue::Text("created_at".to_string()),
            CborValue::Text(input.created_at.to_string()),
        ),
    ];

    let v = CborValue::Map(top);
    let mut bytes = Vec::new();
    // Serialising a `Value` into a `Vec<u8>` cannot fail in practice —
    // ciborium only returns IO errors and `Vec`'s `Write` impl is infallible.
    // Map any unexpected error to an empty body so callers detect via a
    // 32-byte hash mismatch downstream rather than panic.
    if ciborium::ser::into_writer(&v, &mut bytes).is_err() {
        bytes.clear();
    }
    let digest = blake3::hash(&bytes);
    (bytes, *digest.as_bytes())
}

/// Sign the canonical body produced by [`build_usage_ping_body_v1`] with the
/// daemon's Ed25519 passport key and return the [`ReceiptSigV1`] envelope
/// ready to be CBOR-encoded and stored. Mirrors
/// [`crate::memory_use_v1::sign_memory_use_v1`] — same sig envelope schema
/// (`"cuecrux.receipt.sig.v1"`), alg `ed25519`.
#[allow(clippy::too_many_arguments)]
pub fn sign_usage_ping_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    let sig = signing_key.sign(body_bytes).to_bytes().to_vec();
    ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: key_id.to_string(),
        signed_at: signed_at.to_string(),
        signature: sig,
        signed_payload_hash: body_hash.to_vec(),
    }
}

/// Strict kind + shape assertion: parse `body_bytes` as CBOR and return
/// `true` iff the body is a well-formed, metadata-only usage ping —
/// `kind == "usage_ping"`, every top-level key is in
/// [`USAGE_PING_ALLOWED_KEYS_V1`], the `event_class` is one of
/// [`USAGE_EVENT_CLASSES_V1`], and neither `tenant_id` nor `passport_fpr`
/// carries a reserved prefix. Any content-bearing key, unknown event class,
/// reserved-prefix identity, or wrong kind makes this return `false`.
///
/// Run this AFTER [`crate::verify_v1::verify_receipt_v1`] returns `OK`; the
/// generic verifier already checks the signature + body-hash binding, so this
/// adds the class discriminator + the metadata-only guarantee on top.
pub fn assert_usage_ping_kind_v1(body_bytes: &[u8]) -> bool {
    let Ok(v) = ciborium::de::from_reader::<CborValue, _>(std::io::Cursor::new(body_bytes)) else {
        return false;
    };
    let CborValue::Map(map) = v else {
        return false;
    };
    let mut kind_ok = false;
    let mut event_class_ok = false;
    for (k, val) in &map {
        let CborValue::Text(key) = k else {
            // A non-text top-level key is not a shape this class ever emits.
            return false;
        };
        if !USAGE_PING_ALLOWED_KEYS_V1.contains(&key.as_str()) {
            // A key outside the metadata set = a content-bearing body.
            return false;
        }
        match key.as_str() {
            "kind" => {
                if let CborValue::Text(s) = val {
                    kind_ok = s == USAGE_PING_KIND_V1;
                }
            }
            "event_class" => {
                if let CborValue::Text(s) = val {
                    event_class_ok = UsageEventClassV1::parse(s).is_some();
                }
            }
            "tenant_id" | "passport_fpr" => {
                if let CborValue::Text(s) = val {
                    if is_reserved_entity_prefix(s) {
                        return false;
                    }
                }
            }
            _ => {}
        }
    }
    kind_ok && event_class_ok
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::keyring_v1::{Ed25519KeyEntryV1, Ed25519KeyRingV1};
    use crate::verify_v1::{verify_receipt_v1, VerifyReceiptInput};
    use base64::Engine as _;

    fn test_build_info() -> corecrux_types::BuildInfo {
        corecrux_types::BuildInfo {
            version: "0.0.1-test".to_string(),
            commit: "usage_receipt_v1_test".to_string(),
        }
    }

    fn sample_input<'a>(receipt_id: &'a str) -> UsagePingBodyInputV1<'a> {
        UsagePingBodyInputV1 {
            tenant_id: "local",
            receipt_id,
            passport_fpr: "fpr_test",
            event_class: UsageEventClassV1::Session,
            count: 3,
            created_at: "2026-07-03T00:00:00Z",
        }
    }

    #[test]
    fn build_body_is_deterministic() {
        let input = sample_input("r-1");
        let (b1, h1) = build_usage_ping_body_v1(&input);
        let (b2, h2) = build_usage_ping_body_v1(&input);
        assert_eq!(b1, b2, "canonical body bytes must be deterministic");
        assert_eq!(h1, h2, "body hash must be deterministic");
        assert!(assert_usage_ping_kind_v1(&b1));
    }

    #[test]
    fn body_carries_only_metadata() {
        let input = sample_input("r-meta");
        let (body, _) = build_usage_ping_body_v1(&input);
        let text = String::from_utf8_lossy(&body);
        // Positive: the metadata is present.
        assert!(text.contains("usage_ping"));
        assert!(text.contains("session"));
        assert!(text.contains("fpr_test"));
        // Negative: no content-bearing keys ever appear in a usage body.
        for content_key in ["fact_id", "entity", "entries", "query", "prompt_hash", "corpus"] {
            assert!(
                !text.contains(content_key),
                "usage body must not carry content key {content_key}"
            );
        }
    }

    #[test]
    fn event_class_round_trips_and_rejects_unknown() {
        for s in USAGE_EVENT_CLASSES_V1 {
            assert_eq!(UsageEventClassV1::parse(s).unwrap().as_str(), *s);
        }
        assert!(UsageEventClassV1::parse("telemetry").is_none());
        assert!(UsageEventClassV1::parse("").is_none());
    }

    /// End-to-end: build → sign → verify (positive) → assert-kind (positive).
    #[test]
    fn build_sign_verify_round_trip() {
        let input = sample_input("r-up-1");
        let (body_bytes, body_hash) = build_usage_ping_body_v1(&input);
        assert!(assert_usage_ping_kind_v1(&body_bytes));

        let sk = SigningKey::from_bytes(&[13u8; 32]);
        let vk = sk.verifying_key();
        let sig = sign_usage_ping_v1("r-up-1", &body_bytes, body_hash, &sk, "k_test", "2026-07-03T00:00:00Z");
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let keyring = Ed25519KeyRingV1 {
            v: 1,
            keys: vec![Ed25519KeyEntryV1 {
                key_id: "k_test".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
            }],
        };
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "local",
            receipt_id: "r-up-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: body_hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-07-03T00:00:01Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "OK", "happy-path verify must return OK");
        assert!(report.signature_valid);
        assert!(report.integrity.payload_hash_matches);
        assert!(assert_usage_ping_kind_v1(&body_bytes));
    }

    #[test]
    fn assert_kind_rejects_wrong_kind() {
        // A memory-use-shaped body (kind = "answer") must not pass.
        let body = CborValue::Map(vec![(
            CborValue::Text("kind".to_string()),
            CborValue::Text("answer".to_string()),
        )]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        assert!(!assert_usage_ping_kind_v1(&bytes));
    }

    #[test]
    fn assert_kind_rejects_content_bearing_body() {
        // A body that otherwise looks like a usage ping but smuggles a
        // content key (`query`) must be rejected.
        let body = CborValue::Map(vec![
            (
                CborValue::Text("kind".to_string()),
                CborValue::Text(USAGE_PING_KIND_V1.to_string()),
            ),
            (
                CborValue::Text("event_class".to_string()),
                CborValue::Text("query".to_string()),
            ),
            (
                CborValue::Text("query".to_string()),
                CborValue::Text("what did the agent ask".to_string()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        assert!(
            !assert_usage_ping_kind_v1(&bytes),
            "a body carrying a content key must be rejected"
        );
    }

    #[test]
    fn assert_kind_rejects_unknown_event_class() {
        let body = CborValue::Map(vec![
            (
                CborValue::Text("kind".to_string()),
                CborValue::Text(USAGE_PING_KIND_V1.to_string()),
            ),
            (
                CborValue::Text("event_class".to_string()),
                CborValue::Text("telemetry".to_string()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        assert!(!assert_usage_ping_kind_v1(&bytes));
    }

    #[test]
    fn reserved_prefix_identity_yields_empty_body() {
        // Building with a reserved-prefix tenant/passport is refused: an empty
        // body that cannot pass the recognizer.
        let reserved_tenant = UsagePingBodyInputV1 {
            tenant_id: "__ops::internal",
            ..sample_input("r-res-1")
        };
        let (body, _) = build_usage_ping_body_v1(&reserved_tenant);
        assert!(body.is_empty(), "reserved-prefix tenant must not build a body");
        assert!(!assert_usage_ping_kind_v1(&body));

        let reserved_fpr = UsagePingBodyInputV1 {
            passport_fpr: "__agent::alpha",
            ..sample_input("r-res-2")
        };
        let (body2, _) = build_usage_ping_body_v1(&reserved_fpr);
        assert!(body2.is_empty(), "reserved-prefix passport must not build a body");
    }

    #[test]
    fn assert_kind_rejects_reserved_prefix_in_hand_rolled_body() {
        // Defence in depth: even a hand-rolled body with only allowed keys is
        // rejected if it carries a reserved-prefix identity value.
        let body = CborValue::Map(vec![
            (
                CborValue::Text("kind".to_string()),
                CborValue::Text(USAGE_PING_KIND_V1.to_string()),
            ),
            (
                CborValue::Text("event_class".to_string()),
                CborValue::Text("session".to_string()),
            ),
            (
                CborValue::Text("tenant_id".to_string()),
                CborValue::Text("__bootstrap__::pattern".to_string()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        assert!(!assert_usage_ping_kind_v1(&bytes));
    }

    #[test]
    fn assert_kind_rejects_invalid_cbor() {
        assert!(!assert_usage_ping_kind_v1(b"not cbor at all"));
    }

    /// Tamper detection: flipping one bit in the canonical body MUST cause the
    /// verifier to reject with `BODY_HASH_MISMATCH`.
    #[test]
    fn tamper_bit_flip_detected() {
        let input = sample_input("r-up-2");
        let (body_bytes, body_hash) = build_usage_ping_body_v1(&input);

        let sk = SigningKey::from_bytes(&[17u8; 32]);
        let vk = sk.verifying_key();
        let sig = sign_usage_ping_v1(
            "r-up-2",
            &body_bytes,
            body_hash,
            &sk,
            "k_tamper",
            "2026-07-03T00:00:00Z",
        );
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let keyring = Ed25519KeyRingV1 {
            v: 1,
            keys: vec![Ed25519KeyEntryV1 {
                key_id: "k_tamper".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
            }],
        };
        let build = test_build_info();

        let mut tampered = body_bytes.clone();
        let last = tampered.len().saturating_sub(1);
        tampered[last] ^= 0x01;

        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "local",
            receipt_id: "r-up-2",
            body_bytes: &tampered,
            stored_body_payload_hash: body_hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-07-03T00:00:01Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(
            report.error_code, "BODY_HASH_MISMATCH",
            "tampered body must be detected as BODY_HASH_MISMATCH"
        );
        assert!(!report.integrity.payload_hash_matches);
    }
}
