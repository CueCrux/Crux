// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 streaming + context-injection receipt classes (G19).
//!
//! ExecPlan `context-mediation-injection-2026-06-11` M3. Normative spec:
//! `Streaming-Receipts-Spec` (planning monorepo, shared plane).
//! Supersedes the receipts-relevant slice of Reasoning-Stream-Contract
//! v0.1 (archived; its deterministic-replay invariants are retained —
//! see `Shared-Consolidated-2026-05-31.md` §3).
//!
//! ## The two-sided trail
//!
//! Mediation is context-injection + receipts-beside-the-call. That makes
//! the audit trail two-sided, and the sides are never merged:
//!
//! - **Injected side** — [`CONTEXT_INJECTED_KIND_V1`]: what context
//!   entered the model (bundle `stable_hash`, fact ids, budget). Minted
//!   when a `context_bundle/v1` is delivered to a consumer.
//! - **Emitted side** — [`STREAM_COMPLETED_KIND_V1`] /
//!   [`STREAM_ABORTED_KIND_V1`]: what came out, minted at stream **end**
//!   (the gap today: abandoned streams leave no trail). Aborted streams
//!   are first-class, not an error path.
//!
//! Linkage is `(session_id, injected_stable_hash)` — see
//! [`stream_links_injection_v1`]. The emitted side records an
//! `output_digest` (BLAKE3 of the emitted text), never the content
//! itself, so the receipt proves *what* was emitted without storing it.
//!
//! ## Conventions
//!
//! Mirrors `memory_use_v1`: deterministic CBOR key order (byte-identical
//! re-encoding), BLAKE3 body digest, Ed25519 signature via
//! [`crate::verify_v1::ReceiptSigV1`], kind discriminator assertions run
//! after the generic verifier. Reserved-prefix fact entries are filtered
//! in depth via [`crate::memory_use_v1::filter_reserved_entries`].

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::memory_use_v1::{filter_reserved_entries, MemoryUseEntryV1};
use crate::verify_v1::ReceiptSigV1;

/// Receipt schema string — same body schema family as the other v1
/// receipt classes.
pub const STREAM_BODY_SCHEMA_V1: &str = "cuecrux.receipt.body.v1";

/// Kind discriminator: context bundle delivered to a consumer.
pub const CONTEXT_INJECTED_KIND_V1: &str = "context_injected";
/// Kind discriminator: stream ran to completion.
pub const STREAM_COMPLETED_KIND_V1: &str = "stream_completed";
/// Kind discriminator: stream ended early (client disconnect, provider
/// error, operator abort). First-class end-state, not an error path.
pub const STREAM_ABORTED_KIND_V1: &str = "stream_aborted";

/// Input to [`build_context_injected_body_v1`].
#[derive(Debug, Clone)]
pub struct ContextInjectedBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub session_id: &'a str,
    pub actor_passport: &'a str,
    /// `context_bundle/v1` (the bundle's `bundle_version`).
    pub bundle_version: &'a str,
    /// `blake3:<hex>` of the bundle's canonical stable region — the
    /// content address the emitted side links back to.
    pub stable_hash: &'a str,
    /// Injection point used: `harness_hook` | `prompt_prefix` |
    /// `system_prompt` | `llm_shim` (free-form for future points).
    pub injection_point: &'a str,
    pub budget_requested: u64,
    pub budget_spent_est: u64,
    /// Facts that entered the bundle. Reserved-prefix entries are
    /// filtered in depth before canonicalisation.
    pub entries: &'a [MemoryUseEntryV1],
    /// Caller-provided ISO-8601 timestamp for determinism in tests.
    pub created_at: &'a str,
}

/// End state of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEndStateV1 {
    Completed,
    Aborted,
}

impl StreamEndStateV1 {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Completed => STREAM_COMPLETED_KIND_V1,
            Self::Aborted => STREAM_ABORTED_KIND_V1,
        }
    }
}

/// Input to [`build_stream_end_body_v1`].
#[derive(Debug, Clone)]
pub struct StreamEndBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub session_id: &'a str,
    pub actor_passport: &'a str,
    pub end_state: StreamEndStateV1,
    /// Provider label (e.g. `anthropic`, `openai`, `ollama`) — observational.
    pub provider: &'a str,
    /// Model label as reported by the harness/upstream — observational.
    pub model: &'a str,
    /// ISO-8601 time of the first emitted token (None when the stream
    /// aborted before any output).
    pub first_token_at: Option<&'a str>,
    /// ISO-8601 end time (completion or abort).
    pub ended_at: &'a str,
    /// Completed streams: whether the provider truncated the response
    /// (max-tokens, stop condition). Meaningless for aborts.
    pub truncated: Option<bool>,
    /// Aborted streams: best-effort reason (`client_disconnect`,
    /// `provider_error`, `operator_abort`, ...).
    pub abort_reason: Option<&'a str>,
    /// `blake3:<hex>` over the emitted text as observed — proof of what
    /// came out without storing the content. None when nothing was
    /// emitted.
    pub output_digest: Option<&'a str>,
    /// `stable_hash` of the injected bundle this stream consumed — the
    /// two-sided linkage. None when no bundle was injected.
    pub injected_stable_hash: Option<&'a str>,
    /// Caller-provided ISO-8601 timestamp for determinism in tests.
    pub created_at: &'a str,
}

fn text_entry(key: &str, value: &str) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_string()), CborValue::Text(value.to_string()))
}

fn encode(top: Vec<(CborValue, CborValue)>) -> (Vec<u8>, [u8; 32]) {
    let v = CborValue::Map(top);
    let mut bytes = Vec::new();
    // Same rationale as memory_use_v1: ciborium into a Vec is infallible
    // in practice; degrade to an empty body that fails verification
    // cleanly rather than panic.
    if ciborium::ser::into_writer(&v, &mut bytes).is_err() {
        bytes.clear();
    }
    let digest = blake3::hash(&bytes);
    (bytes, *digest.as_bytes())
}

/// Build the canonical CBOR bytes for a context-injected receipt body.
/// Deterministic key order; reserved-prefix entries silently dropped
/// (defence in depth — same contract as `build_memory_use_body_v1`).
pub fn build_context_injected_body_v1(input: &ContextInjectedBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    let entries = filter_reserved_entries(input.entries);

    let mut top: Vec<(CborValue, CborValue)> = vec![
        text_entry("schema", STREAM_BODY_SCHEMA_V1),
        text_entry("kind", CONTEXT_INJECTED_KIND_V1),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        text_entry("session_id", input.session_id),
        text_entry("actor_passport", input.actor_passport),
        text_entry("bundle_version", input.bundle_version),
        text_entry("stable_hash", input.stable_hash),
        text_entry("injection_point", input.injection_point),
        (
            CborValue::Text("budget_requested".to_string()),
            CborValue::Integer(input.budget_requested.into()),
        ),
        (
            CborValue::Text("budget_spent_est".to_string()),
            CborValue::Integer(input.budget_spent_est.into()),
        ),
        text_entry("created_at", input.created_at),
    ];

    let entries_arr = entries
        .iter()
        .map(|e| CborValue::Map(vec![text_entry("fact_id", &e.fact_id), text_entry("entity", &e.entity)]))
        .collect::<Vec<_>>();
    top.push((CborValue::Text("entries".to_string()), CborValue::Array(entries_arr)));

    encode(top)
}

/// Build the canonical CBOR bytes for a stream-end receipt body
/// (completed or aborted — the `kind` field carries the end state).
pub fn build_stream_end_body_v1(input: &StreamEndBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    let mut top: Vec<(CborValue, CborValue)> = vec![
        text_entry("schema", STREAM_BODY_SCHEMA_V1),
        text_entry("kind", input.end_state.kind()),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        text_entry("session_id", input.session_id),
        text_entry("actor_passport", input.actor_passport),
        text_entry("provider", input.provider),
        text_entry("model", input.model),
        (CborValue::Text("stream".to_string()), CborValue::Bool(true)),
        text_entry("ended_at", input.ended_at),
        text_entry("created_at", input.created_at),
    ];
    if let Some(t) = input.first_token_at {
        top.push(text_entry("first_token_at", t));
    }
    if let Some(t) = input.truncated {
        top.push((CborValue::Text("truncated".to_string()), CborValue::Bool(t)));
    }
    if let Some(r) = input.abort_reason {
        top.push(text_entry("abort_reason", r));
    }
    if let Some(d) = input.output_digest {
        top.push(text_entry("output_digest", d));
    }
    if let Some(h) = input.injected_stable_hash {
        top.push(text_entry("injected_stable_hash", h));
    }
    encode(top)
}

/// Sign a canonical stream/context body with the daemon's Ed25519
/// passport key. Identical envelope to the other v1 receipt classes.
pub fn sign_stream_v1(
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

fn top_level_text(body_bytes: &[u8], field: &str) -> Option<String> {
    let v: CborValue = ciborium::de::from_reader(std::io::Cursor::new(body_bytes)).ok()?;
    let CborValue::Map(map) = v else { return None };
    for (k, val) in &map {
        if let (CborValue::Text(k), CborValue::Text(s)) = (k, val) {
            if k == field {
                return Some(s.clone());
            }
        }
    }
    None
}

/// Kind assertion for context-injected receipts. Run AFTER
/// `verify_receipt_v1` returns OK.
pub fn assert_context_injected_kind_v1(body_bytes: &[u8]) -> bool {
    top_level_text(body_bytes, "kind").as_deref() == Some(CONTEXT_INJECTED_KIND_V1)
}

/// Kind assertion for stream-end receipts (either end state). Run AFTER
/// `verify_receipt_v1` returns OK.
pub fn assert_stream_end_kind_v1(body_bytes: &[u8]) -> bool {
    matches!(
        top_level_text(body_bytes, "kind").as_deref(),
        Some(STREAM_COMPLETED_KIND_V1) | Some(STREAM_ABORTED_KIND_V1)
    )
}

/// Two-sided linkage check: `true` iff the stream-end body references
/// the injected body's `stable_hash` AND both sides agree on
/// `session_id`. The sides stay independent receipts — this only proves
/// the pairing.
pub fn stream_links_injection_v1(injected_body: &[u8], stream_body: &[u8]) -> bool {
    let (Some(injected_hash), Some(injected_session)) = (
        top_level_text(injected_body, "stable_hash"),
        top_level_text(injected_body, "session_id"),
    ) else {
        return false;
    };
    let (Some(linked_hash), Some(stream_session)) = (
        top_level_text(stream_body, "injected_stable_hash"),
        top_level_text(stream_body, "session_id"),
    ) else {
        return false;
    };
    injected_hash == linked_hash && injected_session == stream_session
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier as _, VerifyingKey};

    fn injected_input<'a>(entries: &'a [MemoryUseEntryV1]) -> ContextInjectedBodyInputV1<'a> {
        ContextInjectedBodyInputV1 {
            tenant_id: "work",
            receipt_id: "r_inj_1",
            session_id: "s-1",
            actor_passport: "passport:alpha",
            bundle_version: "context_bundle/v1",
            stable_hash: "blake3:abc123",
            injection_point: "harness_hook",
            budget_requested: 2000,
            budget_spent_est: 1812,
            entries,
            created_at: "2026-06-12T00:00:00Z",
        }
    }

    fn stream_input<'a>(end_state: StreamEndStateV1) -> StreamEndBodyInputV1<'a> {
        StreamEndBodyInputV1 {
            tenant_id: "work",
            receipt_id: "r_str_1",
            session_id: "s-1",
            actor_passport: "passport:alpha",
            end_state,
            provider: "ollama",
            model: "llama3:8b",
            first_token_at: Some("2026-06-12T00:00:01Z"),
            ended_at: "2026-06-12T00:00:09Z",
            truncated: Some(false),
            abort_reason: None,
            output_digest: Some("blake3:out999"),
            injected_stable_hash: Some("blake3:abc123"),
            created_at: "2026-06-12T00:00:09Z",
        }
    }

    #[test]
    fn bodies_are_byte_deterministic() {
        let entries = vec![MemoryUseEntryV1 {
            fact_id: "f_1".into(),
            entity: "execplan:x".into(),
        }];
        let (a, ha) = build_context_injected_body_v1(&injected_input(&entries));
        let (b, hb) = build_context_injected_body_v1(&injected_input(&entries));
        assert_eq!(a, b);
        assert_eq!(ha, hb);
        let (sa, sha) = build_stream_end_body_v1(&stream_input(StreamEndStateV1::Completed));
        let (sb, shb) = build_stream_end_body_v1(&stream_input(StreamEndStateV1::Completed));
        assert_eq!(sa, sb);
        assert_eq!(sha, shb);
    }

    #[test]
    fn reserved_prefix_entries_filtered_in_depth() {
        let entries = vec![
            MemoryUseEntryV1 {
                fact_id: "f_pub".into(),
                entity: "execplan:x".into(),
            },
            MemoryUseEntryV1 {
                fact_id: "f_secret".into(),
                entity: "__agent::alpha".into(),
            },
        ];
        let (bytes, _) = build_context_injected_body_v1(&injected_input(&entries));
        let text = format!(
            "{:?}",
            ciborium::de::from_reader::<CborValue, _>(std::io::Cursor::new(&bytes)).unwrap()
        );
        assert!(text.contains("f_pub"));
        assert!(!text.contains("f_secret"));
        assert!(!text.contains("__agent::"));
    }

    #[test]
    fn kind_discriminators() {
        let entries = vec![];
        let (inj, _) = build_context_injected_body_v1(&injected_input(&entries));
        assert!(assert_context_injected_kind_v1(&inj));
        assert!(!assert_stream_end_kind_v1(&inj));

        let (done, _) = build_stream_end_body_v1(&stream_input(StreamEndStateV1::Completed));
        assert!(assert_stream_end_kind_v1(&done));
        assert!(!assert_context_injected_kind_v1(&done));
        assert_eq!(top_level_text(&done, "kind").unwrap(), STREAM_COMPLETED_KIND_V1);

        let mut aborted_in = stream_input(StreamEndStateV1::Aborted);
        aborted_in.abort_reason = Some("client_disconnect");
        aborted_in.truncated = None;
        let (aborted, _) = build_stream_end_body_v1(&aborted_in);
        assert!(assert_stream_end_kind_v1(&aborted));
        assert_eq!(top_level_text(&aborted, "kind").unwrap(), STREAM_ABORTED_KIND_V1);
        assert_eq!(top_level_text(&aborted, "abort_reason").unwrap(), "client_disconnect");
    }

    #[test]
    fn aborted_before_first_token_still_mints() {
        let mut input = stream_input(StreamEndStateV1::Aborted);
        input.first_token_at = None;
        input.output_digest = None;
        input.truncated = None;
        input.abort_reason = Some("provider_error");
        let (bytes, hash) = build_stream_end_body_v1(&input);
        assert!(!bytes.is_empty());
        assert_eq!(hash, *blake3::hash(&bytes).as_bytes());
        assert!(top_level_text(&bytes, "first_token_at").is_none());
        assert!(top_level_text(&bytes, "output_digest").is_none());
    }

    #[test]
    fn two_sided_linkage() {
        let entries = vec![];
        let (inj, _) = build_context_injected_body_v1(&injected_input(&entries));
        let (matching, _) = build_stream_end_body_v1(&stream_input(StreamEndStateV1::Completed));
        assert!(stream_links_injection_v1(&inj, &matching));

        // Wrong hash → no link.
        let mut wrong_hash = stream_input(StreamEndStateV1::Completed);
        wrong_hash.injected_stable_hash = Some("blake3:other");
        let (wrong, _) = build_stream_end_body_v1(&wrong_hash);
        assert!(!stream_links_injection_v1(&inj, &wrong));

        // Wrong session → no link, even with the right hash.
        let mut wrong_session = stream_input(StreamEndStateV1::Completed);
        wrong_session.session_id = "s-2";
        let (wrong, _) = build_stream_end_body_v1(&wrong_session);
        assert!(!stream_links_injection_v1(&inj, &wrong));

        // No injection recorded → no link.
        let mut none = stream_input(StreamEndStateV1::Completed);
        none.injected_stable_hash = None;
        let (no_link, _) = build_stream_end_body_v1(&none);
        assert!(!stream_links_injection_v1(&inj, &no_link));
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let entries = vec![];
        let (bytes, hash) = build_context_injected_body_v1(&injected_input(&entries));
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let sig = sign_stream_v1("r_inj_1", &bytes, hash, &signing_key, "key-1", "2026-06-12T00:00:00Z");
        assert_eq!(sig.signed_payload_hash, hash.to_vec());
        let vk: VerifyingKey = signing_key.verifying_key();
        let sig_bytes: [u8; 64] = sig.signature.as_slice().try_into().unwrap();
        vk.verify(&bytes, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .expect("signature verifies over canonical body bytes");
        // Tamper → fails.
        let mut tampered = bytes.clone();
        tampered[0] ^= 0xFF;
        assert!(vk
            .verify(&tampered, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .is_err());
    }
}
