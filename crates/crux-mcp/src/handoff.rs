// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Agent handoff protocol for multi-agent delegation.
//!
//! A handoff package contains session state and facts that one agent can
//! serialize, sign, and pass to another agent. The receiving agent verifies
//! the cryptographic signature, validates the BLAKE3 content hash, and loads
//! the session state and facts into its local stores.
//!
//! Signatures use ephemeral Ed25519 keypairs — the public key is bundled in the
//! [`SignedHandoff`] so the receiver can verify without a pre-shared key registry.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use corecrux_memory::fact_store::{Fact, FactQuery, StoreFact};
use corecrux_memory::{FactStore, SessionStore};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A handoff package containing session state and facts for delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffPackage {
    pub session_id: String,
    pub session_state: Option<serde_json::Value>,
    pub facts: Vec<Fact>,
    pub created_at: String,
    pub source_agent: String,
    pub message: Option<String>,
}

/// A cryptographically signed handoff package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHandoff {
    /// base64(JSON(HandoffPackage))
    pub payload_b64: String,
    /// BLAKE3 hex digest of the raw payload bytes.
    pub content_hash: String,
    /// base64(Ed25519 signature of the content_hash bytes).
    pub signature_b64: String,
    /// base64(Ed25519 verifying/public key).
    pub public_key_b64: String,
}

/// Result of accepting a handoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptResult {
    pub session_loaded: bool,
    pub facts_loaded: usize,
    pub verified: bool,
}

/// Errors that can occur during handoff creation or acceptance.
#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("content hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

/// Create a signed handoff package from current session state and facts.
///
/// # Arguments
/// * `session_store` — session store to load session state from.
/// * `fact_store` — fact store to query facts from.
/// * `session_id` — the session to package.
/// * `include_facts` — whether to include facts in the package.
/// * `agent_name` — name of the source agent.
/// * `message` — optional human-readable message for the receiving agent.
pub fn create_handoff(
    session_store: &SessionStore,
    fact_store: &FactStore,
    session_id: &str,
    include_facts: bool,
    agent_name: &str,
    message: Option<String>,
) -> Result<SignedHandoff, HandoffError> {
    // 1. Load session state.
    let session_state = session_store.get(session_id).map(|s| s.state.clone());

    // 2. Optionally collect all non-deleted facts.
    let facts = if include_facts {
        let result = fact_store.query(&FactQuery {
            query: None,
            entity: None,
            entity_prefix: None,
            top_k: usize::MAX,
            token_budget: None,
        });
        result.facts
    } else {
        Vec::new()
    };

    // 3. Build package.
    let package = HandoffPackage {
        session_id: session_id.to_string(),
        session_state,
        facts,
        created_at: Utc::now().to_rfc3339(),
        source_agent: agent_name.to_string(),
        message,
    };

    // 4. Serialize -> base64.
    let payload_json = serde_json::to_vec(&package)?;
    let payload_b64 = B64.encode(&payload_json);

    // 5. BLAKE3 hash.
    let content_hash = blake3::hash(&payload_json).to_hex().to_string();

    // 6. Ephemeral Ed25519 keypair -> sign the hash.
    let signing_key = SigningKey::generate(&mut OsRng);
    let signature = signing_key.sign(content_hash.as_bytes());
    let verifying_key = signing_key.verifying_key();

    Ok(SignedHandoff {
        payload_b64,
        content_hash,
        signature_b64: B64.encode(signature.to_bytes()),
        public_key_b64: B64.encode(verifying_key.to_bytes()),
    })
}

// ---------------------------------------------------------------------------
// Accept
// ---------------------------------------------------------------------------

/// Accept and verify a signed handoff, loading its contents into local stores.
///
/// # Arguments
/// * `session_store` — session store to load session state into.
/// * `fact_store` — fact store to load facts into.
/// * `signed` — the signed handoff to verify and accept.
/// * `_agent_name` — name of the receiving agent (reserved for future audit trail).
pub fn accept_handoff(
    session_store: &mut SessionStore,
    fact_store: &mut FactStore,
    signed: &SignedHandoff,
    _agent_name: &str,
) -> Result<AcceptResult, HandoffError> {
    // 1. Decode base64 payload.
    let payload_bytes = B64.decode(&signed.payload_b64)?;

    // 2. Verify BLAKE3 hash.
    let actual_hash = blake3::hash(&payload_bytes).to_hex().to_string();
    if actual_hash != signed.content_hash {
        return Err(HandoffError::HashMismatch {
            expected: signed.content_hash.clone(),
            actual: actual_hash,
        });
    }

    // 3. Verify Ed25519 signature.
    let pubkey_bytes = B64.decode(&signed.public_key_b64)?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| HandoffError::InvalidPublicKey("public key must be 32 bytes".to_string()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_array).map_err(|e| HandoffError::InvalidPublicKey(e.to_string()))?;

    let sig_bytes = B64.decode(&signed.signature_b64)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| HandoffError::SignatureInvalid("signature must be 64 bytes".to_string()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    verifying_key
        .verify(signed.content_hash.as_bytes(), &signature)
        .map_err(|e| HandoffError::SignatureInvalid(e.to_string()))?;

    // 4. Deserialize package.
    let package: HandoffPackage = serde_json::from_slice(&payload_bytes)?;

    // 5. Load session state.
    let session_loaded = if let Some(state) = package.session_state {
        session_store.put(&package.session_id, state, None);
        true
    } else {
        false
    };

    // 6. Load facts.
    let facts_loaded = package.facts.len();
    for fact in package.facts {
        fact_store.store(StoreFact {
            entity: fact.entity,
            key: fact.key,
            value: fact.value,
            source_receipt: fact.source_receipt,
            confidence: fact.confidence,
            private: false,
        });
    }

    Ok(AcceptResult {
        session_loaded,
        facts_loaded,
        verified: true,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use corecrux_memory::fact_store::StoreFact;
    use corecrux_memory::{FactStore, SessionStore};

    use super::*;

    fn seed_stores() -> (SessionStore, FactStore) {
        let mut sessions = SessionStore::new();
        sessions.put("sess_handoff", json!({"step": 3, "notes": "in progress"}), None);

        let mut facts = FactStore::new();
        facts.store(StoreFact {
            entity: "deploy".to_string(),
            key: "strategy".to_string(),
            value: "canary with evaluator".to_string(),
            source_receipt: Some("rcpt_001".to_string()),
            confidence: 0.95,
            private: false,
        });
        facts.store(StoreFact {
            entity: "testing".to_string(),
            key: "approach".to_string(),
            value: "integration tests".to_string(),
            source_receipt: None,
            confidence: 0.8,
            private: false,
        });

        (sessions, facts)
    }

    #[test]
    fn create_and_accept_roundtrip() {
        let (sessions, facts) = seed_stores();

        let signed = create_handoff(
            &sessions,
            &facts,
            "sess_handoff",
            true,
            "agent-alpha",
            Some("Handing off deployment task".to_string()),
        )
        .expect("create_handoff should succeed");

        assert!(!signed.payload_b64.is_empty());
        assert!(!signed.content_hash.is_empty());
        assert!(!signed.signature_b64.is_empty());
        assert!(!signed.public_key_b64.is_empty());

        // Accept into fresh stores.
        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();

        let result = accept_handoff(&mut recv_sessions, &mut recv_facts, &signed, "agent-beta")
            .expect("accept_handoff should succeed");

        assert!(result.session_loaded);
        assert_eq!(result.facts_loaded, 2);
        assert!(result.verified);

        // Verify session was loaded.
        let loaded = recv_sessions.get("sess_handoff").expect("session should exist");
        assert_eq!(loaded.state["step"], 3);

        // Verify facts were loaded.
        assert_eq!(recv_facts.count(), 2);
    }

    #[test]
    fn tampered_payload_rejected() {
        let (sessions, facts) = seed_stores();

        let mut signed = create_handoff(&sessions, &facts, "sess_handoff", true, "agent-alpha", None)
            .expect("create_handoff should succeed");

        // Tamper with the payload.
        signed.payload_b64 = B64.encode(b"tampered payload data");

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();

        let err = accept_handoff(&mut recv_sessions, &mut recv_facts, &signed, "agent-beta")
            .expect_err("should reject tampered payload");

        assert!(
            matches!(err, HandoffError::HashMismatch { .. }),
            "expected HashMismatch, got: {err}"
        );
    }

    #[test]
    fn wrong_signature_rejected() {
        let (sessions, facts) = seed_stores();

        let signed = create_handoff(&sessions, &facts, "sess_handoff", true, "agent-alpha", None)
            .expect("create_handoff should succeed");

        // Create a different keypair and re-sign the same hash.
        let other_key = SigningKey::generate(&mut OsRng);
        let wrong_sig = other_key.sign(signed.content_hash.as_bytes());

        let bad_signed = SignedHandoff {
            payload_b64: signed.payload_b64.clone(),
            content_hash: signed.content_hash.clone(),
            signature_b64: B64.encode(wrong_sig.to_bytes()),
            public_key_b64: signed.public_key_b64.clone(), // original key
        };

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();

        let err = accept_handoff(&mut recv_sessions, &mut recv_facts, &bad_signed, "agent-beta")
            .expect_err("should reject bad signature");

        assert!(
            matches!(err, HandoffError::SignatureInvalid(_)),
            "expected SignatureInvalid, got: {err}"
        );
    }

    #[test]
    fn handoff_without_facts() {
        let (sessions, facts) = seed_stores();

        let signed = create_handoff(
            &sessions,
            &facts,
            "sess_handoff",
            false, // no facts
            "agent-alpha",
            None,
        )
        .expect("create_handoff should succeed");

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();

        let result = accept_handoff(&mut recv_sessions, &mut recv_facts, &signed, "agent-beta")
            .expect("accept_handoff should succeed");

        assert!(result.session_loaded);
        assert_eq!(result.facts_loaded, 0);
        assert_eq!(recv_facts.count(), 0);
    }

    #[test]
    fn handoff_without_session() {
        let sessions = SessionStore::new(); // empty
        let facts = FactStore::new();

        let signed = create_handoff(&sessions, &facts, "no_such_session", false, "agent-alpha", None)
            .expect("create_handoff should succeed even without session");

        let mut recv_sessions = SessionStore::new();
        let mut recv_facts = FactStore::new();

        let result = accept_handoff(&mut recv_sessions, &mut recv_facts, &signed, "agent-beta")
            .expect("accept_handoff should succeed");

        assert!(!result.session_loaded);
        assert_eq!(result.facts_loaded, 0);
    }
}
