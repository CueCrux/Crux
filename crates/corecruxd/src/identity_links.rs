// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Identity-federation link storage + lookup (G4b, ExecPlan
//! `identity-memory-portability-2026-06-11` M5; spec:
//! `PlanCrux docs/master-plan/shared/Identity-Federation-v1.md`).
//!
//! Link records live in the **entity store** (kind `identity_link`) — not the
//! fact store: the entity version chain (`history(kind, id)`) is the
//! receipt-grade audit trail, every create/revoke is an actor-stamped
//! version, and entity records never ride the fact-sync path (born-local,
//! like `__session_binding__::` facts are born-private). Revocation is an
//! upsert that sets `revoked_at` — never a delete, so the trail survives.
//!
//! No third passport store (the known trap): links reference passports by
//! fingerprint; every passport lookup goes through the single
//! `crate::passports::get_passport` path.

use chrono::Utc;
use corecrux_memory::identity_link::{
    check_fingerprint, link_id_for_hash, statement_hash, verify_link_signature, IdentityLinkPayload, LinkStatement,
    LinkVerifyError, IDENTITY_LINK_KIND, IDENTITY_LINK_SCHEMA_V1, IDENTITY_LINK_SCOPE_MEMORY_READ,
};
use corecrux_memory::{EntityQuery, EntityStore, FactStore};

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("local passport '{0}' not found")]
    LocalPassportNotFound(String),
    #[error(transparent)]
    Verify(#[from] LinkVerifyError),
    #[error("link '{0}' not found")]
    LinkNotFound(String),
    #[error("link '{0}' already exists")]
    AlreadyExists(String),
    #[error("entity store error: {0}")]
    Store(String),
}

/// A create-link request: the operator-shuttled halves of the cross-signature
/// ceremony (Identity-Federation-v1 §3).
#[derive(Debug, Clone, serde::Deserialize, utoipa::ToSchema)]
pub struct CreateLinkRequest {
    /// Daemon-local passport record id (e.g. `personal-default`) granting
    /// memory.read.
    pub local_passport_id: String,
    /// Fingerprint of the remote passport being linked.
    pub remote_fpr: String,
    /// 64-hex ed25519 verifying key of the remote passport.
    pub remote_public_key_hex: String,
    /// Statement timestamp both sides signed (RFC 3339).
    pub created_at: String,
    /// 128-hex ed25519 signature by the LOCAL passport over the statement hash.
    pub sig_local: String,
    /// 128-hex ed25519 signature by the REMOTE passport over the statement hash.
    pub sig_remote: String,
}

/// Verify both signatures + fingerprints and store the link. Each check is a
/// hard reject before any write (T.3: an attacker without both private keys
/// cannot fabricate a link).
pub fn create_link(
    entities: &mut EntityStore,
    facts: &FactStore,
    req: &CreateLinkRequest,
    actor: &str,
) -> Result<(String, IdentityLinkPayload), LinkError> {
    let local = crate::passports::get_passport(facts, &req.local_passport_id)
        .ok_or_else(|| LinkError::LocalPassportNotFound(req.local_passport_id.clone()))?;
    let local_fpr = local.principal_id.clone();

    if local_fpr == req.remote_fpr {
        return Err(LinkVerifyError::SelfLink.into());
    }
    // Self-certification on the remote side (the local side's fpr↔pubkey
    // binding is already the passport record's invariant).
    check_fingerprint(&req.remote_fpr, &req.remote_public_key_hex)?;

    let statement = LinkStatement::memory_read(&local_fpr, &req.remote_fpr, &req.created_at);
    let hash = statement_hash(&statement);
    verify_link_signature(&local.public_key_hex, &hash, &req.sig_local, "local")?;
    verify_link_signature(&req.remote_public_key_hex, &hash, &req.sig_remote, "remote")?;

    let link_id = link_id_for_hash(&hash);
    if let Some(existing) = entities.get(IDENTITY_LINK_KIND, &link_id) {
        // Re-creating a revoked link requires a fresh statement (new
        // created_at → new id); an identical live link is a no-op error.
        if !existing.deleted {
            return Err(LinkError::AlreadyExists(link_id));
        }
    }

    let payload = IdentityLinkPayload {
        schema_version: IDENTITY_LINK_SCHEMA_V1.to_string(),
        local_passport_id: req.local_passport_id.clone(),
        local_fpr,
        remote_fpr: req.remote_fpr.clone(),
        remote_public_key_hex: req.remote_public_key_hex.clone(),
        subject_kind: "passport".to_string(),
        scope: IDENTITY_LINK_SCOPE_MEMORY_READ.to_string(),
        statement_hash: format!("blake3:{}", hex::encode(hash)),
        created_at: req.created_at.clone(),
        sig_local: req.sig_local.clone(),
        sig_remote: req.sig_remote.clone(),
        revoked_at: None,
    };
    let value = serde_json::to_value(&payload).map_err(|e| LinkError::Store(e.to_string()))?;
    entities
        .upsert(IDENTITY_LINK_KIND, &link_id, value, actor, None)
        .map_err(|e| LinkError::Store(e.to_string()))?;
    Ok((link_id, payload))
}

/// Revoke a link: upsert with `revoked_at` set. The version chain keeps the
/// live→revoked transition as the receipt (never a delete).
pub fn revoke_link(entities: &mut EntityStore, link_id: &str, actor: &str) -> Result<IdentityLinkPayload, LinkError> {
    let record = entities
        .get(IDENTITY_LINK_KIND, link_id)
        .ok_or_else(|| LinkError::LinkNotFound(link_id.to_string()))?;
    let mut payload: IdentityLinkPayload =
        serde_json::from_value(record.payload.clone()).map_err(|e| LinkError::Store(e.to_string()))?;
    if payload.revoked_at.is_none() {
        payload.revoked_at = Some(Utc::now().to_rfc3339());
        let value = serde_json::to_value(&payload).map_err(|e| LinkError::Store(e.to_string()))?;
        entities
            .upsert(IDENTITY_LINK_KIND, link_id, value, actor, None)
            .map_err(|e| LinkError::Store(e.to_string()))?;
    }
    Ok(payload)
}

/// All link records (live and revoked), as `(link_id, payload)` pairs.
pub fn list_links(entities: &EntityStore) -> Vec<(String, IdentityLinkPayload)> {
    entities
        .list(&EntityQuery {
            kind: Some(IDENTITY_LINK_KIND.to_string()),
            limit: None,
            include_deleted: false,
        })
        .into_iter()
        .filter_map(|record| {
            serde_json::from_value::<IdentityLinkPayload>(record.payload.clone())
                .ok()
                .map(|payload| (record.id.clone(), payload))
        })
        .collect()
}

/// Find the live (non-revoked) link granting `remote_fpr` memory.read. When
/// several match, the oldest statement wins (deterministic resolution; the
/// ambiguity is logged by the caller).
pub fn find_live_link_for_remote(entities: &EntityStore, remote_fpr: &str) -> Option<(String, IdentityLinkPayload)> {
    let mut candidates: Vec<(String, IdentityLinkPayload)> = list_links(entities)
        .into_iter()
        .filter(|(_, p)| p.revoked_at.is_none() && p.remote_fpr == remote_fpr)
        .collect();
    candidates.sort_by(|a, b| a.1.created_at.cmp(&b.1.created_at));
    candidates.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Seed the default passports and return a CreateLinkRequest signed by
    /// the real local key + a synthetic remote key.
    fn signed_request(dir: &std::path::Path, facts: &mut FactStore) -> CreateLinkRequest {
        crate::passports::seed_defaults_if_missing(dir, facts, 1).expect("seed");
        let local = crate::passports::get_passport(facts, "personal-default").expect("local passport");
        let local_key = crux_session::LocalPassportKey::from_path(&dir.join("passports").join("personal-default.key"))
            .expect("local key");
        assert_eq!(local_key.passport_fpr(), local.principal_id);

        let remote_key = SigningKey::from_bytes(&[42_u8; 32]);
        let remote_pub = remote_key.verifying_key().to_bytes();
        let remote_fpr = corecrux_memory::cruxpack::passport_fpr_from_public_key(&remote_pub);

        let created_at = "2026-06-12T00:00:00Z".to_string();
        let statement = LinkStatement::memory_read(&local.principal_id, &remote_fpr, &created_at);
        let hash = statement_hash(&statement);
        CreateLinkRequest {
            local_passport_id: "personal-default".to_string(),
            remote_fpr,
            remote_public_key_hex: hex::encode(remote_pub),
            created_at,
            sig_local: hex::encode(local_key.sign_hash(&hash)),
            sig_remote: hex::encode(remote_key.sign(&hash).to_bytes()),
        }
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        // nanos alone collides on VMs with coarse clocks (parallel tests
        // land in the same quantum and share a dir) — salt with pid + a counter.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "corecruxd-identity-links-{name}-{nanos}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn create_link_verifies_both_signatures_and_stores_versioned_record() {
        let dir = temp_dir("create");
        let mut facts = FactStore::new();
        let mut entities = EntityStore::new();
        let req = signed_request(&dir, &mut facts);

        let (link_id, payload) = create_link(&mut entities, &facts, &req, "operator").expect("create");
        assert!(link_id.starts_with("il_"));
        assert_eq!(payload.scope, "memory.read");
        assert!(payload.revoked_at.is_none());
        // Audit trail: version 1, actor-stamped.
        let record = entities.get(IDENTITY_LINK_KIND, &link_id).expect("stored");
        assert_eq!(record.version, 1);
        assert_eq!(record.actor, "operator");

        // Duplicate live link rejected.
        assert!(matches!(
            create_link(&mut entities, &facts, &req, "operator"),
            Err(LinkError::AlreadyExists(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_link_rejects_forged_signatures() {
        let dir = temp_dir("forged");
        let mut facts = FactStore::new();
        let mut entities = EntityStore::new();
        let good = signed_request(&dir, &mut facts);

        // Forged remote signature (signed by a different key).
        let mut forged = good.clone();
        let attacker = SigningKey::from_bytes(&[9_u8; 32]);
        let statement = LinkStatement::memory_read(
            &crate::passports::get_passport(&facts, "personal-default")
                .expect("p")
                .principal_id,
            &forged.remote_fpr,
            &forged.created_at,
        );
        forged.sig_remote = hex::encode(attacker.sign(&statement_hash(&statement)).to_bytes());
        assert!(matches!(
            create_link(&mut entities, &facts, &forged, "operator"),
            Err(LinkError::Verify(LinkVerifyError::BadSignature(_)))
        ));

        // Substituted remote pubkey breaks the fingerprint binding.
        let mut substituted = good.clone();
        substituted.remote_public_key_hex = hex::encode(attacker.verifying_key().to_bytes());
        assert!(matches!(
            create_link(&mut entities, &facts, &substituted, "operator"),
            Err(LinkError::Verify(LinkVerifyError::FingerprintMismatch { .. }))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoke_link_is_an_upsert_with_audit_trail() {
        let dir = temp_dir("revoke");
        let mut facts = FactStore::new();
        let mut entities = EntityStore::new();
        let req = signed_request(&dir, &mut facts);
        let (link_id, _) = create_link(&mut entities, &facts, &req, "operator").expect("create");

        let revoked = revoke_link(&mut entities, &link_id, "operator").expect("revoke");
        assert!(revoked.revoked_at.is_some());
        // Receipts: the version chain holds both states.
        let history = entities.history(IDENTITY_LINK_KIND, &link_id);
        assert_eq!(history.len(), 2);
        // Live lookup no longer finds it.
        assert!(find_live_link_for_remote(&entities, &req.remote_fpr).is_none());
        // Revoking again is idempotent (no third version).
        revoke_link(&mut entities, &link_id, "operator").expect("idempotent");
        assert_eq!(entities.history(IDENTITY_LINK_KIND, &link_id).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_live_link_matches_remote_fpr_only() {
        let dir = temp_dir("find");
        let mut facts = FactStore::new();
        let mut entities = EntityStore::new();
        let req = signed_request(&dir, &mut facts);
        let (link_id, _) = create_link(&mut entities, &facts, &req, "operator").expect("create");

        let (found_id, payload) = find_live_link_for_remote(&entities, &req.remote_fpr).expect("found");
        assert_eq!(found_id, link_id);
        assert_eq!(payload.local_passport_id, "personal-default");
        assert!(find_live_link_for_remote(&entities, "p_unlinked0000000000000000000000").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
