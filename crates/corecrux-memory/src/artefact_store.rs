// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Content-addressed artefact store (ExecPlan
//! `agent-ux-12-calm-deferred-output-2026-05-27`).
//!
//! Calm-deferred-output's free-tier surface needs a place to park large
//! tool outputs (audit bundles, attestation manifests, design docs) so the
//! chat surface only carries `{artefact_id, size_bytes, summary}` while the
//! actual payload lives in a deterministic, hash-keyed store.
//!
//! Design:
//!
//! - `artefact_id = "art_" + blake3(content).to_hex()`. Identical bytes → the
//!   same id, so two callers writing the same bundle (e.g. retry, parallel
//!   workers) coalesce to a single record without coordination.
//! - Owner is the *passport id* of the caller. `get_artefact()` for a different
//!   owner returns [`ArtefactError::Forbidden`] (QC.3 — cross-passport reads
//!   are 403, not "not found", so the operator can audit the attempt).
//! - TTL is `Some(seconds_from_creation)` or `None` for "no expiry". The
//!   default + cap are policy decisions enforced by the MCP tool surface, not
//!   the store. The store just stamps `expires_at` and lets the reaper / read
//!   path apply the rule.
//! - Reserved-prefix entries (mime_type starts with `__agent::`, `__ops::`,
//!   `__bootstrap__::`) are filtered out of [`ArtefactStore::list`] regardless
//!   of owner so a stray write under a reserved mime can never be surfaced
//!   through the consumer-shaped `artefact_list` tool (T.1).
//! - On-disk persistence is intentionally **not** added in this revision: the
//!   store is in-memory only. Spilling to disk would require companion-lane
//!   registration per the workspace 3-place wiring rule (storage allowlist +
//!   projection registry + load-at-startup) which is out of scope for the
//!   `agent-ux-12` ExecPlan. The plan's Decision Log records this trade-off.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Errors returned by the artefact store.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArtefactError {
    /// The requested artefact id does not exist or expired.
    #[error("artefact not found")]
    NotFound,
    /// The caller's passport does not match the artefact's owner.
    #[error("artefact owned by another passport")]
    Forbidden,
    /// Content was empty (caller forgot to base64-decode, etc).
    #[error("artefact content is empty")]
    EmptyContent,
}

/// One artefact record. The bytes are stored verbatim; the id is the BLAKE3
/// hex of the content with an `art_` prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtefactRecord {
    /// `art_<blake3_hex>` — deterministic for identical content.
    pub artefact_id: String,
    /// Passport id that wrote the artefact (QC.3 attribution).
    pub owner_passport: String,
    /// MIME type as provided by the writer (free-form).
    pub mime_type: String,
    /// Optional "which tool produced this" — surfaced in `artefact_list`.
    pub tool_origin: Option<String>,
    /// Bytes; opaque to the store.
    pub content: Vec<u8>,
    /// Size in bytes (always equal to `content.len()`; mirrored so the
    /// metadata projection can be cheap to assemble).
    pub size_bytes: usize,
    /// UTC create time.
    pub created_at: DateTime<Utc>,
    /// UTC expiry (None = never expires).
    pub expires_at: Option<DateTime<Utc>>,
}

impl ArtefactRecord {
    /// Lightweight metadata-only projection used by `artefact_list`.
    pub fn to_metadata(&self) -> ArtefactMetadata {
        ArtefactMetadata {
            artefact_id: self.artefact_id.clone(),
            owner_passport: self.owner_passport.clone(),
            mime_type: self.mime_type.clone(),
            tool_origin: self.tool_origin.clone(),
            size_bytes: self.size_bytes,
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

/// Metadata-only view of an artefact (no content). Used by list/scan tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtefactMetadata {
    pub artefact_id: String,
    pub owner_passport: String,
    pub mime_type: String,
    pub tool_origin: Option<String>,
    pub size_bytes: usize,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Reserved mime-type prefixes that MUST be filtered out of `list_artefacts`.
/// Mirrors the workspace convention used by `__agent::*`, `__ops::*`,
/// `__bootstrap__::*` entities in the fact store.
pub const RESERVED_MIME_PREFIXES: &[&str] = &["__agent::", "__ops::", "__bootstrap__::"];

/// Returns true if the given mime_type starts with a reserved prefix.
pub fn mime_is_reserved(mime_type: &str) -> bool {
    RESERVED_MIME_PREFIXES.iter().any(|p| mime_type.starts_with(p))
}

/// Compute the deterministic artefact id for a given content blob.
/// `art_<blake3_hex>`. Identical bytes → identical id.
pub fn artefact_id_for(content: &[u8]) -> String {
    let hash = blake3::hash(content);
    format!("art_{}", hash.to_hex())
}

/// In-memory artefact store.
#[derive(Debug, Default)]
pub struct ArtefactStore {
    artefacts: HashMap<String, ArtefactRecord>,
}

/// Request shape for `put_artefact`.
#[derive(Debug, Clone)]
pub struct PutArtefact {
    pub owner_passport: String,
    pub mime_type: String,
    pub tool_origin: Option<String>,
    pub content: Vec<u8>,
    /// Optional TTL in seconds; `None` means no expiry.
    pub ttl_seconds: Option<u64>,
}

impl ArtefactStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store an artefact. Returns the existing record if the content (by
    /// BLAKE3) is already present; in that case the original owner /
    /// created_at / expires_at are preserved (idempotent on content).
    pub fn put(&mut self, req: PutArtefact) -> Result<ArtefactRecord, ArtefactError> {
        if req.content.is_empty() {
            return Err(ArtefactError::EmptyContent);
        }
        let artefact_id = artefact_id_for(&req.content);

        // Idempotent: identical bytes always yield the same id; if we already
        // have it we return the existing record unchanged. This is the
        // BLAKE3-determinism promise the acceptance test pins.
        if let Some(existing) = self.artefacts.get(&artefact_id) {
            return Ok(existing.clone());
        }

        let now = Utc::now();
        let expires_at = req.ttl_seconds.map(|s| now + Duration::seconds(s as i64));
        let size_bytes = req.content.len();
        let record = ArtefactRecord {
            artefact_id: artefact_id.clone(),
            owner_passport: req.owner_passport,
            mime_type: req.mime_type,
            tool_origin: req.tool_origin,
            content: req.content,
            size_bytes,
            created_at: now,
            expires_at,
        };
        self.artefacts.insert(artefact_id, record.clone());
        Ok(record)
    }

    /// Fetch by id. Enforces:
    /// - existence + non-expiry → otherwise `NotFound`.
    /// - owner-passport match → otherwise `Forbidden` (NOT `NotFound`, so the
    ///   operator can audit cross-passport probing attempts; QC.3).
    pub fn get(&self, artefact_id: &str, caller_passport: &str) -> Result<ArtefactRecord, ArtefactError> {
        let record = self.artefacts.get(artefact_id).ok_or(ArtefactError::NotFound)?;
        if record.is_expired_at(Utc::now()) {
            return Err(ArtefactError::NotFound);
        }
        if record.owner_passport != caller_passport {
            return Err(ArtefactError::Forbidden);
        }
        Ok(record.clone())
    }

    /// List metadata for artefacts owned by `caller_passport`. Caps at `top_k`
    /// (newest-first). Expired entries are skipped. Reserved-prefix mime types
    /// are stripped.
    pub fn list(&self, caller_passport: &str, top_k: usize) -> Vec<ArtefactMetadata> {
        let now = Utc::now();
        let mut out: Vec<ArtefactMetadata> = self
            .artefacts
            .values()
            .filter(|r| r.owner_passport == caller_passport)
            .filter(|r| !r.is_expired_at(now))
            .filter(|r| !mime_is_reserved(&r.mime_type))
            .map(ArtefactRecord::to_metadata)
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        out.truncate(top_k);
        out
    }

    /// Reap expired entries. Returns the count purged. Called by the daemon's
    /// background reaper alongside `SessionStore::try_reap_expired`.
    pub fn reap_expired(&mut self) -> usize {
        let now = Utc::now();
        let to_drop: Vec<String> = self
            .artefacts
            .iter()
            .filter(|(_, r)| r.is_expired_at(now))
            .map(|(id, _)| id.clone())
            .collect();
        let count = to_drop.len();
        for id in to_drop {
            self.artefacts.remove(&id);
        }
        count
    }

    /// Number of stored artefacts (including expired-but-not-yet-reaped).
    pub fn count(&self) -> usize {
        self.artefacts.len()
    }

    /// Test-only: forcibly set `expires_at` on an existing record (used by
    /// the TTL expiry acceptance test in the MCP tool layer).
    #[doc(hidden)]
    pub fn set_expires_at_for_test(&mut self, artefact_id: &str, at: DateTime<Utc>) {
        if let Some(r) = self.artefacts.get_mut(artefact_id) {
            r.expires_at = Some(at);
        }
    }
}

impl ArtefactRecord {
    fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn req(owner: &str, mime: &str, content: &[u8]) -> PutArtefact {
        PutArtefact {
            owner_passport: owner.to_string(),
            mime_type: mime.to_string(),
            tool_origin: None,
            content: content.to_vec(),
            ttl_seconds: None,
        }
    }

    #[test]
    fn put_returns_deterministic_id_for_identical_bytes() {
        let mut store = ArtefactStore::new();
        let r1 = store.put(req("p_alice", "text/plain", b"hello")).unwrap();
        let r2 = store.put(req("p_alice", "text/plain", b"hello")).unwrap();
        assert_eq!(r1.artefact_id, r2.artefact_id);
        // BLAKE3 prefix:
        assert!(r1.artefact_id.starts_with("art_"));
        // Same content always coalesces to one record.
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn put_rejects_empty_content() {
        let mut store = ArtefactStore::new();
        let err = store.put(req("p_alice", "text/plain", b"")).unwrap_err();
        assert_eq!(err, ArtefactError::EmptyContent);
    }

    #[test]
    fn get_returns_original_bytes() {
        let mut store = ArtefactStore::new();
        let bytes = b"the bytes go here".to_vec();
        let put = store.put(req("p_alice", "application/octet-stream", &bytes)).unwrap();
        let got = store.get(&put.artefact_id, "p_alice").unwrap();
        assert_eq!(got.content, bytes);
        assert_eq!(got.size_bytes, bytes.len());
    }

    #[test]
    fn cross_passport_get_returns_forbidden_not_notfound() {
        let mut store = ArtefactStore::new();
        let r = store.put(req("p_alice", "text/plain", b"secret")).unwrap();
        let err = store.get(&r.artefact_id, "p_eve").unwrap_err();
        // Important: Forbidden, NOT NotFound — so cross-passport probing is auditable.
        assert_eq!(err, ArtefactError::Forbidden);
    }

    #[test]
    fn list_only_includes_callers_artefacts() {
        let mut store = ArtefactStore::new();
        store.put(req("p_alice", "text/plain", b"alpha")).unwrap();
        store.put(req("p_alice", "text/plain", b"beta")).unwrap();
        store.put(req("p_bob", "text/plain", b"charlie")).unwrap();
        let alice = store.list("p_alice", 20);
        let bob = store.list("p_bob", 20);
        assert_eq!(alice.len(), 2);
        assert_eq!(bob.len(), 1);
        assert!(alice.iter().all(|m| m.owner_passport == "p_alice"));
    }

    #[test]
    fn list_strips_reserved_mime_prefixes() {
        let mut store = ArtefactStore::new();
        // T.1 — reserved-prefix mime entries excluded from list.
        store.put(req("p_alice", "__agent::secret", b"x")).unwrap();
        store.put(req("p_alice", "__ops::config", b"y")).unwrap();
        store.put(req("p_alice", "__bootstrap__::pattern", b"z")).unwrap();
        store.put(req("p_alice", "text/plain", b"hello")).unwrap();
        let listed = store.list("p_alice", 20);
        assert_eq!(listed.len(), 1, "reserved-prefix mime entries must be filtered");
        assert_eq!(listed[0].mime_type, "text/plain");
    }

    #[test]
    fn list_caps_at_top_k_newest_first() {
        let mut store = ArtefactStore::new();
        for i in 0..5 {
            // distinct content → distinct ids
            store
                .put(req("p_alice", "text/plain", format!("blob-{i}").as_bytes()))
                .unwrap();
        }
        let listed = store.list("p_alice", 3);
        assert_eq!(listed.len(), 3);
        // newest first → strictly decreasing created_at
        for w in listed.windows(2) {
            assert!(w[0].created_at >= w[1].created_at);
        }
    }

    #[test]
    fn expired_artefact_is_not_readable_or_listed() {
        let mut store = ArtefactStore::new();
        let r = store
            .put(PutArtefact {
                owner_passport: "p_alice".to_string(),
                mime_type: "text/plain".to_string(),
                tool_origin: None,
                content: b"about to expire".to_vec(),
                ttl_seconds: Some(60),
            })
            .unwrap();
        // Force expiry into the past.
        store.set_expires_at_for_test(&r.artefact_id, Utc::now() - Duration::seconds(5));

        assert_eq!(
            store.get(&r.artefact_id, "p_alice").unwrap_err(),
            ArtefactError::NotFound
        );
        assert!(store.list("p_alice", 20).is_empty());

        let reaped = store.reap_expired();
        assert_eq!(reaped, 1);
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn put_with_no_ttl_never_expires() {
        let mut store = ArtefactStore::new();
        let r = store.put(req("p_alice", "text/plain", b"forever")).unwrap();
        assert!(r.expires_at.is_none());
        // reaper leaves untouched
        assert_eq!(store.reap_expired(), 0);
        assert!(store.get(&r.artefact_id, "p_alice").is_ok());
    }

    #[test]
    fn artefact_id_for_is_pure_function() {
        let id_a = artefact_id_for(b"abc");
        let id_b = artefact_id_for(b"abc");
        let id_c = artefact_id_for(b"abz");
        assert_eq!(id_a, id_b);
        assert_ne!(id_a, id_c);
        assert!(id_a.starts_with("art_"));
        // BLAKE3 hex length = 64 chars
        assert_eq!(id_a.len(), "art_".len() + 64);
    }

    #[test]
    fn mime_is_reserved_detects_all_prefixes() {
        assert!(mime_is_reserved("__agent::x"));
        assert!(mime_is_reserved("__ops::x"));
        assert!(mime_is_reserved("__bootstrap__::x"));
        assert!(!mime_is_reserved("text/plain"));
        assert!(!mime_is_reserved("application/json"));
    }
}
