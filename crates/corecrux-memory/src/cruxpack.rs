// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `.cruxpack` — memory portability transfer envelope (G5).
//!
//! A `.cruxpack` is a passport-signed, hash-anchored snapshot of one daemon's
//! exportable memory, carried by the operator to another daemon and imported
//! there. Spec: `PlanCrux docs/master-plan/shared/Memory-Portability-v1.md`
//! (ExecPlan `identity-memory-portability-2026-06-11`).
//!
//! Verification deliberately mirrors the Result Envelope idiom
//! (`Result-Envelope-Spec-v0_1.md`, Crux PR #188): blake3 content hash over
//! canonical JSON, ed25519 signature over the decoded 32-byte hash, typed
//! hard-reject errors before any write. The difference is who holds the
//! trusted key: a Result Envelope is signed by a *pinned platform key*, a
//! `.cruxpack` is signed by the exporting daemon's *own passport key* and is
//! self-certifying to a fingerprint (`passport_fpr == blake3(pubkey)[..16]`).
//! The shared hash/verify plumbing for both formats lives in
//! [`crate::signed_bundle`] (the unification follow-up tracked in the
//! ExecPlan once #188 merged first).
//!
//! Invariants (the two catastrophic-failure guards):
//!
//! 1. **Private facts never leave by default** — `private: true` facts and
//!    reserved born-private prefixes are excluded unless the operator
//!    explicitly opts in (typed confirmation at the CLI layer).
//! 2. **Erasure survives the round-trip** — soft-deleted (tombstoned) and
//!    compacted facts are excluded *unconditionally* (launch-gate 5.1 /
//!    GDPR Art. 17, same rule as `FactStore::export`'s sync path). There is
//!    no flag that exports deleted facts.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::fact_store::{Fact, FactStore, StoreFact};
use crate::session_store::{SessionState, SessionStore};

/// The only schema version accepted in v1.
pub const CRUXPACK_SCHEMA_V1: &str = "crux.cruxpack.v1";

/// Prefix used in `source_receipt` on imported facts to record pack
/// provenance: `cruxpack:blake3:<64-hex>`.
pub const CRUXPACK_SOURCE_RECEIPT_PREFIX: &str = "cruxpack:";

/// Reserved born-private entity prefixes excluded from every export unless
/// `include_private` is set.
///
/// This is a superset of `corecruxd::fact_privacy::DEFAULT_PRIVATE_PREFIXES`
/// (which flips these to `private: true` at ingest — the primary guard; this
/// list is the belt-and-braces re-check for facts written before that
/// enforcement existed) plus the CLI-side reserved prefixes from
/// `corecruxctl::memory`. A corecruxd test asserts the daemon's default
/// privacy policy stays a subset of this list, so a new born-private prefix
/// cannot silently become exportable.
pub const CRUXPACK_RESERVED_PREFIXES: &[&str] = &[
    // Auto-capture review-only candidates (M1) — must mirror the daemon
    // born-private prefix in fact_privacy::DEFAULT_PRIVATE_PREFIXES.
    "__candidate_fact__::",
    "__agent::",
    "__ops::",
    "__ops__::",
    "__ax__::",
    "__ax_session::",
    "__constraints__::",
    "__project_layer__::",
    "__plane__::",
    "__plane_layer__::",
    "__workspace__::",
    "__workspace_scan__::",
    "__storybook__::",
    "__dossier__::",
    "__project_repo_link__::",
    "__repo_registry__::",
    "__repo_scan__::",
    "__repo_codegraph_ids__::",
    "__repo_extdeps__::",
    "__extension__::",
    "__extension_grant__::",
    "__work__::",
    "__work_transition__::",
    "__workbench__::",
    "__workbench::",
    "__answer_replay_capsule__::",
    "__passport__::",
    "__session_binding__::",
    "__coord__::",
    "__incident__::",
    "__legal_hold__::",
    "__legal_hold_receipt__::",
    "__bootstrap__::",
    "__project__::",
    "__tenant_metadata__::",
    "__memory_pin::",
    "__decisions__::",
    "decisions::",
    "github::",
];

/// Returns the reserved prefix covering `entity`, if any.
pub fn reserved_prefix(entity: &str) -> Option<&'static str> {
    CRUXPACK_RESERVED_PREFIXES
        .iter()
        .find(|p| entity.starts_with(*p))
        .copied()
}

/// Derive the passport fingerprint from a raw 32-byte ed25519 public key:
/// `p_<hex of blake3(pubkey)[..16]>`. Mirrors
/// `crux_session::passport::passport_fpr_from_public_key` (kept in sync by
/// `fpr_derivation_matches_crux_session` below; corecrux-memory cannot depend
/// on crux-session without a cycle).
pub fn passport_fpr_from_public_key(public_key: &[u8; 32]) -> String {
    let digest = blake3::hash(public_key);
    format!("p_{}", hex::encode(&digest.as_bytes()[..16]))
}

// ─── Pack schema ───────────────────────────────────────────────────────────

/// Per-section record counts, embedded in the manifest so a human can audit
/// "what's in this pack" without parsing the sections.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct PackCounts {
    pub facts: usize,
    pub sessions: usize,
    pub entities: usize,
    pub receipts: usize,
}

/// The pack manifest: who exported, from which daemon, for which tenant,
/// at which journal head.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
pub struct PackManifest {
    /// `blake3(install_uuid)` hex — never the raw install UUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_install_fpr: Option<String>,
    /// The exporting daemon's passport fingerprint (`p_<32-hex>`).
    pub passport_fpr: String,
    /// 64-hex ed25519 verifying key — makes the pack self-certifying (§5).
    pub public_key_hex: String,
    /// The tenant this pack was exported for. Import rejects a mismatch (T.1).
    pub tenant_id: String,
    pub exported_at: String,
    /// The `--since` filter applied at export, if any (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Fact-journal head hash at export time, when available
    /// (`blake3:<64-hex>` over the journal bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_head: Option<String>,
    pub counts: PackCounts,
    /// True only when the operator explicitly opted private facts in.
    #[serde(default)]
    pub included_private: bool,
    /// Exporting tool + version, e.g. `corecruxctl 0.3.1`.
    pub tool: String,
}

/// The pack payload. `entities` and `receipts` are schema-reserved: v1
/// exporters always write `[]` (entity records include born-local kinds like
/// `identity_link` and `candidate_link` that must not travel; a receipts chain
/// slice needs the CROWN slice API — both explicit follow-ups in the spec).
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PackSections {
    pub facts: Vec<Fact>,
    #[serde(default)]
    pub sessions: Vec<SessionState>,
    #[serde(default)]
    pub entities: Vec<serde_json::Value>,
    #[serde(default)]
    pub receipts: Vec<serde_json::Value>,
}

/// The exporting passport's ed25519 signature over the decoded 32-byte
/// content hash — the same hash-then-sign pattern as CROWN wipe receipts and
/// the Result Envelope platform signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct PackSignature {
    /// Always `ed25519` in v1.
    pub alg: String,
    /// Must equal `manifest.passport_fpr`.
    pub passport_fpr: String,
    /// 128-hex (64-byte) ed25519 signature.
    pub signature: String,
}

/// The full `.cruxpack` document (`crux.cruxpack.v1`).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CruxPack {
    pub schema_version: String,
    pub manifest: PackManifest,
    pub sections: PackSections,
    /// `blake3:<64-hex>` over the canonical JSON of `manifest` + `sections`.
    pub blake3_content_hash: String,
    pub passport_signature: PackSignature,
}

impl CruxPack {
    /// The provenance stamp imported facts carry in `source_receipt`.
    pub fn source_receipt(&self) -> String {
        format!("{CRUXPACK_SOURCE_RECEIPT_PREFIX}{}", self.blake3_content_hash)
    }
}

/// Compute the canonical content hash over `manifest` + `sections`, returned
/// as `blake3:<64-hex>`. Same idiom as `result_envelope_content_hash`
/// (PR #188) via the shared [`crate::signed_bundle`] helper: stable serde
/// JSON serialization in fixed field order, then blake3.
pub fn cruxpack_content_hash(manifest: &PackManifest, sections: &PackSections) -> Result<String, serde_json::Error> {
    crate::signed_bundle::content_hash_json(&serde_json::json!({
        "manifest": manifest,
        "sections": sections,
    }))
}

// ─── Export ────────────────────────────────────────────────────────────────

/// Options controlling what enters a pack.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Tenant identity recorded in the manifest (import gate, T.1).
    pub tenant_id: String,
    /// Only facts stored at/after this instant.
    pub since: Option<DateTime<Utc>>,
    /// Include `private: true` facts and reserved-prefix entities. The CLI
    /// layer owns the typed-confirmation ceremony; this flag is the result.
    pub include_private: bool,
    /// Include the sessions section (session ids starting `__` are always
    /// excluded).
    pub include_sessions: bool,
    pub tool: String,
    pub daemon_install_fpr: Option<String>,
    pub chain_head: Option<String>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            tenant_id: "local".to_string(),
            since: None,
            include_private: false,
            include_sessions: true,
            tool: format!("corecrux-memory {}", env!("CARGO_PKG_VERSION")),
            daemon_install_fpr: None,
            chain_head: None,
        }
    }
}

/// What was *excluded* from (or, under `include_private`, opted into) a pack
/// — the CLI prints this before asking for typed confirmation.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PrivateSummary {
    /// Facts excluded (or opted in) because `private == true`.
    pub private_flagged: usize,
    /// Facts under a reserved born-private prefix, by prefix.
    pub by_reserved_prefix: BTreeMap<String, usize>,
    /// Facts excluded because they are deleted — NEVER exportable.
    pub deleted_excluded: usize,
}

/// Scan the store and report what the private gate would hold back.
pub fn private_summary(store: &FactStore) -> PrivateSummary {
    let mut summary = PrivateSummary::default();
    for fact in store.all_facts() {
        if fact.deleted {
            summary.deleted_excluded += 1;
            continue;
        }
        if let Some(prefix) = reserved_prefix(&fact.entity) {
            *summary.by_reserved_prefix.entry(prefix.to_string()).or_default() += 1;
        } else if fact.private {
            summary.private_flagged += 1;
        }
    }
    summary
}

/// Build the pack payload from live stores.
///
/// Exclusion rules per fact (Memory-Portability-v1 §3):
/// 1. `deleted == true` → excluded **unconditionally** (erasure, Art. 17 —
///    aligned with `FactStore::export`'s `!f.deleted` sync filter, PR #187).
/// 2. `private == true` → excluded unless `include_private`.
/// 3. reserved prefix → excluded unless `include_private` (belt-and-braces
///    with 2 — see [`CRUXPACK_RESERVED_PREFIXES`]).
/// 4. `stored_at < since` → excluded when a since-filter is given.
///
/// Output ordering is deterministic — facts sorted by
/// `(entity, key, version, fact_id)`, sessions by `session_id` — so two
/// exports of the same store produce byte-identical sections.
pub fn build_pack_sections(
    store: &FactStore,
    sessions: Option<&SessionStore>,
    opts: &ExportOptions,
) -> (PackSections, PrivateSummary) {
    let mut summary = PrivateSummary::default();
    let mut facts: Vec<Fact> = Vec::new();
    for fact in store.all_facts() {
        if fact.deleted {
            // Rule 1 — no flag overrides this.
            summary.deleted_excluded += 1;
            continue;
        }
        let reserved = reserved_prefix(&fact.entity);
        if let Some(prefix) = reserved {
            *summary.by_reserved_prefix.entry(prefix.to_string()).or_default() += 1;
        } else if fact.private {
            summary.private_flagged += 1;
        }
        if (fact.private || reserved.is_some()) && !opts.include_private {
            continue;
        }
        if let Some(since) = opts.since {
            if fact.stored_at < since {
                continue;
            }
        }
        facts.push(fact.clone());
    }
    facts.sort_by(|a, b| (&a.entity, &a.key, a.version, &a.fact_id).cmp(&(&b.entity, &b.key, b.version, &b.fact_id)));

    let mut session_states: Vec<SessionState> = Vec::new();
    if opts.include_sessions {
        if let Some(store) = sessions {
            let mut ids: Vec<String> = store
                .list()
                .into_iter()
                .filter(|id| !id.starts_with("__"))
                .map(str::to_string)
                .collect();
            ids.sort();
            for id in ids {
                if let Some(state) = store.get(&id) {
                    session_states.push(state.clone());
                }
            }
        }
    }

    (
        PackSections {
            facts,
            sessions: session_states,
            entities: Vec::new(),
            receipts: Vec::new(),
        },
        summary,
    )
}

/// Assemble the manifest for a built payload.
pub fn build_manifest(
    sections: &PackSections,
    passport_fpr: &str,
    public_key_hex: &str,
    opts: &ExportOptions,
) -> PackManifest {
    PackManifest {
        daemon_install_fpr: opts.daemon_install_fpr.clone(),
        passport_fpr: passport_fpr.to_string(),
        public_key_hex: public_key_hex.to_string(),
        tenant_id: opts.tenant_id.clone(),
        exported_at: Utc::now().to_rfc3339(),
        since: opts.since.map(|t| t.to_rfc3339()),
        chain_head: opts.chain_head.clone(),
        counts: PackCounts {
            facts: sections.facts.len(),
            sessions: sections.sessions.len(),
            entities: sections.entities.len(),
            receipts: sections.receipts.len(),
        },
        included_private: opts.include_private,
        tool: opts.tool.clone(),
    }
}

/// Hash the payload and sign with the exporting passport's key. The signer is
/// passed as a closure (`LocalPassportKey::sign_hash` at the CLI layer) so
/// this crate never touches private key material.
pub fn sign_pack(
    manifest: PackManifest,
    sections: PackSections,
    sign: impl FnOnce(&[u8; 32]) -> [u8; 64],
) -> Result<CruxPack, PackVerifyError> {
    let content_hash = cruxpack_content_hash(&manifest, &sections)
        .map_err(|err| PackVerifyError::ContentSerialization(err.to_string()))?;
    let hash = decode_content_hash(&content_hash)?;
    let signature = sign(&hash);
    let passport_fpr = manifest.passport_fpr.clone();
    Ok(CruxPack {
        schema_version: CRUXPACK_SCHEMA_V1.to_string(),
        manifest,
        sections,
        blake3_content_hash: content_hash,
        passport_signature: PackSignature {
            alg: "ed25519".to_string(),
            passport_fpr,
            signature: hex::encode(signature),
        },
    })
}

// ─── Verification ──────────────────────────────────────────────────────────

/// Typed verification failures — each is a hard reject before any write,
/// mirroring `EnvelopeVerifyError` (PR #188).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PackVerifyError {
    #[error("unsupported schema_version: {0}")]
    UnsupportedSchema(String),
    #[error("content serialization failed: {0}")]
    ContentSerialization(String),
    #[error("recomputed content hash {recomputed} != stated {stated}")]
    HashMismatch { stated: String, recomputed: String },
    #[error("malformed content hash: {0}")]
    MalformedHash(String),
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
    #[error("malformed public key: {0}")]
    MalformedPubkey(String),
    #[error("manifest passport_fpr {stated} does not match key-derived fingerprint {derived}")]
    FingerprintMismatch { stated: String, derived: String },
    #[error("signature passport_fpr {signature_fpr} does not match manifest passport_fpr {manifest_fpr}")]
    SignerMismatch {
        signature_fpr: String,
        manifest_fpr: String,
    },
    #[error("signature verification failed for passport {0}")]
    BadSignature(String),
    #[error("manifest counts do not match sections ({0})")]
    CountsMismatch(String),
    #[error("pack contains private facts but manifest.included_private is false")]
    PrivateInconsistent,
    #[error("pack contains deleted facts — erased data must never travel in a pack")]
    DeletedFactsPresent,
    #[error("pack was exported for tenant '{pack_tenant}' but import targets tenant '{import_tenant}' (T.1)")]
    TenantMismatch { pack_tenant: String, import_tenant: String },
}

fn decode_content_hash(stated: &str) -> Result<[u8; 32], PackVerifyError> {
    crate::signed_bundle::decode_content_hash(stated).map_err(PackVerifyError::MalformedHash)
}

/// Verify a pack's integrity and signature. Steps, each a hard reject:
///
/// 1. `schema_version` must equal [`CRUXPACK_SCHEMA_V1`].
/// 2. Manifest counts must match the section lengths.
/// 3. No `deleted` fact may be present (erasure non-resurrection).
/// 4. Private facts present require `manifest.included_private` (an
///    inconsistent pack is a tampered pack).
/// 5. Recompute + compare the blake3 content hash.
/// 6. Self-certification: `manifest.passport_fpr` must equal
///    `blake3(public_key)[..16]` of the embedded key, and the signature's
///    `passport_fpr` must match the manifest's.
/// 7. Verify the ed25519 signature over the decoded 32-byte hash.
///
/// On success returns the 32-byte content hash (useful for the import
/// receipt). No network access, no PKI: the pack is self-certifying to a
/// fingerprint; whether to *trust* that fingerprint is the caller's decision
/// (identity federation or operator confirmation).
pub fn verify_pack(pack: &CruxPack) -> Result<[u8; 32], PackVerifyError> {
    use crate::signed_bundle;

    // 1) Schema gate.
    if pack.schema_version != CRUXPACK_SCHEMA_V1 {
        return Err(PackVerifyError::UnsupportedSchema(pack.schema_version.clone()));
    }

    // 2) Counts integrity.
    let counts = &pack.manifest.counts;
    let actual = PackCounts {
        facts: pack.sections.facts.len(),
        sessions: pack.sections.sessions.len(),
        entities: pack.sections.entities.len(),
        receipts: pack.sections.receipts.len(),
    };
    if *counts != actual {
        return Err(PackVerifyError::CountsMismatch(format!(
            "manifest {counts:?} vs sections {actual:?}"
        )));
    }

    // 3) Erasure non-resurrection.
    if pack.sections.facts.iter().any(|f| f.deleted) {
        return Err(PackVerifyError::DeletedFactsPresent);
    }

    // 4) Private consistency.
    if !pack.manifest.included_private
        && pack
            .sections
            .facts
            .iter()
            .any(|f| f.private || reserved_prefix(&f.entity).is_some())
    {
        return Err(PackVerifyError::PrivateInconsistent);
    }

    // 5) Recompute + compare content hash.
    let recomputed = cruxpack_content_hash(&pack.manifest, &pack.sections)
        .map_err(|err| PackVerifyError::ContentSerialization(err.to_string()))?;
    if recomputed != pack.blake3_content_hash {
        return Err(PackVerifyError::HashMismatch {
            stated: pack.blake3_content_hash.clone(),
            recomputed,
        });
    }
    let hash = decode_content_hash(&pack.blake3_content_hash)?;

    // 6) Self-certification.
    let pubkey_arr =
        signed_bundle::decode_public_key(&pack.manifest.public_key_hex).map_err(PackVerifyError::MalformedPubkey)?;
    let derived_fpr = passport_fpr_from_public_key(&pubkey_arr);
    if derived_fpr != pack.manifest.passport_fpr {
        return Err(PackVerifyError::FingerprintMismatch {
            stated: pack.manifest.passport_fpr.clone(),
            derived: derived_fpr,
        });
    }
    if pack.passport_signature.passport_fpr != pack.manifest.passport_fpr {
        return Err(PackVerifyError::SignerMismatch {
            signature_fpr: pack.passport_signature.passport_fpr.clone(),
            manifest_fpr: pack.manifest.passport_fpr.clone(),
        });
    }
    if pack.passport_signature.alg != "ed25519" {
        return Err(PackVerifyError::MalformedSignature(format!(
            "unsupported alg: {}",
            pack.passport_signature.alg
        )));
    }

    // 7) Verify the ed25519 signature over the 32-byte hash.
    let verifying_key = signed_bundle::parse_verifying_key(&pubkey_arr).map_err(PackVerifyError::MalformedPubkey)?;
    let sig_arr = signed_bundle::decode_signature(&pack.passport_signature.signature)
        .map_err(PackVerifyError::MalformedSignature)?;
    if !signed_bundle::verify_signature_over_hash(&verifying_key, &hash, &sig_arr) {
        return Err(PackVerifyError::BadSignature(pack.manifest.passport_fpr.clone()));
    }

    Ok(hash)
}

// ─── Import ────────────────────────────────────────────────────────────────

/// Options controlling how a verified pack is applied.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// The tenant the caller is importing into. Must equal
    /// `manifest.tenant_id` — there is no override in v1 (T.1).
    pub tenant_id: String,
    /// Principal remap table (CE↔Core remap pattern): fact `actor` values
    /// matching a key are rewritten to the mapped value. Unmapped actors are
    /// preserved verbatim — pack provenance in `source_receipt` keeps
    /// attribution honest either way.
    pub principal_map: BTreeMap<String, String>,
}

/// The computed import plan — what would be written, what collides, what is
/// skipped. Imports never overwrite: a colliding `(entity, key)` lands as a
/// new version and the shipped supersession machinery (PR #140) links the
/// chain; `memory_sweep_candidates` surfaces the pairs for review.
#[derive(Debug, Default)]
pub struct ImportPlan {
    /// Facts to write through the normal substrate path (`try_store_bulk`).
    pub to_store: Vec<StoreFact>,
    /// How many of `to_store` collide with an existing live `(entity, key)`
    /// — these will supersede the local version (reviewable, reversible).
    pub collisions: usize,
    /// Facts skipped because this exact pack already imported them
    /// (matching `source_receipt` + entity/key/value).
    pub skipped_duplicates: usize,
    /// How many of `to_store` are `private: true` (only possible when the
    /// pack was exported with `include_private`).
    pub private_facts: usize,
    /// Sessions to add (only sessions absent locally — never overwrite).
    pub sessions_to_add: Vec<SessionState>,
    /// Sessions skipped because a local session with that id exists.
    pub sessions_skipped: usize,
}

/// Verify `pack`, apply the tenant gate, and compute the import plan against
/// the live stores. Read-only — the caller applies `plan.to_store` via
/// `FactStore::try_store_bulk` (the journaled, receipted bulk path; never a
/// raw filesystem write, T.4).
pub fn plan_import(
    pack: &CruxPack,
    store: &FactStore,
    sessions: Option<&SessionStore>,
    opts: &ImportOptions,
) -> Result<ImportPlan, PackVerifyError> {
    verify_pack(pack)?;

    if pack.manifest.tenant_id != opts.tenant_id {
        return Err(PackVerifyError::TenantMismatch {
            pack_tenant: pack.manifest.tenant_id.clone(),
            import_tenant: opts.tenant_id.clone(),
        });
    }

    let pack_ref = pack.source_receipt();

    // Facts this exact pack already delivered (idempotent re-import).
    let already_imported: BTreeSet<(String, String, String)> = store
        .all_facts()
        .filter(|f| !f.deleted && f.source_receipt.as_deref() == Some(pack_ref.as_str()))
        .map(|f| (f.entity.clone(), f.key.clone(), f.value.clone()))
        .collect();

    let mut plan = ImportPlan::default();
    for fact in &pack.sections.facts {
        if fact.deleted {
            // verify_pack already rejects these; defence in depth.
            continue;
        }
        if already_imported.contains(&(fact.entity.clone(), fact.key.clone(), fact.value.clone())) {
            plan.skipped_duplicates += 1;
            continue;
        }
        let collides = store.fact_history(&fact.entity, &fact.key).iter().any(|f| !f.deleted);
        if collides {
            plan.collisions += 1;
        }
        if fact.private {
            plan.private_facts += 1;
        }
        let actor = fact
            .actor
            .as_ref()
            .map(|a| opts.principal_map.get(a).cloned().unwrap_or_else(|| a.clone()));
        plan.to_store.push(StoreFact {
            tenant_hash: fact.tenant_hash.clone(),
            entity: fact.entity.clone(),
            key: fact.key.clone(),
            value: fact.value.clone(),
            // Pack provenance replaces the original receipt ref — the
            // original stays auditable inside the pack file itself.
            source_receipt: Some(pack_ref.clone()),
            confidence: fact.confidence,
            private: fact.private,
            horizon_class: Some(fact.horizon_class),
            actor,
        });
    }

    if let Some(local) = sessions {
        for state in &pack.sections.sessions {
            if local.get(&state.session_id).is_some() {
                plan.sessions_skipped += 1;
            } else {
                plan.sessions_to_add.push(state.clone());
            }
        }
    }

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    fn signer_identity(key: &SigningKey) -> (String, String) {
        let public = key.verifying_key().to_bytes();
        (passport_fpr_from_public_key(&public), hex::encode(public))
    }

    fn opts(tenant: &str) -> ExportOptions {
        ExportOptions {
            tenant_id: tenant.to_string(),
            ..ExportOptions::default()
        }
    }

    fn store_with(facts: Vec<StoreFact>) -> FactStore {
        let mut store = FactStore::new();
        for f in facts {
            store.store(f);
        }
        store
    }

    fn sf(entity: &str, key: &str, value: &str, private: bool) -> StoreFact {
        StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.into(),
            key: key.into(),
            value: value.into(),
            source_receipt: None,
            confidence: 1.0,
            private,
            horizon_class: None,
            actor: Some("agent:test".into()),
        }
    }

    fn build_signed(store: &FactStore, sessions: Option<&SessionStore>, opts: &ExportOptions) -> CruxPack {
        let key = signing_key();
        let (fpr, pub_hex) = signer_identity(&key);
        let (sections, _summary) = build_pack_sections(store, sessions, opts);
        let manifest = build_manifest(&sections, &fpr, &pub_hex, opts);
        sign_pack(manifest, sections, |hash| key.sign(hash).to_bytes()).expect("sign")
    }

    // ── The critical test: private facts never leave by default ─────────

    #[test]
    fn export_excludes_private_and_reserved_by_default() {
        let store = store_with(vec![
            sf("project-alpha", "status", "shipping", false),
            sf("my-agent", "internal_state", "secret-private-value", true),
            sf("__passport__::work-default", "record", "secret-passport-record", false),
            sf("__session_binding__::deadbeef", "record", "secret-binding", false),
            sf("__bootstrap__::patterns", "p1", "secret-bootstrap", false),
            sf("__agent::claude", "scratch", "secret-agent-scratch", true),
        ]);
        let (sections, summary) = build_pack_sections(&store, None, &opts("local"));

        assert_eq!(sections.facts.len(), 1, "only the public fact may leave");
        assert_eq!(sections.facts[0].entity, "project-alpha");
        assert_eq!(summary.private_flagged, 1);
        assert_eq!(summary.by_reserved_prefix.len(), 4);

        // Belt-and-braces: no excluded value may appear anywhere in the
        // serialized pack bytes.
        let serialised = serde_json::to_string(&sections).expect("json");
        for leaked in [
            "secret-private-value",
            "secret-passport-record",
            "secret-binding",
            "secret-bootstrap",
            "secret-agent-scratch",
        ] {
            assert!(!serialised.contains(leaked), "{leaked} leaked into the pack");
        }
    }

    #[test]
    fn reserved_prefix_excluded_even_when_private_flag_false() {
        // A reserved-prefix fact written before fact_privacy enforcement
        // existed (private == false) must still be held back.
        let store = store_with(vec![
            sf("__ops::deploy", "state", "pre-enforcement-secret", false),
            sf("__incident__::inc_1", "case", "private-incident", false),
        ]);
        let (sections, _) = build_pack_sections(&store, None, &opts("local"));
        assert!(sections.facts.is_empty());
    }

    #[test]
    fn include_private_opts_everything_in_and_is_stamped() {
        let store = store_with(vec![
            sf("public", "k", "v", false),
            sf("secret-entity", "k", "v-private", true),
        ]);
        let mut o = opts("local");
        o.include_private = true;
        let pack = build_signed(&store, None, &o);
        assert_eq!(pack.sections.facts.len(), 2);
        assert!(pack.manifest.included_private);
        verify_pack(&pack).expect("verifies");
    }

    // ── Erasure survives the round-trip ──────────────────────────────────

    #[test]
    fn export_excludes_deleted_facts_unconditionally() {
        let mut store = FactStore::new();
        let kept = store.store(sf("keep", "k", "kept-value", false));
        let erased = store.store(sf("erase", "k", "erased-pii-value", false));
        store.delete(&erased.fact_id);

        // Even with include_private (the widest export), deleted stays home.
        let mut o = opts("local");
        o.include_private = true;
        let (sections, summary) = build_pack_sections(&store, None, &o);

        assert_eq!(sections.facts.len(), 1);
        assert_eq!(sections.facts[0].fact_id, kept.fact_id);
        assert_eq!(summary.deleted_excluded, 1);
        let serialised = serde_json::to_string(&sections).expect("json");
        assert!(
            !serialised.contains("erased-pii-value"),
            "deleted fact value leaked into the pack"
        );
    }

    #[test]
    fn verify_rejects_pack_carrying_deleted_facts() {
        let store = store_with(vec![sf("e", "k", "v", false)]);
        let mut pack = build_signed(&store, None, &opts("local"));
        pack.sections.facts[0].deleted = true;
        // Re-sign so only the deleted flag is "wrong" — still rejected.
        let key = signing_key();
        let (fpr, pub_hex) = signer_identity(&key);
        let mut manifest = pack.manifest.clone();
        manifest.passport_fpr = fpr;
        manifest.public_key_hex = pub_hex;
        let resigned = sign_pack(manifest, pack.sections.clone(), |h| key.sign(h).to_bytes()).expect("sign");
        assert_eq!(verify_pack(&resigned), Err(PackVerifyError::DeletedFactsPresent));
    }

    // ── Signature / tamper rejection ──────────────────────────────────────

    #[test]
    fn valid_pack_verifies() {
        let store = store_with(vec![sf("e", "k", "v", false)]);
        let pack = build_signed(&store, None, &opts("local"));
        let hash = verify_pack(&pack).expect("verify");
        assert_eq!(format!("blake3:{}", hex::encode(hash)), pack.blake3_content_hash);
    }

    #[test]
    fn tampered_fact_value_rejected() {
        let store = store_with(vec![sf("e", "k", "honest-value", false)]);
        let mut pack = build_signed(&store, None, &opts("local"));
        pack.sections.facts[0].value = "tampered-value".into();
        assert!(matches!(verify_pack(&pack), Err(PackVerifyError::HashMismatch { .. })));
    }

    #[test]
    fn tampered_manifest_tenant_rejected() {
        let store = store_with(vec![sf("e", "k", "v", false)]);
        let mut pack = build_signed(&store, None, &opts("tenant-a"));
        pack.manifest.tenant_id = "tenant-b".into();
        assert!(matches!(verify_pack(&pack), Err(PackVerifyError::HashMismatch { .. })));
    }

    #[test]
    fn resigned_by_attacker_key_rejected_via_fingerprint() {
        let store = store_with(vec![sf("e", "k", "v", false)]);
        let pack = build_signed(&store, None, &opts("local"));

        // Attacker re-signs the same payload with their own key but keeps
        // the victim's manifest identity → signature check fails. If they
        // also swap the pubkey, the hash changes; if they re-hash+re-sign
        // fully, the fingerprint no longer matches the victim's.
        let attacker = SigningKey::from_bytes(&[9_u8; 32]);
        let mut forged = pack.clone();
        let hash = decode_content_hash(&forged.blake3_content_hash).unwrap();
        forged.passport_signature.signature = hex::encode(attacker.sign(&hash).to_bytes());
        assert!(matches!(verify_pack(&forged), Err(PackVerifyError::BadSignature(_))));

        // Full re-sign under the attacker identity: self-consistent, but the
        // fingerprint is now the attacker's — the operator-visible identity
        // changed, which is exactly what self-certification guarantees.
        let (a_fpr, a_pub) = signer_identity(&attacker);
        let mut manifest = pack.manifest.clone();
        manifest.passport_fpr = a_fpr.clone();
        manifest.public_key_hex = a_pub;
        let refull = sign_pack(manifest, pack.sections.clone(), |h| attacker.sign(h).to_bytes()).expect("sign");
        verify_pack(&refull).expect("self-consistent");
        assert_ne!(refull.manifest.passport_fpr, pack.manifest.passport_fpr);
    }

    #[test]
    fn fingerprint_pubkey_mismatch_rejected() {
        let store = store_with(vec![sf("e", "k", "v", false)]);
        let key = signing_key();
        let (sections, _) = build_pack_sections(&store, None, &opts("local"));
        let (_, pub_hex) = signer_identity(&key);
        let manifest = build_manifest(
            &sections,
            "p_0000000000000000000000000000dead",
            &pub_hex,
            &opts("local"),
        );
        let pack = sign_pack(manifest, sections, |h| key.sign(h).to_bytes()).expect("sign");
        assert!(matches!(
            verify_pack(&pack),
            Err(PackVerifyError::FingerprintMismatch { .. })
        ));
    }

    #[test]
    fn wrong_schema_rejected() {
        let store = store_with(vec![sf("e", "k", "v", false)]);
        let mut pack = build_signed(&store, None, &opts("local"));
        pack.schema_version = "crux.cruxpack.v999".into();
        assert!(matches!(verify_pack(&pack), Err(PackVerifyError::UnsupportedSchema(_))));
    }

    #[test]
    fn counts_mismatch_rejected() {
        let store = store_with(vec![sf("e", "k", "v", false)]);
        let mut pack = build_signed(&store, None, &opts("local"));
        pack.manifest.counts.facts = 99;
        assert!(matches!(verify_pack(&pack), Err(PackVerifyError::CountsMismatch(_))));
    }

    #[test]
    fn private_facts_without_manifest_stamp_rejected() {
        let store = store_with(vec![sf("e", "k", "v", true)]);
        let mut o = opts("local");
        o.include_private = true;
        let mut pack = build_signed(&store, None, &o);
        pack.manifest.included_private = false; // forge the stamp off
        assert!(matches!(
            verify_pack(&pack),
            Err(PackVerifyError::PrivateInconsistent | PackVerifyError::HashMismatch { .. })
        ));
    }

    // ── Import planning ───────────────────────────────────────────────────

    #[test]
    fn cross_tenant_pack_rejected() {
        let store = store_with(vec![sf("e", "k", "v", false)]);
        let pack = build_signed(&store, None, &opts("tenant-a"));
        let target = FactStore::new();
        let err = plan_import(
            &pack,
            &target,
            None,
            &ImportOptions {
                tenant_id: "tenant-b".into(),
                ..ImportOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, PackVerifyError::TenantMismatch { .. }));
    }

    #[test]
    fn import_never_overwrites_collisions_supersede() {
        let source = store_with(vec![sf("shared", "k", "incoming-value", false)]);
        let pack = build_signed(&source, None, &opts("local"));

        let mut target = store_with(vec![sf("shared", "k", "local-value", false)]);
        let plan = plan_import(
            &pack,
            &target,
            None,
            &ImportOptions {
                tenant_id: "local".into(),
                ..ImportOptions::default()
            },
        )
        .expect("plan");
        assert_eq!(plan.collisions, 1);
        assert_eq!(plan.to_store.len(), 1);

        let stored = target.try_store_bulk(plan.to_store).expect("store");
        // The shipped supersession machinery linked the chain — the local
        // value is retired (reviewable), never destroyed.
        assert_eq!(stored[0].version, 2);
        assert!(stored[0].supersedes.is_some());
        let history = target.fact_history("shared", "k");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].value, "local-value"); // still present
        assert_eq!(history[0].superseded_by.as_deref(), Some(stored[0].fact_id.as_str()));
    }

    #[test]
    fn import_remaps_principals_and_stamps_provenance() {
        let source = store_with(vec![sf("e", "k", "v", false)]);
        let pack = build_signed(&source, None, &opts("local"));
        let target = FactStore::new();
        let mut map = BTreeMap::new();
        map.insert("agent:test".to_string(), "tenant:work:myles".to_string());
        let plan = plan_import(
            &pack,
            &target,
            None,
            &ImportOptions {
                tenant_id: "local".into(),
                principal_map: map,
            },
        )
        .expect("plan");
        assert_eq!(plan.to_store[0].actor.as_deref(), Some("tenant:work:myles"));
        assert_eq!(
            plan.to_store[0].source_receipt.as_deref(),
            Some(pack.source_receipt().as_str())
        );
    }

    #[test]
    fn double_import_skips_already_imported() {
        let source = store_with(vec![sf("e", "k", "v", false)]);
        let pack = build_signed(&source, None, &opts("local"));
        let mut target = FactStore::new();
        let opts_in = ImportOptions {
            tenant_id: "local".into(),
            ..ImportOptions::default()
        };
        let plan1 = plan_import(&pack, &target, None, &opts_in).expect("plan1");
        target.try_store_bulk(plan1.to_store).expect("store");
        let plan2 = plan_import(&pack, &target, None, &opts_in).expect("plan2");
        assert_eq!(plan2.skipped_duplicates, 1);
        assert!(plan2.to_store.is_empty());
    }

    #[test]
    fn import_sessions_never_overwrites() {
        let mut source_sessions = SessionStore::new();
        source_sessions.put("execplan:demo", serde_json::json!({"m": 1}), None);
        source_sessions.put("fresh-session", serde_json::json!({"m": 2}), None);
        let source = store_with(vec![sf("e", "k", "v", false)]);
        let pack = build_signed(&source, Some(&source_sessions), &opts("local"));
        assert_eq!(pack.manifest.counts.sessions, 2);

        let target = FactStore::new();
        let mut local_sessions = SessionStore::new();
        local_sessions.put("execplan:demo", serde_json::json!({"local": true}), None);
        let plan = plan_import(
            &pack,
            &target,
            Some(&local_sessions),
            &ImportOptions {
                tenant_id: "local".into(),
                ..ImportOptions::default()
            },
        )
        .expect("plan");
        assert_eq!(plan.sessions_skipped, 1);
        assert_eq!(plan.sessions_to_add.len(), 1);
        assert_eq!(plan.sessions_to_add[0].session_id, "fresh-session");
    }

    #[test]
    fn reserved_session_ids_never_exported() {
        let mut sessions = SessionStore::new();
        sessions.put("__internal::x", serde_json::json!({"secret": true}), None);
        sessions.put("normal", serde_json::json!({}), None);
        let store = FactStore::new();
        let (sections, _) = build_pack_sections(&store, Some(&sessions), &opts("local"));
        assert_eq!(sections.sessions.len(), 1);
        assert_eq!(sections.sessions[0].session_id, "normal");
    }

    // ── Round-trip parity + byte-stability property ───────────────────────

    #[test]
    fn round_trip_export_wipe_import_query_parity() {
        // Daemon A: a store with public facts (plus things that must not travel).
        let dir_a = tempfile::tempdir().expect("tempdir a");
        let mut store_a = FactStore::with_persistence(dir_a.path()).expect("store a");
        store_a.store(sf("project-alpha", "status", "phase 1 complete", false));
        store_a.store(sf("project-alpha", "owner", "myles", false));
        store_a.store(sf("bench:lme-s", "baseline", "91.2%", false));
        store_a.store(sf("secret", "k", "private-stays-home", true));
        let dead = store_a.store(sf("gone", "k", "erased", false));
        store_a.delete(&dead.fact_id);

        let pack = build_signed(&store_a, None, &opts("local"));

        // "Wipe": daemon B starts from an empty data dir.
        let dir_b = tempfile::tempdir().expect("tempdir b");
        let mut store_b = FactStore::with_persistence(dir_b.path()).expect("store b");
        let plan = plan_import(
            &pack,
            &store_b,
            None,
            &ImportOptions {
                tenant_id: "local".into(),
                ..ImportOptions::default()
            },
        )
        .expect("plan");
        assert_eq!(plan.collisions, 0);
        store_b.try_store_bulk(plan.to_store).expect("apply");

        // Parity: every exportable (entity, key, value) recalls identically.
        let extract = |store: &FactStore| -> BTreeSet<(String, String, String)> {
            store
                .all_facts()
                .filter(|f| !f.deleted && !f.private && reserved_prefix(&f.entity).is_none())
                .map(|f| (f.entity.clone(), f.key.clone(), f.value.clone()))
                .collect()
        };
        assert_eq!(extract(&store_a), extract(&store_b));
        // And the non-exportables stayed home.
        assert!(store_b.all_facts().all(|f| !f.private));
        assert!(!store_b.all_facts().any(|f| f.value == "erased"));
    }

    #[test]
    fn property_export_import_export_stable_modulo_volatile_fields() {
        let dir_a = tempfile::tempdir().expect("tempdir a");
        let mut store_a = FactStore::with_persistence(dir_a.path()).expect("store a");
        for i in 0..20 {
            store_a.store(sf(
                &format!("entity-{}", i % 5),
                &format!("key-{i}"),
                &format!("value-{i}"),
                false,
            ));
        }
        let pack1 = build_signed(&store_a, None, &opts("local"));

        let dir_b = tempfile::tempdir().expect("tempdir b");
        let mut store_b = FactStore::with_persistence(dir_b.path()).expect("store b");
        let plan = plan_import(
            &pack1,
            &store_b,
            None,
            &ImportOptions {
                tenant_id: "local".into(),
                ..ImportOptions::default()
            },
        )
        .expect("plan");
        store_b.try_store_bulk(plan.to_store).expect("apply");
        let pack2 = build_signed(&store_b, None, &opts("local"));

        // Manifest stability modulo volatile fields (timestamps, journal head).
        assert_eq!(pack1.manifest.counts, pack2.manifest.counts);
        assert_eq!(pack1.manifest.tenant_id, pack2.manifest.tenant_id);
        assert_eq!(pack1.manifest.included_private, pack2.manifest.included_private);

        // Section stability: canonical content (the portable identity of a
        // fact) is byte-stable; fact_id / stored_at / provenance are
        // per-store by design.
        let canon = |pack: &CruxPack| -> Vec<String> {
            pack.sections
                .facts
                .iter()
                .map(|f| {
                    serde_json::to_string(&serde_json::json!({
                        "entity": f.entity,
                        "key": f.key,
                        "value": f.value,
                        "confidence": f.confidence,
                        "private": f.private,
                        "horizon_class": f.horizon_class,
                    }))
                    .expect("json")
                })
                .collect()
        };
        assert_eq!(canon(&pack1), canon(&pack2));

        // Determinism within one store: two exports are byte-identical
        // section-wise (sorted output).
        let (s1, _) = build_pack_sections(&store_a, None, &opts("local"));
        let (s2, _) = build_pack_sections(&store_a, None, &opts("local"));
        assert_eq!(
            serde_json::to_vec(&s1).expect("s1"),
            serde_json::to_vec(&s2).expect("s2")
        );
    }

    #[test]
    fn since_filter_excludes_older_facts() {
        let mut store = FactStore::new();
        store.store(sf("old", "k", "v", false));
        let mut o = opts("local");
        o.since = Some(Utc::now() + chrono::Duration::hours(1));
        let (sections, _) = build_pack_sections(&store, None, &o);
        assert!(sections.facts.is_empty());
    }

    #[test]
    fn source_receipt_format() {
        let store = store_with(vec![sf("e", "k", "v", false)]);
        let pack = build_signed(&store, None, &opts("local"));
        assert!(pack.source_receipt().starts_with("cruxpack:blake3:"));
    }
}
