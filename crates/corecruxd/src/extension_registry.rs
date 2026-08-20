// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Community-extension registry (M2 of community-extensions ExecPlan).
//!
//! Each installed extension is one fact under
//! `__extension__::{id}` key=`record`, value = a JSON-encoded
//! [`InstalledExtension`]. The privacy gate covers `__extension__::*` so
//! installed records are never push-eligible to a remote.
//!
//! This module is intentionally pure-domain: it owns the persistence shape
//! and validation flow, but knows nothing about HTTP. The HTTP surface
//! lives in `crate::http::extensions`.
//!
//! M3 (RCX token extension) and M4 (Phase A dispatch) build on top of this
//! by adding per-extension grants and a tool dispatcher; both consume the
//! [`InstalledExtension`] records this module produces.

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use crux_integrations::{
    append_audit_event, IntegrationAuditEvent, IntegrationError, IntegrationManifest, TrustTier, TrustedKeyring,
    ValidationPolicy, AUDIT_EXTENSION_INSTALL, AUDIT_EXTENSION_UNINSTALL,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const EXTENSION_ENTITY_PREFIX: &str = "__extension__";
pub const EXTENSION_RECORD_KEY: &str = "record";

/// On-disk filename of the operator-managed keyring under `<data_dir>/extensions/`.
pub const TRUSTED_KEYS_FILENAME: &str = "trusted-keys.json";

#[derive(Debug, thiserror::Error)]
pub enum ExtensionsError {
    /// Manifest signature verification failed (or signature absent in a
    /// non-dev environment). Includes the cause from `crux-integrations`.
    #[error("extension manifest validation failed: {0}")]
    ManifestInvalid(#[from] IntegrationError),
    #[error("extension '{0}' already installed (use DELETE first to replace)")]
    AlreadyInstalled(String),
    #[error("extension '{0}' not found")]
    NotFound(String),
    #[error("manifest id '{0}' contains invalid characters; expected lowercase alphanumerics + . - _")]
    InvalidId(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// What's persisted under `__extension__::{id}::record`. Carries enough
/// context for the dispatcher (M4) and the audit surface to render a row
/// without re-validating from scratch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledExtension {
    /// Frozen copy of the signed manifest. Re-validation on read is cheap;
    /// we keep the manifest verbatim so audit trails are reconstructable
    /// even if the verifier semantics evolve.
    pub manifest: IntegrationManifest,
    /// Stable BLAKE3 hash of the canonical signing payload at install
    /// time. Useful for "did the install record drift from disk" audits.
    pub manifest_hash: String,
    /// Trust tier *as resolved against the operator keyring at install*.
    /// `Unknown` means the manifest was unsigned + dev bypass was active.
    pub trust_tier: TrustTier,
    pub installed_at_unix_ms: u64,
    /// Passport that authored the install (`X-Corecrux-Passport-Id`
    /// header at the time of `POST /v1/extensions/register`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_by_passport: Option<String>,
}

/// Prefix of every [`PackAttribution::actor`] stamp. Namespaces pack
/// authorship against the other `Fact.actor` producers (passport ids and
/// raw agent names), so "which of these facts did a pack write" is a
/// prefix test rather than a join.
pub const PACK_ACTOR_PREFIX: &str = "pack:";

/// Per-mutation provenance for anything a pack originates — the M5
/// frontier seam of `crux-daemon-buyer-fit-buildout-2026-07-13`.
///
/// The dispatcher already recorded *which passport called a pack tool*.
/// What nothing recorded was *which pack build produced the resulting
/// mutation*, and `extension_id` alone cannot answer that: the same id is
/// reinstalled at new versions, and a single version can be re-cut with
/// different bytes. The triple (id, version, install-time `manifest_hash`)
/// is therefore what travels with every pack-originated write.
///
/// Two carriers, deliberately different shapes:
/// - [`PackAttribution::actor`] flattens the triple into one string,
///   because `Fact.actor` is a single `Option<String>` and a pack-written
///   fact has to stay self-describing with no registry lookup.
/// - The struct itself rides verbatim on dispatch outcomes and the audit
///   tail, where structured fields are cheaper to filter on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackAttribution {
    pub extension_id: String,
    pub extension_version: String,
    /// Install-time BLAKE3 over the canonical signing payload, carrying the
    /// `blake3:` prefix exactly as [`InstalledExtension::manifest_hash`]
    /// stores it. Kept whole rather than truncated: a shortened digest would
    /// force every downstream verifier to agree on a truncation length that
    /// is not part of any wire contract.
    pub manifest_hash: String,
}

impl PackAttribution {
    pub fn new(
        extension_id: impl Into<String>,
        extension_version: impl Into<String>,
        manifest_hash: impl Into<String>,
    ) -> Self {
        Self {
            extension_id: extension_id.into(),
            extension_version: extension_version.into(),
            manifest_hash: manifest_hash.into(),
        }
    }

    /// Build from the persisted install record — the only source that has
    /// the hash of the bytes actually installed, as opposed to whatever a
    /// manifest presented later claims.
    pub fn from_installed(installed: &InstalledExtension) -> Self {
        Self::new(
            installed.manifest.id.clone(),
            installed.manifest.version.clone(),
            installed.manifest_hash.clone(),
        )
    }

    /// Flat stamp written to `Fact.actor`:
    /// `pack:<extension_id>@<version>#<manifest_hash>`. The separators are
    /// chosen so the id (lowercase alphanumerics + `.`/`-`/`_`, enforced by
    /// `validate_id`) can never contain them, keeping the stamp unambiguously
    /// splittable by a reader that has only the fact.
    pub fn actor(&self) -> String {
        format!(
            "{PACK_ACTOR_PREFIX}{}@{}#{}",
            self.extension_id, self.extension_version, self.manifest_hash
        )
    }
}

/// Path to the operator keyring under the daemon's data directory.
pub fn trusted_keys_path(data_dir: impl AsRef<Path>) -> PathBuf {
    data_dir.as_ref().join("extensions").join(TRUSTED_KEYS_FILENAME)
}

fn validate_id(id: &str) -> Result<(), ExtensionsError> {
    if id.is_empty() || id.len() > 128 {
        return Err(ExtensionsError::InvalidId(id.to_string()));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_'));
    if !ok {
        return Err(ExtensionsError::InvalidId(id.to_string()));
    }
    Ok(())
}

fn entity_for(id: &str) -> String {
    format!("{EXTENSION_ENTITY_PREFIX}::{id}")
}

/// Build a [`ValidationPolicy`] backed by the operator keyring at
/// `<data_dir>/extensions/trusted-keys.json`. Missing keyring → empty
/// trusted set; the verifier will then reject any signed manifest unless
/// the manifest's signature carries an inline `public_key_hex` *and* dev
/// bypass is active. (`crux-integrations`'s default `ValidationPolicy`
/// allows that path for development convenience.)
///
/// Wired in M3 (RCX token issuance) + M4 (Phase A dispatch) — `install_
/// extension` builds its own policy inline today; this helper exists so
/// downstream code paths share one definition.
#[allow(dead_code)]
pub fn build_policy(data_dir: impl AsRef<Path>) -> Result<ValidationPolicy, ExtensionsError> {
    let keyring = TrustedKeyring::load(trusted_keys_path(&data_dir))?;
    Ok(ValidationPolicy {
        allow_unsigned_first_party: false,
        trusted_public_keys: keyring.as_trusted_public_keys(),
        ..ValidationPolicy::default()
    })
}

/// Install an extension. Validates the signed manifest against the
/// operator keyring; persists the install record on success.
///
/// `allow_unsigned_dev_bypass=true` permits installing an unsigned
/// manifest and tags the trust tier `Unknown`. Operators set this only
/// in development via the `CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED` env knob;
/// the HTTP layer enforces that.
pub fn install_extension(
    store: &mut FactStore,
    data_dir: impl AsRef<Path>,
    manifest: IntegrationManifest,
    installed_by_passport: Option<String>,
    now_unix_ms: u64,
    allow_unsigned_dev_bypass: bool,
) -> Result<InstalledExtension, ExtensionsError> {
    validate_id(&manifest.id)?;
    if get_extension(store, &manifest.id).is_some() {
        return Err(ExtensionsError::AlreadyInstalled(manifest.id.clone()));
    }

    let keyring = TrustedKeyring::load(trusted_keys_path(&data_dir))?;
    let policy = ValidationPolicy {
        trusted_public_keys: keyring.as_trusted_public_keys(),
        allow_unsigned_first_party: false,
        // Dev bypass tolerates unsigned manifests regardless of publisher.
        // Signed manifests are still verified.
        allow_unsigned: allow_unsigned_dev_bypass,
        ..ValidationPolicy::default()
    };

    manifest.validate(&policy)?;

    let manifest_hash = manifest.manifest_hash()?;
    let trust_tier = if manifest.signature.is_some() {
        keyring.resolve_signature(&manifest)
    } else {
        TrustTier::Unknown
    };

    let record = InstalledExtension {
        manifest: manifest.clone(),
        manifest_hash,
        trust_tier,
        installed_at_unix_ms: now_unix_ms,
        installed_by_passport: installed_by_passport.filter(|s| !s.trim().is_empty()),
    };
    let value = serde_json::to_string(&record)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: entity_for(&manifest.id),
        key: EXTENSION_RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    // Force-private via the global gate (the `__extension__::` prefix is
    // in `fact_privacy::DEFAULT_PRIVATE_PREFIXES`).
    crate::fact_privacy::enforce_global(&mut sf);
    store.try_store(sf)?;
    append_audit_event(
        &data_dir,
        &IntegrationAuditEvent::extension(
            now_unix_ms,
            AUDIT_EXTENSION_INSTALL,
            record.installed_by_passport.as_deref(),
            &manifest.id,
            Some(&manifest.version),
            "installed",
            serde_json::json!({
                "manifest_hash": record.manifest_hash,
                "trust_tier": record.trust_tier,
            }),
        ),
    );
    Ok(record)
}

pub fn list_extensions(store: &FactStore) -> Vec<InstalledExtension> {
    let prefix = format!("{EXTENSION_ENTITY_PREFIX}::");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix.clone()),
        top_k: 500,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let mut out: Vec<InstalledExtension> = latest
        .into_iter()
        .filter(|f| f.entity.starts_with(&prefix) && f.key == EXTENSION_RECORD_KEY && !f.value.is_empty())
        .filter_map(|f| serde_json::from_str::<InstalledExtension>(&f.value).ok())
        .collect();
    out.sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));
    out
}

pub fn get_extension(store: &FactStore, id: &str) -> Option<InstalledExtension> {
    list_extensions(store).into_iter().find(|e| e.manifest.id == id)
}

pub fn delete_extension(
    store: &mut FactStore,
    data_dir: impl AsRef<Path>,
    id: &str,
    deleted_by_passport: Option<&str>,
    now_unix_ms: u64,
) -> Result<(), ExtensionsError> {
    let installed = get_extension(store, id).ok_or_else(|| ExtensionsError::NotFound(id.to_string()))?;
    // Tombstone via empty-value write; same pattern as project_repo_links.
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: entity_for(id),
        key: EXTENSION_RECORD_KEY.to_string(),
        value: String::new(),
        source_receipt: None,
        confidence: 0.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.try_store(sf)?;
    append_audit_event(
        data_dir,
        &IntegrationAuditEvent::extension(
            now_unix_ms,
            AUDIT_EXTENSION_UNINSTALL,
            deleted_by_passport,
            id,
            Some(&installed.manifest.version),
            "uninstalled",
            serde_json::json!({}),
        ),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crux_integrations::{
        sign_manifest, DataAccess, EntryKind, IntegrationEntry, ManifestHashes, NetworkAccess, SafetyPolicy,
        TrustedKeyEntry, INTEGRATION_SCHEMA_V1,
    };
    use ed25519_dalek::SigningKey;

    fn fixture_manifest(id: &str, publisher_fpr: &str) -> IntegrationManifest {
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: id.to_string(),
            name: "Quote of the Day".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: publisher_fpr.to_string(),
            summary: "Returns a quote.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::HttpRecipe,
                path: "tools/quote.json".to_string(),
            },
            capabilities: vec!["facts:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
            external_tool_endpoint: None,
            tools: Vec::new(),
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0xab; 32])
    }

    fn write_keyring_with(public_key: &str, fpr: &str, dir: &Path) {
        let mut k = TrustedKeyring::new();
        k.add(
            fpr,
            TrustedKeyEntry {
                public_key_hex: public_key.to_string(),
                trust_tier: TrustTier::CommunityReviewed,
                added_at_unix_ms: 1,
                added_by: "test".to_string(),
            },
        );
        k.save(dir.join("extensions").join(TRUSTED_KEYS_FILENAME))
            .expect("save keyring");
    }

    #[test]
    fn install_then_list_then_get_then_delete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = signing_key();
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        write_keyring_with(&pubkey_hex, "p_alice", dir.path());

        let mut manifest = fixture_manifest("ext.example.quote", "p_alice");
        sign_manifest(&mut manifest, &key, "p_alice").expect("sign");

        let mut store = FactStore::new();
        let installed = install_extension(
            &mut store,
            dir.path(),
            manifest,
            Some("agent-claude".to_string()),
            17_700_000_000_000,
            false,
        )
        .expect("install");
        assert_eq!(installed.manifest.id, "ext.example.quote");
        assert_eq!(installed.trust_tier, TrustTier::CommunityReviewed);

        let listed = list_extensions(&store);
        assert_eq!(listed.len(), 1);
        let got = get_extension(&store, "ext.example.quote").expect("get");
        assert_eq!(got.installed_by_passport.as_deref(), Some("agent-claude"));

        delete_extension(
            &mut store,
            dir.path(),
            "ext.example.quote",
            Some("agent-claude"),
            17_700_000_000_001,
        )
        .expect("delete");
        assert!(list_extensions(&store).is_empty());

        let audit = crux_integrations::read_audit_tail(dir.path(), 50).expect("audit");
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[0].action, AUDIT_EXTENSION_INSTALL);
        assert_eq!(audit[1].action, AUDIT_EXTENSION_UNINSTALL);
        assert_eq!(audit[1].actor, "agent-claude");
    }

    #[test]
    fn install_rejects_duplicate_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = signing_key();
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        write_keyring_with(&pubkey_hex, "p_alice", dir.path());

        let mut manifest = fixture_manifest("ext.example.quote", "p_alice");
        sign_manifest(&mut manifest, &key, "p_alice").expect("sign");

        let mut store = FactStore::new();
        install_extension(&mut store, dir.path(), manifest.clone(), None, 1, false).expect("first install");
        let err = install_extension(&mut store, dir.path(), manifest, None, 2, false).expect_err("dup");
        assert!(matches!(err, ExtensionsError::AlreadyInstalled(_)));
    }

    #[test]
    fn install_rejects_invalid_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = signing_key();
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        write_keyring_with(&pubkey_hex, "p_alice", dir.path());
        // Sign first so the verifier doesn't fail on missing signature.
        let mut manifest = fixture_manifest("Bad/Id", "p_alice");
        // Validate-time the integrations crate will already complain about
        // the id, but our install_extension ALSO validates first; ensure
        // the right error class fires.
        let err =
            install_extension(&mut store_temp(), dir.path(), manifest.clone(), None, 1, true).expect_err("invalid id");
        // Could be either our InvalidId (preferred) or the integrations
        // crate's identifier check (also acceptable). Accept either.
        match err {
            ExtensionsError::InvalidId(_) => {}
            ExtensionsError::ManifestInvalid(IntegrationError::InvalidIdentifier(_)) => {}
            other => panic!("unexpected error: {other}"),
        }
        // (the assignment to manifest above just sets the id; sign would also
        // be valid but isn't needed for the id-validation path)
        let _ = sign_manifest(&mut manifest, &key, "p_alice");
    }

    #[test]
    fn install_rejects_unsigned_when_bypass_off() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Empty keyring; no signature.
        let manifest = fixture_manifest("ext.example.unsigned", "p_alice");
        let err =
            install_extension(&mut store_temp(), dir.path(), manifest, None, 1, false).expect_err("unsigned must fail");
        assert!(matches!(
            err,
            ExtensionsError::ManifestInvalid(IntegrationError::SignatureRequired)
        ));
    }

    #[test]
    fn install_accepts_unsigned_when_bypass_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = fixture_manifest("ext.example.unsigned", "p_alice");
        let mut store = FactStore::new();
        let installed = install_extension(&mut store, dir.path(), manifest, None, 1, true).expect("bypass");
        assert_eq!(installed.trust_tier, TrustTier::Unknown);
    }

    #[test]
    fn delete_unknown_returns_not_found() {
        let mut store = FactStore::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let err = delete_extension(&mut store, dir.path(), "ext.does-not-exist", None, 1).expect_err("not found");
        assert!(matches!(err, ExtensionsError::NotFound(_)));
    }

    #[test]
    fn audit_append_failure_does_not_fail_install() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = fixture_manifest("ext.example.audit-failure", "p_alice");
        std::fs::create_dir_all(dir.path().join("integrations").join("audit.jsonl")).expect("blocking directory");

        let mut store = FactStore::new();
        let installed = install_extension(&mut store, dir.path(), manifest, None, 1, true).expect("install succeeds");
        assert_eq!(installed.manifest.id, "ext.example.audit-failure");
        assert!(get_extension(&store, "ext.example.audit-failure").is_some());
    }

    fn store_temp() -> FactStore {
        FactStore::new()
    }

    /// M5 attribution seam: the stamp a pack-originated mutation carries is
    /// built from the *install record*, so it names the bytes the operator
    /// actually installed rather than whatever a later manifest claims.
    #[test]
    fn pack_attribution_uses_the_install_record_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = fixture_manifest("ext.example.quote", "p_alice");
        let mut store = FactStore::new();
        let installed =
            install_extension(&mut store, dir.path(), manifest, None, 17_700_000_000_000, true).expect("install");

        let attribution = PackAttribution::from_installed(&installed);
        assert_eq!(attribution.extension_id, "ext.example.quote");
        assert_eq!(attribution.extension_version, "0.1.0");
        assert_eq!(attribution.manifest_hash, installed.manifest_hash);
        assert!(
            installed.manifest_hash.starts_with("blake3:"),
            "install hash keeps its algorithm prefix: {}",
            installed.manifest_hash
        );

        let actor = attribution.actor();
        assert!(actor.starts_with(PACK_ACTOR_PREFIX));
        assert_eq!(
            actor,
            format!("pack:ext.example.quote@0.1.0#{}", installed.manifest_hash),
            "the `Fact.actor` stamp is a wire contract; changing its shape breaks every reader"
        );
    }

    /// Why the hash is in the stamp at all: one id at one version can be
    /// re-cut with different bytes, so id+version alone cannot tell two pack
    /// builds apart when attributing a mutation after the fact.
    #[test]
    fn pack_attribution_separates_two_builds_of_the_same_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut first = fixture_manifest("ext.example.quote", "p_alice");
        first.summary = "Returns a quote.".to_string();
        let mut second = fixture_manifest("ext.example.quote", "p_alice");
        second.summary = "Returns a different quote.".to_string();
        assert_eq!(first.id, second.id);
        assert_eq!(first.version, second.version);

        let mut store_a = FactStore::new();
        let a = install_extension(&mut store_a, dir.path(), first, None, 1, true).expect("install a");
        let mut store_b = FactStore::new();
        let b = install_extension(&mut store_b, dir.path(), second, None, 2, true).expect("install b");

        assert_ne!(
            PackAttribution::from_installed(&a).actor(),
            PackAttribution::from_installed(&b).actor()
        );
    }
}
