// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Central Studio template library index (`crux.studio.index.v1`) — L1 of the
//! `crux-integrations-and-template-library-2026-07-25` ExecPlan.
//!
//! This is the *catalog* half of the Studio template library. It is a
//! deliberate, field-for-field mirror of the community-extensions registry
//! index ([`crate::CommunityExtensionsIndex`]): a curator-signed JSON document
//! hosted at a stable URL, synced by `corecruxctl studio sync`, cached under
//! `<data-dir>/studio/library/index.json`, and re-verified by the daemon on
//! every read. The trust rails are identical — same Ed25519 envelope, same
//! [`crate::TrustedKeyring`] rule (an inline `signature.public_key_hex` is
//! accepted ONLY when it matches the operator's trusted-keyring entry for the
//! declared `passport_fpr`) — because the security properties we want are
//! identical. Nothing here is a new trust model.
//!
//! What differs is the *payload* each entry points at. A community-extension
//! entry points at a `crux.integration.v1` manifest that installs executable
//! surface (MCP/HTTP/WASM recipes). A Studio library entry points at a
//! **Studio pack** — a `crux.studio.v1` payload (board doc + tile designs +
//! workspaces + pages) wrapped in a `crux.integration.v1` manifest, exactly the
//! artefact `POST /v1/studio/pack/build` emits. Installing one writes console
//! facts, never code.
//!
//! Sync flow (mirror of the community registry, M8):
//! 1. HTTPS GET the index from a configured URL.
//! 2. Verify the signature against the curator's public key.
//! 3. Cache the verified document under `<data-dir>/studio/library/index.json`.
//! 4. `corecruxctl studio list-library` / `GET /v1/studio/library` render the
//!    cached entries; install stays an explicit, operator-gated per-entry action.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{decode_fixed_hex, IntegrationError, SignatureEnvelope, ValidationPolicy};

/// Tier vocabulary is the RCX one — reused verbatim rather than forked, so a
/// catalog server and a daemon never disagree about what `"pro"` means.
pub use rcx_capability_token::RcxTier;

/// On-the-wire schema for the central Studio template library index.
pub const STUDIO_LIBRARY_INDEX_SCHEMA_V1: &str = "crux.studio.index.v1";

/// Maximum entries in one index. Bounds the work a malicious mirror can make
/// the daemon do after signature verification succeeds.
const MAX_ENTRIES: usize = 2048;
const MAX_ID_LEN: usize = 128;
const MAX_TAGS: usize = 16;
const MAX_TAG_LEN: usize = 32;
/// `preview` is a SHORT TEXT hint (a one-line description of what the template
/// renders). It is never binary, never a data: URI, never markup — the console
/// renders it as plain text.
const MAX_PREVIEW_LEN: usize = 512;
const MAX_NAME_LEN: usize = 128;
const MAX_SUMMARY_LEN: usize = 2048;

/// What a library entry installs. Drives the console badge and (for the
/// daemon) nothing else — the pack payload itself decides which console facts
/// get written, so `kind` is descriptive metadata the curator publishes, not an
/// authorization input.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioEntryKind {
    /// A single Canvas Studio tile board (`console:tileboard:<id>`).
    Board,
    /// One or more saved tile designs (`console:tiledesign:<slug>`).
    Design,
    /// A workspace + its pages (`console:workspace:<uid>` / `console:page:<uid>`).
    Workspace,
    /// A full pack: any combination of the above.
    Pack,
}

impl StudioEntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Board => "board",
            Self::Design => "design",
            Self::Workspace => "workspace",
            Self::Pack => "pack",
        }
    }
}

/// One row in a curator-signed [`StudioLibraryIndex`]. Carries enough metadata
/// for an operator to decide whether to install, plus the content-addressable
/// `pack_sha256` the daemon uses to prove the bytes it downloaded are exactly
/// the ones the curator endorsed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StudioLibraryEntry {
    /// Library id, e.g. `studio.ops-overview`. Lowercase `[a-z0-9]` with `-`
    /// and `.` separators; also the default console artifact id on install.
    pub id: String,
    pub kind: StudioEntryKind,
    pub name: String,
    /// Semver `MAJOR.MINOR.PATCH`, optionally `-prerelease` / `+build`.
    pub version: String,
    pub summary: String,
    /// Passport fingerprint of whoever built + signed the pack (which may
    /// differ from the index curator who endorsed it).
    pub publisher_passport_fpr: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Advisory subscription tier the CATALOG SERVER requires to serve this
    /// pack. The daemon does not enforce it — see the module docs on
    /// `http/studio_library.rs` and the `tier_enforcement: "advisory"` field on
    /// the install response.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_required_tier"
    )]
    pub required_tier: Option<RcxTier>,
    /// Public HTTPS URL the pack JSON is fetched from (loopback `http://` is
    /// accepted for local mirrors + tests).
    pub pack_url: String,
    /// SHA-256 of the pack bytes, lowercase hex.
    pub pack_sha256: String,
    /// Homepage / source URL for humans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_url: Option<String>,
    /// Short PLAIN-TEXT hint rendered before install ("12 tiles: retrieval
    /// latency, receipt freshness, lane weights"). Never binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

/// `RcxTier` derives `Deserialize` only (it is a verification-side vocabulary in
/// `rcx-capability-token`), so serialize through its canonical `as_str()` —
/// the exact tokens its `rename_all = "snake_case"` `Deserialize` accepts. This
/// keeps sign→publish→verify byte-stable without forking the enum.
// `&Option<T>` is not idiomatic in general, but serde's `serialize_with` calls
// this with a reference to the FIELD, so the signature is fixed by the contract.
#[allow(clippy::ref_option)]
fn serialize_required_tier<S>(tier: &Option<RcxTier>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match tier {
        Some(tier) => serializer.serialize_str(tier.as_str()),
        None => serializer.serialize_none(),
    }
}

/// Curator-signed template library index. See the module docs for the sync flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StudioLibraryIndex {
    pub schema: String,
    pub updated_at_unix_ms: u64,
    #[serde(default)]
    pub curator_passport_fpr: String,
    #[serde(default)]
    pub entries: Vec<StudioLibraryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,
}

#[derive(Debug, Serialize)]
struct StudioIndexSigningPayload<'a> {
    schema: &'a str,
    updated_at_unix_ms: u64,
    curator_passport_fpr: &'a str,
    entries: &'a [StudioLibraryEntry],
}

impl StudioLibraryIndex {
    pub fn new(curator_passport_fpr: impl Into<String>, now_unix_ms: u64) -> Self {
        Self {
            schema: STUDIO_LIBRARY_INDEX_SCHEMA_V1.to_string(),
            updated_at_unix_ms: now_unix_ms,
            curator_passport_fpr: curator_passport_fpr.into(),
            entries: Vec::new(),
            signature: None,
        }
    }

    fn signing_payload(&self) -> Result<Vec<u8>, IntegrationError> {
        let payload = StudioIndexSigningPayload {
            schema: &self.schema,
            updated_at_unix_ms: self.updated_at_unix_ms,
            curator_passport_fpr: &self.curator_passport_fpr,
            entries: &self.entries,
        };
        Ok(serde_json::to_vec(&payload)?)
    }

    /// Sign the index in place with the given Ed25519 key. The matching public
    /// key (looked up by `curator_passport_fpr`) MUST be present in the
    /// operator's `ValidationPolicy.trusted_public_keys` for [`Self::verify`] to
    /// succeed. Byte-for-byte the same ceremony as
    /// [`crate::CommunityExtensionsIndex::sign`].
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) -> Result<(), IntegrationError> {
        use ed25519_dalek::Signer as _;
        if self.curator_passport_fpr.is_empty() {
            return Err(IntegrationError::MissingField("curator_passport_fpr"));
        }
        let payload = self.signing_payload()?;
        let signature = signing_key.sign(&payload);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        self.signature = Some(SignatureEnvelope {
            alg: "ed25519".to_string(),
            passport_fpr: self.curator_passport_fpr.clone(),
            public_key_hex: Some(public_key_hex),
            sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        });
        Ok(())
    }

    /// Verify the signature against `policy.trusted_public_keys`, then validate
    /// the entry shapes.
    ///
    /// Signature semantics are identical to
    /// [`crate::CommunityExtensionsIndex::verify`]: inline
    /// `signature.public_key_hex` is permitted ONLY if it matches the trusted
    /// keyring entry for `passport_fpr`.
    ///
    /// DELIBERATE DIFFERENCE from the community index: shape validation
    /// ([`Self::validate`]) runs here, AFTER the signature check. A signed
    /// index whose entries carry a non-https `pack_url` or a malformed
    /// `pack_sha256` is rejected at the trust boundary rather than at the point
    /// of use, so no caller can forget to call it.
    pub fn verify(&self, policy: &ValidationPolicy) -> Result<(), IntegrationError> {
        if self.schema != STUDIO_LIBRARY_INDEX_SCHEMA_V1 {
            return Err(IntegrationError::InvalidSchema(self.schema.clone()));
        }
        let signature = self.signature.as_ref().ok_or(IntegrationError::SignatureRequired)?;
        if signature.alg != "ed25519" {
            return Err(IntegrationError::UnsupportedSignatureAlgorithm(signature.alg.clone()));
        }
        let key_hex = policy
            .trusted_public_keys
            .get(&signature.passport_fpr)
            .ok_or_else(|| IntegrationError::MissingTrustedKey(signature.passport_fpr.clone()))?;
        if signature
            .public_key_hex
            .as_ref()
            .is_some_and(|inline| !inline.eq_ignore_ascii_case(key_hex))
        {
            return Err(IntegrationError::InvalidSignatureMaterial(
                "signature public_key_hex does not match trusted keyring entry".to_string(),
            ));
        }
        let pk_bytes = decode_fixed_hex::<32>(key_hex, "public key")?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| IntegrationError::InvalidSignatureMaterial(format!("public key: {e}")))?;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signature.sig)
            .map_err(|e| IntegrationError::InvalidSignatureMaterial(format!("signature base64: {e}")))?;
        let sig: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| IntegrationError::InvalidSignatureMaterial("signature length".into()))?;
        let signature_obj = ed25519_dalek::Signature::from_bytes(&sig);
        let payload = self.signing_payload()?;
        verifying_key
            .verify_strict(&payload, &signature_obj)
            .map_err(|_| IntegrationError::SignatureInvalid)?;
        self.validate()
    }

    /// Shape validation, independent of the signature. Callable on an unsigned
    /// draft (a curator tool builds an index, validates it, then signs).
    pub fn validate(&self) -> Result<(), IntegrationError> {
        if self.schema != STUDIO_LIBRARY_INDEX_SCHEMA_V1 {
            return Err(IntegrationError::InvalidSchema(self.schema.clone()));
        }
        if self.curator_passport_fpr.trim().is_empty() {
            return Err(IntegrationError::MissingField("curator_passport_fpr"));
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(IntegrationError::InvalidIdentifier(format!(
                "index carries {} entries, cap is {MAX_ENTRIES}",
                self.entries.len()
            )));
        }
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if !seen.insert(entry.id.as_str()) {
                return Err(IntegrationError::InvalidIdentifier(format!(
                    "duplicate entry id '{}'",
                    entry.id
                )));
            }
        }
        Ok(())
    }
}

impl StudioLibraryEntry {
    /// Field-shape validation. Every rejection names the offending field so an
    /// operator sees which catalog row is malformed, not a bare "invalid index".
    pub fn validate(&self) -> Result<(), IntegrationError> {
        validate_library_id(&self.id)?;
        if self.name.trim().is_empty() || self.name.len() > MAX_NAME_LEN {
            return Err(IntegrationError::InvalidIdentifier(format!(
                "entry '{}': name must be 1..={MAX_NAME_LEN} chars",
                self.id
            )));
        }
        validate_semver(&self.id, &self.version)?;
        if self.summary.len() > MAX_SUMMARY_LEN {
            return Err(IntegrationError::InvalidIdentifier(format!(
                "entry '{}': summary exceeds {MAX_SUMMARY_LEN} chars",
                self.id
            )));
        }
        if self.publisher_passport_fpr.trim().is_empty() {
            return Err(IntegrationError::MissingField("publisher_passport_fpr"));
        }
        if !pack_url_allowed(&self.pack_url) {
            return Err(IntegrationError::InvalidIdentifier(format!(
                "entry '{}': pack_url must be https://, or loopback http:// for local mirrors (got '{}')",
                self.id, self.pack_url
            )));
        }
        if !is_sha256_hex(&self.pack_sha256) {
            return Err(IntegrationError::InvalidIdentifier(format!(
                "entry '{}': pack_sha256 must be 64 lowercase hex chars",
                self.id
            )));
        }
        if let Some(repo_url) = &self.repo_url {
            if !repo_url.starts_with("https://") {
                return Err(IntegrationError::InvalidIdentifier(format!(
                    "entry '{}': repo_url must be https://",
                    self.id
                )));
            }
        }
        if self.tags.len() > MAX_TAGS {
            return Err(IntegrationError::InvalidIdentifier(format!(
                "entry '{}': at most {MAX_TAGS} tags",
                self.id
            )));
        }
        for tag in &self.tags {
            if tag.is_empty()
                || tag.len() > MAX_TAG_LEN
                || !tag
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(IntegrationError::InvalidIdentifier(format!(
                    "entry '{}': tag '{tag}' must be 1..={MAX_TAG_LEN} lowercase [a-z0-9-] chars",
                    self.id
                )));
            }
        }
        if let Some(preview) = &self.preview {
            if preview.len() > MAX_PREVIEW_LEN {
                return Err(IntegrationError::InvalidIdentifier(format!(
                    "entry '{}': preview exceeds {MAX_PREVIEW_LEN} chars (it is a short text hint, not an asset)",
                    self.id
                )));
            }
            if preview.chars().any(|c| c.is_control() && c != '\n') {
                return Err(IntegrationError::InvalidIdentifier(format!(
                    "entry '{}': preview must be plain text (no control characters)",
                    self.id
                )));
            }
        }
        Ok(())
    }

    /// The advisory tier token (`"free"` / `"pro"` / …) or `None`.
    pub fn required_tier_str(&self) -> Option<&'static str> {
        self.required_tier.as_ref().map(RcxTier::as_str)
    }
}

/// Library ids are lowercase `[a-z0-9]` with `-` and `.` as separators. Dots
/// are permitted because the existing Studio export flow mints ids of the form
/// `studio.<slug>` (console `render.js` `openExportWorkspace`), and the id also
/// becomes a console artifact id — no slashes, no whitespace, no uppercase.
pub fn validate_library_id(id: &str) -> Result<(), IntegrationError> {
    let bad = |why: &str| IntegrationError::InvalidIdentifier(format!("library id '{id}': {why}"));
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return Err(bad("must be 1..=128 chars"));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
    {
        return Err(bad("only lowercase [a-z0-9], '-' and '.' are allowed"));
    }
    let first = id.as_bytes()[0];
    let last = id.as_bytes()[id.len() - 1];
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(bad("must start with [a-z0-9]"));
    }
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        return Err(bad("must end with [a-z0-9]"));
    }
    if id.contains("..") || id.contains("--") || id.contains(".-") || id.contains("-.") {
        return Err(bad("separators '-' and '.' must not be adjacent"));
    }
    Ok(())
}

/// `MAJOR.MINOR.PATCH` with optional `-prerelease` and/or `+build`.
fn validate_semver(id: &str, version: &str) -> Result<(), IntegrationError> {
    let bad = || {
        IntegrationError::InvalidIdentifier(format!(
            "entry '{id}': version '{version}' must be semver MAJOR.MINOR.PATCH"
        ))
    };
    let core = version.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return Err(bad());
    }
    for part in parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return Err(bad());
        }
    }
    Ok(())
}

/// Same allowlist the daemon's extension-manifest fetch applies: public HTTPS,
/// or loopback HTTP so a local mirror / integration test can serve a pack.
pub fn pack_url_allowed(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost")
}

/// 64 lowercase hex characters.
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(id: &str) -> StudioLibraryEntry {
        StudioLibraryEntry {
            id: id.to_string(),
            kind: StudioEntryKind::Pack,
            name: "Ops Overview".to_string(),
            version: "0.1.0".to_string(),
            summary: "Retrieval latency + receipt freshness board.".to_string(),
            publisher_passport_fpr: "p_publisher".to_string(),
            tags: vec!["ops".to_string(), "retrieval".to_string()],
            required_tier: Some(RcxTier::Pro),
            pack_url: "https://example.com/packs/ops-overview.json".to_string(),
            pack_sha256: "0".repeat(64),
            repo_url: Some("https://github.com/CueCrux/studio-library".to_string()),
            preview: Some("12 tiles: retrieval latency, receipt freshness, lane weights.".to_string()),
        }
    }

    // ── Signature round-trip (mirrors the community-index tests) ───────────

    #[test]
    fn studio_index_sign_then_verify_round_trip() -> Result<(), IntegrationError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xab_u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let curator_fpr = "p_curator_studio".to_string();

        let mut index = StudioLibraryIndex::new(curator_fpr.clone(), 1_700_000_000_000);
        index.entries.push(sample_entry("studio.ops-overview"));
        index.sign(&signing_key)?;
        assert!(index.signature.is_some());

        let mut policy = ValidationPolicy::default();
        policy.trusted_public_keys.insert(curator_fpr, public_key_hex);
        index.verify(&policy)?;
        Ok(())
    }

    #[test]
    fn studio_index_rejects_tampered_entries_after_signing() -> Result<(), IntegrationError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xcd_u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let curator_fpr = "p_curator_studio_tamper".to_string();

        let mut index = StudioLibraryIndex::new(curator_fpr.clone(), 1_700_000_000_000);
        index.entries.push(sample_entry("studio.ops-overview"));
        index.sign(&signing_key)?;

        // Repoint the pack at an attacker-controlled URL after signing.
        index.entries[0].pack_url = "https://attacker.example.com/evil-pack.json".to_string();

        let mut policy = ValidationPolicy::default();
        policy.trusted_public_keys.insert(curator_fpr, public_key_hex);
        let err = index.verify(&policy).err().expect("verify must fail post-tamper");
        assert!(matches!(err, IntegrationError::SignatureInvalid), "got {err:?}");
        Ok(())
    }

    #[test]
    fn studio_index_rejects_tampered_sha256_after_signing() -> Result<(), IntegrationError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5a_u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let curator_fpr = "p_curator_studio_sha".to_string();

        let mut index = StudioLibraryIndex::new(curator_fpr.clone(), 1_700_000_000_000);
        index.entries.push(sample_entry("studio.ops-overview"));
        index.sign(&signing_key)?;
        index.entries[0].pack_sha256 = "f".repeat(64);

        let mut policy = ValidationPolicy::default();
        policy.trusted_public_keys.insert(curator_fpr, public_key_hex);
        assert!(matches!(
            index.verify(&policy).err().expect("must fail"),
            IntegrationError::SignatureInvalid
        ));
        Ok(())
    }

    #[test]
    fn studio_index_rejects_index_signed_by_wrong_key() -> Result<(), IntegrationError> {
        let curator_key = ed25519_dalek::SigningKey::from_bytes(&[0xee_u8; 32]);
        let curator_pub = hex::encode(curator_key.verifying_key().to_bytes());
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0x11_u8; 32]);
        let curator_fpr = "p_curator_studio_real".to_string();

        let mut index = StudioLibraryIndex::new(curator_fpr.clone(), 1_700_000_000_000);
        index.entries.push(sample_entry("studio.x"));
        // Signed by the attacker, but the envelope claims the curator's fpr and
        // the operator's keyring holds the REAL curator key.
        index.sign(&attacker_key)?;
        if let Some(sig) = &mut index.signature {
            sig.passport_fpr = curator_fpr.clone();
            sig.public_key_hex = None;
        }

        let mut policy = ValidationPolicy::default();
        policy.trusted_public_keys.insert(curator_fpr, curator_pub);
        let err = index.verify(&policy).err().expect("must reject wrong-key signature");
        assert!(matches!(err, IntegrationError::SignatureInvalid), "got {err:?}");
        Ok(())
    }

    #[test]
    fn studio_index_rejects_inline_pubkey_that_doesnt_match_keyring() -> Result<(), IntegrationError> {
        let curator_key = ed25519_dalek::SigningKey::from_bytes(&[0x21_u8; 32]);
        let curator_pub = hex::encode(curator_key.verifying_key().to_bytes());
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0x22_u8; 32]);
        let attacker_pub = hex::encode(attacker_key.verifying_key().to_bytes());
        let curator_fpr = "p_curator_studio_inline".to_string();

        let mut index = StudioLibraryIndex::new(curator_fpr.clone(), 1_700_000_000_000);
        index.entries.push(sample_entry("studio.x"));
        index.sign(&attacker_key)?;
        if let Some(sig) = &mut index.signature {
            sig.public_key_hex = Some(attacker_pub);
            sig.passport_fpr = curator_fpr.clone();
        }

        let mut policy = ValidationPolicy::default();
        policy.trusted_public_keys.insert(curator_fpr, curator_pub);
        let err = index
            .verify(&policy)
            .err()
            .expect("verify must reject mismatched inline pubkey");
        assert!(
            matches!(err, IntegrationError::InvalidSignatureMaterial(_)),
            "got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn studio_index_unsigned_is_rejected() {
        let index = StudioLibraryIndex::new("p_curator", 1);
        let err = index.verify(&ValidationPolicy::default()).err().expect("must fail");
        assert!(matches!(err, IntegrationError::SignatureRequired), "got {err:?}");
    }

    #[test]
    fn studio_index_wrong_schema_is_rejected() {
        let mut index = StudioLibraryIndex::new("p_curator", 1);
        index.schema = "crux.community-extensions.index.v1".to_string();
        let err = index.verify(&ValidationPolicy::default()).err().expect("must fail");
        assert!(matches!(err, IntegrationError::InvalidSchema(_)), "got {err:?}");
    }

    // ── Shape validation ──────────────────────────────────────────────────

    #[test]
    fn valid_entry_passes_validation() -> Result<(), IntegrationError> {
        sample_entry("studio.ops-overview").validate()
    }

    #[test]
    fn rejects_bad_id_shapes() {
        for id in [
            "",
            "Studio.Ops",
            "studio ops",
            "studio/ops",
            "-studio",
            "studio-",
            "studio..ops",
            "studio--ops",
        ] {
            let mut entry = sample_entry("studio.ok");
            entry.id = id.to_string();
            assert!(entry.validate().is_err(), "id '{id}' must be rejected");
        }
    }

    #[test]
    fn rejects_non_https_pack_url() {
        let mut entry = sample_entry("studio.ok");
        entry.pack_url = "http://evil.example.com/pack.json".to_string();
        assert!(entry.validate().is_err());
        // Loopback http:// stays allowed for local mirrors + tests.
        entry.pack_url = "http://127.0.0.1:8080/pack.json".to_string();
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn rejects_malformed_sha256() {
        for sha in ["", &"0".repeat(63), &"0".repeat(65), &"A".repeat(64), &"z".repeat(64)] {
            let mut entry = sample_entry("studio.ok");
            entry.pack_sha256 = sha.to_string();
            assert!(entry.validate().is_err(), "sha '{sha}' must be rejected");
        }
    }

    #[test]
    fn rejects_non_semver_version() {
        for version in ["", "1", "1.0", "v1.0.0", "1.0.x"] {
            let mut entry = sample_entry("studio.ok");
            entry.version = version.to_string();
            assert!(entry.validate().is_err(), "version '{version}' must be rejected");
        }
        for version in ["0.1.0", "1.2.3", "1.2.3-rc1", "1.2.3+build7"] {
            let mut entry = sample_entry("studio.ok");
            entry.version = version.to_string();
            assert!(entry.validate().is_ok(), "version '{version}' must be accepted");
        }
    }

    #[test]
    fn rejects_oversized_or_binary_preview() {
        let mut entry = sample_entry("studio.ok");
        entry.preview = Some("x".repeat(MAX_PREVIEW_LEN + 1));
        assert!(entry.validate().is_err());
        entry.preview = Some("has\u{0}a nul".to_string());
        assert!(entry.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_entry_ids() {
        let mut index = StudioLibraryIndex::new("p_curator", 1);
        index.entries.push(sample_entry("studio.dup"));
        index.entries.push(sample_entry("studio.dup"));
        let err = index.validate().err().expect("duplicate must be rejected");
        assert!(matches!(err, IntegrationError::InvalidIdentifier(_)), "got {err:?}");
    }

    #[test]
    fn signed_index_with_invalid_entry_fails_verify() -> Result<(), IntegrationError> {
        // A curator can sign anything; verify still refuses a malformed row so
        // no downstream caller has to remember to call validate().
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x33_u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let curator_fpr = "p_curator_studio_badrow".to_string();

        let mut index = StudioLibraryIndex::new(curator_fpr.clone(), 1_700_000_000_000);
        let mut entry = sample_entry("studio.ok");
        entry.pack_url = "http://evil.example.com/pack.json".to_string();
        index.entries.push(entry);
        index.sign(&signing_key)?;

        let mut policy = ValidationPolicy::default();
        policy.trusted_public_keys.insert(curator_fpr, public_key_hex);
        let err = index.verify(&policy).err().expect("must fail");
        assert!(matches!(err, IntegrationError::InvalidIdentifier(_)), "got {err:?}");
        Ok(())
    }

    // ── Wire shape ────────────────────────────────────────────────────────

    #[test]
    fn required_tier_serialises_with_the_rcx_tier_tokens() {
        let entry = sample_entry("studio.ok");
        let value = serde_json::to_value(&entry).expect("serialise");
        assert_eq!(value["required_tier"], "pro");
        assert_eq!(value["kind"], "pack");
        // Round-trips back into the RCX enum (no parallel vocabulary).
        let back: StudioLibraryEntry = serde_json::from_value(value).expect("round-trip");
        assert_eq!(back.required_tier, Some(RcxTier::Pro));
        assert_eq!(back, entry);
    }

    #[test]
    fn absent_required_tier_is_omitted_from_the_wire() {
        let mut entry = sample_entry("studio.ok");
        entry.required_tier = None;
        entry.repo_url = None;
        entry.preview = None;
        let value = serde_json::to_value(&entry).expect("serialise");
        let obj = value.as_object().expect("object");
        assert!(!obj.contains_key("required_tier"));
        assert!(!obj.contains_key("repo_url"));
        assert!(!obj.contains_key("preview"));
    }

    #[test]
    fn index_round_trips_through_json_and_still_verifies() -> Result<(), IntegrationError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x44_u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let curator_fpr = "p_curator_studio_json".to_string();

        let mut index = StudioLibraryIndex::new(curator_fpr.clone(), 1_700_000_000_000);
        index.entries.push(sample_entry("studio.a"));
        index.entries.push(sample_entry("studio.b"));
        index.sign(&signing_key)?;

        let bytes = serde_json::to_vec(&index)?;
        let parsed: StudioLibraryIndex = serde_json::from_slice(&bytes)?;
        assert_eq!(parsed, index);

        let mut policy = ValidationPolicy::default();
        policy.trusted_public_keys.insert(curator_fpr, public_key_hex);
        parsed.verify(&policy)
    }
}
