// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Manifest contract for Crux Daemon integration packs.
//!
//! Version 1 is intentionally declarative: packs can describe MCP, HTTP, SDK,
//! CLI, file watcher, and webhook recipes, but they do not execute code inside
//! the daemon process.

use std::collections::BTreeMap;

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const INTEGRATION_SCHEMA_V1: &str = "crux.integration.v1";
pub const FIRST_PARTY_PASSPORT: &str = "cuecrux:first-party";

const ALLOWED_CAPABILITIES: &[&str] = &[
    "integrations:read",
    "integrations:install",
    "integrations:grant",
    "integrations:disable",
    "facts:read",
    "facts:write",
    "facts:private:read",
    "sessions:read",
    "sessions:write",
    "passport:read",
    "tenant:metadata:read",
    "tenant:chunks:read",
    "tenant:content:preview",
    "admin:read",
];

#[derive(Debug, thiserror::Error)]
pub enum IntegrationError {
    #[error("invalid integration schema '{0}'")]
    InvalidSchema(String),
    #[error("field '{0}' is required")]
    MissingField(&'static str),
    #[error("invalid identifier '{0}'")]
    InvalidIdentifier(String),
    #[error("unknown capability '{0}'")]
    UnknownCapability(String),
    #[error("external helpers are disabled by policy")]
    ExternalHelperDisabled,
    #[error("manifest hash mismatch: expected {expected}, actual {actual}")]
    ManifestHashMismatch { expected: String, actual: String },
    #[error("signature is required")]
    SignatureRequired,
    #[error("unsupported signature algorithm '{0}'")]
    UnsupportedSignatureAlgorithm(String),
    #[error("no trusted public key for passport '{0}'")]
    MissingTrustedKey(String),
    #[error("invalid signature material: {0}")]
    InvalidSignatureMaterial(String),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationManifest {
    pub schema: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher_passport_fpr: String,
    pub summary: String,
    pub entry: IntegrationEntry,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub network: NetworkAccess,
    #[serde(default)]
    pub data_access: DataAccess,
    #[serde(default)]
    pub safety: SafetyPolicy,
    #[serde(default)]
    pub hashes: ManifestHashes,
    #[serde(default)]
    pub signature: Option<SignatureEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationEntry {
    pub kind: EntryKind,
    pub path: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    McpConfig,
    HttpRecipe,
    SdkRecipe,
    CliRecipe,
    FileWatcher,
    WebhookAdapter,
    ExternalHelper,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkAccess {
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub requires_user_token: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataAccess {
    #[serde(default)]
    pub tenant_scopes: Vec<String>,
    #[serde(default)]
    pub content_preview: bool,
    #[serde(default)]
    pub private_facts: bool,
}

impl Default for DataAccess {
    fn default() -> Self {
        Self {
            tenant_scopes: vec!["selected".to_string()],
            content_preview: false,
            private_facts: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafetyPolicy {
    pub sandbox: SandboxKind,
    pub max_runtime_ms: u64,
    pub max_output_bytes: u64,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            sandbox: SandboxKind::None,
            max_runtime_ms: 0,
            max_output_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxKind {
    None,
    Command,
    Wasm,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestHashes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub alg: String,
    pub passport_fpr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    pub sig: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    FirstParty,
    LocallySigned,
    CommunityReviewed,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallState {
    Available,
    Installed,
    Enabled,
    Blocked,
    UpdateAvailable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationPackDescriptor {
    pub manifest: IntegrationManifest,
    pub manifest_hash: String,
    pub trust_tier: TrustTier,
    pub install_state: InstallState,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone)]
pub struct ValidationPolicy {
    pub allow_unsigned_first_party: bool,
    pub allow_executable_helpers: bool,
    pub trusted_public_keys: BTreeMap<String, String>,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            allow_unsigned_first_party: true,
            allow_executable_helpers: false,
            trusted_public_keys: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ManifestSigningPayload<'a> {
    schema: &'a str,
    id: &'a str,
    name: &'a str,
    version: &'a str,
    publisher_passport_fpr: &'a str,
    summary: &'a str,
    entry: &'a IntegrationEntry,
    capabilities: &'a [String],
    network: &'a NetworkAccess,
    data_access: &'a DataAccess,
    safety: &'a SafetyPolicy,
}

impl IntegrationManifest {
    pub fn validate(&self, policy: &ValidationPolicy) -> Result<(), IntegrationError> {
        if self.schema != INTEGRATION_SCHEMA_V1 {
            return Err(IntegrationError::InvalidSchema(self.schema.clone()));
        }
        validate_non_empty("id", &self.id)?;
        validate_non_empty("name", &self.name)?;
        validate_non_empty("version", &self.version)?;
        validate_non_empty("publisher_passport_fpr", &self.publisher_passport_fpr)?;
        validate_identifier(&self.id)?;
        validate_non_empty("entry.path", &self.entry.path)?;

        for capability in &self.capabilities {
            if !ALLOWED_CAPABILITIES.contains(&capability.as_str()) {
                return Err(IntegrationError::UnknownCapability(capability.clone()));
            }
        }

        if self.entry.kind == EntryKind::ExternalHelper && !policy.allow_executable_helpers {
            return Err(IntegrationError::ExternalHelperDisabled);
        }

        if let Some(expected) = &self.hashes.manifest {
            let actual = self.manifest_hash()?;
            if expected != &actual {
                return Err(IntegrationError::ManifestHashMismatch {
                    expected: expected.clone(),
                    actual,
                });
            }
        }

        if let Some(signature) = &self.signature {
            verify_signature(self, signature, policy)?;
        } else if !(policy.allow_unsigned_first_party && self.publisher_passport_fpr == FIRST_PARTY_PASSPORT) {
            return Err(IntegrationError::SignatureRequired);
        }

        Ok(())
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>, IntegrationError> {
        let payload = ManifestSigningPayload {
            schema: &self.schema,
            id: &self.id,
            name: &self.name,
            version: &self.version,
            publisher_passport_fpr: &self.publisher_passport_fpr,
            summary: &self.summary,
            entry: &self.entry,
            capabilities: &self.capabilities,
            network: &self.network,
            data_access: &self.data_access,
            safety: &self.safety,
        };
        Ok(serde_json::to_vec(&payload)?)
    }

    pub fn manifest_hash(&self) -> Result<String, IntegrationError> {
        let bytes = self.signing_payload()?;
        Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
    }
}

pub fn allowed_capabilities() -> &'static [&'static str] {
    ALLOWED_CAPABILITIES
}

pub fn builtin_packs() -> Result<Vec<IntegrationPackDescriptor>, IntegrationError> {
    let mut out = Vec::new();
    for manifest in builtin_manifests() {
        manifest.validate(&ValidationPolicy::default())?;
        let manifest_hash = manifest.manifest_hash()?;
        out.push(IntegrationPackDescriptor {
            risk_level: risk_level(&manifest),
            manifest,
            manifest_hash,
            trust_tier: TrustTier::FirstParty,
            install_state: InstallState::Available,
        });
    }
    Ok(out)
}

pub fn builtin_manifests() -> Vec<IntegrationManifest> {
    vec![
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "mcp.claude-desktop".to_string(),
            name: "Claude Desktop MCP".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: FIRST_PARTY_PASSPORT.to_string(),
            summary: "Generate a Claude Desktop MCP server entry for the local Crux Daemon.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::McpConfig,
                path: "recipes/mcp/claude-desktop.json".to_string(),
            },
            capabilities: vec!["integrations:read".to_string(), "passport:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
        },
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "mcp.cursor".to_string(),
            name: "Cursor MCP".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: FIRST_PARTY_PASSPORT.to_string(),
            summary: "Generate a Cursor .cursor/mcp.json entry for the local Crux MCP endpoint.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::McpConfig,
                path: "recipes/mcp/cursor.json".to_string(),
            },
            capabilities: vec!["integrations:read".to_string(), "passport:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
        },
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "sdk.typescript.quickstart".to_string(),
            name: "TypeScript SDK Quickstart".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: FIRST_PARTY_PASSPORT.to_string(),
            summary: "Set up TypeScript examples for facts, sessions, and event streaming.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::SdkRecipe,
                path: "recipes/sdk/typescript-quickstart.json".to_string(),
            },
            capabilities: vec![
                "integrations:read".to_string(),
                "facts:read".to_string(),
                "facts:write".to_string(),
                "sessions:read".to_string(),
            ],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
        },
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "github.pr-facts".to_string(),
            name: "GitHub PR Fact Capture".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: FIRST_PARTY_PASSPORT.to_string(),
            summary: "Capture PR review decisions and release notes as receipted facts.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::HttpRecipe,
                path: "recipes/github/pr-facts.json".to_string(),
            },
            capabilities: vec!["facts:read".to_string(), "facts:write".to_string()],
            network: NetworkAccess {
                allowed_hosts: vec!["api.github.com".to_string()],
                requires_user_token: true,
            },
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
        },
    ]
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), IntegrationError> {
    if value.trim().is_empty() {
        return Err(IntegrationError::MissingField(field));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), IntegrationError> {
    let valid = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(IntegrationError::InvalidIdentifier(value.to_string()))
    }
}

fn verify_signature(
    manifest: &IntegrationManifest,
    signature: &SignatureEnvelope,
    policy: &ValidationPolicy,
) -> Result<(), IntegrationError> {
    if signature.alg != "ed25519" {
        return Err(IntegrationError::UnsupportedSignatureAlgorithm(signature.alg.clone()));
    }

    let key_hex = signature
        .public_key_hex
        .as_ref()
        .or_else(|| policy.trusted_public_keys.get(&signature.passport_fpr))
        .ok_or_else(|| IntegrationError::MissingTrustedKey(signature.passport_fpr.clone()))?;
    let public_key = decode_fixed_hex::<32>(key_hex, "public key")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|e| IntegrationError::InvalidSignatureMaterial(format!("public key: {e}")))?;

    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&signature.sig)
        .map_err(|e| IntegrationError::InvalidSignatureMaterial(format!("signature base64: {e}")))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| IntegrationError::InvalidSignatureMaterial("signature must be 64 bytes".to_string()))?;
    let sig = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(&manifest.signing_payload()?, &sig)
        .map_err(|_| IntegrationError::SignatureInvalid)
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], IntegrationError> {
    let decoded =
        hex::decode(value).map_err(|e| IntegrationError::InvalidSignatureMaterial(format!("{label} hex: {e}")))?;
    decoded
        .try_into()
        .map_err(|_| IntegrationError::InvalidSignatureMaterial(format!("{label} must be {N} bytes")))
}

fn risk_level(manifest: &IntegrationManifest) -> RiskLevel {
    if manifest.entry.kind == EntryKind::ExternalHelper {
        return RiskLevel::Blocked;
    }
    if manifest.data_access.content_preview
        || manifest.data_access.private_facts
        || manifest.capabilities.iter().any(|c| c == "admin:read")
    {
        return RiskLevel::High;
    }
    if manifest
        .capabilities
        .iter()
        .any(|c| c.ends_with(":write") || c == "integrations:grant" || c == "integrations:install")
    {
        return RiskLevel::Medium;
    }
    RiskLevel::Low
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_manifest() -> IntegrationManifest {
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "test.pack".to_string(),
            name: "Test Pack".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: "p_test".to_string(),
            summary: "A test integration pack.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::HttpRecipe,
                path: "recipes/test.json".to_string(),
            },
            capabilities: vec!["facts:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
        }
    }

    #[test]
    fn builtin_manifests_validate() -> Result<(), IntegrationError> {
        let packs = builtin_packs()?;
        assert_eq!(packs.len(), 4);
        assert!(packs.iter().all(|pack| pack.trust_tier == TrustTier::FirstParty));
        Ok(())
    }

    #[test]
    fn rejects_unknown_capability() {
        let mut manifest = sample_manifest();
        manifest.capabilities.push("secrets:read".to_string());
        let err = manifest
            .validate(&ValidationPolicy {
                allow_unsigned_first_party: false,
                allow_executable_helpers: false,
                trusted_public_keys: BTreeMap::new(),
            })
            .err();
        assert!(matches!(err, Some(IntegrationError::UnknownCapability(cap)) if cap == "secrets:read"));
    }

    #[test]
    fn rejects_external_helper_by_default() {
        let mut manifest = sample_manifest();
        manifest.entry.kind = EntryKind::ExternalHelper;
        let err = manifest
            .validate(&ValidationPolicy {
                allow_unsigned_first_party: false,
                allow_executable_helpers: false,
                trusted_public_keys: BTreeMap::new(),
            })
            .err();
        assert!(matches!(err, Some(IntegrationError::ExternalHelperDisabled)));
    }

    #[test]
    fn detects_manifest_hash_mismatch() {
        let mut manifest = sample_manifest();
        manifest.hashes.manifest = Some("blake3:not-the-hash".to_string());
        let err = manifest.validate(&ValidationPolicy::default()).err();
        assert!(matches!(err, Some(IntegrationError::ManifestHashMismatch { .. })));
    }

    #[test]
    fn verifies_signature_with_keyring() -> Result<(), IntegrationError> {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.to_bytes());
        let mut manifest = sample_manifest();
        let signature = signing_key.sign(&manifest.signing_payload()?);
        manifest.signature = Some(SignatureEnvelope {
            alg: "ed25519".to_string(),
            passport_fpr: "p_test".to_string(),
            public_key_hex: None,
            sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        });
        let mut trusted_public_keys = BTreeMap::new();
        trusted_public_keys.insert("p_test".to_string(), public_key_hex);

        manifest.validate(&ValidationPolicy {
            allow_unsigned_first_party: false,
            allow_executable_helpers: false,
            trusted_public_keys,
        })?;
        Ok(())
    }

    #[test]
    fn rejects_tampered_signature() -> Result<(), IntegrationError> {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut manifest = sample_manifest();
        let signature = signing_key.sign(&manifest.signing_payload()?);
        manifest.summary = "Tampered after signing.".to_string();
        manifest.signature = Some(SignatureEnvelope {
            alg: "ed25519".to_string(),
            passport_fpr: "p_test".to_string(),
            public_key_hex: Some(hex::encode(verifying_key.to_bytes())),
            sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        });
        let err = manifest
            .validate(&ValidationPolicy {
                allow_unsigned_first_party: false,
                allow_executable_helpers: false,
                trusted_public_keys: BTreeMap::new(),
            })
            .err();
        assert!(matches!(err, Some(IntegrationError::SignatureInvalid)));
        Ok(())
    }
}
