// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Manifest contract for Crux Daemon integration packs.
//!
//! Version 1 is intentionally declarative: packs can describe MCP, HTTP, SDK,
//! CLI, file watcher, and webhook recipes, but they do not execute code inside
//! the daemon process.

pub mod c2pa_signer_selector;
pub mod conformance;
pub mod signing;
pub mod studio_index;

pub use conformance::{
    BehaviouralEnvelope, CompatibilityAssertions, ConformanceDeclarationError, DecayEnvelope, DeclaredCase,
    ExpectedFactMutation, ExpectedMutations, ExpectedReceiptMutation, FactMutationOp, InvariantKind, InvariantTest,
    MigrationAssertion, MigrationKind, PackConformance, ReceiptMutationKind, ReplayCorpus, UndoEnvelope,
    PACK_CONFORMANCE_SCHEMA_V1,
};
pub use signing::{fingerprint_from_public_key, sign_manifest, TrustedKeyEntry, TrustedKeyring};
pub use studio_index::{
    RcxTier, StudioEntryKind, StudioLibraryEntry, StudioLibraryIndex, STUDIO_LIBRARY_INDEX_SCHEMA_V1,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const INTEGRATION_SCHEMA_V1: &str = "crux.integration.v1";
pub const FIRST_PARTY_PASSPORT: &str = "cuecrux:first-party";
pub const INTEGRATION_INDEX_SCHEMA_V1: &str = "crux.integration.index.v1";

/// On-the-wire schema for the community-extensions registry index
/// (M8 of the community-extensions ExecPlan). Curator-signed JSON
/// document hosted at a stable URL (e.g.
/// `https://raw.githubusercontent.com/CueCrux/community-extensions/main/index.json`).
pub const COMMUNITY_REGISTRY_SCHEMA_V1: &str = "crux.community-extensions.index.v1";

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
    #[error("pack '{pack_id}' version '{version}' is not installed")]
    PackNotInstalled { pack_id: String, version: String },
    #[error("grant for pack '{pack_id}' and passport '{passport_fpr}' was not found")]
    GrantNotFound { pack_id: String, passport_fpr: String },
    #[error("capability '{capability}' is not declared by pack '{pack_id}'")]
    CapabilityNotDeclared { pack_id: String, capability: String },
    #[error("invalid path component '{0}'")]
    InvalidPathComponent(String),
    #[error("invalid index schema '{0}'")]
    InvalidIndexSchema(String),
    #[error("invalid conformance declaration: {0}")]
    Conformance(#[from] conformance::ConformanceDeclarationError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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
    /// HTTPS endpoint the daemon POSTs `tools/call` payloads to when
    /// `entry.kind == ExternalTool`. The daemon enforces this is the only
    /// outbound destination for the extension (egress allowlist is
    /// per-extension, not workspace-wide). Required for `ExternalTool`,
    /// must be `None` for any other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_tool_endpoint: Option<String>,
    /// Tools the extension exposes. Required + non-empty for
    /// `ExternalTool` and `Wasm`; ignored for other kinds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ExternalToolDefinition>,

    // ── Wasm-extension fields (kind == EntryKind::Wasm) ──────────────────
    /// Local filesystem path to the `.wasm` module bytes, relative to
    /// `<data_dir>/extensions/{id}/`. Required for `Wasm` when
    /// [`Self::wasm_module_url`] is unset; mutually exclusive with the
    /// URL form. Forbidden for any other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_module_path: Option<String>,
    /// HTTPS URL the daemon downloads the `.wasm` module from at install
    /// time, then caches under
    /// `<data_dir>/extensions/{id}/extension.wasm`. Mutually exclusive
    /// with [`Self::wasm_module_path`]. The download is verified against
    /// [`Self::wasm_module_sha256`] before any bytes are persisted.
    /// Forbidden for any kind other than `Wasm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_module_url: Option<String>,
    /// SHA-256 of the canonical `.wasm` module bytes, hex-encoded
    /// (lowercase, no `0x` prefix, 64 chars). Required for `Wasm`. The
    /// daemon refuses to load a module whose on-disk bytes don't match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_module_sha256: Option<String>,

    /// `pack.conformance.v1` — what the pack declares it does, so a replay
    /// can later prove whether it did that (M0 of
    /// `proof-carrying-adaptive-packs-2026-07-13`). Only valid for the kinds
    /// that execute (`ExternalTool`, `Wasm`); see
    /// [`conformance::PackConformance`].
    ///
    /// Covered by [`Self::signing_payload`], so the declaration is inside the
    /// publisher's signature rather than beside it. Skipped when absent, so a
    /// manifest that predates the block hashes and verifies exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformance: Option<conformance::PackConformance>,
}

/// One MCP-callable tool an external-tool extension exposes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalToolDefinition {
    /// Fully-qualified MCP tool name (typically `"<extension_id>.<verb>"`,
    /// e.g. `"ext.example.quote.daily"`). Globally unique across the
    /// daemon's MCP catalog.
    pub name: String,
    pub description: String,
    /// JSON Schema for the call's `arguments` object. Pass-through to MCP
    /// `tools/list`; the daemon doesn't validate against it (the
    /// extension endpoint is responsible for arg validation).
    pub input_schema: serde_json::Value,
    /// Optional semantic consequence metadata for the tool. When present, the
    /// daemon passes it through to MCP discovery so agents can reason about
    /// reversibility, materiality, idempotency, blast radius, and compensating
    /// actions before calling the tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consequence_metadata: Option<serde_json::Value>,
    /// Optional shared-secret reference: id of an entry in the daemon's
    /// `encrypted_secrets` store. The daemon decrypts this at dispatch
    /// time and forwards as `Authorization: Bearer <decrypted>` to the
    /// endpoint. None = no auth header sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_shared_secret_id: Option<String>,
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
    /// Community Phase-A external tool — the daemon proxies MCP `tools/call`
    /// out to the manifest's HTTPS endpoint with a per-call grant scope.
    /// Manifests of this kind MUST set `external_tool_endpoint` and
    /// declare at least one entry in `tools[]`.
    ExternalTool,
    /// Community Phase-B WASM module — the daemon runs the extension
    /// in-process inside a wasmtime sandbox with fuel + memory + epoch
    /// limits. Manifests of this kind MUST declare at least one entry
    /// in `tools[]` and set either `wasm_module_path` (locally bundled)
    /// or `wasm_module_url` (HTTPS download at install time), and a
    /// `wasm_module_sha256` to verify the on-disk bytes against. They
    /// MUST NOT set `external_tool_endpoint`.
    Wasm,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkAccess {
    /// Literal outbound host allowlist for `ExternalTool` endpoints. Entries
    /// are case-insensitive host names with an optional `:port`; when a port
    /// is present, it must match the endpoint's effective port. Wildcards,
    /// URL schemes, and paths are not supported. An empty list retains
    /// endpoint-pinning only.
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
    /// For `ExternalTool`, a non-zero value tightens (but never raises) the
    /// daemon-configured outbound request timeout.
    pub max_runtime_ms: u64,
    /// For `ExternalTool`, a non-zero value tightens (but never raises) the
    /// daemon-configured maximum response size.
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledPackRecord {
    pub id: String,
    pub version: String,
    pub manifest_hash: String,
    pub trust_tier: TrustTier,
    pub installed_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationGrant {
    pub passport_fpr: String,
    pub pack_id: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub enabled: bool,
    pub granted_by_passport_fpr: String,
    pub granted_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationAuditEvent {
    pub ts_unix_ms: u64,
    pub action: String,
    #[serde(default = "default_audit_actor")]
    pub actor: String,
    /// Retained for compatibility with the original pack-audit JSONL
    /// shape. New extension events put the acting passport in `actor`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub passport_fpr: String,
    pub pack_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

fn default_audit_actor() -> String {
    "operator".to_string()
}

impl IntegrationAuditEvent {
    pub fn extension(
        ts_unix_ms: u64,
        action: impl Into<String>,
        actor: Option<&str>,
        extension_id: impl Into<String>,
        version: Option<&str>,
        outcome: impl Into<String>,
        detail: serde_json::Value,
    ) -> Self {
        Self {
            ts_unix_ms,
            action: action.into(),
            actor: actor
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("operator")
                .to_string(),
            passport_fpr: String::new(),
            pack_id: extension_id.into(),
            version: version.unwrap_or_default().to_string(),
            capabilities: Vec::new(),
            outcome: outcome.into(),
            detail: Some(detail),
        }
    }
}

pub const AUDIT_EXTENSION_INSTALL: &str = "extension_install";
pub const AUDIT_EXTENSION_UNINSTALL: &str = "extension_uninstall";
pub const AUDIT_EXTENSION_GRANT_ADDED: &str = "extension_grant_added";
pub const AUDIT_EXTENSION_GRANT_REMOVED: &str = "extension_grant_removed";
pub const AUDIT_TRUSTED_KEY_ADDED: &str = "trusted_key_added";
pub const AUDIT_TRUSTED_KEY_REMOVED: &str = "trusted_key_removed";
pub const AUDIT_EXTENSION_INVOKE_OK: &str = "extension_invoke_ok";
pub const AUDIT_EXTENSION_INVOKE_REJECTED: &str = "extension_invoke_rejected";
/// A pack moved between lifecycle states (staged / active / quarantined).
/// The `detail` carries `from`, `to`, and the operator's `reason`, so the
/// audit tail alone answers "who took this pack live, and why was it put
/// back" without replaying the install-record fact chain.
pub const AUDIT_EXTENSION_LIFECYCLE: &str = "extension_lifecycle";
/// A staged pack was dispatched: it ran, and its writes were observed
/// rather than committed. Distinct from `extension_invoke_ok` precisely so
/// "this call changed memory" and "this call only proved what it would
/// change" are never conflated in the tail.
pub const AUDIT_EXTENSION_INVOKE_STAGED: &str = "extension_invoke_staged";
/// A staged pack's declared operations were replayed and observed. The
/// `detail` carries the corpus id and the run's `observed_digest`, so the
/// audit tail alone shows that a replay happened and which behaviour it
/// saw, even if the run body itself is never persisted.
pub const AUDIT_EXTENSION_CONFORMANCE_RUN: &str = "extension_conformance_run";
/// A pinned prior pack build was atomically restored. The `detail` names
/// the build moved from and to plus the operator's `reason`, so the trail
/// answers why a pack's bytes changed, not only that they did.
pub const AUDIT_EXTENSION_ROLLBACK: &str = "extension_rollback";
pub const AUDIT_SUPPRESSED: &str = "audit_suppressed";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationLibrarySnapshot {
    pub packs: Vec<IntegrationPackDescriptor>,
    pub grants: Vec<IntegrationGrant>,
    pub audit_tail: Vec<IntegrationAuditEvent>,
}

#[derive(Debug, Clone)]
pub struct GrantPackRequest<'a> {
    pub passport_fpr: &'a str,
    pub granted_by_passport_fpr: &'a str,
    pub pack_id: &'a str,
    pub version: &'a str,
    pub capabilities: &'a [String],
    pub reason: Option<String>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IntegrationIndex {
    schema: String,
    updated_at_unix_ms: u64,
    #[serde(default)]
    packs: Vec<InstalledPackRecord>,
}

#[derive(Debug, Clone)]
pub struct ValidationPolicy {
    /// When true (the original behaviour, kept for backwards compat),
    /// unsigned manifests are accepted iff the publisher fingerprint
    /// equals [`FIRST_PARTY_PASSPORT`]. The first-party packs baked into
    /// the daemon binary rely on this.
    pub allow_unsigned_first_party: bool,
    /// When true, unsigned manifests are accepted regardless of
    /// publisher. Intended for development convenience only — the
    /// daemon's HTTP layer maps this to the
    /// `CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED` environment knob and
    /// requires it to be opt-in. Default false.
    pub allow_unsigned: bool,
    pub allow_executable_helpers: bool,
    pub trusted_public_keys: BTreeMap<String, String>,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            allow_unsigned_first_party: true,
            allow_unsigned: false,
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
    /// The conformance declaration is signed with the rest of the manifest:
    /// a promise an attacker can edit after signing is not evidence. Appended
    /// last and skipped when absent so every manifest written before the
    /// block existed serialises to exactly the same bytes — and therefore to
    /// the same `manifest_hash` and the same valid signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    conformance: Option<&'a conformance::PackConformance>,
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

        // External-tool kind: endpoint + tools[] are co-required. Reject
        // either-without-the-other, and surface the requirement loudly so
        // contributors see what's missing without grepping source.
        if self.entry.kind == EntryKind::ExternalTool {
            let endpoint = self
                .external_tool_endpoint
                .as_deref()
                .ok_or(IntegrationError::MissingField("external_tool_endpoint"))?;
            if endpoint.trim().is_empty() {
                return Err(IntegrationError::MissingField("external_tool_endpoint"));
            }
            if !endpoint.starts_with("https://") && !endpoint.starts_with("http://") {
                return Err(IntegrationError::InvalidIdentifier(format!(
                    "external_tool_endpoint must be an http(s) URL, got '{endpoint}'"
                )));
            }
            if self.tools.is_empty() {
                return Err(IntegrationError::MissingField("tools"));
            }
            for tool in &self.tools {
                if tool.name.trim().is_empty() {
                    return Err(IntegrationError::MissingField("tools[].name"));
                }
                if tool.description.trim().is_empty() {
                    return Err(IntegrationError::MissingField("tools[].description"));
                }
            }
            if self.wasm_module_path.is_some() || self.wasm_module_url.is_some() || self.wasm_module_sha256.is_some() {
                return Err(IntegrationError::InvalidIdentifier(
                    "wasm_module_* fields only valid when entry.kind=wasm".to_string(),
                ));
            }
        } else if self.entry.kind == EntryKind::Wasm {
            // tools[] required + same shape as external-tool.
            if self.tools.is_empty() {
                return Err(IntegrationError::MissingField("tools"));
            }
            for tool in &self.tools {
                if tool.name.trim().is_empty() {
                    return Err(IntegrationError::MissingField("tools[].name"));
                }
                if tool.description.trim().is_empty() {
                    return Err(IntegrationError::MissingField("tools[].description"));
                }
                if tool.auth_shared_secret_id.is_some() {
                    // Wasm modules call `crux::get_secret_decrypted` directly;
                    // the wire-Bearer-header path is HTTPS-only.
                    return Err(IntegrationError::InvalidIdentifier(
                        "wasm tools must not set tools[].auth_shared_secret_id; use crux::get_secret_decrypted in-module instead".to_string(),
                    ));
                }
            }
            if self.external_tool_endpoint.is_some() {
                return Err(IntegrationError::InvalidIdentifier(
                    "external_tool_endpoint must be unset for entry.kind=wasm".to_string(),
                ));
            }
            // Module location: exactly one of path / url, plus sha256.
            let sha256 = self
                .wasm_module_sha256
                .as_deref()
                .ok_or(IntegrationError::MissingField("wasm_module_sha256"))?;
            if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
                return Err(IntegrationError::InvalidIdentifier(format!(
                    "wasm_module_sha256 must be 64 lowercase hex chars, got {} chars",
                    sha256.len()
                )));
            }
            match (self.wasm_module_path.as_deref(), self.wasm_module_url.as_deref()) {
                (Some(p), None) => {
                    if p.trim().is_empty() {
                        return Err(IntegrationError::MissingField("wasm_module_path"));
                    }
                    // Reject any path component that escapes the
                    // per-extension directory the daemon caches into.
                    if p.starts_with('/') || p.contains("..") {
                        return Err(IntegrationError::InvalidIdentifier(format!(
                            "wasm_module_path must be relative to <data_dir>/extensions/{{id}}/, got '{p}'"
                        )));
                    }
                }
                (None, Some(u)) => {
                    if !u.starts_with("https://") {
                        return Err(IntegrationError::InvalidIdentifier(format!(
                            "wasm_module_url must be an https:// URL, got '{u}'"
                        )));
                    }
                }
                (Some(_), Some(_)) => {
                    return Err(IntegrationError::InvalidIdentifier(
                        "wasm_module_path and wasm_module_url are mutually exclusive".to_string(),
                    ));
                }
                (None, None) => {
                    return Err(IntegrationError::MissingField("wasm_module_path or wasm_module_url"));
                }
            }
        } else if self.external_tool_endpoint.is_some()
            || !self.tools.is_empty()
            || self.wasm_module_path.is_some()
            || self.wasm_module_url.is_some()
            || self.wasm_module_sha256.is_some()
        {
            // Inverse rule: only `ExternalTool` / `Wasm` may set these fields.
            return Err(IntegrationError::InvalidIdentifier(format!(
                "external_tool_endpoint, tools[], or wasm_module_* fields are only valid when entry.kind in {{external_tool, wasm}}, got {:?}",
                self.entry.kind
            )));
        }

        // Before the hash + signature checks: a malformed declaration is a
        // problem with the pack regardless of who signed it, and the error
        // pack authors need to read is "your envelope does not cover your
        // declared writes", not "signature invalid".
        if let Some(declaration) = &self.conformance {
            declaration.validate(self)?;
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
        } else if !(policy.allow_unsigned
            || policy.allow_unsigned_first_party && self.publisher_passport_fpr == FIRST_PARTY_PASSPORT)
        {
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
            conformance: self.conformance.as_ref(),
        };
        Ok(serde_json::to_vec(&payload)?)
    }

    pub fn manifest_hash(&self) -> Result<String, IntegrationError> {
        let bytes = self.signing_payload()?;
        Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
    }
}

// ── Community-extensions registry index (M8) ────────────────────────────

/// One row in a curator-signed [`CommunityExtensionsIndex`]. Carries
/// enough metadata for the operator to decide whether to install,
/// plus the content-addressable shas the daemon uses to verify the
/// downloaded manifest + module bytes are exactly the ones the
/// curator endorsed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityExtensionEntry {
    /// Extension id (e.g. `ext.quote`, `ext.summarise`). Matches the
    /// id inside the published manifest.
    pub id: String,
    pub name: String,
    pub version: String,
    pub summary: String,
    /// Public HTTPS URL the manifest can be fetched from.
    pub manifest_url: String,
    /// SHA-256 of the canonical manifest JSON bytes (lowercase hex).
    pub manifest_sha256: String,
    /// Homepage / source-code URL for humans.
    pub repo_url: String,
    /// What kind of extension this is. Lets the console render the
    /// right "Phase A external-tool / Phase B WASM" badge before
    /// download.
    pub kind: EntryKind,
    /// Trust tier the curator has assigned. Operators can override
    /// at install time via their local keyring.
    pub trust_tier: TrustTier,
}

/// Curator-signed registry index. Sync flow:
/// 1. HTTPS GET the index from a configured URL.
/// 2. Verify the signature against the curator's public key.
/// 3. Cache the verified index under
///    `<data_dir>/extensions/registry/index.json`.
/// 4. `corecruxctl extensions list-registry` and the console render
///    the cached entries; install is still explicit per-extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityExtensionsIndex {
    pub schema: String,
    pub updated_at_unix_ms: u64,
    #[serde(default)]
    pub curator_passport_fpr: String,
    #[serde(default)]
    pub entries: Vec<CommunityExtensionEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,
}

#[derive(Debug, Serialize)]
struct CommunityIndexSigningPayload<'a> {
    schema: &'a str,
    updated_at_unix_ms: u64,
    curator_passport_fpr: &'a str,
    entries: &'a [CommunityExtensionEntry],
}

impl CommunityExtensionsIndex {
    pub fn new(curator_passport_fpr: impl Into<String>, now_unix_ms: u64) -> Self {
        Self {
            schema: COMMUNITY_REGISTRY_SCHEMA_V1.to_string(),
            updated_at_unix_ms: now_unix_ms,
            curator_passport_fpr: curator_passport_fpr.into(),
            entries: Vec::new(),
            signature: None,
        }
    }

    fn signing_payload(&self) -> Result<Vec<u8>, IntegrationError> {
        let payload = CommunityIndexSigningPayload {
            schema: &self.schema,
            updated_at_unix_ms: self.updated_at_unix_ms,
            curator_passport_fpr: &self.curator_passport_fpr,
            entries: &self.entries,
        };
        Ok(serde_json::to_vec(&payload)?)
    }

    /// Sign the index in place with the given Ed25519 key. The matching
    /// public key (looked up by `curator_passport_fpr`) MUST be present
    /// in the operator's `ValidationPolicy.trusted_public_keys` for
    /// [`Self::verify`] to succeed.
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

    /// Verify the signature against `policy.trusted_public_keys`. Same
    /// semantics as [`IntegrationManifest::validate`]'s signature path:
    /// inline `signature.public_key_hex` is permitted ONLY if it
    /// matches the trusted-keyring entry for `passport_fpr`.
    pub fn verify(&self, policy: &ValidationPolicy) -> Result<(), IntegrationError> {
        if self.schema != COMMUNITY_REGISTRY_SCHEMA_V1 {
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
        Ok(())
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

pub fn integration_root(data_dir: impl AsRef<Path>) -> PathBuf {
    data_dir.as_ref().join("integrations")
}

pub fn library_snapshot(
    data_dir: impl AsRef<Path>,
    passport_fpr: &str,
    policy: &ValidationPolicy,
) -> Result<IntegrationLibrarySnapshot, IntegrationError> {
    let root = integration_root(&data_dir);
    let index = read_index(&root)?;
    let grants = load_grants_from_root(&root, passport_fpr)?;
    let enabled_keys: BTreeSet<(String, String)> = grants
        .iter()
        .filter(|grant| grant.enabled)
        .map(|grant| (grant.pack_id.clone(), grant.version.clone()))
        .collect();
    let installed_keys: BTreeSet<(String, String)> = index
        .packs
        .iter()
        .map(|record| (record.id.clone(), record.version.clone()))
        .collect();

    let mut descriptors = Vec::new();
    for mut descriptor in builtin_packs()? {
        let key = (descriptor.manifest.id.clone(), descriptor.manifest.version.clone());
        descriptor.install_state = if enabled_keys.contains(&key) {
            InstallState::Enabled
        } else if installed_keys.contains(&key) {
            InstallState::Installed
        } else {
            InstallState::Available
        };
        descriptors.push(descriptor);
    }

    let builtin_keys: BTreeSet<(String, String)> = descriptors
        .iter()
        .map(|descriptor| (descriptor.manifest.id.clone(), descriptor.manifest.version.clone()))
        .collect();
    for record in index.packs {
        let key = (record.id.clone(), record.version.clone());
        if builtin_keys.contains(&key) {
            continue;
        }
        let manifest = read_installed_manifest(&root, &record.id, &record.version)?;
        manifest.validate(policy)?;
        let manifest_hash = manifest.manifest_hash()?;
        let install_state = if enabled_keys.contains(&key) {
            InstallState::Enabled
        } else {
            InstallState::Installed
        };
        descriptors.push(IntegrationPackDescriptor {
            risk_level: risk_level(&manifest),
            manifest,
            manifest_hash,
            trust_tier: record.trust_tier,
            install_state,
        });
    }

    descriptors.sort_by(|a, b| {
        a.manifest
            .id
            .cmp(&b.manifest.id)
            .then_with(|| a.manifest.version.cmp(&b.manifest.version))
    });

    Ok(IntegrationLibrarySnapshot {
        packs: descriptors,
        grants,
        audit_tail: read_audit_tail_from_root(&root, 50)?,
    })
}

pub fn install_pack(
    data_dir: impl AsRef<Path>,
    manifest: &IntegrationManifest,
    trust_tier: TrustTier,
    installed_at_unix_ms: u64,
    policy: &ValidationPolicy,
) -> Result<IntegrationPackDescriptor, IntegrationError> {
    manifest.validate(policy)?;
    let root = integration_root(&data_dir);
    let manifest_hash = manifest.manifest_hash()?;
    let id_component = safe_path_component(&manifest.id)?;
    let version_component = safe_path_component(&manifest.version)?;
    let manifest_path = root
        .join("packs")
        .join(id_component)
        .join(version_component)
        .join("manifest.json");
    write_json_atomic(&manifest_path, manifest)?;

    let mut index = read_index(&root)?;
    index.packs.retain(|record| {
        !(record.id == manifest.id && record.version == manifest.version && record.manifest_hash != manifest_hash)
    });
    if let Some(existing) = index
        .packs
        .iter_mut()
        .find(|record| record.id == manifest.id && record.version == manifest.version)
    {
        existing.manifest_hash.clone_from(&manifest_hash);
        existing.trust_tier = trust_tier;
        existing.installed_at_unix_ms = installed_at_unix_ms;
    } else {
        index.packs.push(InstalledPackRecord {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
            manifest_hash: manifest_hash.clone(),
            trust_tier,
            installed_at_unix_ms,
        });
    }
    index.updated_at_unix_ms = installed_at_unix_ms;
    index
        .packs
        .sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.version.cmp(&b.version)));
    write_json_atomic(&root.join("index.json"), &index)?;
    append_audit_event(
        data_dir,
        &IntegrationAuditEvent {
            ts_unix_ms: installed_at_unix_ms,
            action: "install".to_string(),
            actor: manifest.publisher_passport_fpr.clone(),
            passport_fpr: manifest.publisher_passport_fpr.clone(),
            pack_id: manifest.id.clone(),
            version: manifest.version.clone(),
            capabilities: manifest.capabilities.clone(),
            outcome: "installed".to_string(),
            detail: Some(serde_json::json!({ "manifest_hash": manifest_hash })),
        },
    );

    Ok(IntegrationPackDescriptor {
        risk_level: risk_level(manifest),
        manifest: manifest.clone(),
        manifest_hash,
        trust_tier,
        install_state: InstallState::Installed,
    })
}

pub fn grant_pack(
    data_dir: impl AsRef<Path>,
    request: GrantPackRequest<'_>,
) -> Result<IntegrationGrant, IntegrationError> {
    let root = integration_root(&data_dir);
    let manifest = read_installed_manifest(&root, request.pack_id, request.version)?;
    validate_capability_list(request.pack_id, request.capabilities)?;
    for capability in request.capabilities {
        if !manifest.capabilities.contains(capability) {
            return Err(IntegrationError::CapabilityNotDeclared {
                pack_id: request.pack_id.to_string(),
                capability: capability.clone(),
            });
        }
    }

    let mut requested = request.capabilities.to_vec();
    requested.sort();
    requested.dedup();
    let grant = IntegrationGrant {
        passport_fpr: request.passport_fpr.to_string(),
        pack_id: request.pack_id.to_string(),
        version: request.version.to_string(),
        capabilities: requested.clone(),
        enabled: true,
        granted_by_passport_fpr: request.granted_by_passport_fpr.to_string(),
        granted_at_unix_ms: request.now_unix_ms,
        disabled_at_unix_ms: None,
        reason: request.reason,
    };
    write_json_atomic(&grant_path(&root, request.passport_fpr, request.pack_id)?, &grant)?;
    append_audit_event(
        data_dir,
        &IntegrationAuditEvent {
            ts_unix_ms: request.now_unix_ms,
            action: "grant".to_string(),
            actor: request.granted_by_passport_fpr.to_string(),
            passport_fpr: request.passport_fpr.to_string(),
            pack_id: request.pack_id.to_string(),
            version: request.version.to_string(),
            capabilities: requested,
            outcome: "enabled".to_string(),
            detail: None,
        },
    );
    Ok(grant)
}

pub fn disable_pack(
    data_dir: impl AsRef<Path>,
    passport_fpr: &str,
    pack_id: &str,
    reason: Option<String>,
    now_unix_ms: u64,
) -> Result<IntegrationGrant, IntegrationError> {
    let root = integration_root(&data_dir);
    let path = grant_path(&root, passport_fpr, pack_id)?;
    if !path.exists() {
        return Err(IntegrationError::GrantNotFound {
            pack_id: pack_id.to_string(),
            passport_fpr: passport_fpr.to_string(),
        });
    }
    let bytes = fs::read(&path)?;
    let mut grant: IntegrationGrant = serde_json::from_slice(&bytes)?;
    grant.enabled = false;
    grant.disabled_at_unix_ms = Some(now_unix_ms);
    if reason.is_some() {
        grant.reason = reason;
    }
    write_json_atomic(&path, &grant)?;
    append_audit_event(
        data_dir,
        &IntegrationAuditEvent {
            ts_unix_ms: now_unix_ms,
            action: "disable".to_string(),
            actor: passport_fpr.to_string(),
            passport_fpr: passport_fpr.to_string(),
            pack_id: pack_id.to_string(),
            version: grant.version.clone(),
            capabilities: grant.capabilities.clone(),
            outcome: "disabled".to_string(),
            detail: None,
        },
    );
    Ok(grant)
}

/// Manifests of every pack that is **installed AND enabled by at least one
/// passport** whose entry kind matches `kind`.
///
/// This is the runtime activation predicate for daemon-side entry-kind
/// runtimes (the file-watcher runtime is the first client). It deliberately
/// scans grants across *all* passports rather than taking one
/// `passport_fpr` the way [`library_snapshot`] does: a background daemon job
/// has no calling passport, and the operator's intent ("this pack may run
/// here") is expressed by any enabled grant on the node.
///
/// A grant can only be written by [`grant_pack`], which first resolves an
/// installed manifest — so an enabled grant implies installed. The installed
/// index is still consulted so the returned manifest is the on-disk one
/// (or the builtin, when the pack ships first-party).
///
/// Missing integration root, missing grants directory, or zero grants all
/// return an empty vector — never an error. Grant files that fail to parse
/// are skipped rather than failing the whole scan, so one corrupt file cannot
/// wedge an unrelated runtime.
pub fn enabled_packs_of_kind(
    data_dir: impl AsRef<Path>,
    kind: EntryKind,
) -> Result<Vec<IntegrationManifest>, IntegrationError> {
    let root = integration_root(data_dir);
    let grants_root = root.join("grants");
    if !grants_root.exists() {
        return Ok(Vec::new());
    }

    let builtins: BTreeMap<(String, String), IntegrationManifest> = builtin_manifests()
        .into_iter()
        .map(|manifest| ((manifest.id.clone(), manifest.version.clone()), manifest))
        .collect();

    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut out = Vec::new();
    for passport_dir in fs::read_dir(&grants_root)? {
        let passport_dir = passport_dir?;
        if !passport_dir.file_type()?.is_dir() {
            continue;
        }
        for entry in fs::read_dir(passport_dir.path())? {
            let entry = entry?;
            if !entry.file_type()?.is_file()
                || entry.path().extension().and_then(|extension| extension.to_str()) != Some("json")
            {
                continue;
            }
            let Ok(bytes) = fs::read(entry.path()) else {
                continue;
            };
            let Ok(grant) = serde_json::from_slice::<IntegrationGrant>(&bytes) else {
                continue;
            };
            if !grant.enabled {
                continue;
            }
            let key = (grant.pack_id.clone(), grant.version.clone());
            if !seen.insert(key.clone()) {
                continue;
            }
            let manifest = match read_installed_manifest(&root, &grant.pack_id, &grant.version) {
                Ok(manifest) => manifest,
                // A first-party builtin that was granted without an on-disk
                // copy still counts: the manifest is compiled in.
                Err(IntegrationError::PackNotInstalled { .. }) => match builtins.get(&key) {
                    Some(manifest) => manifest.clone(),
                    None => continue,
                },
                Err(err) => return Err(err),
            };
            if manifest.entry.kind == kind {
                out.push(manifest);
            }
        }
    }

    out.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.version.cmp(&b.version)));
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
            external_tool_endpoint: None,
            tools: Vec::new(),
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
            conformance: None,
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
            external_tool_endpoint: None,
            tools: Vec::new(),
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
            conformance: None,
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
            external_tool_endpoint: None,
            tools: Vec::new(),
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
            conformance: None,
        },
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "vault.markdown-watcher".to_string(),
            name: "Markdown Vault Watcher".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: FIRST_PARTY_PASSPORT.to_string(),
            summary: "Poll local Obsidian-shaped markdown vaults and ingest changed notes into the \
                      local docs corpus. Inert until the operator sets CORECRUXD_VAULT_WATCH_ROOTS \
                      (colon-separated absolute directories); cadence via \
                      CORECRUXD_VAULT_WATCH_INTERVAL_SECS (default 300). Both this grant and the \
                      roots env are required — either alone does nothing."
                .to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::FileWatcher,
                path: "recipes/watcher/markdown-vault.json".to_string(),
            },
            capabilities: vec!["facts:write".to_string(), "facts:read".to_string()],
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
            conformance: None,
        },
        // Note: a `github.pr-facts` declarative recipe used to live here.
        // Removed in favour of the live GitHub indexer integration which
        // already pulls PRs (alongside commits + issues + comments) into
        // the fact store via /v1/integrations/github/sync. The recipe
        // entry was redundant and confusing in the Integrations panel.
    ]
}

fn read_index(root: &Path) -> Result<IntegrationIndex, IntegrationError> {
    let path = root.join("index.json");
    if !path.exists() {
        return Ok(IntegrationIndex {
            schema: INTEGRATION_INDEX_SCHEMA_V1.to_string(),
            updated_at_unix_ms: 0,
            packs: Vec::new(),
        });
    }
    let bytes = fs::read(path)?;
    let index: IntegrationIndex = serde_json::from_slice(&bytes)?;
    if index.schema != INTEGRATION_INDEX_SCHEMA_V1 {
        return Err(IntegrationError::InvalidIndexSchema(index.schema));
    }
    Ok(index)
}

fn load_grants_from_root(root: &Path, passport_fpr: &str) -> Result<Vec<IntegrationGrant>, IntegrationError> {
    let passport_dir = root.join("grants").join(safe_path_component(passport_fpr)?);
    if !passport_dir.exists() {
        return Ok(Vec::new());
    }
    let mut grants = Vec::new();
    for entry in fs::read_dir(passport_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry.path().extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let bytes = fs::read(entry.path())?;
            grants.push(serde_json::from_slice(&bytes)?);
        }
    }
    grants.sort_by(|a: &IntegrationGrant, b| a.pack_id.cmp(&b.pack_id).then_with(|| a.version.cmp(&b.version)));
    Ok(grants)
}

fn read_installed_manifest(root: &Path, pack_id: &str, version: &str) -> Result<IntegrationManifest, IntegrationError> {
    let path = root
        .join("packs")
        .join(safe_path_component(pack_id)?)
        .join(safe_path_component(version)?)
        .join("manifest.json");
    if !path.exists() {
        return Err(IntegrationError::PackNotInstalled {
            pack_id: pack_id.to_string(),
            version: version.to_string(),
        });
    }
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn read_audit_tail(
    data_dir: impl AsRef<Path>,
    max_events: usize,
) -> Result<Vec<IntegrationAuditEvent>, IntegrationError> {
    read_audit_tail_from_root(&integration_root(data_dir), max_events)
}

fn read_audit_tail_from_root(root: &Path, max_events: usize) -> Result<Vec<IntegrationAuditEvent>, IntegrationError> {
    let path = root.join("audit.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)?;
    let lines: Vec<&str> = text.lines().rev().take(max_events).collect();
    let mut events = Vec::new();
    for line in lines.into_iter().rev() {
        events.push(serde_json::from_str(line)?);
    }
    Ok(events)
}

/// Append to the unified pack + extension audit log. Audit persistence is
/// deliberately best-effort: a broken audit path is warn-logged but never
/// changes the outcome of the primary operation.
pub fn append_audit_event(data_dir: impl AsRef<Path>, event: &IntegrationAuditEvent) {
    let path = integration_root(data_dir);
    if let Err(error) = append_audit_event_to_root(&path, event) {
        tracing::warn!(
            audit_path = %path.join("audit.jsonl").display(),
            action = %event.action,
            subject_id = %event.pack_id,
            %error,
            "failed to append integration audit event"
        );
    }
}

fn append_audit_event_to_root(root: &Path, event: &IntegrationAuditEvent) -> Result<(), IntegrationError> {
    fs::create_dir_all(root)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("audit.jsonl"))?;
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    file.write_all(&line)?;
    Ok(())
}

fn grant_path(root: &Path, passport_fpr: &str, pack_id: &str) -> Result<PathBuf, IntegrationError> {
    Ok(root
        .join("grants")
        .join(safe_path_component(passport_fpr)?)
        .join(format!("{}.json", safe_path_component(pack_id)?)))
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<(), IntegrationError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn safe_path_component(value: &str) -> Result<String, IntegrationError> {
    let valid = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(value.to_string())
    } else {
        Err(IntegrationError::InvalidPathComponent(value.to_string()))
    }
}

fn validate_capability_list(pack_id: &str, capabilities: &[String]) -> Result<(), IntegrationError> {
    for capability in capabilities {
        if !ALLOWED_CAPABILITIES.contains(&capability.as_str()) {
            return Err(IntegrationError::UnknownCapability(capability.clone()));
        }
        validate_non_empty("capability", capability)?;
        if capability.contains('/') || capability.contains('\\') {
            return Err(IntegrationError::CapabilityNotDeclared {
                pack_id: pack_id.to_string(),
                capability: capability.clone(),
            });
        }
    }
    Ok(())
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

pub(crate) fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], IntegrationError> {
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
            external_tool_endpoint: None,
            tools: Vec::new(),
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
            conformance: None,
        }
    }

    /// Self-cleaning temp dir: the returned [`tempfile::TempDir`] removes itself
    /// on Drop (even when a test returns early via `?` or panics), so tests bind
    /// it to a guard instead of leaking a `crux-integrations-*` dir into `/tmp`
    /// every run. Prefix retained for debuggability.
    fn temp_data_dir(name: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("crux-integrations-{name}-"))
            .tempdir()
            .expect("create temp integration dir")
    }

    #[test]
    fn builtin_manifests_validate() -> Result<(), IntegrationError> {
        let packs = builtin_packs()?;
        // 4 first-party packs ship by default: 2 MCP configs, the TypeScript
        // SDK quickstart, and the markdown-vault file watcher. (`github.pr-facts`
        // was dropped — the live GitHub indexer covers PR fact capture.)
        assert_eq!(packs.len(), 4);
        assert!(packs.iter().all(|pack| pack.trust_tier == TrustTier::FirstParty));
        Ok(())
    }

    /// Install + grant the builtin markdown-vault watcher under `passport`.
    fn install_and_grant_vault_watcher(root: &Path, passport: &str) -> Result<(), IntegrationError> {
        let manifest = builtin_manifests()
            .into_iter()
            .find(|manifest| manifest.id == "vault.markdown-watcher")
            .expect("builtin vault watcher manifest");
        install_pack(
            root,
            &manifest,
            TrustTier::FirstParty,
            1_000,
            &ValidationPolicy::default(),
        )?;
        grant_pack(
            root,
            GrantPackRequest {
                passport_fpr: passport,
                granted_by_passport_fpr: "p_operator",
                pack_id: "vault.markdown-watcher",
                version: "0.1.0",
                capabilities: &["facts:write".to_string(), "facts:read".to_string()],
                reason: None,
                now_unix_ms: 2_000,
            },
        )?;
        Ok(())
    }

    #[test]
    fn enabled_packs_of_kind_is_empty_without_grants() -> Result<(), IntegrationError> {
        let tmp = temp_data_dir("watcher-ungranted");
        let root = tmp.path().to_path_buf();
        // Installed but never granted → not active.
        let manifest = builtin_manifests()
            .into_iter()
            .find(|manifest| manifest.id == "vault.markdown-watcher")
            .expect("builtin vault watcher manifest");
        install_pack(
            &root,
            &manifest,
            TrustTier::FirstParty,
            1_000,
            &ValidationPolicy::default(),
        )?;
        assert!(enabled_packs_of_kind(&root, EntryKind::FileWatcher)?.is_empty());
        // Missing integration root entirely → empty, not an error.
        let empty = temp_data_dir("watcher-nothing");
        assert!(enabled_packs_of_kind(empty.path(), EntryKind::FileWatcher)?.is_empty());
        Ok(())
    }

    #[test]
    fn enabled_packs_of_kind_finds_granted_file_watcher() -> Result<(), IntegrationError> {
        let tmp = temp_data_dir("watcher-granted");
        let root = tmp.path().to_path_buf();
        install_and_grant_vault_watcher(&root, "p_agent")?;

        let found = enabled_packs_of_kind(&root, EntryKind::FileWatcher)?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "vault.markdown-watcher");
        assert_eq!(found[0].entry.kind, EntryKind::FileWatcher);

        // Kind filter is exact: the same grant must not surface as an MCP pack.
        assert!(enabled_packs_of_kind(&root, EntryKind::McpConfig)?.is_empty());

        // Disabling the grant deactivates it.
        disable_pack(&root, "p_agent", "vault.markdown-watcher", None, 3_000)?;
        assert!(enabled_packs_of_kind(&root, EntryKind::FileWatcher)?.is_empty());
        Ok(())
    }

    #[test]
    fn enabled_packs_of_kind_dedupes_across_passports() -> Result<(), IntegrationError> {
        let tmp = temp_data_dir("watcher-multi-passport");
        let root = tmp.path().to_path_buf();
        install_and_grant_vault_watcher(&root, "p_agent")?;
        install_and_grant_vault_watcher(&root, "p_other")?;
        assert_eq!(enabled_packs_of_kind(&root, EntryKind::FileWatcher)?.len(), 1);
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
                ..ValidationPolicy::default()
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
                ..ValidationPolicy::default()
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
            ..ValidationPolicy::default()
        })?;
        Ok(())
    }

    #[test]
    fn rejects_tampered_signature() -> Result<(), IntegrationError> {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.to_bytes());
        let mut manifest = sample_manifest();
        let signature = signing_key.sign(&manifest.signing_payload()?);
        manifest.summary = "Tampered after signing.".to_string();
        manifest.signature = Some(SignatureEnvelope {
            alg: "ed25519".to_string(),
            passport_fpr: "p_test".to_string(),
            public_key_hex: Some(hex::encode(verifying_key.to_bytes())),
            sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        });
        let mut trusted_public_keys = BTreeMap::new();
        trusted_public_keys.insert("p_test".to_string(), public_key_hex);
        let err = manifest
            .validate(&ValidationPolicy {
                allow_unsigned_first_party: false,
                allow_executable_helpers: false,
                trusted_public_keys,
                ..ValidationPolicy::default()
            })
            .err();
        assert!(matches!(err, Some(IntegrationError::SignatureInvalid)));
        Ok(())
    }

    #[test]
    fn rejects_signature_with_only_inline_public_key() -> Result<(), IntegrationError> {
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut manifest = sample_manifest();
        let signature = signing_key.sign(&manifest.signing_payload()?);
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
                ..ValidationPolicy::default()
            })
            .err();
        assert!(matches!(err, Some(IntegrationError::MissingTrustedKey(_))));
        Ok(())
    }

    #[test]
    fn install_grant_disable_roundtrip_persists() -> Result<(), IntegrationError> {
        let tmp = temp_data_dir("grant-roundtrip");
        let root = tmp.path().to_path_buf();
        let mut manifest = builtin_manifests()
            .into_iter()
            .find(|manifest| manifest.id == "sdk.typescript.quickstart")
            .expect("builtin manifest");
        manifest.hashes.manifest = Some(manifest.manifest_hash()?);

        let descriptor = install_pack(
            &root,
            &manifest,
            TrustTier::FirstParty,
            1_000,
            &ValidationPolicy::default(),
        )?;
        assert_eq!(descriptor.install_state, InstallState::Installed);

        let grant = grant_pack(
            &root,
            GrantPackRequest {
                passport_fpr: "p_local",
                granted_by_passport_fpr: "p_local",
                pack_id: "sdk.typescript.quickstart",
                version: "0.1.0",
                capabilities: &["facts:read".to_string(), "facts:write".to_string()],
                reason: Some("test".to_string()),
                now_unix_ms: 2_000,
            },
        )?;
        assert!(grant.enabled);

        let snapshot = library_snapshot(&root, "p_local", &ValidationPolicy::default())?;
        let pack = snapshot
            .packs
            .iter()
            .find(|pack| pack.manifest.id == "sdk.typescript.quickstart")
            .expect("installed pack in snapshot");
        assert_eq!(pack.install_state, InstallState::Enabled);
        assert_eq!(snapshot.grants.len(), 1);
        assert_eq!(snapshot.audit_tail.len(), 2);

        let disabled = disable_pack(
            &root,
            "p_local",
            "sdk.typescript.quickstart",
            Some("off".to_string()),
            3_000,
        )?;
        assert!(!disabled.enabled);
        assert_eq!(disabled.disabled_at_unix_ms, Some(3_000));

        let snapshot = library_snapshot(&root, "p_local", &ValidationPolicy::default())?;
        let pack = snapshot
            .packs
            .iter()
            .find(|pack| pack.manifest.id == "sdk.typescript.quickstart")
            .expect("disabled pack in snapshot");
        assert_eq!(pack.install_state, InstallState::Installed);
        assert_eq!(snapshot.audit_tail.len(), 3);
        Ok(())
    }

    #[test]
    fn audit_tail_parses_pre_extension_jsonl_and_includes_extension_events() -> Result<(), IntegrationError> {
        let tmp = temp_data_dir("audit-backward-compat");
        let audit_root = integration_root(tmp.path());
        fs::create_dir_all(&audit_root)?;
        fs::write(
            audit_root.join("audit.jsonl"),
            concat!(
                "{\"ts_unix_ms\":1000,\"action\":\"install\",\"passport_fpr\":\"p_legacy\",",
                "\"pack_id\":\"legacy.pack\",\"version\":\"0.1.0\",\"capabilities\":[\"facts:read\"],",
                "\"outcome\":\"installed\",\"detail\":\"manifest_hash=abc\"}\n"
            ),
        )?;
        append_audit_event(
            tmp.path(),
            &IntegrationAuditEvent::extension(
                2_000,
                AUDIT_EXTENSION_INSTALL,
                Some("p_operator"),
                "ext.example.quote",
                Some("0.2.0"),
                "installed",
                serde_json::json!({ "manifest_hash": "def" }),
            ),
        );

        let snapshot = library_snapshot(tmp.path(), "p_local", &ValidationPolicy::default())?;
        assert_eq!(snapshot.audit_tail.len(), 2);
        assert_eq!(snapshot.audit_tail[0].action, "install");
        assert_eq!(snapshot.audit_tail[0].actor, "operator");
        assert_eq!(
            snapshot.audit_tail[0].detail,
            Some(serde_json::Value::String("manifest_hash=abc".to_string()))
        );
        assert_eq!(snapshot.audit_tail[1].action, AUDIT_EXTENSION_INSTALL);
        assert_eq!(snapshot.audit_tail[1].actor, "p_operator");
        Ok(())
    }

    #[test]
    fn audit_append_failure_does_not_fail_pack_install() -> Result<(), IntegrationError> {
        let tmp = temp_data_dir("audit-append-failure");
        fs::create_dir_all(integration_root(tmp.path()).join("audit.jsonl"))?;
        let manifest = builtin_manifests()
            .into_iter()
            .find(|manifest| manifest.id == "sdk.typescript.quickstart")
            .expect("builtin manifest");

        let descriptor = install_pack(
            tmp.path(),
            &manifest,
            TrustTier::FirstParty,
            1_000,
            &ValidationPolicy::default(),
        )?;
        assert_eq!(descriptor.install_state, InstallState::Installed);
        Ok(())
    }

    #[test]
    fn grant_rejects_capability_not_declared_by_pack() -> Result<(), IntegrationError> {
        let tmp = temp_data_dir("capability-subset");
        let root = tmp.path().to_path_buf();
        let manifest = builtin_manifests()
            .into_iter()
            .find(|manifest| manifest.id == "mcp.cursor")
            .expect("builtin manifest");
        install_pack(
            &root,
            &manifest,
            TrustTier::FirstParty,
            1_000,
            &ValidationPolicy::default(),
        )?;

        let err = grant_pack(
            &root,
            GrantPackRequest {
                passport_fpr: "p_local",
                granted_by_passport_fpr: "p_local",
                pack_id: "mcp.cursor",
                version: "0.1.0",
                capabilities: &["facts:write".to_string()],
                reason: None,
                now_unix_ms: 2_000,
            },
        )
        .err();
        assert!(matches!(
            err,
            Some(IntegrationError::CapabilityNotDeclared {
                pack_id,
                capability
            }) if pack_id == "mcp.cursor" && capability == "facts:write"
        ));
        Ok(())
    }

    // ── M8: community-extensions registry index ────────────────────────

    #[test]
    fn community_index_sign_then_verify_round_trip() -> Result<(), IntegrationError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xab_u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let curator_fpr = "p_curator_test".to_string();

        let mut index = CommunityExtensionsIndex::new(curator_fpr.clone(), 1_700_000_000_000);
        index.entries.push(CommunityExtensionEntry {
            id: "ext.quote".to_string(),
            name: "Quote".to_string(),
            version: "0.1.0".to_string(),
            summary: "Reference Phase A external tool.".to_string(),
            manifest_url: "https://example.com/manifest.json".to_string(),
            manifest_sha256: "0".repeat(64),
            repo_url: "https://github.com/CueCrux/example-extension-quote-of-the-day".to_string(),
            kind: EntryKind::ExternalTool,
            trust_tier: TrustTier::CommunityReviewed,
        });

        index.sign(&signing_key)?;
        assert!(index.signature.is_some());

        let mut policy = ValidationPolicy::default();
        policy.trusted_public_keys.insert(curator_fpr.clone(), public_key_hex);
        index.verify(&policy)?;
        Ok(())
    }

    #[test]
    fn community_index_rejects_tampered_entries_after_signing() -> Result<(), IntegrationError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xcd_u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let curator_fpr = "p_curator_test_tamper".to_string();

        let mut index = CommunityExtensionsIndex::new(curator_fpr.clone(), 1_700_000_000_000);
        index.entries.push(CommunityExtensionEntry {
            id: "ext.quote".to_string(),
            name: "Quote".to_string(),
            version: "0.1.0".to_string(),
            summary: "Original.".to_string(),
            manifest_url: "https://example.com/manifest.json".to_string(),
            manifest_sha256: "0".repeat(64),
            repo_url: "https://github.com/x".to_string(),
            kind: EntryKind::ExternalTool,
            trust_tier: TrustTier::CommunityReviewed,
        });
        index.sign(&signing_key)?;

        // Tamper a published field.
        index.entries[0].manifest_url = "https://attacker.example.com/evil-manifest.json".to_string();

        let mut policy = ValidationPolicy::default();
        policy.trusted_public_keys.insert(curator_fpr, public_key_hex);
        let err = index.verify(&policy).err().expect("verify must fail post-tamper");
        assert!(matches!(err, IntegrationError::SignatureInvalid), "got {err:?}");
        Ok(())
    }

    #[test]
    fn community_index_rejects_inline_pubkey_that_doesnt_match_keyring() -> Result<(), IntegrationError> {
        let curator_key = ed25519_dalek::SigningKey::from_bytes(&[0xee_u8; 32]);
        let curator_pub = hex::encode(curator_key.verifying_key().to_bytes());
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0x11_u8; 32]);
        let attacker_pub = hex::encode(attacker_key.verifying_key().to_bytes());
        let curator_fpr = "p_curator_real".to_string();

        let mut index = CommunityExtensionsIndex::new(curator_fpr.clone(), 1_700_000_000_000);
        index.entries.push(CommunityExtensionEntry {
            id: "ext.x".to_string(),
            name: "X".to_string(),
            version: "0.1.0".to_string(),
            summary: "X.".to_string(),
            manifest_url: "https://example.com/m.json".to_string(),
            manifest_sha256: "0".repeat(64),
            repo_url: "https://example.com/repo".to_string(),
            kind: EntryKind::ExternalTool,
            trust_tier: TrustTier::CommunityReviewed,
        });
        // Sign with the attacker key but fpr says it's the curator.
        index.sign(&attacker_key)?;
        // Override the signature's inline public_key_hex to claim
        // it's the curator's. Verify must reject because the keyring
        // entry doesn't match the inline value.
        if let Some(sig) = &mut index.signature {
            sig.public_key_hex = Some(attacker_pub.clone());
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
}
