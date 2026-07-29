// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

#![deny(clippy::unwrap_used, clippy::expect_used)]

//! RCX Capability Token schema-lock and strict verification crate.
//!
//! Legacy v1.0 tokens remain byte-stable. Delegation-capable v1.1 tokens opt in
//! through an issuer-signed policy and require recipient proof of possession,
//! a verifier-issued nonce, and an exact request context.
//!
//! A v1.1 token is *contextual*: the generic `verify_token` path fails it closed,
//! so a delegation-aware verifier (`verify_token_attenuated`) must be deployed
//! before any v1.1 token is minted — mint-before-verify. The spec version is not
//! bumped per token beyond `rcx-ct/1.1`; the fail-closed guarantee for older
//! verifiers comes from `#[serde(deny_unknown_fields)]` and the contextual gate,
//! not a version field.

use crux_session::canonical::{to_canonical_json, CborValue};
use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey};
use serde::Deserialize;

pub const RCX_CT_SPEC_VERSION: &str = "rcx-ct/1.0";
pub const RCX_CT_DELEGATION_SPEC_VERSION: &str = "rcx-ct/1.1";
pub const RCX_CT_SIGNATURE_LEN: usize = 64;
pub const RCX_CT_HASH_LEN: usize = 32;
pub const RCX_CT_PUBLIC_KEY_LEN: usize = 32;
pub const RCX_DELEGATION_ENVELOPE_VERSION: u8 = 1;
pub const RCX_SYNC_DELEGATION_AUDIENCE: &str = "crux-sync";
/// Backend id a CruxEngine-issued sync-delegation token carries, and the
/// `AttenuationContext.backend_id` the sync boundary presents (macaroon M3′).
/// Distinct from `"local"` (the router's signature short-circuit) and from the
/// legacy hosted backend id.
pub const RCX_SYNC_BACKEND_ID: &str = "crux-sync";
/// Capability for a delegated sync **read** (tenant manifest/collection pull).
pub const RCX_SYNC_PULL_CAPABILITY: &str = "corecrux.sync.pull";
/// Capability for a delegated sync **write** (tenant promote/offboard push).
pub const RCX_SYNC_PUSH_CAPABILITY: &str = "corecrux.sync.push";
/// Attestation the sync boundary presents once the peer handshake has proven
/// possession of the delegate key; sync-delegation capabilities require it.
pub const RCX_SYNC_PASSPORT_ATTESTATION: &str = "passport_bound";
pub const RCX_MAX_DELEGATION_CAVEATS: usize = 16;
pub const RCX_MAX_DELEGATION_SCOPES: usize = 64;
pub const RCX_MAX_DELEGATION_PRINCIPALS: usize = 64;
pub const RCX_MAX_DELEGATION_VALUE_LEN: usize = 128;
pub const RCX_HOSTED_BACKEND_ID: &str = "hosted.vaultcrux.com";
pub const RCX_HOSTED_RETRIEVE_CAPABILITY: &str = "vaultcrux.retrieve";
pub const RCX_TEAM_CONSTRAINTS_SYNC_CAPABILITY: &str = "vaultcrux.team.constraints.sync";
pub const RCX_TEAM_DECISIONS_SYNC_CAPABILITY: &str = "vaultcrux.team.decisions.sync";
pub const RCX_CUSTOMER_BACKEND_PREFIX: &str = "customer:";
pub const RCX_ENTERPRISE_ENCRYPTED_BLOB_MIRROR_CAPABILITY: &str = "vaultcrux.enterprise.encrypted_blob.mirror";

// ── CoreCrux retrieval-lane registry (free → paid) ───────────────────────────
//
// The AMR lane authority in CoreCrux (`corecrux-rcx-token::lanes`) gates the 13
// premium retrieval lanes on a verified token capability. These constants are
// the MINT side: a paid token carries one `corecrux.lane.<slug>` capability per
// premium lane. The slugs MUST stay identical to the CoreCrux `lanes::Lane`
// vocabulary (free baseline bm25/dense/sparse are never minted — never gated).
//
// `rerank` / `dense_managed` are the metered "better dense" upsell (ExecPlan
// dense-lane-and-extraction-upsell / corecrux-dense-extraction-services). They are
// premium like the rest — local dense retrieval is the FREE `dense` baseline lane
// and is never clipped (C1).
pub const CORECRUX_LANE_CAPABILITY_PREFIX: &str = "corecrux.lane.";

/// The 13 premium retrieval-lane slugs. Order is the canonical lane order
/// (must match CoreCrux `lanes::ALL_LANES` premium ordering).
pub const CORECRUX_PREMIUM_LANE_SLUGS: [&str; 13] = [
    "topology",
    "trait",
    "entity",
    "event",
    "event_count",
    "projection",
    "navtree",
    "vernacular",
    "indexing",
    "hyde",
    "amr_orchestration",
    "rerank",
    "dense_managed",
];

/// Full capability name for a lane slug, e.g. `corecrux.lane.topology`.
pub fn corecrux_lane_capability(slug: &str) -> String {
    format!("{CORECRUX_LANE_CAPABILITY_PREFIX}{slug}")
}

/// Per-call credit cost for a premium lane. Most premium lanes use the token's
/// base `per_call_cost`; the metered dense lanes are priced explicitly (3:1):
/// `rerank` = 3 (a K-pass cross-encoder over the candidate window, heavy per
/// query) vs `dense_managed` = 1 (a single hosted query embedding). MUST match
/// the hosted TS minter (`@cuecrux-shared/contracts::CORECRUX_LANE_CREDIT_COST`).
pub fn corecrux_lane_credit_cost(slug: &str, per_call_cost: u64) -> u64 {
    match slug {
        "rerank" => 3,
        "dense_managed" => 1,
        _ => per_call_cost,
    }
}

/// Permitted-capability set for a PAID token: every premium lane (Text egress).
/// Most cost `per_call_cost` credits/call; the metered dense lanes are priced by
/// [`corecrux_lane_credit_cost`]. Free tokens carry none of these, so their
/// premium lanes are hard-gated off in CoreCrux.
pub fn corecrux_premium_lane_capabilities(per_call_cost: u64) -> Vec<PermittedCapability> {
    CORECRUX_PREMIUM_LANE_SLUGS
        .iter()
        .map(|slug| PermittedCapability {
            capability: corecrux_lane_capability(slug),
            data_egress_classes: vec![DataEgressClass::Text],
            required_attestations: Vec::new(),
            credit_cost: Some(CreditCost {
                unit: CreditCostUnit::Call,
                cost: corecrux_lane_credit_cost(slug, per_call_cost),
            }),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RcxTier {
    Free,
    Pro,
    Team,
    Enterprise,
}

impl RcxTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Pro => "pro",
            Self::Team => "team",
            Self::Enterprise => "enterprise",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptClass {
    Verified,
    Dev,
    Replay,
}

impl ReceiptClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Dev => "dev",
            Self::Replay => "replay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataEgressClass {
    None,
    Vectors,
    ReceiptHashes,
    ConstraintRecords,
    DecisionRecords,
    EncryptedBlob,
    Text,
}

impl DataEgressClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Vectors => "vectors",
            Self::ReceiptHashes => "receipt_hashes",
            Self::ConstraintRecords => "constraint_records",
            Self::DecisionRecords => "decision_records",
            Self::EncryptedBlob => "encrypted_blob",
            Self::Text => "text",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditCostUnit {
    Call,
    Token,
    Byte,
}

impl CreditCostUnit {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Token => "token",
            Self::Byte => "byte",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefillPeriod {
    Daily,
    Monthly,
    None,
}

impl RefillPeriod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Monthly => "monthly",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverdraftPolicy {
    Forbid,
    Warn,
    AllowToLimit,
}

impl OverdraftPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Forbid => "forbid",
            Self::Warn => "warn",
            Self::AllowToLimit => "allow_to_limit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackAction {
    DegradeToLocal,
    Refuse,
    Queue,
}

impl FallbackAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DegradeToLocal => "degrade_to_local",
            Self::Refuse => "refuse",
            Self::Queue => "queue",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    pub passport_kid: String,
    pub issuer_org: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub passport_fpr: String,
    pub daemon_instance_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantScope {
    pub tenant_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamSeatRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl TeamSeatRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamScope {
    pub team_id: String,
    pub seat_id: Option<String>,
    pub seat_role: Option<TeamSeatRole>,
    pub pooled_credit_agent_id: String,
    pub principal_passport_fprs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseScope {
    pub customer_id: String,
    pub contract_id: Option<String>,
    pub backend_id: String,
    pub endpoint_url: String,
    pub trust_root_kid: String,
    pub airgap: bool,
    pub cross_signed_by_vaultcrux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreditCost {
    pub unit: CreditCostUnit,
    pub cost: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermittedCapability {
    pub capability: String,
    pub data_egress_classes: Vec<DataEgressClass>,
    pub required_attestations: Vec<String>,
    pub credit_cost: Option<CreditCost>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub backend_id: String,
    pub trust_root_kid: String,
    pub endpoint_url: Option<String>,
    pub permitted_capabilities: Vec<PermittedCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreditRefill {
    pub period: RefillPeriod,
    pub amount: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credits {
    pub balance: Option<u64>,
    pub refill: CreditRefill,
    pub overdraft: OverdraftPolicy,
    pub overdraft_limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackPolicy {
    pub on_backend_unreachable: FallbackAction,
    pub on_credits_exhausted: FallbackAction,
    pub on_expiry: FallbackAction,
    pub queue_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub crl_url: Option<String>,
    pub push_channel: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub alg: String,
    pub kid: String,
    #[serde(deserialize_with = "deserialize_signature_hex")]
    pub sig: [u8; RCX_CT_SIGNATURE_LEN],
}

fn deserialize_signature_hex<'de, D>(deserializer: D) -> Result<[u8; RCX_CT_SIGNATURE_LEN], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let decoded = hex::decode(encoded).map_err(serde::de::Error::custom)?;
    decoded
        .try_into()
        .map_err(|_| serde::de::Error::custom("signature.sig must be exactly 64 bytes of hex"))
}

fn deserialize_public_key_hex<'de, D>(deserializer: D) -> Result<[u8; RCX_CT_PUBLIC_KEY_LEN], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let decoded = hex::decode(encoded).map_err(serde::de::Error::custom)?;
    decoded
        .try_into()
        .map_err(|_| serde::de::Error::custom("delegation public keys must be exactly 32 bytes of hex"))
}

/// A first-party caveat: a restriction an issuer-named subject uses to narrow a
/// recipient-bound token. Unknown variants or fields fail deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Caveat {
    /// The effective expiry must be ≤ this instant (shrink lifetime only).
    ExpiresAtLe { expires_at: u64 },
    /// The tenant scope must be exactly this tenant (already permitted by the grant).
    TenantIdEq { tenant_id: String },
    /// The usable scope must be a subset of these entries.
    ScopeSubset { scopes: Vec<String> },
}

/// Issuer-signed opt-in policy for PoP-only, one-hop delegation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationPolicy {
    pub presentation: DelegationPresentation,
    pub max_depth: u8,
    pub audience: DelegationAudience,
    pub allowed_delegate_fprs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationPresentation {
    ProofOfPossession,
}

impl DelegationPresentation {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProofOfPossession => "proof_of_possession",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DelegationAudience {
    CruxSync,
}

impl DelegationAudience {
    fn as_str(self) -> &'static str {
        match self {
            Self::CruxSync => RCX_SYNC_DELEGATION_AUDIENCE,
        }
    }
}

/// Atomic one-hop envelope signed by the issuer-named subject.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationEnvelope {
    pub version: u8,
    pub delegation_id: String,
    pub audience: DelegationAudience,
    #[serde(deserialize_with = "deserialize_public_key_hex")]
    pub delegator_public_key: [u8; RCX_CT_PUBLIC_KEY_LEN],
    #[serde(deserialize_with = "deserialize_public_key_hex")]
    pub delegate_public_key: [u8; RCX_CT_PUBLIC_KEY_LEN],
    pub caveats: Vec<Caveat>,
    #[serde(deserialize_with = "deserialize_signature_hex")]
    pub signature: [u8; RCX_CT_SIGNATURE_LEN],
}

pub const DELEGATION_BINDING_DOMAIN: &[u8] = b"rcx-capability-token/delegation-envelope/v1\0";
pub const PRESENTATION_PROOF_DOMAIN: &[u8] = b"rcx-capability-token/presentation-proof/v1\0";

/// Canonical bytes signed by the subject. Every envelope field and the exact
/// issuer-signed base token are bound.
pub fn delegation_binding_message(
    base_token_hash: &[u8; RCX_CT_HASH_LEN],
    version: u8,
    delegation_id: &str,
    audience: DelegationAudience,
    delegator_public_key: &[u8; RCX_CT_PUBLIC_KEY_LEN],
    delegate_public_key: &[u8; RCX_CT_PUBLIC_KEY_LEN],
    caveats: &[Caveat],
) -> Vec<u8> {
    let mut message = DELEGATION_BINDING_DOMAIN.to_vec();
    message.extend_from_slice(
        &CborValue::Map(vec![
            (
                "base_token_hash".to_string(),
                CborValue::Bytes(base_token_hash.to_vec()),
            ),
            ("version".to_string(), CborValue::Uint(u64::from(version))),
            ("delegation_id".to_string(), CborValue::Text(delegation_id.to_string())),
            ("audience".to_string(), CborValue::Text(audience.as_str().to_string())),
            (
                "delegator_public_key".to_string(),
                CborValue::Bytes(delegator_public_key.to_vec()),
            ),
            (
                "delegate_public_key".to_string(),
                CborValue::Bytes(delegate_public_key.to_vec()),
            ),
            (
                "caveats".to_string(),
                CborValue::Array(caveats.iter().map(caveat_to_cbor).collect()),
            ),
        ])
        .encode(),
    );
    message
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttenuationContext<'a> {
    pub audience: DelegationAudience,
    pub tenant_id: &'a str,
    pub backend_id: &'a str,
    pub capability: &'a str,
    pub data_egress_classes: &'a [DataEgressClass],
    pub present_attestations: &'a [&'a str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationProof<'a> {
    pub public_key: [u8; RCX_CT_PUBLIC_KEY_LEN],
    pub nonce: &'a [u8],
    pub signature: [u8; RCX_CT_SIGNATURE_LEN],
}

/// Challenge signed by the presenter. It binds the full wire token, exact
/// request context, and a verifier-issued nonce.
pub fn presentation_proof_message(
    token: &RcxCapabilityToken,
    context: AttenuationContext<'_>,
    nonce: &[u8],
) -> Vec<u8> {
    let token_digest = blake3::hash(&token.to_canonical_cbor());
    let mut egress: Vec<&str> = context
        .data_egress_classes
        .iter()
        .map(DataEgressClass::as_str)
        .collect();
    egress.sort_unstable();
    egress.dedup();
    let mut attestations = context.present_attestations.to_vec();
    attestations.sort_unstable();
    attestations.dedup();

    let mut message = PRESENTATION_PROOF_DOMAIN.to_vec();
    message.extend_from_slice(
        &CborValue::Map(vec![
            (
                "token_digest".to_string(),
                CborValue::Bytes(token_digest.as_bytes().to_vec()),
            ),
            (
                "audience".to_string(),
                CborValue::Text(context.audience.as_str().to_string()),
            ),
            ("tenant_id".to_string(), CborValue::Text(context.tenant_id.to_string())),
            (
                "backend_id".to_string(),
                CborValue::Text(context.backend_id.to_string()),
            ),
            (
                "capability".to_string(),
                CborValue::Text(context.capability.to_string()),
            ),
            (
                "data_egress_classes".to_string(),
                CborValue::Array(
                    egress
                        .into_iter()
                        .map(|value| CborValue::Text(value.to_string()))
                        .collect(),
                ),
            ),
            (
                "present_attestations".to_string(),
                CborValue::Array(
                    attestations
                        .into_iter()
                        .map(|value| CborValue::Text(value.to_string()))
                        .collect(),
                ),
            ),
            ("nonce".to_string(), CborValue::Bytes(nonce.to_vec())),
        ])
        .encode(),
    );
    message
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttenuateError {
    DelegationNotPermitted,
    AlreadyDelegated,
    DelegatorMismatch,
    DelegateNotPermitted,
    SelfDelegation,
    InvalidDelegationId,
    EmptyCaveats,
    InvalidCaveatEncoding,
    CaveatDoesNotNarrow,
    CaveatOutsideBaseGrant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttenuation {
    pub actor_fpr: String,
    pub delegated_by: Option<String>,
    pub delegation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttenuatedOutcome {
    Verified(VerifiedAttenuation),
    Base(VerifyOutcome),
    ContextDenied,
    DelegationNotPermitted,
    DelegatorMismatch,
    DelegateMismatch,
    SelfDelegation,
    PrincipalRevoked,
    BadPossessionProof,
    MalformedEnvelope,
    BadDelegationSignature,
    CaveatDenied,
}

/// Verify a subject-PoP base or recipient-bound one-hop delegation. The caller
/// owns nonce issuance and must consume the outstanding nonce atomically after a
/// successful result; the independently supplied `expected_nonce` prevents a
/// captured proof from satisfying a fresh challenge.
pub fn verify_token_attenuated<F>(
    token: &RcxCapabilityToken,
    trust_root_pubkey: &[u8],
    now_unix_seconds: u64,
    proof: &PresentationProof<'_>,
    expected_nonce: &[u8],
    context: AttenuationContext<'_>,
    is_principal_revoked: F,
) -> AttenuatedOutcome
where
    F: Fn(&str) -> bool,
{
    match verify_issuer_signed_token(token, trust_root_pubkey, now_unix_seconds) {
        VerifyOutcome::Verified => {}
        other => return AttenuatedOutcome::Base(other),
    }

    if token.delegation_envelope.as_ref().is_some_and(|envelope| {
        envelope.version != RCX_DELEGATION_ENVELOPE_VERSION
            || !valid_delegation_id(&envelope.delegation_id)
            || envelope.caveats.is_empty()
            || !caveats_are_canonical(&envelope.caveats)
    }) {
        return AttenuatedOutcome::MalformedEnvelope;
    }

    if token.tenant_scope.tenant_id != context.tenant_id
        || !token.backends.iter().any(|backend| {
            backend.backend_id == context.backend_id
                && backend.permitted_capabilities.iter().any(|permitted| {
                    permitted.capability == context.capability
                        && context
                            .data_egress_classes
                            .iter()
                            .all(|required| permitted.data_egress_classes.iter().any(|allowed| allowed == required))
                        && permitted
                            .required_attestations
                            .iter()
                            .all(|required| context.present_attestations.iter().any(|present| present == required))
                })
        })
    {
        return AttenuatedOutcome::ContextDenied;
    }

    if expected_nonce.is_empty() || proof.nonce != expected_nonce {
        return AttenuatedOutcome::BadPossessionProof;
    }
    let presenter_key = match VerifyingKey::from_bytes(&proof.public_key) {
        Ok(key) => key,
        Err(_) => return AttenuatedOutcome::BadPossessionProof,
    };
    let message = presentation_proof_message(token, context, proof.nonce);
    if presenter_key
        .verify_strict(&message, &Ed25519Signature::from_bytes(&proof.signature))
        .is_err()
    {
        return AttenuatedOutcome::BadPossessionProof;
    }

    let subject_fpr = token.subject.passport_fpr.as_str();
    if is_principal_revoked(subject_fpr) {
        return AttenuatedOutcome::PrincipalRevoked;
    }

    let Some(envelope) = token.delegation_envelope.as_ref() else {
        if token
            .delegation_policy
            .as_ref()
            .is_some_and(|policy| policy.audience != context.audience)
        {
            return AttenuatedOutcome::ContextDenied;
        }
        return if crux_session::passport::passport_fpr_from_public_key(&proof.public_key) == subject_fpr {
            AttenuatedOutcome::Verified(VerifiedAttenuation {
                actor_fpr: subject_fpr.to_string(),
                delegated_by: None,
                delegation_id: None,
            })
        } else {
            AttenuatedOutcome::DelegateMismatch
        };
    };

    let Some(policy) = token.delegation_policy.as_ref() else {
        return AttenuatedOutcome::DelegationNotPermitted;
    };
    if token.spec_version != RCX_CT_DELEGATION_SPEC_VERSION
        || policy.presentation != DelegationPresentation::ProofOfPossession
        || policy.max_depth != 1
    {
        return AttenuatedOutcome::DelegationNotPermitted;
    }
    if policy.audience != context.audience || envelope.audience != policy.audience {
        return AttenuatedOutcome::ContextDenied;
    }
    if crux_session::passport::passport_fpr_from_public_key(&envelope.delegator_public_key) != subject_fpr {
        return AttenuatedOutcome::DelegatorMismatch;
    }
    let delegate_fpr = crux_session::passport::passport_fpr_from_public_key(&envelope.delegate_public_key);
    if delegate_fpr == subject_fpr {
        return AttenuatedOutcome::SelfDelegation;
    }
    if envelope.delegate_public_key != proof.public_key {
        return AttenuatedOutcome::DelegateMismatch;
    }
    if !policy
        .allowed_delegate_fprs
        .iter()
        .any(|allowed| allowed == &delegate_fpr)
        || token.team_scope.as_ref().is_some_and(|team| {
            !team
                .principal_passport_fprs
                .iter()
                .any(|allowed| allowed == &delegate_fpr)
        })
    {
        return AttenuatedOutcome::DelegationNotPermitted;
    }
    if is_principal_revoked(&delegate_fpr) {
        return AttenuatedOutcome::PrincipalRevoked;
    }

    let delegator_key = match VerifyingKey::from_bytes(&envelope.delegator_public_key) {
        Ok(key) => key,
        Err(_) => return AttenuatedOutcome::DelegatorMismatch,
    };
    let message = delegation_binding_message(
        &token.token_hash(),
        envelope.version,
        &envelope.delegation_id,
        envelope.audience,
        &envelope.delegator_public_key,
        &envelope.delegate_public_key,
        &envelope.caveats,
    );
    if delegator_key
        .verify_strict(&message, &Ed25519Signature::from_bytes(&envelope.signature))
        .is_err()
    {
        return AttenuatedOutcome::BadDelegationSignature;
    }
    if validate_caveats_against_base(token, &envelope.caveats).is_err() {
        return AttenuatedOutcome::CaveatDenied;
    }
    if now_unix_seconds >= token.attenuated_expires_at()
        || !token.caveats_permit_tenant(context.tenant_id)
        || !token.caveats_permit_capability(context.capability)
    {
        return AttenuatedOutcome::CaveatDenied;
    }

    AttenuatedOutcome::Verified(VerifiedAttenuation {
        actor_fpr: delegate_fpr,
        delegated_by: Some(subject_fpr.to_string()),
        delegation_id: Some(envelope.delegation_id.clone()),
    })
}

fn caveat_to_cbor(caveat: &Caveat) -> CborValue {
    match caveat {
        Caveat::ExpiresAtLe { expires_at } => CborValue::Map(vec![
            ("type".to_string(), CborValue::Text("expires_at_le".to_string())),
            ("expires_at".to_string(), CborValue::Uint(*expires_at)),
        ]),
        Caveat::TenantIdEq { tenant_id } => CborValue::Map(vec![
            ("type".to_string(), CborValue::Text("tenant_id_eq".to_string())),
            ("tenant_id".to_string(), CborValue::Text(tenant_id.clone())),
        ]),
        Caveat::ScopeSubset { scopes } => CborValue::Map(vec![
            ("type".to_string(), CborValue::Text("scope_subset".to_string())),
            (
                "scopes".to_string(),
                CborValue::Array(scopes.iter().map(|s| CborValue::Text(s.clone())).collect()),
            ),
        ]),
    }
}

fn caveats_are_canonical(caveats: &[Caveat]) -> bool {
    if caveats.is_empty() || caveats.len() > RCX_MAX_DELEGATION_CAVEATS {
        return false;
    }

    let mut previous: Option<Vec<u8>> = None;
    for caveat in caveats {
        let valid = match caveat {
            Caveat::ExpiresAtLe { .. } => true,
            Caveat::TenantIdEq { tenant_id } => valid_delegation_value(tenant_id),
            Caveat::ScopeSubset { scopes } => {
                !scopes.is_empty()
                    && scopes.len() <= RCX_MAX_DELEGATION_SCOPES
                    && scopes.iter().all(|scope| valid_delegation_value(scope))
                    && scopes.windows(2).all(|pair| pair[0] < pair[1])
            }
        };
        if !valid {
            return false;
        }

        let encoded = caveat_to_cbor(caveat).encode();
        if previous.as_ref().is_some_and(|prior| prior >= &encoded) {
            return false;
        }
        previous = Some(encoded);
    }
    true
}

fn normalize_scope_caveats(caveats: &mut [Caveat]) {
    for caveat in caveats.iter_mut() {
        if let Caveat::ScopeSubset { scopes } = caveat {
            scopes.sort();
            scopes.dedup();
        }
    }
    caveats.sort_by_key(|caveat| caveat_to_cbor(caveat).encode());
}

fn validate_caveats_against_base(token: &RcxCapabilityToken, caveats: &[Caveat]) -> Result<(), AttenuateError> {
    if caveats.is_empty() {
        return Err(AttenuateError::EmptyCaveats);
    }
    if !caveats_are_canonical(caveats) {
        return Err(AttenuateError::InvalidCaveatEncoding);
    }

    let base_capabilities: std::collections::BTreeSet<&str> = token
        .backends
        .iter()
        .flat_map(|backend| {
            backend
                .permitted_capabilities
                .iter()
                .map(|permitted| permitted.capability.as_str())
        })
        .collect();
    let mut strictly_narrows = false;

    for caveat in caveats {
        match caveat {
            Caveat::ExpiresAtLe { expires_at } => {
                if *expires_at > token.expires_at {
                    return Err(AttenuateError::CaveatOutsideBaseGrant);
                }
                strictly_narrows |= *expires_at < token.expires_at;
            }
            Caveat::TenantIdEq { tenant_id } => {
                if tenant_id != &token.tenant_scope.tenant_id {
                    return Err(AttenuateError::CaveatOutsideBaseGrant);
                }
            }
            Caveat::ScopeSubset { scopes } => {
                if scopes.iter().any(|scope| !base_capabilities.contains(scope.as_str())) {
                    return Err(AttenuateError::CaveatOutsideBaseGrant);
                }
                strictly_narrows |= scopes.len() < base_capabilities.len();
            }
        }
    }

    if strictly_narrows {
        Ok(())
    } else {
        Err(AttenuateError::CaveatDoesNotNarrow)
    }
}

fn valid_delegation_id(value: &str) -> bool {
    valid_delegation_value(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_delegation_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= RCX_MAX_DELEGATION_VALUE_LEN && !value.chars().any(char::is_control)
}

fn valid_passport_fpr(value: &str) -> bool {
    value.len() == 34
        && value.starts_with("p_")
        && value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn delegation_policy_to_cbor(policy: &DelegationPolicy) -> CborValue {
    CborValue::Map(vec![
        (
            "presentation".to_string(),
            CborValue::Text(policy.presentation.as_str().to_string()),
        ),
        ("max_depth".to_string(), CborValue::Uint(u64::from(policy.max_depth))),
        (
            "audience".to_string(),
            CborValue::Text(policy.audience.as_str().to_string()),
        ),
        (
            "allowed_delegate_fprs".to_string(),
            CborValue::Array(
                policy
                    .allowed_delegate_fprs
                    .iter()
                    .map(|fpr| CborValue::Text(fpr.clone()))
                    .collect(),
            ),
        ),
    ])
}

fn delegation_envelope_to_cbor(envelope: &DelegationEnvelope) -> CborValue {
    CborValue::Map(vec![
        ("version".to_string(), CborValue::Uint(u64::from(envelope.version))),
        (
            "delegation_id".to_string(),
            CborValue::Text(envelope.delegation_id.clone()),
        ),
        (
            "audience".to_string(),
            CborValue::Text(envelope.audience.as_str().to_string()),
        ),
        (
            "delegator_public_key".to_string(),
            CborValue::Bytes(envelope.delegator_public_key.to_vec()),
        ),
        (
            "delegate_public_key".to_string(),
            CborValue::Bytes(envelope.delegate_public_key.to_vec()),
        ),
        (
            "caveats".to_string(),
            CborValue::Array(envelope.caveats.iter().map(caveat_to_cbor).collect()),
        ),
        ("signature".to_string(), CborValue::Bytes(envelope.signature.to_vec())),
    ])
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RcxCapabilityToken {
    pub spec_version: String,
    pub token_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub refresh_hint_at: u64,
    pub issuer: Issuer,
    pub subject: Subject,
    pub tenant_scope: TenantScope,
    pub team_scope: Option<TeamScope>,
    pub enterprise_scope: Option<EnterpriseScope>,
    pub tier: RcxTier,
    pub receipt_class: ReceiptClass,
    pub backends: Vec<Backend>,
    pub credits: Credits,
    pub fallback: FallbackPolicy,
    pub revocation: Revocation,
    /// Issuer-signed opt-in. Its absence preserves the exact v1.0 signing bytes.
    #[serde(default)]
    pub delegation_policy: Option<DelegationPolicy>,
    /// Subject-signed one-hop delegation. It is a presentation envelope, so it is
    /// carried on the wire but excluded from the issuer's signing bytes.
    #[serde(default)]
    pub delegation_envelope: Option<DelegationEnvelope>,
    pub signature: Signature,
}

impl RcxCapabilityToken {
    pub fn to_cbor_value(&self, zero_signature: bool) -> CborValue {
        let mut pairs = vec![
            ("spec_version".to_string(), CborValue::Text(self.spec_version.clone())),
            ("token_id".to_string(), CborValue::Text(self.token_id.clone())),
            ("issued_at".to_string(), CborValue::Uint(self.issued_at)),
            ("expires_at".to_string(), CborValue::Uint(self.expires_at)),
            ("refresh_hint_at".to_string(), CborValue::Uint(self.refresh_hint_at)),
            ("issuer".to_string(), issuer_to_cbor(&self.issuer)),
            ("subject".to_string(), subject_to_cbor(&self.subject)),
            ("tenant_scope".to_string(), tenant_scope_to_cbor(&self.tenant_scope)),
        ];
        if let Some(team_scope) = &self.team_scope {
            pairs.push(("team_scope".to_string(), team_scope_to_cbor(team_scope)));
        }
        if let Some(enterprise_scope) = &self.enterprise_scope {
            pairs.push((
                "enterprise_scope".to_string(),
                enterprise_scope_to_cbor(enterprise_scope),
            ));
        }
        pairs.extend([
            ("tier".to_string(), CborValue::Text(self.tier.as_str().to_string())),
            (
                "receipt_class".to_string(),
                CborValue::Text(self.receipt_class.as_str().to_string()),
            ),
            (
                "backends".to_string(),
                CborValue::Array(self.backends.iter().map(backend_to_cbor).collect()),
            ),
            ("credits".to_string(), credits_to_cbor(&self.credits)),
            ("fallback".to_string(), fallback_to_cbor(&self.fallback)),
            ("revocation".to_string(), revocation_to_cbor(&self.revocation)),
        ]);
        if let Some(policy) = &self.delegation_policy {
            pairs.push(("delegation_policy".to_string(), delegation_policy_to_cbor(policy)));
        }
        if !zero_signature {
            if let Some(envelope) = &self.delegation_envelope {
                pairs.push(("delegation_envelope".to_string(), delegation_envelope_to_cbor(envelope)));
            }
        }
        pairs.push((
            "signature".to_string(),
            signature_to_cbor(&self.signature, zero_signature),
        ));
        CborValue::Map(pairs)
    }

    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.to_cbor_value(false).encode()
    }

    pub fn to_signing_cbor(&self) -> Vec<u8> {
        self.to_cbor_value(true).encode()
    }

    pub fn to_canonical_json(&self) -> String {
        to_canonical_json(&self.to_cbor_value(false))
    }

    pub fn token_hash(&self) -> [u8; RCX_CT_HASH_LEN] {
        *blake3::hash(&self.to_signing_cbor()).as_bytes()
    }

    pub fn token_hash_hex(&self) -> String {
        hex::encode(self.token_hash())
    }

    pub fn requires_contextual_verification(&self) -> bool {
        self.spec_version == RCX_CT_DELEGATION_SPEC_VERSION
            || self.delegation_policy.is_some()
            || self.delegation_envelope.is_some()
    }

    /// Create a canonical, recipient-bound one-hop envelope without the issuer key.
    pub fn attenuate_for(
        &self,
        mut caveats: Vec<Caveat>,
        delegate_public_key: [u8; RCX_CT_PUBLIC_KEY_LEN],
        delegation_id: impl Into<String>,
        subject_key: &SigningKey,
    ) -> Result<RcxCapabilityToken, AttenuateError> {
        if self.delegation_envelope.is_some() {
            return Err(AttenuateError::AlreadyDelegated);
        }
        let Some(policy) = self.delegation_policy.as_ref() else {
            return Err(AttenuateError::DelegationNotPermitted);
        };
        if self.spec_version != RCX_CT_DELEGATION_SPEC_VERSION
            || policy.presentation != DelegationPresentation::ProofOfPossession
            || policy.max_depth != 1
        {
            return Err(AttenuateError::DelegationNotPermitted);
        }

        let delegator_public_key = subject_key.verifying_key().to_bytes();
        let delegator_fpr = crux_session::passport::passport_fpr_from_public_key(&delegator_public_key);
        if delegator_fpr != self.subject.passport_fpr {
            return Err(AttenuateError::DelegatorMismatch);
        }
        let delegate_fpr = crux_session::passport::passport_fpr_from_public_key(&delegate_public_key);
        if delegate_fpr == delegator_fpr {
            return Err(AttenuateError::SelfDelegation);
        }
        if !policy
            .allowed_delegate_fprs
            .iter()
            .any(|allowed| allowed == &delegate_fpr)
            || self.team_scope.as_ref().is_some_and(|team| {
                !team
                    .principal_passport_fprs
                    .iter()
                    .any(|allowed| allowed == &delegate_fpr)
            })
        {
            return Err(AttenuateError::DelegateNotPermitted);
        }

        let delegation_id = delegation_id.into();
        if !valid_delegation_id(&delegation_id) {
            return Err(AttenuateError::InvalidDelegationId);
        }
        normalize_scope_caveats(&mut caveats);
        validate_caveats_against_base(self, &caveats)?;

        let signature = subject_key
            .sign(&delegation_binding_message(
                &self.token_hash(),
                RCX_DELEGATION_ENVELOPE_VERSION,
                &delegation_id,
                policy.audience,
                &delegator_public_key,
                &delegate_public_key,
                &caveats,
            ))
            .to_bytes();
        let mut token = self.clone();
        token.delegation_envelope = Some(DelegationEnvelope {
            version: RCX_DELEGATION_ENVELOPE_VERSION,
            delegation_id,
            audience: policy.audience,
            delegator_public_key,
            delegate_public_key,
            caveats,
            signature,
        });
        Ok(token)
    }

    fn caveats(&self) -> &[Caveat] {
        self.delegation_envelope
            .as_ref()
            .map_or(&[], |envelope| envelope.caveats.as_slice())
    }

    fn attenuated_expires_at(&self) -> u64 {
        self.caveats().iter().fold(self.expires_at, |acc, caveat| match caveat {
            Caveat::ExpiresAtLe { expires_at } => acc.min(*expires_at),
            _ => acc,
        })
    }

    fn caveats_permit_tenant(&self, tenant_id: &str) -> bool {
        self.caveats().iter().all(|caveat| match caveat {
            Caveat::TenantIdEq { tenant_id: allowed } => allowed == tenant_id,
            _ => true,
        })
    }

    fn caveats_permit_capability(&self, capability: &str) -> bool {
        self.caveats().iter().all(|caveat| match caveat {
            Caveat::ScopeSubset { scopes } => scopes.iter().any(|s| s == capability),
            _ => true,
        })
    }

    /// Default clock-skew tolerance (seconds) applied to the `issued_at` and
    /// `expires_at` comparisons. Matches the JWT auth path
    /// (`corecruxd::auth`, `validation.leeway = 30`): in a federated deployment
    /// the issuer and verifier are different machines, so a token minted on a
    /// slightly-fast node must not be rejected as future-dated by a
    /// slightly-slow verifier (and symmetrically at expiry).
    pub const DEFAULT_CLOCK_SKEW_LEEWAY_SECS: u64 = 30;

    /// Structural + temporal validation using the default clock-skew leeway
    /// ([`Self::DEFAULT_CLOCK_SKEW_LEEWAY_SECS`]). This is the entry point the
    /// verification path (`verify_token`) uses.
    pub fn validate_basic(&self, now_unix_seconds: u64) -> TokenValidationResult {
        self.validate_basic_with_leeway(now_unix_seconds, Self::DEFAULT_CLOCK_SKEW_LEEWAY_SECS)
    }

    /// As [`Self::validate_basic`], but with an explicit clock-skew tolerance
    /// (seconds) applied symmetrically to the not-yet-valid and expired
    /// comparisons. Pass `0` for exact-boundary semantics.
    pub fn validate_basic_with_leeway(&self, now_unix_seconds: u64, leeway_seconds: u64) -> TokenValidationResult {
        let mut result = self.validate_issuer_base_with_leeway(now_unix_seconds, leeway_seconds);
        if self.requires_contextual_verification() {
            result.issues.push(TokenValidationIssue::new(
                "proof_of_possession_context_required",
                "delegation-capable tokens require contextual proof-of-possession verification",
            ));
            result.valid = false;
        }
        result
    }

    fn validate_issuer_base_with_leeway(&self, now_unix_seconds: u64, leeway_seconds: u64) -> TokenValidationResult {
        let mut issues = Vec::new();
        match (&*self.spec_version, &self.delegation_policy) {
            (RCX_CT_SPEC_VERSION, None) if self.delegation_envelope.is_none() => {}
            (RCX_CT_DELEGATION_SPEC_VERSION, Some(policy)) => {
                let delegates_valid = !policy.allowed_delegate_fprs.is_empty()
                    && policy.allowed_delegate_fprs.len() <= RCX_MAX_DELEGATION_PRINCIPALS
                    && policy.allowed_delegate_fprs.iter().all(|fpr| valid_passport_fpr(fpr))
                    && policy.allowed_delegate_fprs.windows(2).all(|pair| pair[0] < pair[1]);
                if policy.presentation != DelegationPresentation::ProofOfPossession
                    || policy.max_depth != 1
                    || policy.audience != DelegationAudience::CruxSync
                    || !delegates_valid
                {
                    issues.push(TokenValidationIssue::new(
                        "invalid_delegation_policy",
                        "delegation policy must be canonical PoP-only, one-hop, crux-sync policy",
                    ));
                }
            }
            _ => issues.push(TokenValidationIssue::new(
                "invalid_spec_version",
                "delegation fields require issuer-signed rcx-ct/1.1 policy",
            )),
        }
        if self.token_id.trim().is_empty() {
            issues.push(TokenValidationIssue::new("missing_token_id", "token_id is required"));
        }
        if self.issued_at > now_unix_seconds.saturating_add(leeway_seconds) {
            issues.push(TokenValidationIssue::new(
                "token_not_yet_valid",
                "issued_at must be at or before the validation time",
            ));
        }
        if self.expires_at.saturating_add(leeway_seconds) <= now_unix_seconds {
            issues.push(TokenValidationIssue::new("token_expired", "token has expired"));
        }
        if self.refresh_hint_at >= self.expires_at {
            issues.push(TokenValidationIssue::new(
                "invalid_refresh_hint",
                "refresh_hint_at must be before expires_at",
            ));
        }
        if self.signature.alg != "ed25519" {
            issues.push(TokenValidationIssue::new(
                "unsupported_signature_alg",
                "signature.alg must be ed25519",
            ));
        }
        if self.signature.kid != self.issuer.passport_kid {
            issues.push(TokenValidationIssue::new(
                "signature_kid_mismatch",
                "signature.kid must match issuer.passport_kid",
            ));
        }
        if self.backends.is_empty() {
            issues.push(TokenValidationIssue::new(
                "missing_backend",
                "at least one backend is required",
            ));
        }
        if self.tier == RcxTier::Team && self.team_scope.is_none() {
            issues.push(TokenValidationIssue::new(
                "missing_team_scope",
                "team tier tokens require team_scope",
            ));
        }
        if self.tier == RcxTier::Enterprise && self.enterprise_scope.is_none() {
            issues.push(TokenValidationIssue::new(
                "missing_enterprise_scope",
                "enterprise tier tokens require enterprise_scope",
            ));
        }
        if let Some(team_scope) = &self.team_scope {
            if team_scope.team_id.trim().is_empty() {
                issues.push(TokenValidationIssue::new(
                    "missing_team_id",
                    "team_scope.team_id is required",
                ));
            }
            if team_scope.pooled_credit_agent_id.trim().is_empty() {
                issues.push(TokenValidationIssue::new(
                    "missing_pooled_credit_agent_id",
                    "team_scope.pooled_credit_agent_id is required",
                ));
            }
            if team_scope.principal_passport_fprs.is_empty() {
                issues.push(TokenValidationIssue::new(
                    "missing_principal_scope",
                    "team_scope.principal_passport_fprs must not be empty",
                ));
            }
        }
        if let Some(scope) = &self.enterprise_scope {
            if scope.customer_id.trim().is_empty() {
                issues.push(TokenValidationIssue::new(
                    "missing_enterprise_customer_id",
                    "enterprise_scope.customer_id is required",
                ));
            }
            if !scope.backend_id.starts_with(RCX_CUSTOMER_BACKEND_PREFIX) {
                issues.push(TokenValidationIssue::new(
                    "invalid_enterprise_backend",
                    "enterprise_scope.backend_id must start with customer:",
                ));
            }
            if scope.trust_root_kid.trim().is_empty() {
                issues.push(TokenValidationIssue::new(
                    "missing_enterprise_trust_root",
                    "enterprise_scope.trust_root_kid is required",
                ));
            }
            let backend = self
                .backends
                .iter()
                .find(|backend| backend.backend_id == scope.backend_id);
            match backend {
                Some(backend) if backend.trust_root_kid != scope.trust_root_kid => {
                    issues.push(TokenValidationIssue::new(
                        "trust_root_mismatch",
                        "enterprise backend trust root does not match enterprise_scope",
                    ));
                }
                None => issues.push(TokenValidationIssue::new(
                    "enterprise_backend_missing",
                    "enterprise_scope backend is not present in token backends",
                )),
                _ => {}
            }
            if scope.airgap
                && self
                    .backends
                    .iter()
                    .any(|backend| backend.backend_id == RCX_HOSTED_BACKEND_ID)
            {
                issues.push(TokenValidationIssue::new(
                    "backend_not_permitted",
                    "airgap enterprise tokens must not permit hosted.vaultcrux.com",
                ));
            }
        }

        TokenValidationResult {
            valid: issues.is_empty(),
            issues,
            token_hash: self.token_hash_hex(),
        }
    }

    pub fn permits_egress(
        &self,
        trust_root_pubkey: &[u8],
        now_unix_seconds: u64,
        backend_id: &str,
        capability: &str,
        egress_class: DataEgressClass,
    ) -> bool {
        verify_token(self, trust_root_pubkey, now_unix_seconds) == VerifyOutcome::Verified
            && self.base_permits_egress(backend_id, capability, &egress_class)
    }

    fn base_permits_egress(&self, backend_id: &str, capability: &str, egress_class: &DataEgressClass) -> bool {
        self.backends.iter().any(|backend| {
            backend.backend_id == backend_id
                && backend.permitted_capabilities.iter().any(|permitted| {
                    permitted.capability == capability
                        && permitted
                            .data_egress_classes
                            .iter()
                            .any(|candidate| candidate == egress_class)
                })
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenValidationIssue {
    pub code: String,
    pub message: String,
}

impl TokenValidationIssue {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenValidationResult {
    pub valid: bool,
    pub issues: Vec<TokenValidationIssue>,
    pub token_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    Verified,
    StructuralFailure(Vec<String>),
    BadSignature,
    BadTrustRoot,
}

pub fn verify_token(token: &RcxCapabilityToken, trust_root_pubkey: &[u8], now_unix_seconds: u64) -> VerifyOutcome {
    match verify_issuer_signed_token(token, trust_root_pubkey, now_unix_seconds) {
        VerifyOutcome::Verified if token.requires_contextual_verification() => {
            VerifyOutcome::StructuralFailure(vec!["proof_of_possession_context_required".to_string()])
        }
        outcome => outcome,
    }
}

fn verify_issuer_signed_token(
    token: &RcxCapabilityToken,
    trust_root_pubkey: &[u8],
    now_unix_seconds: u64,
) -> VerifyOutcome {
    let basic =
        token.validate_issuer_base_with_leeway(now_unix_seconds, RcxCapabilityToken::DEFAULT_CLOCK_SKEW_LEEWAY_SECS);
    if !basic.valid {
        return VerifyOutcome::StructuralFailure(basic.issues.into_iter().map(|issue| issue.code).collect());
    }

    let key_bytes: [u8; 32] = match trust_root_pubkey.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return VerifyOutcome::BadTrustRoot,
    };
    let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(_) => return VerifyOutcome::BadTrustRoot,
    };

    let signature = Ed25519Signature::from_bytes(&token.signature.sig);
    let message = token.token_hash();
    match verifying_key.verify_strict(&message, &signature) {
        Ok(()) => VerifyOutcome::Verified,
        Err(_) => VerifyOutcome::BadSignature,
    }
}

pub fn free_local_verified_fixture() -> RcxCapabilityToken {
    let passport_fpr = "p_0123456789abcdef0123456789abcdef";
    RcxCapabilityToken {
        spec_version: RCX_CT_SPEC_VERSION.to_string(),
        token_id: "rcxct_free_0123456789abcdef_default".to_string(),
        issued_at: 1_776_989_600,
        expires_at: 1_780_143_200,
        refresh_hint_at: 1_780_139_600,
        issuer: Issuer {
            passport_kid: passport_fpr.to_string(),
            issuer_org: "local".to_string(),
        },
        subject: Subject {
            passport_fpr: passport_fpr.to_string(),
            daemon_instance_id: Some("daemon_01HV0000000000000000000000".to_string()),
        },
        tenant_scope: TenantScope {
            tenant_id: "default".to_string(),
            display_name: Some("Local".to_string()),
        },
        team_scope: None,
        enterprise_scope: None,
        tier: RcxTier::Free,
        receipt_class: ReceiptClass::Verified,
        backends: vec![Backend {
            backend_id: "local".to_string(),
            trust_root_kid: passport_fpr.to_string(),
            endpoint_url: None,
            permitted_capabilities: vec![PermittedCapability {
                capability: "corecrux.query.local".to_string(),
                data_egress_classes: vec![DataEgressClass::None],
                required_attestations: Vec::new(),
                credit_cost: None,
            }],
        }],
        credits: Credits {
            balance: None,
            refill: CreditRefill {
                period: RefillPeriod::None,
                amount: None,
            },
            overdraft: OverdraftPolicy::Forbid,
            overdraft_limit: None,
        },
        fallback: FallbackPolicy {
            on_backend_unreachable: FallbackAction::Refuse,
            on_credits_exhausted: FallbackAction::Refuse,
            on_expiry: FallbackAction::Refuse,
            queue_ttl_seconds: None,
        },
        revocation: Revocation {
            crl_url: None,
            push_channel: None,
        },
        delegation_policy: None,
        delegation_envelope: None,
        signature: Signature {
            alg: "ed25519".to_string(),
            kid: passport_fpr.to_string(),
            sig: [0x11; RCX_CT_SIGNATURE_LEN],
        },
    }
}

fn issuer_to_cbor(issuer: &Issuer) -> CborValue {
    CborValue::Map(vec![
        ("passport_kid".to_string(), CborValue::Text(issuer.passport_kid.clone())),
        ("issuer_org".to_string(), CborValue::Text(issuer.issuer_org.clone())),
    ])
}

fn subject_to_cbor(subject: &Subject) -> CborValue {
    CborValue::Map(vec![
        (
            "passport_fpr".to_string(),
            CborValue::Text(subject.passport_fpr.clone()),
        ),
        (
            "daemon_instance_id".to_string(),
            opt_text_to_cbor(subject.daemon_instance_id.as_deref()),
        ),
    ])
}

fn tenant_scope_to_cbor(scope: &TenantScope) -> CborValue {
    CborValue::Map(vec![
        ("tenant_id".to_string(), CborValue::Text(scope.tenant_id.clone())),
        (
            "display_name".to_string(),
            opt_text_to_cbor(scope.display_name.as_deref()),
        ),
    ])
}

fn team_scope_to_cbor(scope: &TeamScope) -> CborValue {
    CborValue::Map(vec![
        ("team_id".to_string(), CborValue::Text(scope.team_id.clone())),
        ("seat_id".to_string(), opt_text_to_cbor(scope.seat_id.as_deref())),
        (
            "seat_role".to_string(),
            match &scope.seat_role {
                Some(role) => CborValue::Text(role.as_str().to_string()),
                None => CborValue::Null,
            },
        ),
        (
            "pooled_credit_agent_id".to_string(),
            CborValue::Text(scope.pooled_credit_agent_id.clone()),
        ),
        (
            "principal_passport_fprs".to_string(),
            CborValue::Array(
                scope
                    .principal_passport_fprs
                    .iter()
                    .map(|item| CborValue::Text(item.clone()))
                    .collect(),
            ),
        ),
    ])
}

fn enterprise_scope_to_cbor(scope: &EnterpriseScope) -> CborValue {
    CborValue::Map(vec![
        ("customer_id".to_string(), CborValue::Text(scope.customer_id.clone())),
        (
            "contract_id".to_string(),
            opt_text_to_cbor(scope.contract_id.as_deref()),
        ),
        ("backend_id".to_string(), CborValue::Text(scope.backend_id.clone())),
        ("endpoint_url".to_string(), CborValue::Text(scope.endpoint_url.clone())),
        (
            "trust_root_kid".to_string(),
            CborValue::Text(scope.trust_root_kid.clone()),
        ),
        ("airgap".to_string(), CborValue::Bool(scope.airgap)),
        (
            "cross_signed_by_vaultcrux".to_string(),
            CborValue::Bool(scope.cross_signed_by_vaultcrux),
        ),
    ])
}

fn backend_to_cbor(backend: &Backend) -> CborValue {
    CborValue::Map(vec![
        ("backend_id".to_string(), CborValue::Text(backend.backend_id.clone())),
        (
            "trust_root_kid".to_string(),
            CborValue::Text(backend.trust_root_kid.clone()),
        ),
        (
            "endpoint_url".to_string(),
            opt_text_to_cbor(backend.endpoint_url.as_deref()),
        ),
        (
            "permitted_capabilities".to_string(),
            CborValue::Array(backend.permitted_capabilities.iter().map(capability_to_cbor).collect()),
        ),
    ])
}

fn capability_to_cbor(capability: &PermittedCapability) -> CborValue {
    CborValue::Map(vec![
        ("capability".to_string(), CborValue::Text(capability.capability.clone())),
        (
            "data_egress_classes".to_string(),
            CborValue::Array(
                capability
                    .data_egress_classes
                    .iter()
                    .map(|class| CborValue::Text(class.as_str().to_string()))
                    .collect(),
            ),
        ),
        (
            "required_attestations".to_string(),
            CborValue::Array(
                capability
                    .required_attestations
                    .iter()
                    .map(|item| CborValue::Text(item.clone()))
                    .collect(),
            ),
        ),
        (
            "credit_cost".to_string(),
            match &capability.credit_cost {
                Some(cost) => CborValue::Map(vec![
                    ("unit".to_string(), CborValue::Text(cost.unit.as_str().to_string())),
                    ("cost".to_string(), CborValue::Uint(cost.cost)),
                ]),
                None => CborValue::Null,
            },
        ),
    ])
}

fn credits_to_cbor(credits: &Credits) -> CborValue {
    CborValue::Map(vec![
        ("balance".to_string(), opt_u64_to_cbor(credits.balance)),
        (
            "refill".to_string(),
            CborValue::Map(vec![
                (
                    "period".to_string(),
                    CborValue::Text(credits.refill.period.as_str().to_string()),
                ),
                ("amount".to_string(), opt_u64_to_cbor(credits.refill.amount)),
            ]),
        ),
        (
            "overdraft".to_string(),
            CborValue::Text(credits.overdraft.as_str().to_string()),
        ),
        ("overdraft_limit".to_string(), opt_u64_to_cbor(credits.overdraft_limit)),
    ])
}

fn fallback_to_cbor(fallback: &FallbackPolicy) -> CborValue {
    CborValue::Map(vec![
        (
            "on_backend_unreachable".to_string(),
            CborValue::Text(fallback.on_backend_unreachable.as_str().to_string()),
        ),
        (
            "on_credits_exhausted".to_string(),
            CborValue::Text(fallback.on_credits_exhausted.as_str().to_string()),
        ),
        (
            "on_expiry".to_string(),
            CborValue::Text(fallback.on_expiry.as_str().to_string()),
        ),
        (
            "queue_ttl_seconds".to_string(),
            opt_u64_to_cbor(fallback.queue_ttl_seconds),
        ),
    ])
}

fn revocation_to_cbor(revocation: &Revocation) -> CborValue {
    CborValue::Map(vec![
        ("crl_url".to_string(), opt_text_to_cbor(revocation.crl_url.as_deref())),
        (
            "push_channel".to_string(),
            opt_text_to_cbor(revocation.push_channel.as_deref()),
        ),
    ])
}

fn signature_to_cbor(signature: &Signature, zero_signature: bool) -> CborValue {
    CborValue::Map(vec![
        ("alg".to_string(), CborValue::Text(signature.alg.clone())),
        ("kid".to_string(), CborValue::Text(signature.kid.clone())),
        (
            "sig".to_string(),
            CborValue::Bytes(if zero_signature {
                vec![0; RCX_CT_SIGNATURE_LEN]
            } else {
                signature.sig.to_vec()
            }),
        ),
    ])
}

fn opt_text_to_cbor(value: Option<&str>) -> CborValue {
    match value {
        Some(value) => CborValue::Text(value.to_owned()),
        None => CborValue::Null,
    }
}

fn opt_u64_to_cbor(value: Option<u64>) -> CborValue {
    match value {
        Some(value) => CborValue::Uint(value),
        None => CborValue::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_fixture(signing: &SigningKey) -> RcxCapabilityToken {
        let mut token = free_local_verified_fixture();
        token.signature.sig = signing.sign(&token.token_hash()).to_bytes();
        token
    }

    const FREE_LOCAL_VERIFIED_CBOR_HEX: &str = "af6474696572646672656566697373756572a26a6973737565725f6f7267656c6f63616c6c70617373706f72745f6b69647822705f30313233343536373839616263646566303132333435363738396162636465666763726564697473a466726566696c6ca266616d6f756e74f666706572696f64646e6f6e656762616c616e6365f6696f766572647261667466666f726269646f6f76657264726166745f6c696d6974f6677375626a656374a26c70617373706f72745f6670727822705f3031323334353637383961626364656630313233343536373839616263646566726461656d6f6e5f696e7374616e63655f696478216461656d6f6e5f3031485630303030303030303030303030303030303030303030686261636b656e647381a46a6261636b656e645f6964656c6f63616c6c656e64706f696e745f75726cf66e74727573745f726f6f745f6b69647822705f3031323334353637383961626364656630313233343536373839616263646566767065726d69747465645f6361706162696c697469657381a46a6361706162696c69747974636f7265637275782e71756572792e6c6f63616c6b6372656469745f636f7374f673646174615f6567726573735f636c617373657381646e6f6e657572657175697265645f6174746573746174696f6e73806866616c6c6261636ba4696f6e5f657870697279667265667573657171756575655f74746c5f7365636f6e6473f6746f6e5f637265646974735f65786861757374656466726566757365766f6e5f6261636b656e645f756e726561636861626c656672656675736568746f6b656e5f6964782372637863745f667265655f303132333435363738396162636465665f64656661756c74696973737565645f61741a69eab5a0697369676e6174757265a363616c676765643235353139636b69647822705f3031323334353637383961626364656630313233343536373839616263646566637369675840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111116a657870697265735f61741a6a1ad4606a7265766f636174696f6ea26763726c5f75726cf66c707573685f6368616e6e656cf66c737065635f76657273696f6e6a7263782d63742f312e306c74656e616e745f73636f7065a26974656e616e745f69646764656661756c746c646973706c61795f6e616d65654c6f63616c6d726563656970745f636c6173736876657269666965646f726566726573685f68696e745f61741a6a1ac650";
    const FREE_LOCAL_VERIFIED_TOKEN_HASH: &str = "fec9ac825cd4f1f2ccbb3c4cf95495d61416e867818413153e86cc4539b3cee9";

    #[test]
    fn corecrux_premium_lane_registry_is_complete_and_named() {
        let caps = corecrux_premium_lane_capabilities(3);
        assert_eq!(caps.len(), 13, "exactly 13 premium lanes");
        for (cap, slug) in caps.iter().zip(CORECRUX_PREMIUM_LANE_SLUGS) {
            assert_eq!(cap.capability, format!("corecrux.lane.{slug}"));
            assert_eq!(
                cap.credit_cost.as_ref().map(|c| c.cost),
                Some(corecrux_lane_credit_cost(slug, 3))
            );
            assert_eq!(cap.data_egress_classes, vec![DataEgressClass::Text]);
        }
        // the metered dense-service lanes are premium and priced 3:1
        assert!(CORECRUX_PREMIUM_LANE_SLUGS.contains(&"rerank"));
        assert!(CORECRUX_PREMIUM_LANE_SLUGS.contains(&"dense_managed"));
        assert_eq!(corecrux_lane_credit_cost("rerank", 3), 3);
        assert_eq!(corecrux_lane_credit_cost("dense_managed", 3), 1);
        // other premium lanes keep the token's base per-call cost
        assert_eq!(corecrux_lane_credit_cost("topology", 7), 7);
        // free baseline must NOT appear in the premium registry
        for free in ["bm25", "dense", "sparse"] {
            assert!(
                !CORECRUX_PREMIUM_LANE_SLUGS.contains(&free),
                "{free} is free, not premium"
            );
        }
    }

    #[test]
    fn free_fixture_has_stable_canonical_bytes() {
        let token = free_local_verified_fixture();
        assert_eq!(hex::encode(token.to_canonical_cbor()), FREE_LOCAL_VERIFIED_CBOR_HEX);
        assert_eq!(token.token_hash_hex(), FREE_LOCAL_VERIFIED_TOKEN_HASH);
    }

    // --- rcx-ct/1.1 sync-delegation cross-language byte-parity vector ---------
    // Deterministic base token that CruxEngine will mint (spec 1.1, one crux-sync
    // backend with corecrux.sync.pull/push, an issuer-signed PoP/one-hop/crux-sync
    // delegation_policy). The CruxEngine TS fixture `syncDelegationVectorFixture`
    // (packages/shared/packages/contracts/src/rcx-capability-token.ts) mirrors this
    // byte-for-byte; the shared hex constants below lock the two encoders together.
    // ExecPlan cruxengine-sync-delegation-minting-2026-07-22 M1.
    const SYNC_DELEGATION_ISSUER_SEED: [u8; 32] = [7u8; 32];
    const SYNC_DELEGATION_VECTOR_CBOR_HEX: &str = "b06474696572646672656566697373756572a26a6973737565725f6f7267656c6f63616c6c70617373706f72745f6b69647822705f30313233343536373839616263646566303132333435363738396162636465666763726564697473a466726566696c6ca266616d6f756e74f666706572696f64646e6f6e656762616c616e6365f6696f766572647261667466666f726269646f6f76657264726166745f6c696d6974f6677375626a656374a26c70617373706f72745f6670727822705f3031323334353637383961626364656630313233343536373839616263646566726461656d6f6e5f696e7374616e63655f696478216461656d6f6e5f3031485630303030303030303030303030303030303030303030686261636b656e647381a46a6261636b656e645f696469637275782d73796e636c656e64706f696e745f75726cf66e74727573745f726f6f745f6b69647822705f3031323334353637383961626364656630313233343536373839616263646566767065726d69747465645f6361706162696c697469657382a46a6361706162696c69747972636f7265637275782e73796e632e70756c6c6b6372656469745f636f7374f673646174615f6567726573735f636c617373657381646e6f6e657572657175697265645f6174746573746174696f6e73816e70617373706f72745f626f756e64a46a6361706162696c69747972636f7265637275782e73796e632e707573686b6372656469745f636f7374f673646174615f6567726573735f636c617373657381646e6f6e657572657175697265645f6174746573746174696f6e73816e70617373706f72745f626f756e646866616c6c6261636ba4696f6e5f657870697279667265667573657171756575655f74746c5f7365636f6e6473f6746f6e5f637265646974735f65786861757374656466726566757365766f6e5f6261636b656e645f756e726561636861626c656672656675736568746f6b656e5f6964782672637863745f73796e6364656c5f303132333435363738396162636465665f64656661756c74696973737565645f61741a69eab5a0697369676e6174757265a363616c676765643235353139636b69647822705f3031323334353637383961626364656630313233343536373839616263646566637369675840111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111116a657870697265735f61741a6a1ad4606a7265766f636174696f6ea26763726c5f75726cf66c707573685f6368616e6e656cf66c737065635f76657273696f6e6a7263782d63742f312e316c74656e616e745f73636f7065a26974656e616e745f69646764656661756c746c646973706c61795f6e616d65654c6f63616c6d726563656970745f636c6173736876657269666965646f726566726573685f68696e745f61741a6a1ac6507164656c65676174696f6e5f706f6c696379a46861756469656e636569637275782d73796e63696d61785f6465707468016c70726573656e746174696f6e7370726f6f665f6f665f706f7373657373696f6e75616c6c6f7765645f64656c65676174655f66707273827822705f30303030303030303030303030303030303030303030303030303030303030317822705f3030303030303030303030303030303030303030303030303030303030303032";
    const SYNC_DELEGATION_VECTOR_TOKEN_HASH: &str = "1ca9e0d2f4e74af7314a80d6f376b73a52e30df04a10d8cb435d11766a73b0c7";
    const SYNC_DELEGATION_VECTOR_ISSUER_SIG: &str = "6441eb1f1678566b7d0e81b52b331c77e3a500ae210cdbdeda67dbbe71ed1dc78ee1be37434735b19ac61362afb64c3f962fb3a3b5659cd96b4012f344ee3801";

    fn sync_delegation_vector_fixture() -> RcxCapabilityToken {
        let mut token = free_local_verified_fixture();
        token.spec_version = RCX_CT_DELEGATION_SPEC_VERSION.to_string();
        token.token_id = "rcxct_syncdel_0123456789abcdef_default".to_string();
        token.backends = vec![Backend {
            backend_id: RCX_SYNC_BACKEND_ID.to_string(),
            trust_root_kid: token.issuer.passport_kid.clone(),
            endpoint_url: None,
            permitted_capabilities: vec![
                PermittedCapability {
                    capability: RCX_SYNC_PULL_CAPABILITY.to_string(),
                    data_egress_classes: vec![DataEgressClass::None],
                    required_attestations: vec![RCX_SYNC_PASSPORT_ATTESTATION.to_string()],
                    credit_cost: None,
                },
                PermittedCapability {
                    capability: RCX_SYNC_PUSH_CAPABILITY.to_string(),
                    data_egress_classes: vec![DataEgressClass::None],
                    required_attestations: vec![RCX_SYNC_PASSPORT_ATTESTATION.to_string()],
                    credit_cost: None,
                },
            ],
        }];
        token.delegation_policy = Some(DelegationPolicy {
            presentation: DelegationPresentation::ProofOfPossession,
            max_depth: 1,
            audience: DelegationAudience::CruxSync,
            allowed_delegate_fprs: vec![
                "p_00000000000000000000000000000001".to_string(),
                "p_00000000000000000000000000000002".to_string(),
            ],
        });
        token
    }

    #[test]
    fn sync_delegation_vector_has_stable_bytes_and_verifies() {
        let unsigned = sync_delegation_vector_fixture();
        let issuer = SigningKey::from_bytes(&SYNC_DELEGATION_ISSUER_SEED);
        let mut signed = sync_delegation_vector_fixture();
        // token_hash zeroes the signature, so signing over it is stable.
        signed.signature.sig = issuer.sign(&signed.token_hash()).to_bytes();

        assert_eq!(
            hex::encode(unsigned.to_canonical_cbor()),
            SYNC_DELEGATION_VECTOR_CBOR_HEX
        );
        assert_eq!(unsigned.token_hash_hex(), SYNC_DELEGATION_VECTOR_TOKEN_HASH);
        assert_eq!(hex::encode(signed.signature.sig), SYNC_DELEGATION_VECTOR_ISSUER_SIG);
        // Signing must not perturb the signing bytes.
        assert_eq!(signed.token_hash_hex(), SYNC_DELEGATION_VECTOR_TOKEN_HASH);

        // The base delegation token is a valid, issuer-signed, contextual token:
        // verify_token confirms the issuer signature + canonical policy, then reports
        // that presentation-time proof-of-possession is still required.
        let now = unsigned.issued_at;
        assert_eq!(
            verify_token(&signed, &issuer.verifying_key().to_bytes(), now),
            VerifyOutcome::StructuralFailure(vec!["proof_of_possession_context_required".to_string()]),
        );
        // A wrong trust root must fail the signature, not fall through to contextual.
        let wrong = SigningKey::from_bytes(&[9u8; 32]);
        assert_eq!(
            verify_token(&signed, &wrong.verifying_key().to_bytes(), now),
            VerifyOutcome::BadSignature,
        );
    }

    #[test]
    fn cruxengine_shaped_sync_delegation_verifies_end_to_end() {
        // The exact base-token shape CruxEngine mints (crux-sync backend,
        // corecrux.sync.pull/push, PoP/one-hop/crux-sync policy) flows through
        // the M3′ mint→attenuate→present→accept path. ExecPlan
        // cruxengine-sync-delegation-minting-2026-07-22 M4.
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);

        // Mint: the CruxEngine shape, bound to the real subject + delegate fprs
        // and issuer-signed (matches issueSyncDelegationToken's output shape).
        let mut base = sync_delegation_vector_fixture();
        base.subject.passport_fpr =
            crux_session::passport::passport_fpr_from_public_key(&subject.verifying_key().to_bytes());
        base.delegation_policy
            .as_mut()
            .unwrap_or_else(|| panic!("policy required"))
            .allowed_delegate_fprs = vec![crux_session::passport::passport_fpr_from_public_key(
            &delegate.verifying_key().to_bytes(),
        )];
        base.signature.sig = issuer.sign(&base.token_hash()).to_bytes();

        // The issuer-signed base token is a valid contextual token.
        assert_eq!(
            verify_token(&base, &issuer.verifying_key().to_bytes(), M2_REPAIR_NOW),
            VerifyOutcome::StructuralFailure(vec!["proof_of_possession_context_required".to_string()]),
        );

        // Attenuate: the subject narrows and binds the delegate offline.
        let delegated = base
            .attenuate_for(
                vec![
                    Caveat::TenantIdEq {
                        tenant_id: "default".to_string(),
                    },
                    Caveat::ExpiresAtLe {
                        expires_at: 1_780_143_100,
                    },
                ],
                delegate.verifying_key().to_bytes(),
                "sync-delegation-1",
                &subject,
            )
            .unwrap_or_else(|error| panic!("sync-delegation attenuation failed: {error:?}"));

        // Present + accept: the delegate proves possession at the crux-sync boundary.
        let context = AttenuationContext {
            audience: DelegationAudience::CruxSync,
            tenant_id: "default",
            backend_id: RCX_SYNC_BACKEND_ID,
            capability: RCX_SYNC_PULL_CAPABILITY,
            data_egress_classes: &[DataEgressClass::None],
            present_attestations: &[RCX_SYNC_PASSPORT_ATTESTATION],
        };
        let nonce = b"sync-boundary-nonce";
        let proof = presentation_proof(&delegated, context, nonce, &delegate);
        assert_eq!(
            verify_token_attenuated(
                &delegated,
                &issuer.verifying_key().to_bytes(),
                M2_REPAIR_NOW,
                &proof,
                nonce,
                context,
                |_| false,
            ),
            AttenuatedOutcome::Verified(VerifiedAttenuation {
                actor_fpr: crux_session::passport::passport_fpr_from_public_key(&delegate.verifying_key().to_bytes()),
                delegated_by: Some(crux_session::passport::passport_fpr_from_public_key(
                    &subject.verifying_key().to_bytes()
                )),
                delegation_id: Some("sync-delegation-1".to_string()),
            })
        );
    }

    const M2_REPAIR_NOW: u64 = 1_776_989_601;
    const M2_NONCE: &[u8] = b"verifier-issued-single-use-nonce";

    fn delegation_enabled_fixture(
        issuer: &SigningKey,
        subject: &SigningKey,
        delegate: &SigningKey,
    ) -> RcxCapabilityToken {
        let mut token = free_local_verified_fixture();
        token.spec_version = RCX_CT_DELEGATION_SPEC_VERSION.to_string();
        token.subject.passport_fpr =
            crux_session::passport::passport_fpr_from_public_key(&subject.verifying_key().to_bytes());
        token.backends[0].permitted_capabilities.push(PermittedCapability {
            capability: "corecrux.query.explain".to_string(),
            data_egress_classes: vec![DataEgressClass::None],
            required_attestations: vec!["passport_bound".to_string()],
            credit_cost: None,
        });
        token.delegation_policy = Some(DelegationPolicy {
            presentation: DelegationPresentation::ProofOfPossession,
            max_depth: 1,
            audience: DelegationAudience::CruxSync,
            allowed_delegate_fprs: vec![crux_session::passport::passport_fpr_from_public_key(
                &delegate.verifying_key().to_bytes(),
            )],
        });
        token.signature.sig = issuer.sign(&token.token_hash()).to_bytes();
        token
    }

    fn query_context<'a>(
        capability: &'a str,
        tenant_id: &'a str,
        attestations: &'a [&'a str],
    ) -> AttenuationContext<'a> {
        AttenuationContext {
            audience: DelegationAudience::CruxSync,
            tenant_id,
            backend_id: "local",
            capability,
            data_egress_classes: &[DataEgressClass::None],
            present_attestations: attestations,
        }
    }

    fn presentation_proof<'a>(
        token: &RcxCapabilityToken,
        context: AttenuationContext<'_>,
        nonce: &'a [u8],
        presenter: &SigningKey,
    ) -> PresentationProof<'a> {
        PresentationProof {
            public_key: presenter.verifying_key().to_bytes(),
            nonce,
            signature: presenter
                .sign(&presentation_proof_message(token, context, nonce))
                .to_bytes(),
        }
    }

    fn verify_as(
        token: &RcxCapabilityToken,
        issuer: &SigningKey,
        presenter: &SigningKey,
        context: AttenuationContext<'_>,
        nonce: &[u8],
        expected_nonce: &[u8],
    ) -> AttenuatedOutcome {
        let proof = presentation_proof(token, context, nonce, presenter);
        verify_token_attenuated(
            token,
            &issuer.verifying_key().to_bytes(),
            M2_REPAIR_NOW,
            &proof,
            expected_nonce,
            context,
            |_| false,
        )
    }

    fn valid_delegation(issuer: &SigningKey, subject: &SigningKey, delegate: &SigningKey) -> RcxCapabilityToken {
        delegation_enabled_fixture(issuer, subject, delegate)
            .attenuate_for(
                vec![
                    Caveat::TenantIdEq {
                        tenant_id: "default".to_string(),
                    },
                    Caveat::ExpiresAtLe {
                        expires_at: 1_780_143_100,
                    },
                ],
                delegate.verifying_key().to_bytes(),
                "delegation-1",
                subject,
            )
            .unwrap_or_else(|error| panic!("valid delegation fixture failed: {error:?}"))
    }

    fn resign_envelope(token: &mut RcxCapabilityToken, subject: &SigningKey) {
        let base_hash = token.token_hash();
        let envelope = token
            .delegation_envelope
            .as_mut()
            .unwrap_or_else(|| panic!("delegation envelope required"));
        envelope.signature = subject
            .sign(&delegation_binding_message(
                &base_hash,
                envelope.version,
                &envelope.delegation_id,
                envelope.audience,
                &envelope.delegator_public_key,
                &envelope.delegate_public_key,
                &envelope.caveats,
            ))
            .to_bytes();
    }

    #[test]
    fn v11_policy_is_issuer_signed_and_envelope_is_subject_signed() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let base = delegation_enabled_fixture(&issuer, &subject, &delegate);
        let delegated = valid_delegation(&issuer, &subject, &delegate);

        assert_eq!(base.token_hash(), delegated.token_hash());
        assert_ne!(base.to_canonical_cbor(), delegated.to_canonical_cbor());
        let mut changed_policy = base;
        changed_policy
            .delegation_policy
            .as_mut()
            .unwrap_or_else(|| panic!("policy required"))
            .allowed_delegate_fprs = vec![crux_session::passport::passport_fpr_from_public_key(
            &SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes(),
        )];
        assert_eq!(
            verify_token(&changed_policy, &issuer.verifying_key().to_bytes(), M2_REPAIR_NOW),
            VerifyOutcome::BadSignature
        );
    }

    #[test]
    fn v11_canonical_json_round_trips_without_losing_binding_fields() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let token = valid_delegation(&issuer, &subject, &delegate);
        let decoded: RcxCapabilityToken = serde_json::from_str(&token.to_canonical_json())
            .unwrap_or_else(|error| panic!("v1.1 canonical JSON must decode: {error}"));

        assert_eq!(decoded, token);
        assert_eq!(decoded.to_canonical_cbor(), token.to_canonical_cbor());
        assert_eq!(decoded.token_hash(), token.token_hash());
    }

    #[test]
    fn valid_one_hop_verifies_with_attributed_actor() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let token = valid_delegation(&issuer, &subject, &delegate);
        let context = query_context("corecrux.query.local", "default", &[]);

        assert_eq!(
            verify_as(&token, &issuer, &delegate, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::Verified(VerifiedAttenuation {
                actor_fpr: crux_session::passport::passport_fpr_from_public_key(&delegate.verifying_key().to_bytes()),
                delegated_by: Some(crux_session::passport::passport_fpr_from_public_key(
                    &subject.verifying_key().to_bytes()
                )),
                delegation_id: Some("delegation-1".to_string()),
            })
        );
    }

    #[test]
    fn subject_pop_base_verifies_only_for_subject() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let token = delegation_enabled_fixture(&issuer, &subject, &delegate);
        let context = query_context("corecrux.query.local", "default", &[]);

        assert!(matches!(
            verify_as(&token, &issuer, &subject, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::Verified(_)
        ));
        assert_eq!(
            verify_as(&token, &issuer, &delegate, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::DelegateMismatch
        );
    }

    #[test]
    fn generic_paths_reject_every_v11_token() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        for token in [
            delegation_enabled_fixture(&issuer, &subject, &delegate),
            valid_delegation(&issuer, &subject, &delegate),
        ] {
            assert!(token
                .validate_basic(M2_REPAIR_NOW)
                .issues
                .iter()
                .any(|issue| issue.code == "proof_of_possession_context_required"));
            assert_eq!(
                verify_token(&token, &issuer.verifying_key().to_bytes(), M2_REPAIR_NOW),
                VerifyOutcome::StructuralFailure(vec!["proof_of_possession_context_required".to_string()])
            );
            assert!(!token.permits_egress(
                &issuer.verifying_key().to_bytes(),
                M2_REPAIR_NOW,
                "local",
                "corecrux.query.local",
                DataEgressClass::None
            ));
        }
    }

    #[test]
    fn stripping_envelope_does_not_let_delegate_use_subject_base() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let mut token = valid_delegation(&issuer, &subject, &delegate);
        token.delegation_envelope = None;
        let context = query_context("corecrux.query.local", "default", &[]);
        assert_eq!(
            verify_as(&token, &issuer, &delegate, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::DelegateMismatch
        );
    }

    #[test]
    fn stripping_all_v11_markers_breaks_issuer_signature() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let mut token = valid_delegation(&issuer, &subject, &delegate);
        token.delegation_policy = None;
        token.delegation_envelope = None;
        token.spec_version = RCX_CT_SPEC_VERSION.to_string();
        assert_eq!(
            verify_token(&token, &issuer.verifying_key().to_bytes(), M2_REPAIR_NOW),
            VerifyOutcome::BadSignature
        );
    }

    #[test]
    fn envelope_mutation_removal_and_reordering_fail_closed() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let context = query_context("corecrux.query.local", "default", &[]);
        let base = valid_delegation(&issuer, &subject, &delegate);

        let mut mutated = base.clone();
        mutated
            .delegation_envelope
            .as_mut()
            .unwrap_or_else(|| panic!("envelope required"))
            .delegation_id = "changed".to_string();
        assert_eq!(
            verify_as(&mutated, &issuer, &delegate, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::BadDelegationSignature
        );

        let mut removed = base.clone();
        removed
            .delegation_envelope
            .as_mut()
            .unwrap_or_else(|| panic!("envelope required"))
            .caveats
            .pop();
        assert_eq!(
            verify_as(&removed, &issuer, &delegate, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::BadDelegationSignature
        );

        let mut reordered = base;
        reordered
            .delegation_envelope
            .as_mut()
            .unwrap_or_else(|| panic!("envelope required"))
            .caveats
            .reverse();
        assert_eq!(
            verify_as(&reordered, &issuer, &delegate, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::MalformedEnvelope
        );
    }

    #[test]
    fn envelope_cannot_be_lifted_to_another_base_or_recipient() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let other = SigningKey::from_bytes(&[4; 32]);
        let context = query_context("corecrux.query.local", "default", &[]);

        let delegated = valid_delegation(&issuer, &subject, &delegate);
        let mut lifted = delegated.clone();
        lifted.token_id.push_str("-other-base");
        lifted.signature.sig = issuer.sign(&lifted.token_hash()).to_bytes();
        assert_eq!(
            verify_as(&lifted, &issuer, &delegate, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::BadDelegationSignature
        );

        let mut base = delegation_enabled_fixture(&issuer, &subject, &delegate);
        let mut allowed = vec![
            crux_session::passport::passport_fpr_from_public_key(&delegate.verifying_key().to_bytes()),
            crux_session::passport::passport_fpr_from_public_key(&other.verifying_key().to_bytes()),
        ];
        allowed.sort();
        base.delegation_policy
            .as_mut()
            .unwrap_or_else(|| panic!("policy required"))
            .allowed_delegate_fprs = allowed;
        base.signature.sig = issuer.sign(&base.token_hash()).to_bytes();
        let mut substituted = base
            .attenuate_for(
                vec![Caveat::ExpiresAtLe {
                    expires_at: base.expires_at - 1,
                }],
                delegate.verifying_key().to_bytes(),
                "recipient-binding",
                &subject,
            )
            .unwrap_or_else(|error| panic!("valid delegation: {error:?}"));
        substituted
            .delegation_envelope
            .as_mut()
            .unwrap_or_else(|| panic!("envelope required"))
            .delegate_public_key = other.verifying_key().to_bytes();
        assert_eq!(
            verify_as(&substituted, &issuer, &other, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::BadDelegationSignature
        );
    }

    #[test]
    fn subject_signed_noop_or_widening_caveats_are_denied() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let context = query_context("corecrux.query.local", "default", &[]);

        for hostile in [
            vec![Caveat::ExpiresAtLe {
                expires_at: 1_780_143_200,
            }],
            vec![Caveat::ExpiresAtLe {
                expires_at: 1_780_143_201,
            }],
            vec![Caveat::TenantIdEq {
                tenant_id: "attacker".to_string(),
            }],
            vec![Caveat::ScopeSubset {
                scopes: vec!["ungranted".to_string()],
            }],
        ] {
            let mut token = valid_delegation(&issuer, &subject, &delegate);
            let envelope = token
                .delegation_envelope
                .as_mut()
                .unwrap_or_else(|| panic!("envelope required"));
            envelope.caveats = hostile;
            normalize_scope_caveats(&mut envelope.caveats);
            resign_envelope(&mut token, &subject);
            assert_eq!(
                verify_as(&token, &issuer, &delegate, context, M2_NONCE, M2_NONCE),
                AttenuatedOutcome::CaveatDenied
            );
        }
    }

    #[test]
    fn proof_binds_full_token_context_and_expected_nonce() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let token = valid_delegation(&issuer, &subject, &delegate);
        let context = query_context("corecrux.query.local", "default", &[]);
        let proof = presentation_proof(&token, context, M2_NONCE, &delegate);

        assert_eq!(
            verify_token_attenuated(
                &token,
                &issuer.verifying_key().to_bytes(),
                M2_REPAIR_NOW,
                &proof,
                b"different-live-challenge",
                context,
                |_| false
            ),
            AttenuatedOutcome::BadPossessionProof
        );
        assert_eq!(
            verify_token_attenuated(
                &token,
                &issuer.verifying_key().to_bytes(),
                M2_REPAIR_NOW,
                &proof,
                b"",
                context,
                |_| false
            ),
            AttenuatedOutcome::BadPossessionProof
        );

        let changed_context = query_context("corecrux.query.explain", "default", &["passport_bound"]);
        assert_eq!(
            verify_token_attenuated(
                &token,
                &issuer.verifying_key().to_bytes(),
                M2_REPAIR_NOW,
                &proof,
                M2_NONCE,
                changed_context,
                |_| false
            ),
            AttenuatedOutcome::BadPossessionProof
        );

        let mut different_token = token.clone();
        different_token
            .delegation_envelope
            .as_mut()
            .unwrap_or_else(|| panic!("envelope required"))
            .delegation_id = "different-delegation".to_string();
        resign_envelope(&mut different_token, &subject);
        assert_eq!(
            verify_token_attenuated(
                &different_token,
                &issuer.verifying_key().to_bytes(),
                M2_REPAIR_NOW,
                &proof,
                M2_NONCE,
                context,
                |_| false
            ),
            AttenuatedOutcome::BadPossessionProof
        );
    }

    #[test]
    fn proof_from_wrong_key_is_rejected() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let attacker = SigningKey::from_bytes(&[4; 32]);
        let token = valid_delegation(&issuer, &subject, &delegate);
        let context = query_context("corecrux.query.local", "default", &[]);
        assert_eq!(
            verify_as(&token, &issuer, &attacker, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::DelegateMismatch
        );
    }

    #[test]
    fn constructor_rejects_legacy_self_unlisted_second_hop_and_invalid_caveats() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let outsider = SigningKey::from_bytes(&[4; 32]);
        let base = delegation_enabled_fixture(&issuer, &subject, &delegate);
        let expiry = vec![Caveat::ExpiresAtLe {
            expires_at: base.expires_at - 1,
        }];

        assert_eq!(
            base.attenuate_for(Vec::new(), delegate.verifying_key().to_bytes(), "d", &subject),
            Err(AttenuateError::EmptyCaveats)
        );
        assert_eq!(
            base.attenuate_for(
                (0..=RCX_MAX_DELEGATION_CAVEATS)
                    .map(|offset| Caveat::ExpiresAtLe {
                        expires_at: base.expires_at - 1 - offset as u64,
                    })
                    .collect(),
                delegate.verifying_key().to_bytes(),
                "d",
                &subject
            ),
            Err(AttenuateError::InvalidCaveatEncoding)
        );
        assert_eq!(
            base.attenuate_for(
                expiry.clone(),
                delegate.verifying_key().to_bytes(),
                "not valid",
                &subject
            ),
            Err(AttenuateError::InvalidDelegationId)
        );

        let mut legacy = base.clone();
        legacy.spec_version = RCX_CT_SPEC_VERSION.to_string();
        legacy.delegation_policy = None;
        assert_eq!(
            legacy.attenuate_for(expiry.clone(), delegate.verifying_key().to_bytes(), "d", &subject),
            Err(AttenuateError::DelegationNotPermitted)
        );
        assert_eq!(
            base.attenuate_for(expiry.clone(), subject.verifying_key().to_bytes(), "d", &subject),
            Err(AttenuateError::SelfDelegation)
        );
        assert_eq!(
            base.attenuate_for(expiry.clone(), outsider.verifying_key().to_bytes(), "d", &subject),
            Err(AttenuateError::DelegateNotPermitted)
        );
        assert_eq!(
            base.attenuate_for(
                vec![Caveat::ExpiresAtLe {
                    expires_at: base.expires_at,
                }],
                delegate.verifying_key().to_bytes(),
                "d",
                &subject
            ),
            Err(AttenuateError::CaveatDoesNotNarrow)
        );
        assert_eq!(
            base.attenuate_for(
                vec![Caveat::ExpiresAtLe {
                    expires_at: base.expires_at + 1,
                }],
                delegate.verifying_key().to_bytes(),
                "d",
                &subject
            ),
            Err(AttenuateError::CaveatOutsideBaseGrant)
        );

        let once = valid_delegation(&issuer, &subject, &delegate);
        assert_eq!(
            once.attenuate_for(expiry, outsider.verifying_key().to_bytes(), "d2", &delegate),
            Err(AttenuateError::AlreadyDelegated)
        );
    }

    #[test]
    fn forged_delegate_to_third_party_second_hop_is_rejected() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let third_party = SigningKey::from_bytes(&[4; 32]);
        let mut token = delegation_enabled_fixture(&issuer, &subject, &delegate);
        let mut allowed = vec![
            crux_session::passport::passport_fpr_from_public_key(&delegate.verifying_key().to_bytes()),
            crux_session::passport::passport_fpr_from_public_key(&third_party.verifying_key().to_bytes()),
        ];
        allowed.sort();
        token
            .delegation_policy
            .as_mut()
            .unwrap_or_else(|| panic!("policy required"))
            .allowed_delegate_fprs = allowed;
        token.signature.sig = issuer.sign(&token.token_hash()).to_bytes();
        let caveats = vec![Caveat::ExpiresAtLe {
            expires_at: token.expires_at - 1,
        }];
        let delegator_public_key = delegate.verifying_key().to_bytes();
        let delegate_public_key = third_party.verifying_key().to_bytes();
        let signature = delegate
            .sign(&delegation_binding_message(
                &token.token_hash(),
                RCX_DELEGATION_ENVELOPE_VERSION,
                "forged-second-hop",
                DelegationAudience::CruxSync,
                &delegator_public_key,
                &delegate_public_key,
                &caveats,
            ))
            .to_bytes();
        token.delegation_envelope = Some(DelegationEnvelope {
            version: RCX_DELEGATION_ENVELOPE_VERSION,
            delegation_id: "forged-second-hop".to_string(),
            audience: DelegationAudience::CruxSync,
            delegator_public_key,
            delegate_public_key,
            caveats,
            signature,
        });
        let context = query_context("corecrux.query.local", "default", &[]);

        assert_eq!(
            verify_as(&token, &issuer, &third_party, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::DelegatorMismatch
        );
    }

    #[test]
    fn team_membership_is_enforced_by_constructor_and_verifier() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let outsider = SigningKey::from_bytes(&[4; 32]);
        let mut base = delegation_enabled_fixture(&issuer, &subject, &delegate);
        base.tier = RcxTier::Team;
        base.team_scope = Some(TeamScope {
            team_id: "team-1".to_string(),
            seat_id: None,
            seat_role: Some(TeamSeatRole::Member),
            pooled_credit_agent_id: "pool-1".to_string(),
            principal_passport_fprs: vec![
                crux_session::passport::passport_fpr_from_public_key(&subject.verifying_key().to_bytes()),
                crux_session::passport::passport_fpr_from_public_key(&delegate.verifying_key().to_bytes()),
            ],
        });
        base.signature.sig = issuer.sign(&base.token_hash()).to_bytes();
        assert!(base
            .attenuate_for(
                vec![Caveat::ExpiresAtLe {
                    expires_at: base.expires_at - 1,
                }],
                delegate.verifying_key().to_bytes(),
                "team-d",
                &subject
            )
            .is_ok());

        base.delegation_policy
            .as_mut()
            .unwrap_or_else(|| panic!("policy required"))
            .allowed_delegate_fprs = vec![crux_session::passport::passport_fpr_from_public_key(
            &outsider.verifying_key().to_bytes(),
        )];
        base.signature.sig = issuer.sign(&base.token_hash()).to_bytes();
        assert_eq!(
            base.attenuate_for(
                vec![Caveat::ExpiresAtLe {
                    expires_at: base.expires_at - 1,
                }],
                outsider.verifying_key().to_bytes(),
                "team-outsider",
                &subject
            ),
            Err(AttenuateError::DelegateNotPermitted)
        );

        let caveats = vec![Caveat::ExpiresAtLe {
            expires_at: base.expires_at - 1,
        }];
        let delegator_public_key = subject.verifying_key().to_bytes();
        let delegate_public_key = outsider.verifying_key().to_bytes();
        let signature = subject
            .sign(&delegation_binding_message(
                &base.token_hash(),
                RCX_DELEGATION_ENVELOPE_VERSION,
                "team-outsider-forged",
                DelegationAudience::CruxSync,
                &delegator_public_key,
                &delegate_public_key,
                &caveats,
            ))
            .to_bytes();
        base.delegation_envelope = Some(DelegationEnvelope {
            version: RCX_DELEGATION_ENVELOPE_VERSION,
            delegation_id: "team-outsider-forged".to_string(),
            audience: DelegationAudience::CruxSync,
            delegator_public_key,
            delegate_public_key,
            caveats,
            signature,
        });
        let context = query_context("corecrux.query.local", "default", &[]);
        assert_eq!(
            verify_as(&base, &issuer, &outsider, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::DelegationNotPermitted
        );
    }

    #[test]
    fn context_intersects_base_grant_caveats_and_attestations() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let base = delegation_enabled_fixture(&issuer, &subject, &delegate);
        let token = base
            .attenuate_for(
                vec![Caveat::ScopeSubset {
                    scopes: vec!["corecrux.query.explain".to_string()],
                }],
                delegate.verifying_key().to_bytes(),
                "scope-only",
                &subject,
            )
            .unwrap_or_else(|error| panic!("valid scope delegation: {error:?}"));

        let permitted = query_context("corecrux.query.explain", "default", &["passport_bound"]);
        assert!(matches!(
            verify_as(&token, &issuer, &delegate, permitted, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::Verified(_)
        ));
        for denied in [
            query_context("corecrux.query.local", "default", &[]),
            query_context("corecrux.query.explain", "other", &["passport_bound"]),
            query_context("corecrux.query.explain", "default", &[]),
        ] {
            assert!(matches!(
                verify_as(&token, &issuer, &delegate, denied, M2_NONCE, M2_NONCE),
                AttenuatedOutcome::ContextDenied | AttenuatedOutcome::CaveatDenied
            ));
        }
    }

    #[test]
    fn subject_and_delegate_revocation_both_deny() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let token = valid_delegation(&issuer, &subject, &delegate);
        let context = query_context("corecrux.query.local", "default", &[]);
        let proof = presentation_proof(&token, context, M2_NONCE, &delegate);
        let subject_fpr = token.subject.passport_fpr.clone();
        let delegate_fpr = crux_session::passport::passport_fpr_from_public_key(&delegate.verifying_key().to_bytes());
        for revoked in [subject_fpr, delegate_fpr] {
            assert_eq!(
                verify_token_attenuated(
                    &token,
                    &issuer.verifying_key().to_bytes(),
                    M2_REPAIR_NOW,
                    &proof,
                    M2_NONCE,
                    context,
                    |candidate| candidate == revoked
                ),
                AttenuatedOutcome::PrincipalRevoked
            );
        }
    }

    #[test]
    fn malformed_envelope_and_bad_issuer_fail_closed() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let wrong_issuer = SigningKey::from_bytes(&[9; 32]);
        let subject = SigningKey::from_bytes(&[2; 32]);
        let delegate = SigningKey::from_bytes(&[3; 32]);
        let context = query_context("corecrux.query.local", "default", &[]);
        let mut malformed = valid_delegation(&issuer, &subject, &delegate);
        malformed
            .delegation_envelope
            .as_mut()
            .unwrap_or_else(|| panic!("envelope required"))
            .version = 2;
        assert_eq!(
            verify_as(&malformed, &issuer, &delegate, context, M2_NONCE, M2_NONCE),
            AttenuatedOutcome::MalformedEnvelope
        );
        assert!(matches!(
            verify_as(
                &valid_delegation(&issuer, &subject, &delegate),
                &wrong_issuer,
                &delegate,
                context,
                M2_NONCE,
                M2_NONCE
            ),
            AttenuatedOutcome::Base(VerifyOutcome::BadSignature)
        ));
    }

    #[test]
    fn unknown_caveat_type_or_member_is_rejected_by_serde() {
        assert!(serde_json::from_str::<Caveat>(r#"{"type":"future_caveat","value":1}"#).is_err());
        assert!(serde_json::from_str::<Caveat>(r#"{"type":"expires_at_le","expires_at":1,"ignored":true}"#).is_err());
    }

    #[test]
    fn free_fixture_json_mirror_is_jcs_sorted() {
        let token = free_local_verified_fixture();
        let json = token.to_canonical_json();
        assert!(json.starts_with("{\"backends\""));
        assert!(json.contains("\"spec_version\":\"rcx-ct/1.0\""));
        assert!(json.contains("\"sig\":\"11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111\""));
    }

    #[test]
    fn basic_validation_reports_expiry_and_hash() {
        let mut token = free_local_verified_fixture();
        let ok = token.validate_basic(1_776_989_601);
        assert!(ok.valid);
        assert_eq!(ok.token_hash, FREE_LOCAL_VERIFIED_TOKEN_HASH);

        token.expires_at = 1;
        // Exact-boundary check (no skew tolerance): expired one second before `now`.
        let expired = token.validate_basic_with_leeway(2, 0);
        assert!(!expired.valid);
        assert!(expired.issues.iter().any(|issue| issue.code == "token_expired"));
    }

    #[test]
    fn default_leeway_absorbs_small_clock_skew() {
        let token = free_local_verified_fixture();
        // Verifier clock 5s behind the issuer: issued_at looks 5s in the future.
        let now_behind = token.issued_at - 5;
        assert!(
            token.validate_basic(now_behind).valid,
            "issued_at 5s in the future must pass within the default 30s leeway"
        );
        // Verifier clock 5s ahead at expiry: the token looks 5s expired.
        let now_ahead = token.expires_at + 5;
        assert!(
            token.validate_basic(now_ahead).valid,
            "expiry 5s in the past must pass within the default 30s leeway"
        );
    }

    #[test]
    fn leeway_still_rejects_skew_beyond_tolerance() {
        let token = free_local_verified_fixture();
        let leeway = RcxCapabilityToken::DEFAULT_CLOCK_SKEW_LEEWAY_SECS;

        let too_early = token.issued_at - leeway - 5;
        assert!(
            token
                .validate_basic(too_early)
                .issues
                .iter()
                .any(|issue| issue.code == "token_not_yet_valid"),
            "issued_at beyond the leeway window must still be rejected"
        );

        let too_late = token.expires_at + leeway + 5;
        assert!(
            token
                .validate_basic(too_late)
                .issues
                .iter()
                .any(|issue| issue.code == "token_expired"),
            "expiry beyond the leeway window must still be rejected"
        );
    }

    #[test]
    fn basic_validation_rejects_future_issued_token() {
        let mut token = free_local_verified_fixture();
        token.issued_at = 1_776_989_700;
        let validation = token.validate_basic(1_776_989_601);
        assert!(!validation.valid);
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.code == "token_not_yet_valid"));
    }

    #[test]
    fn strict_verify_accepts_signed_token() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let token = sign_fixture(&signing);
        let pubkey = signing.verifying_key().to_bytes();
        assert_eq!(verify_token(&token, &pubkey, 1_776_989_601), VerifyOutcome::Verified);
    }

    #[test]
    fn strict_verify_rejects_tampered_token() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut token = sign_fixture(&signing);
        token.backends[0].permitted_capabilities[0].capability = "corecrux.query.tampered".to_string();
        let pubkey = signing.verifying_key().to_bytes();
        assert_eq!(
            verify_token(&token, &pubkey, 1_776_989_601),
            VerifyOutcome::BadSignature
        );
    }

    #[test]
    fn strict_verify_rejects_wrong_trust_root() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let token = sign_fixture(&signing);
        let wrong_pubkey = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_token(&token, &wrong_pubkey, 1_776_989_601),
            VerifyOutcome::BadSignature
        );
    }

    #[test]
    fn strict_verify_rejects_malformed_trust_root() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let token = sign_fixture(&signing);
        assert_eq!(
            verify_token(&token, &[0u8; 5], 1_776_989_601),
            VerifyOutcome::BadTrustRoot
        );
    }

    #[test]
    fn strict_verify_reports_future_issued_token_structurally() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut token = sign_fixture(&signing);
        token.issued_at = 1_776_989_700;
        let pubkey = signing.verifying_key().to_bytes();
        match verify_token(&token, &pubkey, 1_776_989_601) {
            VerifyOutcome::StructuralFailure(codes) => {
                assert!(codes.iter().any(|code| code == "token_not_yet_valid"));
            }
            other => panic!("expected structural failure, got {other:?}"),
        }
    }

    #[test]
    fn egress_matrix_defaults_to_no_text() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let token = sign_fixture(&signing);
        let pubkey = signing.verifying_key().to_bytes();
        assert!(token.permits_egress(
            &pubkey,
            1_776_989_601,
            "local",
            "corecrux.query.local",
            DataEgressClass::None
        ));
        assert!(!token.permits_egress(
            &pubkey,
            1_776_989_601,
            "local",
            "corecrux.query.local",
            DataEgressClass::Text
        ));
    }

    #[test]
    fn team_scope_supports_constraint_egress_without_changing_free_fixture() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut token = free_local_verified_fixture();
        token.token_id = "rcxct_team_0123456789abcdef".to_string();
        token.tier = RcxTier::Team;
        token.team_scope = Some(TeamScope {
            team_id: "team-a".to_string(),
            seat_id: Some("seat-a".to_string()),
            seat_role: Some(TeamSeatRole::Member),
            pooled_credit_agent_id: "team-pool-a".to_string(),
            principal_passport_fprs: vec![
                "p_0123456789abcdef0123456789abcdef".to_string(),
                "p_teammate".to_string(),
            ],
        });
        token.backends[0].backend_id = RCX_HOSTED_BACKEND_ID.to_string();
        token.backends[0].permitted_capabilities[0].capability = RCX_TEAM_CONSTRAINTS_SYNC_CAPABILITY.to_string();
        token.backends[0].permitted_capabilities[0].data_egress_classes =
            vec![DataEgressClass::ConstraintRecords, DataEgressClass::ReceiptHashes];
        token.backends[0].permitted_capabilities[0].required_attestations =
            vec!["passport_bound".to_string(), "team_seat_active".to_string()];
        token.backends[0].permitted_capabilities[0].credit_cost = Some(CreditCost {
            unit: CreditCostUnit::Call,
            cost: 1,
        });
        token.signature.sig = signing.sign(&token.token_hash()).to_bytes();

        let validation = token.validate_basic(1_776_989_601);
        assert!(validation.valid);
        assert!(token.permits_egress(
            &signing.verifying_key().to_bytes(),
            1_776_989_601,
            RCX_HOSTED_BACKEND_ID,
            RCX_TEAM_CONSTRAINTS_SYNC_CAPABILITY,
            DataEgressClass::ConstraintRecords
        ));
        let json = token.to_canonical_json();
        assert!(json.contains("\"team_scope\""));
        assert!(json.contains("\"pooled_credit_agent_id\":\"team-pool-a\""));
    }

    #[test]
    fn enterprise_scope_supports_customer_hosted_encrypted_blob_egress() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut token = free_local_verified_fixture();
        token.token_id = "rcxct_enterprise_0123456789abcdef".to_string();
        token.tier = RcxTier::Enterprise;
        token.enterprise_scope = Some(EnterpriseScope {
            customer_id: "customer-a".to_string(),
            contract_id: Some("contract-a".to_string()),
            backend_id: "customer:cluster-a".to_string(),
            endpoint_url: "https://cluster-a.customer.example/rcx".to_string(),
            trust_root_kid: "customer-root-a".to_string(),
            airgap: true,
            cross_signed_by_vaultcrux: true,
        });
        token.backends[0].backend_id = "customer:cluster-a".to_string();
        token.backends[0].trust_root_kid = "customer-root-a".to_string();
        token.backends[0].endpoint_url = Some("https://cluster-a.customer.example/rcx".to_string());
        token.backends[0].permitted_capabilities[0].capability =
            RCX_ENTERPRISE_ENCRYPTED_BLOB_MIRROR_CAPABILITY.to_string();
        token.backends[0].permitted_capabilities[0].data_egress_classes =
            vec![DataEgressClass::EncryptedBlob, DataEgressClass::ReceiptHashes];
        token.backends[0].permitted_capabilities[0].required_attestations = vec![
            "passport_bound".to_string(),
            "customer_trust_root".to_string(),
            "enterprise_contract_active".to_string(),
        ];
        token.backends[0].permitted_capabilities[0].credit_cost = Some(CreditCost {
            unit: CreditCostUnit::Call,
            cost: 0,
        });
        token.signature.sig = signing.sign(&token.token_hash()).to_bytes();

        let validation = token.validate_basic(1_776_989_601);
        assert!(validation.valid);
        assert!(token.permits_egress(
            &signing.verifying_key().to_bytes(),
            1_776_989_601,
            "customer:cluster-a",
            RCX_ENTERPRISE_ENCRYPTED_BLOB_MIRROR_CAPABILITY,
            DataEgressClass::EncryptedBlob
        ));
        let json = token.to_canonical_json();
        assert!(json.contains("\"enterprise_scope\""));
        assert!(json.contains("\"airgap\":true"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use proptest::prelude::*;

    proptest! {
        // The capability-token parser/verifier must never panic on arbitrary
        // input. `verify_token` is fed an attacker-controlled trust-root key (any
        // length) and an arbitrary `now`; it returns BadTrustRoot / BadSignature /
        // StructuralFailure / Verified, never a panic. `validate_basic` and
        // `permits_egress` are likewise exercised against arbitrary clock values.
        //
        // NOTE: the *canonical CBOR decode* path (`crux_session::canonical::decode`)
        // exercised by fuzz_targets/rcx_canonical_token.rs is deliberately NOT
        // driven here — it is owned by the `crux-session` crate and currently
        // pre-allocates an attacker-controlled length prefix (unbounded-allocation
        // OOM, see canonical.rs read_value MAJOR_ARRAY/MAJOR_MAP). The scheduled
        // libFuzzer target catches that class under its `-rss_limit_mb` guard; a
        // proptest cannot bound the allocator, so it would abort the test process.
        #[test]
        fn token_parser_never_panics(
            key in proptest::collection::vec(any::<u8>(), 0..96),
            now in any::<u64>(),
        ) {
            let token = free_local_verified_fixture();
            let _ = token.validate_basic(now);
            let _ = token.permits_egress(
                &key,
                now,
                "local",
                "corecrux.query.local",
                DataEgressClass::None,
            );
            let _ = verify_token(&token, &key, now);
        }

        #[test]
        fn arbitrary_attenuation_never_widens_issuer_authority(
            base_caps in proptest::collection::btree_set(0u8..6, 1..6),
            text_caps in proptest::collection::btree_set(0u8..6, 0..7),
            attestation_caps in proptest::collection::btree_set(0u8..6, 0..7),
            caveat_scopes in proptest::collection::btree_set(0u8..8, 1..9),
            requested_cap in 0u8..8,
            request_text in any::<bool>(),
            present_attestation in any::<bool>(),
            context_tenant_matches in any::<bool>(),
            caveat_tenant_matches in any::<bool>(),
            expiry_mode in 0u8..3,
        ) {
            const NOW: u64 = 1_776_989_601;
            let issuer = SigningKey::from_bytes(&[0x51; 32]);
            let subject = SigningKey::from_bytes(&[0x52; 32]);
            let delegate = SigningKey::from_bytes(&[0x53; 32]);
            let mut token = free_local_verified_fixture();
            token.spec_version = RCX_CT_DELEGATION_SPEC_VERSION.to_string();
            token.subject.passport_fpr = crux_session::passport::passport_fpr_from_public_key(
                &subject.verifying_key().to_bytes(),
            );
            token.backends[0].permitted_capabilities = base_caps
                .iter()
                .map(|id| {
                    let mut egress = vec![DataEgressClass::None];
                    if text_caps.contains(id) {
                        egress.push(DataEgressClass::Text);
                    }
                    PermittedCapability {
                        capability: format!("cap-{id}"),
                        data_egress_classes: egress,
                        required_attestations: if attestation_caps.contains(id) {
                            vec!["passport_bound".to_string()]
                        } else {
                            Vec::new()
                        },
                        credit_cost: None,
                    }
                })
                .collect();
            token.delegation_policy = Some(DelegationPolicy {
                presentation: DelegationPresentation::ProofOfPossession,
                max_depth: 1,
                audience: DelegationAudience::CruxSync,
                allowed_delegate_fprs: vec![crux_session::passport::passport_fpr_from_public_key(
                    &delegate.verifying_key().to_bytes(),
                )],
            });
            token.signature.sig = issuer.sign(&token.token_hash()).to_bytes();

            let expires_at = match expiry_mode {
                0 => token.expires_at - 1,
                1 => token.expires_at,
                _ => token.expires_at + 1,
            };
            let mut caveats = vec![
                Caveat::ExpiresAtLe { expires_at },
                Caveat::ScopeSubset {
                    scopes: caveat_scopes.iter().map(|id| format!("cap-{id}")).collect(),
                },
                Caveat::TenantIdEq {
                    tenant_id: if caveat_tenant_matches {
                        "default".to_string()
                    } else {
                        "other".to_string()
                    },
                },
            ];
            normalize_scope_caveats(&mut caveats);
            let delegator_public_key = subject.verifying_key().to_bytes();
            let delegate_public_key = delegate.verifying_key().to_bytes();
            let envelope_signature = subject
                .sign(&delegation_binding_message(
                    &token.token_hash(),
                    RCX_DELEGATION_ENVELOPE_VERSION,
                    "property-delegation",
                    DelegationAudience::CruxSync,
                    &delegator_public_key,
                    &delegate_public_key,
                    &caveats,
                ))
                .to_bytes();
            token.delegation_envelope = Some(DelegationEnvelope {
                version: RCX_DELEGATION_ENVELOPE_VERSION,
                delegation_id: "property-delegation".to_string(),
                audience: DelegationAudience::CruxSync,
                delegator_public_key,
                delegate_public_key,
                caveats,
                signature: envelope_signature,
            });

            let requested_capability = format!("cap-{requested_cap}");
            let requested_egress = if request_text {
                vec![DataEgressClass::Text]
            } else {
                vec![DataEgressClass::None]
            };
            let present_attestations = if present_attestation {
                vec!["passport_bound"]
            } else {
                Vec::new()
            };
            let context = AttenuationContext {
                audience: DelegationAudience::CruxSync,
                tenant_id: if context_tenant_matches { "default" } else { "other" },
                backend_id: "local",
                capability: &requested_capability,
                data_egress_classes: &requested_egress,
                present_attestations: &present_attestations,
            };
            let nonce = b"property-verifier-nonce";
            let proof = PresentationProof {
                public_key: delegate_public_key,
                nonce,
                signature: delegate
                    .sign(&presentation_proof_message(&token, context, nonce))
                    .to_bytes(),
            };
            let outcome = verify_token_attenuated(
                &token,
                &issuer.verifying_key().to_bytes(),
                NOW,
                &proof,
                nonce,
                context,
                |_| false,
            );

            if matches!(outcome, AttenuatedOutcome::Verified(_)) {
                prop_assert!(base_caps.contains(&requested_cap));
                prop_assert!(!request_text || text_caps.contains(&requested_cap));
                prop_assert!(!attestation_caps.contains(&requested_cap) || present_attestation);
                prop_assert!(context_tenant_matches);
                prop_assert!(caveat_tenant_matches);
                prop_assert!(caveat_scopes.contains(&requested_cap));
                prop_assert!(expires_at <= token.expires_at);
                prop_assert!(NOW < expires_at);
            }
        }
    }
}
