// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! RCX Capability Token v1.0 schema-lock crate.
//!
//! Phase 1 intentionally keeps this crate pure: it defines the token model,
//! deterministic CBOR/JSON mirror, token hash input, structural validation, and
//! strict Ed25519 verification helpers used by the daemon router and hosted
//! issuer.

use crux_session::canonical::{to_canonical_json, CborValue};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};

pub const RCX_CT_SPEC_VERSION: &str = "rcx-ct/1.0";
pub const RCX_CT_SIGNATURE_LEN: usize = 64;
pub const RCX_CT_HASH_LEN: usize = 32;
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

/// Permitted-capability set for a PAID token: every premium lane, each costing
/// `per_call_cost` credits per call (Text egress). Free tokens carry none of
/// these, so their premium lanes are hard-gated off in CoreCrux.
pub fn corecrux_premium_lane_capabilities(per_call_cost: u64) -> Vec<PermittedCapability> {
    CORECRUX_PREMIUM_LANE_SLUGS
        .iter()
        .map(|slug| PermittedCapability {
            capability: corecrux_lane_capability(slug),
            data_egress_classes: vec![DataEgressClass::Text],
            required_attestations: Vec::new(),
            credit_cost: Some(CreditCost {
                unit: CreditCostUnit::Call,
                cost: per_call_cost,
            }),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuer {
    pub passport_kid: String,
    pub issuer_org: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub passport_fpr: String,
    pub daemon_instance_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantScope {
    pub tenant_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamScope {
    pub team_id: String,
    pub seat_id: Option<String>,
    pub seat_role: Option<TeamSeatRole>,
    pub pooled_credit_agent_id: String,
    pub principal_passport_fprs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseScope {
    pub customer_id: String,
    pub contract_id: Option<String>,
    pub backend_id: String,
    pub endpoint_url: String,
    pub trust_root_kid: String,
    pub airgap: bool,
    pub cross_signed_by_vaultcrux: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditCost {
    pub unit: CreditCostUnit,
    pub cost: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermittedCapability {
    pub capability: String,
    pub data_egress_classes: Vec<DataEgressClass>,
    pub required_attestations: Vec<String>,
    pub credit_cost: Option<CreditCost>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    pub backend_id: String,
    pub trust_root_kid: String,
    pub endpoint_url: Option<String>,
    pub permitted_capabilities: Vec<PermittedCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditRefill {
    pub period: RefillPeriod,
    pub amount: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credits {
    pub balance: Option<u64>,
    pub refill: CreditRefill,
    pub overdraft: OverdraftPolicy,
    pub overdraft_limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackPolicy {
    pub on_backend_unreachable: FallbackAction,
    pub on_credits_exhausted: FallbackAction,
    pub on_expiry: FallbackAction,
    pub queue_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub crl_url: Option<String>,
    pub push_channel: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub alg: String,
    pub kid: String,
    pub sig: [u8; RCX_CT_SIGNATURE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
            (
                "signature".to_string(),
                signature_to_cbor(&self.signature, zero_signature),
            ),
        ]);
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

    pub fn validate_basic(&self, now_unix_seconds: u64) -> TokenValidationResult {
        let mut issues = Vec::new();
        if self.spec_version != RCX_CT_SPEC_VERSION {
            issues.push(TokenValidationIssue::new(
                "invalid_spec_version",
                "spec_version must be rcx-ct/1.0",
            ));
        }
        if self.token_id.trim().is_empty() {
            issues.push(TokenValidationIssue::new("missing_token_id", "token_id is required"));
        }
        if self.issued_at > now_unix_seconds {
            issues.push(TokenValidationIssue::new(
                "token_not_yet_valid",
                "issued_at must be at or before the validation time",
            ));
        }
        if self.expires_at <= now_unix_seconds {
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

    pub fn permits_egress(&self, backend_id: &str, capability: &str, egress_class: DataEgressClass) -> bool {
        self.backends.iter().any(|backend| {
            backend.backend_id == backend_id
                && backend.permitted_capabilities.iter().any(|permitted| {
                    permitted.capability == capability
                        && permitted
                            .data_egress_classes
                            .iter()
                            .any(|candidate| candidate == &egress_class)
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
    let basic = token.validate_basic(now_unix_seconds);
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
            assert_eq!(cap.credit_cost.as_ref().map(|c| c.cost), Some(3));
            assert_eq!(cap.data_egress_classes, vec![DataEgressClass::Text]);
        }
        // the metered dense-service lanes are present and premium
        for slug in ["rerank", "dense_managed"] {
            assert!(
                CORECRUX_PREMIUM_LANE_SLUGS.contains(&slug),
                "{slug} should be a premium lane"
            );
        }
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
        let expired = token.validate_basic(2);
        assert!(!expired.valid);
        assert!(expired.issues.iter().any(|issue| issue.code == "token_expired"));
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
        let token = free_local_verified_fixture();
        assert!(token.permits_egress("local", "corecrux.query.local", DataEgressClass::None));
        assert!(!token.permits_egress("local", "corecrux.query.local", DataEgressClass::Text));
    }

    #[test]
    fn team_scope_supports_constraint_egress_without_changing_free_fixture() {
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

        let validation = token.validate_basic(1_776_989_601);
        assert!(validation.valid);
        assert!(token.permits_egress(
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

        let validation = token.validate_basic(1_776_989_601);
        assert!(validation.valid);
        assert!(token.permits_egress(
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
            let _ = token.permits_egress("local", "corecrux.query.local", DataEgressClass::None);
            let _ = verify_token(&token, &key, now);
        }
    }
}
