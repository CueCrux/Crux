// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Enterprise customer-hosted RCX Capability Token validation contract.
//!
//! The production enterprise distribution can bind this contract to a customer
//! KMS/HSM verifier. This crate keeps the deterministic policy surface pure:
//! trust-root selection, airgap enforcement, backend/capability matching, and
//! egress refusal reasons.

use rcx_capability_token::{
    Backend, CreditCost, CreditCostUnit, DataEgressClass, EnterpriseScope, PermittedCapability, RcxCapabilityToken,
    RcxTier, TokenValidationIssue, RCX_CUSTOMER_BACKEND_PREFIX, RCX_ENTERPRISE_ENCRYPTED_BLOB_MIRROR_CAPABILITY,
    RCX_HOSTED_BACKEND_ID, RCX_HOSTED_RETRIEVE_CAPABILITY,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseTrustRoot {
    pub customer_id: String,
    pub backend_id: String,
    pub trust_root_kid: String,
    pub trusted_issuer_kids: Vec<String>,
    pub airgap: bool,
    pub allow_vaultcrux_cross_sign: bool,
}

pub fn validate_enterprise_trust_root(root: &EnterpriseTrustRoot) -> Vec<TokenValidationIssue> {
    let mut issues = Vec::new();
    if root.customer_id.trim().is_empty() {
        issues.push(issue("enterprise_customer_id_required"));
    }
    if !root.backend_id.starts_with(RCX_CUSTOMER_BACKEND_PREFIX) {
        issues.push(issue("enterprise_backend_must_be_customer_hosted"));
    }
    if root.trust_root_kid.trim().is_empty() {
        issues.push(issue("enterprise_trust_root_kid_required"));
    }
    if root.trusted_issuer_kids.is_empty() && !root.allow_vaultcrux_cross_sign {
        issues.push(issue("enterprise_trusted_issuer_or_cross_sign_required"));
    }
    if root.airgap && root.backend_id == RCX_HOSTED_BACKEND_ID {
        issues.push(issue("enterprise_airgap_cannot_use_hosted_backend"));
    }
    issues
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseShimCall {
    pub backend_id: String,
    pub capability: String,
    pub data_egress_classes: Vec<DataEgressClass>,
}

impl EnterpriseShimCall {
    pub fn encrypted_blob_mirror(backend_id: impl Into<String>) -> Self {
        Self {
            backend_id: backend_id.into(),
            capability: RCX_ENTERPRISE_ENCRYPTED_BLOB_MIRROR_CAPABILITY.to_string(),
            data_egress_classes: vec![DataEgressClass::EncryptedBlob, DataEgressClass::ReceiptHashes],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseShimDecision {
    pub allowed: bool,
    pub mode: EnterpriseShimMode,
    pub token_hash: String,
    pub backend_id: Option<String>,
    pub refusal_code: Option<String>,
    pub issues: Vec<TokenValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterpriseShimMode {
    CustomerHosted,
    Refused,
}

impl EnterpriseShimMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CustomerHosted => "customer_hosted",
            Self::Refused => "refused",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnterpriseShim {
    trust_root: EnterpriseTrustRoot,
}

impl EnterpriseShim {
    pub fn new(trust_root: EnterpriseTrustRoot) -> Self {
        Self { trust_root }
    }

    pub fn validate(
        &self,
        token: &RcxCapabilityToken,
        call: &EnterpriseShimCall,
        now_unix_seconds: u64,
    ) -> EnterpriseShimDecision {
        let validation = token.validate_basic(now_unix_seconds);
        if !validation.valid {
            return Self::refuse(token, call, "token_invalid", validation.issues);
        }

        if token.tier != RcxTier::Enterprise {
            return Self::refuse(
                token,
                call,
                "capability_not_permitted",
                vec![issue("not_enterprise_tier")],
            );
        }

        let Some(scope) = &token.enterprise_scope else {
            return Self::refuse(token, call, "token_invalid", vec![issue("missing_enterprise_scope")]);
        };

        let Some(scope_issue) = self.validate_scope(token, scope, call) else {
            return EnterpriseShimDecision {
                allowed: true,
                mode: EnterpriseShimMode::CustomerHosted,
                token_hash: token.token_hash_hex(),
                backend_id: Some(call.backend_id.clone()),
                refusal_code: None,
                issues: Vec::new(),
            };
        };
        Self::refuse(token, call, scope_issue.refusal_code, vec![scope_issue.issue])
    }

    fn validate_scope(
        &self,
        token: &RcxCapabilityToken,
        scope: &EnterpriseScope,
        call: &EnterpriseShimCall,
    ) -> Option<ScopedIssue> {
        if scope.customer_id != self.trust_root.customer_id {
            return Some(scoped("tenant_mismatch", "enterprise_customer_mismatch"));
        }
        if !scope.backend_id.starts_with(RCX_CUSTOMER_BACKEND_PREFIX)
            || scope.backend_id != self.trust_root.backend_id
            || call.backend_id != self.trust_root.backend_id
        {
            return Some(scoped("backend_not_permitted", "enterprise_backend_mismatch"));
        }
        if scope.trust_root_kid != self.trust_root.trust_root_kid {
            return Some(scoped("trust_root_mismatch", "enterprise_trust_root_mismatch"));
        }
        if self.trust_root.airgap
            && (call.backend_id == RCX_HOSTED_BACKEND_ID
                || token
                    .backends
                    .iter()
                    .any(|backend| backend.backend_id == RCX_HOSTED_BACKEND_ID))
        {
            return Some(scoped("backend_not_permitted", "enterprise_airgap_hosted_backend"));
        }
        if !self.issuer_is_trusted(token, scope) {
            return Some(scoped("issuer_not_trusted", "enterprise_issuer_not_trusted"));
        }

        let backend = token
            .backends
            .iter()
            .find(|backend| backend.backend_id == call.backend_id)?;
        if backend.trust_root_kid != self.trust_root.trust_root_kid {
            return Some(scoped("trust_root_mismatch", "backend_trust_root_mismatch"));
        }
        if !backend_permits_call(backend, call) {
            return Some(scoped("egress_not_permitted", "enterprise_egress_not_permitted"));
        }
        None
    }

    fn issuer_is_trusted(&self, token: &RcxCapabilityToken, scope: &EnterpriseScope) -> bool {
        self.trust_root
            .trusted_issuer_kids
            .iter()
            .any(|kid| kid == &token.issuer.passport_kid)
            || (self.trust_root.allow_vaultcrux_cross_sign
                && scope.cross_signed_by_vaultcrux
                && token.issuer.issuer_org == "vaultcrux")
    }

    fn refuse(
        token: &RcxCapabilityToken,
        call: &EnterpriseShimCall,
        refusal_code: &str,
        issues: Vec<TokenValidationIssue>,
    ) -> EnterpriseShimDecision {
        EnterpriseShimDecision {
            allowed: false,
            mode: EnterpriseShimMode::Refused,
            token_hash: token.token_hash_hex(),
            backend_id: Some(call.backend_id.clone()),
            refusal_code: Some(refusal_code.to_string()),
            issues,
        }
    }
}

struct ScopedIssue {
    refusal_code: &'static str,
    issue: TokenValidationIssue,
}

fn scoped(refusal_code: &'static str, code: &str) -> ScopedIssue {
    ScopedIssue {
        refusal_code,
        issue: issue(code),
    }
}

fn issue(code: &str) -> TokenValidationIssue {
    TokenValidationIssue::new(code, code)
}

fn backend_permits_call(backend: &Backend, call: &EnterpriseShimCall) -> bool {
    backend.permitted_capabilities.iter().any(|capability| {
        capability.capability == call.capability
            && call.data_egress_classes.iter().all(|egress| {
                capability
                    .data_egress_classes
                    .iter()
                    .any(|permitted| permitted == egress)
            })
    })
}

pub fn enterprise_encrypted_blob_backend(
    backend_id: impl Into<String>,
    endpoint_url: impl Into<String>,
    trust_root_kid: impl Into<String>,
) -> Backend {
    let trust_root_kid = trust_root_kid.into();
    Backend {
        backend_id: backend_id.into(),
        trust_root_kid: trust_root_kid.clone(),
        endpoint_url: Some(endpoint_url.into()),
        permitted_capabilities: vec![
            PermittedCapability {
                capability: RCX_HOSTED_RETRIEVE_CAPABILITY.to_string(),
                data_egress_classes: vec![DataEgressClass::EncryptedBlob, DataEgressClass::ReceiptHashes],
                required_attestations: vec![
                    "passport_bound".to_string(),
                    "customer_trust_root".to_string(),
                    "enterprise_contract_active".to_string(),
                ],
                credit_cost: Some(CreditCost {
                    unit: CreditCostUnit::Call,
                    cost: 0,
                }),
            },
            PermittedCapability {
                capability: RCX_ENTERPRISE_ENCRYPTED_BLOB_MIRROR_CAPABILITY.to_string(),
                data_egress_classes: vec![DataEgressClass::EncryptedBlob, DataEgressClass::ReceiptHashes],
                required_attestations: vec![
                    "passport_bound".to_string(),
                    "customer_trust_root".to_string(),
                    "enterprise_contract_active".to_string(),
                ],
                credit_cost: Some(CreditCost {
                    unit: CreditCostUnit::Call,
                    cost: 0,
                }),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcx_capability_token::{free_local_verified_fixture, RcxTier};

    fn enterprise_token() -> RcxCapabilityToken {
        let mut token = free_local_verified_fixture();
        token.token_id = "rcxct_enterprise_0123456789abcdef".to_string();
        token.issuer.passport_kid = "rcx-test-kid".to_string();
        token.issuer.issuer_org = "vaultcrux".to_string();
        token.signature.kid = "rcx-test-kid".to_string();
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
        token.backends = vec![enterprise_encrypted_blob_backend(
            "customer:cluster-a",
            "https://cluster-a.customer.example/rcx",
            "customer-root-a",
        )];
        token
    }

    fn shim() -> EnterpriseShim {
        EnterpriseShim::new(EnterpriseTrustRoot {
            customer_id: "customer-a".to_string(),
            backend_id: "customer:cluster-a".to_string(),
            trust_root_kid: "customer-root-a".to_string(),
            trusted_issuer_kids: vec!["customer-issuer-a".to_string()],
            airgap: true,
            allow_vaultcrux_cross_sign: true,
        })
    }

    #[test]
    fn allows_customer_hosted_encrypted_blob_calls() {
        let decision = shim().validate(
            &enterprise_token(),
            &EnterpriseShimCall::encrypted_blob_mirror("customer:cluster-a"),
            1_776_989_601,
        );

        assert!(decision.allowed);
        assert_eq!(decision.mode, EnterpriseShimMode::CustomerHosted);
        assert_eq!(decision.backend_id.as_deref(), Some("customer:cluster-a"));
    }

    #[test]
    fn validates_enterprise_trust_root_static_contract() {
        let root = EnterpriseTrustRoot {
            customer_id: "customer-a".to_string(),
            backend_id: "customer:cluster-a".to_string(),
            trust_root_kid: "customer-root-a".to_string(),
            trusted_issuer_kids: vec!["customer-issuer-a".to_string()],
            airgap: true,
            allow_vaultcrux_cross_sign: false,
        };

        assert!(validate_enterprise_trust_root(&root).is_empty());
    }

    #[test]
    fn refuses_invalid_enterprise_trust_root_static_contract() {
        let root = EnterpriseTrustRoot {
            customer_id: String::new(),
            backend_id: "hosted.vaultcrux.com".to_string(),
            trust_root_kid: String::new(),
            trusted_issuer_kids: Vec::new(),
            airgap: true,
            allow_vaultcrux_cross_sign: false,
        };
        let issues = validate_enterprise_trust_root(&root);

        assert!(issues
            .iter()
            .any(|issue| issue.code == "enterprise_customer_id_required"));
        assert!(issues
            .iter()
            .any(|issue| issue.code == "enterprise_backend_must_be_customer_hosted"));
        assert!(issues
            .iter()
            .any(|issue| issue.code == "enterprise_trust_root_kid_required"));
        assert!(issues
            .iter()
            .any(|issue| issue.code == "enterprise_trusted_issuer_or_cross_sign_required"));
        assert!(issues
            .iter()
            .any(|issue| issue.code == "enterprise_airgap_cannot_use_hosted_backend"));
    }

    #[test]
    fn refuses_airgap_tokens_that_include_hosted_backend() {
        let mut token = enterprise_token();
        token.backends.push(Backend {
            backend_id: RCX_HOSTED_BACKEND_ID.to_string(),
            trust_root_kid: "rcx-test-kid".to_string(),
            endpoint_url: Some("https://hosted.vaultcrux.com".to_string()),
            permitted_capabilities: Vec::new(),
        });

        let decision = shim().validate(
            &token,
            &EnterpriseShimCall::encrypted_blob_mirror("customer:cluster-a"),
            1_776_989_601,
        );

        assert!(!decision.allowed);
        assert_eq!(decision.refusal_code.as_deref(), Some("token_invalid"));
        assert!(decision
            .issues
            .iter()
            .any(|issue| issue.code == "backend_not_permitted"));
    }

    #[test]
    fn refuses_untrusted_customer_issuer_without_vaultcrux_cross_sign() {
        let mut token = enterprise_token();
        token.issuer.issuer_org = "customer-a".to_string();
        token.issuer.passport_kid = "unknown-customer-issuer".to_string();
        token.signature.kid = "unknown-customer-issuer".to_string();
        token
            .enterprise_scope
            .as_mut()
            .expect("enterprise scope")
            .cross_signed_by_vaultcrux = false;

        let decision = shim().validate(
            &token,
            &EnterpriseShimCall::encrypted_blob_mirror("customer:cluster-a"),
            1_776_989_601,
        );

        assert!(!decision.allowed);
        assert_eq!(decision.refusal_code.as_deref(), Some("issuer_not_trusted"));
    }
}
