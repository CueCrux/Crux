// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! RCX daemon router primitives.
//!
//! This crate is deliberately pure for Phase 1: it consumes an
//! [`rcx_capability_token::RcxCapabilityToken`] and returns deterministic
//! routing/refusal decisions. Network refresh, hosted debits, and revocation IO
//! land in later phases.

use rcx_capability_token::{
    Backend, CreditRefill, Credits, DataEgressClass, FallbackAction, FallbackPolicy, Issuer, OverdraftPolicy,
    PermittedCapability, RcxCapabilityToken, RcxTier, ReceiptClass, Revocation, Signature, Subject, TenantScope,
    TokenValidationIssue, RCX_CT_SIGNATURE_LEN, RCX_CT_SPEC_VERSION,
};

pub const RCX_MODE_HEADER: &str = "X-Crux-Mode";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterMode {
    Local,
    Hosted,
    CustomerHosted,
    DegradedLocal,
    DegradedQueued,
    Refused,
}

impl RouterMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Hosted => "hosted",
            Self::CustomerHosted => "customer_hosted",
            Self::DegradedLocal => "degraded-local",
            Self::DegradedQueued => "degraded-queued",
            Self::Refused => "refused",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    TokenInvalid,
    TokenExpired,
    CapabilityNotPermitted,
    EgressNotPermitted,
    InsufficientCredit,
    ReceiptClassSideEffectDenied,
    BackendUnavailable,
}

impl DenialReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TokenInvalid => "denied:token_invalid",
            Self::TokenExpired => "denied:token_expired",
            Self::CapabilityNotPermitted => "denied:capability_not_permitted",
            Self::EgressNotPermitted => "denied:egress_not_permitted",
            Self::InsufficientCredit => "denied:insufficient_credit",
            Self::ReceiptClassSideEffectDenied => "denied:receipt_class_side_effect_denied",
            Self::BackendUnavailable => "denied:backend_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallContext {
    pub capability: String,
    pub preferred_backend: Option<String>,
    pub data_egress_classes: Vec<DataEgressClass>,
    pub estimated_credit_cost: u64,
    pub backend_reachable: bool,
}

impl CallContext {
    pub fn local(capability: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            preferred_backend: Some("local".to_string()),
            data_egress_classes: vec![DataEgressClass::None],
            estimated_credit_cost: 0,
            backend_reachable: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterDecision {
    pub authorised: bool,
    pub mode: RouterMode,
    pub backend_id: Option<String>,
    pub reason_code: Option<String>,
    pub token_id: String,
    pub token_hash: String,
    pub stamp: CruxModeStamp,
    pub refusal_receipt: Option<RefusalReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CruxModeStamp {
    pub header_name: String,
    pub mode: String,
    pub reason_code: Option<String>,
    pub token_id: String,
    pub token_hash: String,
    pub queue_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalReceipt {
    pub event_type: String,
    pub token_id: String,
    pub token_hash: String,
    pub capability: String,
    pub backend_id: Option<String>,
    pub data_egress_classes: Vec<String>,
    pub reason_code: String,
    pub receipt_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolCapability {
    pub tool_name: String,
    pub capability: String,
    pub backend_id: String,
    pub data_egress_classes: Vec<DataEgressClass>,
}

impl McpToolCapability {
    pub fn local_none(tool_name: impl Into<String>, capability: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            capability: capability.into(),
            backend_id: "local".to_string(),
            data_egress_classes: vec![DataEgressClass::None],
        }
    }
}

#[derive(Debug, Clone)]
pub struct RcxRouter {
    token: RcxCapabilityToken,
}

impl RcxRouter {
    pub fn new(token: RcxCapabilityToken) -> Self {
        Self { token }
    }

    pub fn token(&self) -> &RcxCapabilityToken {
        &self.token
    }

    pub fn decide(&self, call: &CallContext, now_unix_seconds: u64) -> RouterDecision {
        let validation = self.token.validate_basic(now_unix_seconds);
        if !validation.valid {
            let reason = first_validation_reason(&validation.issues);
            if reason == DenialReason::TokenExpired
                && validation.issues.iter().all(|issue| issue.code == "token_expired")
            {
                return self.apply_expiry_fallback(call, reason);
            }
            return self.refuse(call, reason);
        }

        let backend = self.select_backend(call);
        let Some(backend) = backend else {
            return self.refuse(call, DenialReason::CapabilityNotPermitted);
        };

        if !call.backend_reachable && backend.backend_id != "local" {
            return self.apply_fallback_action(
                call,
                &self.token.fallback.on_backend_unreachable,
                DenialReason::BackendUnavailable,
            );
        }

        let Some(capability) = backend
            .permitted_capabilities
            .iter()
            .find(|candidate| candidate.capability == call.capability)
        else {
            return self.refuse(call, DenialReason::CapabilityNotPermitted);
        };

        if call.data_egress_classes.iter().any(|class| {
            !capability
                .data_egress_classes
                .iter()
                .any(|permitted| permitted == class)
        }) {
            return self.refuse(call, DenialReason::EgressNotPermitted);
        }

        let debitable =
            capability.credit_cost.as_ref().is_some_and(|cost| cost.cost > 0) || call.estimated_credit_cost > 0;
        if self.token.receipt_class == ReceiptClass::Replay && debitable {
            return self.refuse(call, DenialReason::ReceiptClassSideEffectDenied);
        }
        if debitable && !has_credit(&self.token, call.estimated_credit_cost) {
            return self.apply_fallback_action(
                call,
                &self.token.fallback.on_credits_exhausted,
                DenialReason::InsufficientCredit,
            );
        }

        let mode = if backend.backend_id == "local" {
            RouterMode::Local
        } else if backend.backend_id.starts_with("customer:") {
            RouterMode::CustomerHosted
        } else {
            RouterMode::Hosted
        };
        let stamp = self.crux_mode_stamp(&mode, None, None);
        RouterDecision {
            authorised: true,
            mode,
            backend_id: Some(backend.backend_id.clone()),
            reason_code: None,
            token_id: self.token.token_id.clone(),
            token_hash: self.token.token_hash_hex(),
            stamp,
            refusal_receipt: None,
        }
    }

    pub fn filter_mcp_tools(&self, tools: &[McpToolCapability], now_unix_seconds: u64) -> Vec<String> {
        tools
            .iter()
            .filter_map(|tool| {
                let decision = self.decide(
                    &CallContext {
                        capability: tool.capability.clone(),
                        preferred_backend: Some(tool.backend_id.clone()),
                        data_egress_classes: tool.data_egress_classes.clone(),
                        estimated_credit_cost: 0,
                        backend_reachable: true,
                    },
                    now_unix_seconds,
                );
                decision.authorised.then(|| tool.tool_name.clone())
            })
            .collect()
    }

    fn select_backend<'a>(&'a self, call: &CallContext) -> Option<&'a Backend> {
        let preferred = call.preferred_backend.as_deref().unwrap_or("local");
        self.token.backends.iter().find(|backend| {
            backend.backend_id == preferred
                && backend
                    .permitted_capabilities
                    .iter()
                    .any(|capability| capability.capability == call.capability)
        })
    }

    fn apply_expiry_fallback(&self, call: &CallContext, reason: DenialReason) -> RouterDecision {
        match &self.token.fallback.on_expiry {
            FallbackAction::DegradeToLocal => self.degraded_local(reason),
            _ => self.refuse(call, reason),
        }
    }

    fn apply_fallback_action(
        &self,
        call: &CallContext,
        action: &FallbackAction,
        reason: DenialReason,
    ) -> RouterDecision {
        match action {
            FallbackAction::DegradeToLocal => self.degraded_local(reason),
            FallbackAction::Queue if self.token.fallback.queue_ttl_seconds.is_some() => {
                self.degraded_queued(call, reason)
            }
            _ => self.refuse(call, reason),
        }
    }

    fn degraded_local(&self, reason: DenialReason) -> RouterDecision {
        let mode = RouterMode::DegradedLocal;
        let reason_code = reason.as_str().to_string();
        let stamp = self.crux_mode_stamp(&mode, Some(&reason_code), None);
        RouterDecision {
            authorised: true,
            mode,
            backend_id: Some("local".to_string()),
            reason_code: Some(reason_code),
            token_id: self.token.token_id.clone(),
            token_hash: self.token.token_hash_hex(),
            stamp,
            refusal_receipt: None,
        }
    }

    fn degraded_queued(&self, call: &CallContext, reason: DenialReason) -> RouterDecision {
        let mode = RouterMode::DegradedQueued;
        let reason_code = reason.as_str().to_string();
        let stamp = self.crux_mode_stamp(&mode, Some(&reason_code), self.token.fallback.queue_ttl_seconds);
        RouterDecision {
            authorised: true,
            mode,
            backend_id: call.preferred_backend.clone(),
            reason_code: Some(reason_code),
            token_id: self.token.token_id.clone(),
            token_hash: self.token.token_hash_hex(),
            stamp,
            refusal_receipt: None,
        }
    }

    fn refuse(&self, call: &CallContext, reason: DenialReason) -> RouterDecision {
        let reason_code = reason.as_str().to_string();
        let mode = RouterMode::Refused;
        let stamp = self.crux_mode_stamp(&mode, Some(&reason_code), None);
        RouterDecision {
            authorised: false,
            mode,
            backend_id: call.preferred_backend.clone(),
            reason_code: Some(reason_code.clone()),
            token_id: self.token.token_id.clone(),
            token_hash: self.token.token_hash_hex(),
            stamp,
            refusal_receipt: Some(RefusalReceipt {
                event_type: "rcx.capability_token.call_refused.v1".to_string(),
                token_id: self.token.token_id.clone(),
                token_hash: self.token.token_hash_hex(),
                capability: call.capability.clone(),
                backend_id: call.preferred_backend.clone(),
                data_egress_classes: call
                    .data_egress_classes
                    .iter()
                    .map(|class| class.as_str().to_string())
                    .collect(),
                reason_code,
                receipt_class: self.token.receipt_class.as_str().to_string(),
            }),
        }
    }

    fn crux_mode_stamp(
        &self,
        mode: &RouterMode,
        reason_code: Option<&str>,
        queue_ttl_seconds: Option<u64>,
    ) -> CruxModeStamp {
        CruxModeStamp {
            header_name: RCX_MODE_HEADER.to_string(),
            mode: mode.as_str().to_string(),
            reason_code: reason_code.map(str::to_string),
            token_id: self.token.token_id.clone(),
            token_hash: self.token.token_hash_hex(),
            queue_ttl_seconds,
        }
    }
}

pub fn mint_free_local_token(
    passport_fpr: impl Into<String>,
    daemon_instance_id: impl Into<String>,
    tenant_id: impl Into<String>,
    local_capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    signature: [u8; RCX_CT_SIGNATURE_LEN],
) -> RcxCapabilityToken {
    let passport_fpr = passport_fpr.into();
    let tenant_id = tenant_id.into();
    let short_fpr: String = passport_fpr.trim_start_matches("p_").chars().take(16).collect();
    RcxCapabilityToken {
        spec_version: RCX_CT_SPEC_VERSION.to_string(),
        token_id: format!("rcxct_free_{short_fpr}_{tenant_id}"),
        issued_at,
        expires_at,
        refresh_hint_at: expires_at.saturating_sub(3600),
        issuer: Issuer {
            passport_kid: passport_fpr.clone(),
            issuer_org: "local".to_string(),
        },
        subject: Subject {
            passport_fpr: passport_fpr.clone(),
            daemon_instance_id: Some(daemon_instance_id.into()),
        },
        tenant_scope: TenantScope {
            tenant_id,
            display_name: Some("Local".to_string()),
        },
        team_scope: None,
        enterprise_scope: None,
        tier: RcxTier::Free,
        receipt_class: ReceiptClass::Verified,
        backends: vec![Backend {
            backend_id: "local".to_string(),
            trust_root_kid: passport_fpr.clone(),
            endpoint_url: None,
            permitted_capabilities: local_capabilities
                .into_iter()
                .map(|capability| PermittedCapability {
                    capability,
                    data_egress_classes: vec![DataEgressClass::None],
                    required_attestations: Vec::new(),
                    credit_cost: None,
                })
                .collect(),
        }],
        credits: Credits {
            balance: None,
            refill: CreditRefill {
                period: rcx_capability_token::RefillPeriod::None,
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
            kid: passport_fpr,
            sig: signature,
        },
    }
}

pub fn mint_signed_free_local_token(
    passport_fpr: impl Into<String>,
    daemon_instance_id: impl Into<String>,
    tenant_id: impl Into<String>,
    local_capabilities: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    sign_hash: impl FnOnce(&[u8; rcx_capability_token::RCX_CT_HASH_LEN]) -> [u8; RCX_CT_SIGNATURE_LEN],
) -> RcxCapabilityToken {
    let mut token = mint_free_local_token(
        passport_fpr,
        daemon_instance_id,
        tenant_id,
        local_capabilities,
        issued_at,
        expires_at,
        [0_u8; RCX_CT_SIGNATURE_LEN],
    );
    token.signature.sig = sign_hash(&token.token_hash());
    token
}

fn first_validation_reason(issues: &[TokenValidationIssue]) -> DenialReason {
    if issues.iter().any(|issue| issue.code == "token_expired") {
        DenialReason::TokenExpired
    } else {
        DenialReason::TokenInvalid
    }
}

fn has_credit(token: &RcxCapabilityToken, estimated_credit_cost: u64) -> bool {
    match token.credits.balance {
        Some(balance) => balance >= estimated_credit_cost,
        None => token.tier == RcxTier::Free && estimated_credit_cost == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn router() -> RcxRouter {
        RcxRouter::new(mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec![
                "corecrux.query.local".to_string(),
                "crux-mcp.query".to_string(),
                "crux-mcp.store_fact".to_string(),
            ],
            1_776_989_600,
            1_780_143_200,
            [0x11; RCX_CT_SIGNATURE_LEN],
        ))
    }

    fn hosted_router(
        fallback_on_backend_unreachable: FallbackAction,
        fallback_on_credits_exhausted: FallbackAction,
        fallback_on_expiry: FallbackAction,
        queue_ttl_seconds: Option<u64>,
        balance: Option<u64>,
    ) -> RcxRouter {
        let mut token = mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec![],
            1_776_989_600,
            1_780_143_200,
            [0x11; RCX_CT_SIGNATURE_LEN],
        );
        token.tier = RcxTier::Pro;
        token.backends = vec![Backend {
            backend_id: "hosted.vaultcrux.com".to_string(),
            trust_root_kid: "p_0123456789abcdef0123456789abcdef".to_string(),
            endpoint_url: Some("https://hosted.vaultcrux.com".to_string()),
            permitted_capabilities: vec![PermittedCapability {
                capability: "vaultcrux.retrieve".to_string(),
                data_egress_classes: vec![DataEgressClass::Vectors, DataEgressClass::ReceiptHashes],
                required_attestations: vec!["passport_bound".to_string()],
                credit_cost: Some(rcx_capability_token::CreditCost {
                    unit: rcx_capability_token::CreditCostUnit::Call,
                    cost: 1,
                }),
            }],
        }];
        token.credits.balance = balance;
        token.fallback = FallbackPolicy {
            on_backend_unreachable: fallback_on_backend_unreachable,
            on_credits_exhausted: fallback_on_credits_exhausted,
            on_expiry: fallback_on_expiry,
            queue_ttl_seconds,
        };
        RcxRouter::new(token)
    }

    fn hosted_retrieve_call(estimated_credit_cost: u64, backend_reachable: bool) -> CallContext {
        CallContext {
            capability: "vaultcrux.retrieve".to_string(),
            preferred_backend: Some("hosted.vaultcrux.com".to_string()),
            data_egress_classes: vec![DataEgressClass::Vectors, DataEgressClass::ReceiptHashes],
            estimated_credit_cost,
            backend_reachable,
        }
    }

    #[test]
    fn authorises_local_free_capability() {
        let decision = router().decide(&CallContext::local("corecrux.query.local"), 1_776_989_601);
        assert!(decision.authorised);
        assert_eq!(decision.mode, RouterMode::Local);
        assert_eq!(decision.backend_id.as_deref(), Some("local"));
        assert_eq!(decision.stamp.header_name, RCX_MODE_HEADER);
        assert_eq!(decision.stamp.mode, "local");
    }

    #[test]
    fn refuses_unknown_capability_with_receipt_payload() {
        let decision = router().decide(&CallContext::local("hosted.gpu.query"), 1_776_989_601);
        assert!(!decision.authorised);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:capability_not_permitted"));
        let receipt = decision.refusal_receipt.expect("refusal receipt");
        assert_eq!(receipt.event_type, "rcx.capability_token.call_refused.v1");
        assert_eq!(receipt.capability, "hosted.gpu.query");
    }

    #[test]
    fn refuses_text_egress_by_default() {
        let decision = router().decide(
            &CallContext {
                capability: "corecrux.query.local".to_string(),
                preferred_backend: Some("local".to_string()),
                data_egress_classes: vec![DataEgressClass::Text],
                estimated_credit_cost: 0,
                backend_reachable: true,
            },
            1_776_989_601,
        );
        assert!(!decision.authorised);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:egress_not_permitted"));
    }

    #[test]
    fn filters_mcp_tool_names_through_token_matrix() {
        let tools = vec![
            McpToolCapability::local_none("query", "crux-mcp.query"),
            McpToolCapability::local_none("store_fact", "crux-mcp.store_fact"),
            McpToolCapability::local_none("hosted_gpu_query", "crux-mcp.hosted_gpu_query"),
        ];
        let names = router().filter_mcp_tools(&tools, 1_776_989_601);
        assert_eq!(names, vec!["query".to_string(), "store_fact".to_string()]);
    }

    #[test]
    fn expired_token_fails_closed() {
        let decision = router().decide(&CallContext::local("corecrux.query.local"), 1_780_143_201);
        assert!(!decision.authorised);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:token_expired"));
        assert_eq!(decision.stamp.mode, "refused");
    }

    #[test]
    fn queues_when_hosted_backend_unreachable_and_queue_fallback_is_configured() {
        let decision = hosted_router(
            FallbackAction::Queue,
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            Some(120),
            Some(10),
        )
        .decide(&hosted_retrieve_call(1, false), 1_776_989_601);

        assert!(decision.authorised);
        assert_eq!(decision.mode, RouterMode::DegradedQueued);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:backend_unavailable"));
        assert_eq!(decision.stamp.mode, "degraded-queued");
        assert_eq!(decision.stamp.queue_ttl_seconds, Some(120));
    }

    #[test]
    fn credit_exhaustion_uses_configured_degraded_local_fallback() {
        let decision = hosted_router(
            FallbackAction::Refuse,
            FallbackAction::DegradeToLocal,
            FallbackAction::Refuse,
            None,
            Some(0),
        )
        .decide(&hosted_retrieve_call(1, true), 1_776_989_601);

        assert!(decision.authorised);
        assert_eq!(decision.mode, RouterMode::DegradedLocal);
        assert_eq!(decision.backend_id.as_deref(), Some("local"));
        assert_eq!(decision.reason_code.as_deref(), Some("denied:insufficient_credit"));
        assert_eq!(decision.stamp.mode, "degraded-local");
    }

    #[test]
    fn expiry_can_degrade_to_local_when_token_policy_allows_it() {
        let decision = hosted_router(
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            FallbackAction::DegradeToLocal,
            None,
            Some(10),
        )
        .decide(&hosted_retrieve_call(1, true), 1_780_143_201);

        assert!(decision.authorised);
        assert_eq!(decision.mode, RouterMode::DegradedLocal);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:token_expired"));
    }

    #[test]
    fn mint_signed_free_local_token_signs_token_hash() {
        let token = mint_signed_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec!["corecrux.query.local".to_string()],
            1_776_989_600,
            1_780_143_200,
            |hash| {
                let mut sig = [0_u8; RCX_CT_SIGNATURE_LEN];
                sig[..hash.len()].copy_from_slice(hash);
                sig
            },
        );
        assert_eq!(
            &token.signature.sig[..rcx_capability_token::RCX_CT_HASH_LEN],
            &token.token_hash()
        );
    }

    #[test]
    fn router_decision_p99_stays_below_one_millisecond() {
        let router = router();
        let call = CallContext::local("corecrux.query.local");
        let mut latencies = Vec::with_capacity(20_000);

        for _ in 0..20_000 {
            let start = Instant::now();
            let decision = router.decide(&call, 1_776_989_601);
            latencies.push(start.elapsed().as_nanos());
            assert!(decision.authorised);
        }

        latencies.sort_unstable();
        let p99 = latencies[(latencies.len() * 99 / 100).min(latencies.len() - 1)];
        eprintln!("rcx_router_decision_p99_ns={p99}");
        assert!(p99 <= 1_000_000, "router p99 decision latency exceeded 1ms: {p99}ns");
    }
}
