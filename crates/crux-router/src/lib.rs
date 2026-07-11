// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![deny(clippy::unwrap_used, clippy::expect_used)]

//! RCX daemon router primitives.
//!
//! This crate is deliberately pure for Phase 1: it consumes an
//! [`rcx_capability_token::RcxCapabilityToken`] and returns deterministic
//! routing/refusal decisions. Network refresh and revocation IO land in later phases.

pub mod hosted;
pub mod quota;

use rcx_capability_token::{
    verify_token, Backend, CreditRefill, Credits, DataEgressClass, FallbackAction, FallbackPolicy, Issuer,
    OverdraftPolicy, PermittedCapability, RcxCapabilityToken, RcxTier, ReceiptClass, Revocation, Signature, Subject,
    TenantScope, TokenValidationIssue, VerifyOutcome, RCX_CT_SIGNATURE_LEN, RCX_CT_SPEC_VERSION,
};

pub const RCX_MODE_HEADER: &str = "X-Crux-Mode";
pub const FEDERATION_READ_CAPABILITY: &str = "federation.read";

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
    AttestationMissing,
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
            Self::AttestationMissing => "denied:attestation_missing",
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
    pub present_attestations: Vec<String>,
    pub estimated_credit_cost: u64,
    pub backend_reachable: bool,
}

impl CallContext {
    pub fn local(capability: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            preferred_backend: Some("local".to_string()),
            data_egress_classes: vec![DataEgressClass::None],
            present_attestations: Vec::new(),
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
    /// Whether the router consulted token revocation state (CRL / push channel)
    /// before authorising. Currently always `false`: revocation is modelled on
    /// the token (`crl_url`, `push_channel`) but `decide()` does not yet consult
    /// it, so a revoked-but-unexpired token is still authorised. Surfaced here so
    /// downstream auditors do not read an authorised decision as implying the
    /// token was checked for revocation. See `docs/THREAT_MODEL.md`.
    pub revocation_checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalReceipt {
    pub event_type: String,
    pub token_id: String,
    pub token_hash: String,
    pub capability: String,
    pub backend_id: Option<String>,
    pub data_egress_classes: Vec<String>,
    pub required_attestations: Vec<String>,
    pub present_attestations: Vec<String>,
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
    trusted_issuer_pubkey: Option<[u8; 32]>,
    runtime_credit_balance: RuntimeCreditBalance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeCreditBalance {
    FromToken,
    Override(Option<u64>),
}

impl RcxRouter {
    pub fn new(token: RcxCapabilityToken) -> Self {
        Self {
            token,
            trusted_issuer_pubkey: None,
            runtime_credit_balance: RuntimeCreditBalance::FromToken,
        }
    }

    pub fn new_with_trusted_issuer_pubkey(token: RcxCapabilityToken, trusted_issuer_pubkey: [u8; 32]) -> Self {
        Self {
            token,
            trusted_issuer_pubkey: Some(trusted_issuer_pubkey),
            runtime_credit_balance: RuntimeCreditBalance::FromToken,
        }
    }

    pub fn with_runtime_credit_balance(mut self, balance: Option<u64>) -> Self {
        self.runtime_credit_balance = RuntimeCreditBalance::Override(balance);
        self
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

        if !self.token_signature_permits_backend(backend, now_unix_seconds) {
            return self.refuse(call, DenialReason::TokenInvalid);
        }

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
        if capability
            .required_attestations
            .iter()
            .any(|required| !call.present_attestations.iter().any(|present| present == required))
        {
            return self.refuse(call, DenialReason::AttestationMissing);
        }

        let credit_cost = capability
            .credit_cost
            .as_ref()
            .map_or(call.estimated_credit_cost, |cost| {
                call.estimated_credit_cost.max(cost.cost)
            });
        let debitable = credit_cost > 0;
        if self.token.receipt_class == ReceiptClass::Replay && debitable {
            return self.refuse(call, DenialReason::ReceiptClassSideEffectDenied);
        }
        if debitable && !self.has_credit(credit_cost) {
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
                        present_attestations: Vec::new(),
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

    /// Whether the token's signature authorises routing to `backend`.
    ///
    /// INVARIANT: the `local` backend skips signature verification. This is sound
    /// only because the token reaching `decide()` is always daemon-minted (see
    /// `RcxRouter::new`, fed a self-minted local token in `corecruxd::main`) and
    /// never a client-injected `RcxCapabilityToken`. The local token never crosses
    /// a trust boundary, so there is no signer to verify against.
    ///
    /// Any future wiring that routes a client-supplied token through `decide()`
    /// MUST construct the router via `new_with_trusted_issuer_pubkey` so non-local
    /// backends are signature-checked; the local short-circuit must not be relied
    /// on to authorise a hosted backend. The negative test
    /// `local_signature_bypass_does_not_extend_to_hosted_backend` pins this: a
    /// router built with `new()` (no trusted issuer) authorises a local capability
    /// but refuses any hosted backend with `TokenInvalid`.
    fn token_signature_permits_backend(&self, backend: &Backend, now_unix_seconds: u64) -> bool {
        if backend.backend_id == "local" {
            return true;
        }
        let Some(trusted_issuer_pubkey) = self.trusted_issuer_pubkey.as_ref() else {
            return false;
        };
        verify_token(&self.token, trusted_issuer_pubkey, now_unix_seconds) == VerifyOutcome::Verified
    }

    fn has_credit(&self, estimated_credit_cost: u64) -> bool {
        if estimated_credit_cost == 0 {
            return true;
        }
        let balance = match self.runtime_credit_balance {
            RuntimeCreditBalance::FromToken => self.token.credits.balance,
            RuntimeCreditBalance::Override(balance) => balance,
        }
        .unwrap_or(0);
        if balance >= estimated_credit_cost {
            return true;
        }
        match self.token.credits.overdraft {
            OverdraftPolicy::Forbid => false,
            OverdraftPolicy::Warn | OverdraftPolicy::AllowToLimit => {
                balance.saturating_add(self.token.credits.overdraft_limit.unwrap_or(0)) >= estimated_credit_cost
            }
        }
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
                required_attestations: self
                    .select_backend(call)
                    .and_then(|backend| {
                        backend
                            .permitted_capabilities
                            .iter()
                            .find(|capability| capability.capability == call.capability)
                    })
                    .map(|capability| capability.required_attestations.clone())
                    .unwrap_or_default(),
                present_attestations: call.present_attestations.clone(),
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
            // Revocation IO is not yet wired into decide(); never claim it was
            // checked. Flip this to `true` only once a CRL/timestamp consult runs.
            revocation_checked: false,
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

/// Build a PAID local token: a free local token rebranded to a paying tier
/// (`RcxTier::Pro`) that additionally carries every premium `corecrux.lane.*`
/// capability and a bundled credit balance. This is the free → paid step:
/// CoreCrux hard-gates premium lanes on these capabilities + a positive
/// balance (`OverdraftPolicy::Forbid`). Signature is left zeroed — sign via
/// [`mint_signed_paid_local_token`] or set it on the returned token.
#[allow(clippy::too_many_arguments)]
pub fn build_paid_local_token(
    passport_fpr: impl Into<String>,
    daemon_instance_id: impl Into<String>,
    tenant_id: impl Into<String>,
    extra_local_capabilities: Vec<String>,
    credit_balance: u64,
    per_call_cost: u64,
    issued_at: u64,
    expires_at: u64,
) -> RcxCapabilityToken {
    let passport_fpr = passport_fpr.into();
    let tenant_id = tenant_id.into();
    let short_fpr: String = passport_fpr.trim_start_matches("p_").chars().take(16).collect();
    let mut token = mint_free_local_token(
        passport_fpr,
        daemon_instance_id,
        tenant_id.clone(),
        extra_local_capabilities,
        issued_at,
        expires_at,
        [0_u8; RCX_CT_SIGNATURE_LEN],
    );
    token.token_id = format!("rcxct_paid_{short_fpr}_{tenant_id}");
    token.tier = RcxTier::Pro;
    // Append the premium lane capabilities to the local backend.
    if let Some(backend) = token.backends.first_mut() {
        backend
            .permitted_capabilities
            .extend(rcx_capability_token::corecrux_premium_lane_capabilities(per_call_cost));
    }
    // Bundled credit amount; hard gate (Forbid) so an exhausted balance denies.
    token.credits.balance = Some(credit_balance);
    token
}

/// Mint + sign a paid local token (see [`build_paid_local_token`]).
#[allow(clippy::too_many_arguments)]
pub fn mint_signed_paid_local_token(
    passport_fpr: impl Into<String>,
    daemon_instance_id: impl Into<String>,
    tenant_id: impl Into<String>,
    extra_local_capabilities: Vec<String>,
    credit_balance: u64,
    per_call_cost: u64,
    issued_at: u64,
    expires_at: u64,
    sign_hash: impl FnOnce(&[u8; rcx_capability_token::RCX_CT_HASH_LEN]) -> [u8; RCX_CT_SIGNATURE_LEN],
) -> RcxCapabilityToken {
    let mut token = build_paid_local_token(
        passport_fpr,
        daemon_instance_id,
        tenant_id,
        extra_local_capabilities,
        credit_balance,
        per_call_cost,
        issued_at,
        expires_at,
    );
    token.signature.sig = sign_hash(&token.token_hash());
    token
}

/// Per-call credit cost for one premium lane, read from the token's
/// capabilities (0 if the lane is not present / has no cost).
pub fn lane_call_cost(token: &RcxCapabilityToken, lane_slug: &str) -> u64 {
    let capability = rcx_capability_token::corecrux_lane_capability(lane_slug);
    token
        .backends
        .iter()
        .flat_map(|backend| backend.permitted_capabilities.iter())
        .find(|cap| cap.capability == capability)
        .and_then(|cap| cap.credit_cost.as_ref())
        .map_or(0, |cost| cost.cost)
}

/// Debit a usage report for the premium lanes used this request against a
/// [`crate::hosted::CreditLedger`]. Sums per-lane cost from the token, then
/// debits once. This is the M4 ledger-side of the CoreCrux→Crux usage report
/// (the HTTP ingest route is wired in M5). Hard gate: a `Forbid` token whose
/// balance can't cover the cost returns `Err(CreditDebitDenied)`.
pub fn debit_lane_usage(
    ledger: &mut crate::hosted::CreditLedger,
    token: &RcxCapabilityToken,
    lanes_used: &[&str],
) -> Result<crate::hosted::CreditDebit, crate::hosted::CreditDebitDenied> {
    let cost: u64 = lanes_used.iter().map(|slug| lane_call_cost(token, slug)).sum();
    ledger.try_debit(cost)
}

/// A premium-lane usage report from a CoreCrux retrieval daemon
/// (`corecrux.lane.usage.v1`). Plain struct — the daemon HTTP route owns JSON
/// (de)serialisation so this crate stays serde-free and pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageReport {
    pub token_hash: String,
    pub tenant_id: String,
    pub lanes_used: Vec<String>,
    /// Credits CoreCrux computed from the (verified) token's per-lane costs.
    pub credits_used: u64,
}

/// Receipt for an ingested usage report: whether the debit was applied and the
/// resulting balance, or why it was denied (hard gate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageReceipt {
    pub token_hash: String,
    pub accepted: bool,
    pub debited: u64,
    pub balance_after: Option<u64>,
    pub denied_reason: Option<String>,
}

/// Ingest a usage report against a credit ledger (the Crux billing side of the
/// CoreCrux→Crux report). Applies a refill first, then debits
/// `report.credits_used`. A `Forbid` ledger that can't cover the cost yields an
/// `accepted: false` receipt with the balance unchanged (hard gate).
///
/// Note: CoreCrux is first-party and computes `credits_used` from the verified
/// token's lane costs; in the current stateless model the ledger is supplied by
/// the caller (reconstructed from the token / a persistent store when one
/// exists — see ExecPlan M5 note on the persistent-ledger boundary).
pub fn ingest_usage_report(
    report: &UsageReport,
    ledger: &mut crate::hosted::CreditLedger,
    now_unix_seconds: u64,
) -> UsageReceipt {
    let _ = ledger.apply_refill(now_unix_seconds);
    match ledger.try_debit(report.credits_used) {
        Ok(debit) => UsageReceipt {
            token_hash: report.token_hash.clone(),
            accepted: true,
            debited: debit.cost,
            balance_after: debit.balance_after,
            denied_reason: None,
        },
        Err(denied) => UsageReceipt {
            token_hash: report.token_hash.clone(),
            accepted: false,
            debited: 0,
            balance_after: ledger.balance(),
            denied_reason: Some(format!(
                "insufficient_credit: need {} have {}",
                denied.cost, denied.available
            )),
        },
    }
}

fn first_validation_reason(issues: &[TokenValidationIssue]) -> DenialReason {
    if issues.iter().any(|issue| issue.code == "token_expired") {
        DenialReason::TokenExpired
    } else {
        DenialReason::TokenInvalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
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

    fn hosted_token(
        fallback_on_backend_unreachable: FallbackAction,
        fallback_on_credits_exhausted: FallbackAction,
        fallback_on_expiry: FallbackAction,
        queue_ttl_seconds: Option<u64>,
        balance: Option<u64>,
    ) -> RcxCapabilityToken {
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
        token
    }

    fn hosted_router(
        fallback_on_backend_unreachable: FallbackAction,
        fallback_on_credits_exhausted: FallbackAction,
        fallback_on_expiry: FallbackAction,
        queue_ttl_seconds: Option<u64>,
        balance: Option<u64>,
    ) -> RcxRouter {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let mut token = hosted_token(
            fallback_on_backend_unreachable,
            fallback_on_credits_exhausted,
            fallback_on_expiry,
            queue_ttl_seconds,
            balance,
        );
        token.signature.sig = signing.sign(&token.token_hash()).to_bytes();
        RcxRouter::new_with_trusted_issuer_pubkey(token, signing.verifying_key().to_bytes())
    }

    fn hosted_retrieve_call(estimated_credit_cost: u64, backend_reachable: bool) -> CallContext {
        CallContext {
            capability: "vaultcrux.retrieve".to_string(),
            preferred_backend: Some("hosted.vaultcrux.com".to_string()),
            data_egress_classes: vec![DataEgressClass::Vectors, DataEgressClass::ReceiptHashes],
            present_attestations: vec!["passport_bound".to_string()],
            estimated_credit_cost,
            backend_reachable,
        }
    }

    #[test]
    fn refuses_hosted_without_trusted_issuer_key() {
        let token = hosted_token(
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            None,
            Some(10),
        );
        let decision = RcxRouter::new(token).decide(&hosted_retrieve_call(1, true), 1_776_989_601);
        assert!(!decision.authorised);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:token_invalid"));
    }

    #[test]
    fn mode_stamp_reports_revocation_unchecked() {
        // Revocation IO is not wired into decide(); an authorised decision must
        // never claim the token was checked for revocation.
        let decision = router().decide(&CallContext::local("corecrux.query.local"), 1_776_989_601);
        assert!(decision.authorised);
        assert!(
            !decision.stamp.revocation_checked,
            "stamp must report revocation_checked=false until a CRL/timestamp consult is wired"
        );
    }

    #[test]
    fn local_signature_bypass_does_not_extend_to_hosted_backend() {
        // A router built via new() (no trusted issuer pubkey) models the
        // daemon-minted-local-token case. The local signature bypass authorises a
        // local capability, but the SAME router must refuse a hosted backend with
        // TokenInvalid — the bypass cannot be leveraged to reach a hosted lane.
        let token = hosted_token(
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            None,
            Some(10),
        );
        // Grant the same token a local capability so we can prove local is allowed.
        let mut token = token;
        token.backends.push(Backend {
            backend_id: "local".to_string(),
            trust_root_kid: "p_0123456789abcdef0123456789abcdef".to_string(),
            endpoint_url: None,
            permitted_capabilities: vec![PermittedCapability {
                capability: "corecrux.query.local".to_string(),
                data_egress_classes: vec![DataEgressClass::None],
                required_attestations: vec![],
                credit_cost: None,
            }],
        });
        let router = RcxRouter::new(token);

        let local = router.decide(&CallContext::local("corecrux.query.local"), 1_776_989_601);
        assert!(
            local.authorised,
            "local capability must be authorised via the local bypass"
        );
        assert_eq!(local.backend_id.as_deref(), Some("local"));

        let hosted = router.decide(&hosted_retrieve_call(1, true), 1_776_989_601);
        assert!(
            !hosted.authorised,
            "hosted backend must not ride the local signature bypass"
        );
        assert_eq!(hosted.reason_code.as_deref(), Some("denied:token_invalid"));
    }

    #[test]
    fn refuses_hosted_with_wrong_trust_root() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let wrong = SigningKey::from_bytes(&[43u8; 32]);
        let mut token = hosted_token(
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            None,
            Some(10),
        );
        token.signature.sig = signing.sign(&token.token_hash()).to_bytes();

        let decision = RcxRouter::new_with_trusted_issuer_pubkey(token, wrong.verifying_key().to_bytes())
            .decide(&hosted_retrieve_call(1, true), 1_776_989_601);
        assert!(!decision.authorised);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:token_invalid"));
    }

    #[test]
    fn refuses_hosted_when_signed_payload_is_tampered() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let mut token = hosted_token(
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            None,
            Some(10),
        );
        token.signature.sig = signing.sign(&token.token_hash()).to_bytes();
        token.credits.balance = Some(0);

        let decision = RcxRouter::new_with_trusted_issuer_pubkey(token, signing.verifying_key().to_bytes())
            .decide(&hosted_retrieve_call(1, true), 1_776_989_601);
        assert!(!decision.authorised);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:token_invalid"));
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
                present_attestations: Vec::new(),
                estimated_credit_cost: 0,
                backend_reachable: true,
            },
            1_776_989_601,
        );
        assert!(!decision.authorised);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:egress_not_permitted"));
    }

    #[test]
    fn refuses_when_required_attestation_is_missing() {
        let mut call = hosted_retrieve_call(1, true);
        call.present_attestations.clear();

        let decision = hosted_router(
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            None,
            Some(10),
        )
        .decide(&call, 1_776_989_601);

        assert!(!decision.authorised);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:attestation_missing"));
        let receipt = decision.refusal_receipt.expect("refusal receipt");
        assert_eq!(receipt.required_attestations, vec!["passport_bound".to_string()]);
        assert!(receipt.present_attestations.is_empty());
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
    fn hosted_credit_cost_is_enforced_when_call_estimate_is_zero() {
        let decision = hosted_router(
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            FallbackAction::Refuse,
            None,
            Some(0),
        )
        .decide(&hosted_retrieve_call(0, true), 1_776_989_601);

        assert!(!decision.authorised);
        assert_eq!(decision.reason_code.as_deref(), Some("denied:insufficient_credit"));
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
    fn router_decision_throughput_is_fast() {
        // Hot-path regression guard on `decide()`, which is pure in-memory
        // logic (sub-microsecond in practice). The asserted signal is the
        // AMORTIZED mean over the whole loop, taken with a single Instant pair
        // -- NOT per-iteration wall-clock. On loaded shared CI runners per-call
        // timing is dominated by clock-syscall overhead and scheduler
        // preemption: an earlier per-call p99<=1ms assertion saw 3-4ms tail
        // spikes, and even a per-call p50<=100us assertion tripped at ~150us
        // when the runner was uniformly starved. Amortizing over 20k calls with
        // one clock pair removes the 20k Instant::now() syscalls (the main
        // contention amplifier) and a generous 1ms cap is immune to that jitter
        // while still tripping on a genuine catastrophic regression (e.g.
        // decide() accidentally doing I/O or O(n) work).
        let router = router();
        let call = CallContext::local("corecrux.query.local");
        const N: usize = 20_000;

        // Asserted, jitter-robust signal: amortized mean, single clock pair.
        let start = Instant::now();
        let mut authorised = 0u64;
        for _ in 0..N {
            authorised += router.decide(&call, 1_776_989_601).authorised as u64;
        }
        let mean = start.elapsed() / N as u32;
        std::hint::black_box(authorised);
        assert_eq!(authorised, N as u64, "every decision should be authorised");

        // Per-call percentiles for observability only -- NOT asserted, because
        // per-call wall-clock is runner-jitter sensitive on shared CI.
        let mut latencies = Vec::with_capacity(N);
        for _ in 0..N {
            let s = Instant::now();
            let decision = router.decide(&call, 1_776_989_601);
            latencies.push(s.elapsed().as_nanos());
            std::hint::black_box(decision.authorised);
        }
        latencies.sort_unstable();
        let p50 = latencies[N / 2];
        let p99 = latencies[(N * 99 / 100).min(N - 1)];
        eprintln!(
            "rcx_router_decision_mean_ns={} rcx_router_decision_p50_ns={p50} rcx_router_decision_p99_ns={p99}",
            mean.as_nanos()
        );

        assert!(
            mean <= std::time::Duration::from_millis(1),
            "router decision mean latency exceeded 1ms: {}ns (real cost is sub-microsecond; check for a hot-path regression)",
            mean.as_nanos()
        );
    }

    fn paid_token(balance: u64, per_call: u64) -> RcxCapabilityToken {
        build_paid_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec!["corecrux.query.local".to_string()],
            balance,
            per_call,
            1_776_989_600,
            1_780_143_200,
        )
    }

    #[test]
    fn paid_token_carries_all_premium_lanes_and_is_structurally_valid() {
        let token = paid_token(100, 2);
        assert_eq!(token.tier, RcxTier::Pro);
        assert!(token.token_id.starts_with("rcxct_paid_"));
        assert_eq!(token.credits.balance, Some(100));
        // all 13 premium lanes present, each at its per-lane cost (base 2, but the
        // metered dense lanes are 3:1 — rerank=3, dense_managed=1); baseline absent
        for slug in rcx_capability_token::CORECRUX_PREMIUM_LANE_SLUGS {
            assert_eq!(
                lane_call_cost(&token, slug),
                rcx_capability_token::corecrux_lane_credit_cost(slug, 2),
                "lane {slug} cost"
            );
        }
        assert_eq!(lane_call_cost(&token, "bm25"), 0, "free baseline never minted");
        // Pro tier needs no team/enterprise scope → structurally valid.
        assert!(token.validate_basic(1_776_989_601).valid);
    }

    #[test]
    fn debit_lane_usage_charges_sum_then_hard_gate_denies_when_exhausted() {
        let token = paid_token(5, 2);
        let mut ledger = crate::hosted::CreditLedger::from_token(&token, 1_776_989_600);
        // two premium lanes @2 = 4 debited, balance 5 → 1
        let debit = debit_lane_usage(&mut ledger, &token, &["topology", "event"]).expect("debit ok");
        assert_eq!(debit.cost, 4);
        assert_eq!(ledger.balance(), Some(1));
        // next 2-lane call costs 4 but only 1 left + Forbid overdraft → denied
        let denied = debit_lane_usage(&mut ledger, &token, &["trait", "navtree"]).unwrap_err();
        assert_eq!(denied.cost, 4);
        assert_eq!(denied.available, 1);
        // balance unchanged after a denied debit
        assert_eq!(ledger.balance(), Some(1));
    }

    #[test]
    fn free_token_has_no_premium_lane_capabilities() {
        let token = mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec!["corecrux.query.local".to_string()],
            1_776_989_600,
            1_780_143_200,
            [0_u8; RCX_CT_SIGNATURE_LEN],
        );
        for slug in rcx_capability_token::CORECRUX_PREMIUM_LANE_SLUGS {
            assert_eq!(lane_call_cost(&token, slug), 0, "free token must not carry {slug}");
        }
    }

    #[test]
    fn paid_token_signature_verifies_over_token_hash() {
        // Cross-convention guard: a token signed by mint_signed_paid_local_token
        // (Ed25519 over token_hash) must verify over token_hash with the public
        // key — exactly what CoreCrux's corecrux-rcx-token::verify does. If this
        // breaks, real paid tokens would fail verification in the retrieval daemon.
        use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let verifying: VerifyingKey = signing.verifying_key();
        let token = mint_signed_paid_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec!["corecrux.query.local".to_string()],
            100,
            2,
            1_776_989_600,
            1_780_143_200,
            |hash| signing.sign(hash).to_bytes(),
        );
        let sig = ed25519_dalek::Signature::from_bytes(&token.signature.sig);
        assert!(verifying.verify(&token.token_hash(), &sig).is_ok());
        assert!(token.validate_basic(1_776_989_601).valid);
    }

    /// Operator helper for the M6 sidelab runbook: prints a trust-root public
    /// key + a signed paid-token hex to paste into the daemon config + the
    /// `X-RCX-Token` header. Run: `cargo test -p crux-router -- --ignored
    /// --nocapture print_sidelab_paid_token`.
    #[test]
    #[ignore = "operator runbook helper; prints a token, not an assertion"]
    fn print_sidelab_paid_token() {
        use ed25519_dalek::{Signer, SigningKey};
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());
        let token = mint_signed_paid_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec!["corecrux.query.local".to_string()],
            100,           // bundled credit balance
            2,             // per-lane per-call cost
            1_776_989_600, // issued_at
            4_102_444_800, // far-future expiry for a long-lived sidelab token
            |hash| signing.sign(hash).to_bytes(),
        );
        let token_hex = hex::encode(token.to_canonical_cbor());
        println!("TRUST_ROOT_PUBKEY_HEX={pubkey_hex}");
        println!("X_RCX_TOKEN_HEX={token_hex}");
    }

    #[test]
    fn ingest_usage_report_debits_then_hard_gate_denies() {
        let token = paid_token(10, 2);
        let mut ledger = crate::hosted::CreditLedger::from_token(&token, 1_776_989_600);
        let report = UsageReport {
            token_hash: token.token_hash_hex(),
            tenant_id: "default".to_string(),
            lanes_used: vec!["topology".to_string(), "event".to_string()],
            credits_used: 8,
        };
        let receipt = ingest_usage_report(&report, &mut ledger, 1_776_989_600);
        assert!(receipt.accepted);
        assert_eq!(receipt.debited, 8);
        assert_eq!(receipt.balance_after, Some(2));

        // a second report for 8 exceeds the remaining 2 → hard-gate denied
        let receipt2 = ingest_usage_report(&report, &mut ledger, 1_776_989_600);
        assert!(!receipt2.accepted);
        assert_eq!(receipt2.debited, 0);
        assert_eq!(receipt2.balance_after, Some(2));
        assert!(receipt2.denied_reason.unwrap().contains("insufficient_credit"));
    }
}
