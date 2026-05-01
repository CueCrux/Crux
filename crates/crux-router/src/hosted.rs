// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Mockable hosted-backend bridge for RCX-authorised Tier 2 calls.

use crate::{CallContext, RcxRouter, RouterDecision, RouterMode};
use rcx_capability_token::{CreditRefill, OverdraftPolicy, RcxCapabilityToken, RefillPeriod};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditLedger {
    balance: Option<u64>,
    refill: CreditRefill,
    overdraft: OverdraftPolicy,
    overdraft_limit: Option<u64>,
    overdraft_used: u64,
    last_refill_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditRefillApplied {
    pub periods: u64,
    pub amount: u64,
    pub balance_after: Option<u64>,
    pub overdraft_used_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditDebit {
    pub cost: u64,
    pub balance_after: Option<u64>,
    pub overdraft_used_after: u64,
    pub used_overdraft: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditDebitDenied {
    pub cost: u64,
    pub available: u64,
}

impl CreditLedger {
    pub fn from_token(token: &RcxCapabilityToken, now_unix_seconds: u64) -> Self {
        Self {
            balance: token.credits.balance,
            refill: token.credits.refill.clone(),
            overdraft: token.credits.overdraft.clone(),
            overdraft_limit: token.credits.overdraft_limit,
            overdraft_used: 0,
            last_refill_at: now_unix_seconds,
        }
    }

    pub fn balance(&self) -> Option<u64> {
        self.balance
    }

    pub fn overdraft_used(&self) -> u64 {
        self.overdraft_used
    }

    pub fn apply_refill(&mut self, now_unix_seconds: u64) -> Option<CreditRefillApplied> {
        let period_seconds = refill_period_seconds(&self.refill.period)?;
        let amount = self.refill.amount.filter(|amount| *amount > 0)?;
        let elapsed = now_unix_seconds.saturating_sub(self.last_refill_at);
        let periods = elapsed / period_seconds;
        if periods == 0 {
            return None;
        }
        let refill_amount = amount.saturating_mul(periods);
        let overdraft_paydown = self.overdraft_used.min(refill_amount);
        self.overdraft_used = self.overdraft_used.saturating_sub(overdraft_paydown);
        let remaining_refill = refill_amount.saturating_sub(overdraft_paydown);
        self.balance = Some(self.balance.unwrap_or(0).saturating_add(remaining_refill));
        self.last_refill_at = self
            .last_refill_at
            .saturating_add(period_seconds.saturating_mul(periods));

        Some(CreditRefillApplied {
            periods,
            amount: refill_amount,
            balance_after: self.balance,
            overdraft_used_after: self.overdraft_used,
        })
    }

    pub fn try_debit(&mut self, cost: u64) -> Result<CreditDebit, CreditDebitDenied> {
        if cost == 0 {
            return Ok(CreditDebit {
                cost,
                balance_after: self.balance,
                overdraft_used_after: self.overdraft_used,
                used_overdraft: false,
            });
        }

        let balance = self.balance.unwrap_or(0);
        if balance >= cost {
            self.balance = Some(balance - cost);
            return Ok(CreditDebit {
                cost,
                balance_after: self.balance,
                overdraft_used_after: self.overdraft_used,
                used_overdraft: false,
            });
        }

        let available_overdraft = match self.overdraft {
            OverdraftPolicy::Forbid => 0,
            OverdraftPolicy::Warn | OverdraftPolicy::AllowToLimit => {
                self.overdraft_limit.unwrap_or(0).saturating_sub(self.overdraft_used)
            }
        };
        let needed_overdraft = cost.saturating_sub(balance);
        if needed_overdraft > available_overdraft {
            return Err(CreditDebitDenied {
                cost,
                available: balance.saturating_add(available_overdraft),
            });
        }

        self.balance = Some(0);
        self.overdraft_used = self.overdraft_used.saturating_add(needed_overdraft);
        Ok(CreditDebit {
            cost,
            balance_after: self.balance,
            overdraft_used_after: self.overdraft_used,
            used_overdraft: needed_overdraft > 0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedRequest {
    pub backend_id: String,
    pub capability: String,
    pub token_id: String,
    pub token_hash: String,
    pub estimated_credit_cost: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub receipt_ref: Option<String>,
}

pub trait HostedBackendClient {
    fn is_reachable(&self, backend_id: &str) -> bool;
    fn call(&mut self, request: HostedRequest) -> HostedResponse;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedBridgeOutcome {
    pub decision: RouterDecision,
    pub refill: Option<CreditRefillApplied>,
    pub debit: Option<CreditDebit>,
    pub debit_denied: Option<CreditDebitDenied>,
    pub response: Option<HostedResponse>,
    pub client_called: bool,
}

#[derive(Debug, Clone)]
pub struct HostedBridge<C> {
    client: C,
    ledger: CreditLedger,
}

impl<C> HostedBridge<C> {
    pub fn new(client: C, ledger: CreditLedger) -> Self {
        Self { client, ledger }
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    pub fn ledger(&self) -> &CreditLedger {
        &self.ledger
    }
}

impl<C: HostedBackendClient> HostedBridge<C> {
    pub fn call(
        &mut self,
        router: &RcxRouter,
        mut call: CallContext,
        now_unix_seconds: u64,
        payload: Vec<u8>,
    ) -> HostedBridgeOutcome {
        call.estimated_credit_cost = hosted_credit_cost(router.token(), &call);
        let refill = self.ledger.apply_refill(now_unix_seconds);
        if let Some(backend_id) = call.preferred_backend.as_deref() {
            call.backend_reachable = self.client.is_reachable(backend_id);
        }

        let mut token = router.token().clone();
        token.credits.balance = self.ledger.balance();
        let decision = RcxRouter::new(token).decide(&call, now_unix_seconds);
        if !matches!(&decision.mode, RouterMode::Hosted | RouterMode::CustomerHosted) {
            return HostedBridgeOutcome {
                decision,
                refill,
                debit: None,
                debit_denied: None,
                response: None,
                client_called: false,
            };
        }

        let debit = match self.ledger.try_debit(call.estimated_credit_cost) {
            Ok(debit) => debit,
            Err(debit_denied) => {
                return HostedBridgeOutcome {
                    decision,
                    refill,
                    debit: None,
                    debit_denied: Some(debit_denied),
                    response: None,
                    client_called: false,
                };
            }
        };
        let request = HostedRequest {
            backend_id: decision.backend_id.clone().unwrap_or_default(),
            capability: call.capability,
            token_id: decision.token_id.clone(),
            token_hash: decision.token_hash.clone(),
            estimated_credit_cost: debit.cost,
            payload,
        };
        let response = self.client.call(request);

        HostedBridgeOutcome {
            decision,
            refill,
            debit: Some(debit),
            debit_denied: None,
            response: Some(response),
            client_called: true,
        }
    }
}

fn refill_period_seconds(period: &RefillPeriod) -> Option<u64> {
    match period {
        RefillPeriod::Daily => Some(86_400),
        RefillPeriod::Monthly => Some(30 * 86_400),
        RefillPeriod::None => None,
    }
}

fn hosted_credit_cost(token: &RcxCapabilityToken, call: &CallContext) -> u64 {
    let capability_cost = token
        .backends
        .iter()
        .filter(|backend| {
            call.preferred_backend
                .as_deref()
                .is_none_or(|preferred| preferred == backend.backend_id)
        })
        .flat_map(|backend| backend.permitted_capabilities.iter())
        .find(|capability| capability.capability == call.capability)
        .and_then(|capability| capability.credit_cost.as_ref())
        .map_or(0, |cost| cost.cost);
    call.estimated_credit_cost.max(capability_cost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint_free_local_token;
    use rcx_capability_token::{
        Backend, CreditCost, CreditCostUnit, Credits, DataEgressClass, FallbackAction, FallbackPolicy, OverdraftPolicy,
        PermittedCapability, RcxTier, RCX_CT_SIGNATURE_LEN, RCX_HOSTED_BACKEND_ID, RCX_HOSTED_RETRIEVE_CAPABILITY,
    };

    #[derive(Debug, Clone)]
    struct MockHostedClient {
        reachable: bool,
        calls: Vec<HostedRequest>,
    }

    impl HostedBackendClient for MockHostedClient {
        fn is_reachable(&self, _backend_id: &str) -> bool {
            self.reachable
        }

        fn call(&mut self, request: HostedRequest) -> HostedResponse {
            self.calls.push(request);
            HostedResponse {
                status: 200,
                body: b"{\"ok\":true}".to_vec(),
                receipt_ref: Some("receipt_01".to_string()),
            }
        }
    }

    fn hosted_router(balance: Option<u64>, fallback: FallbackAction) -> RcxRouter {
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
            backend_id: RCX_HOSTED_BACKEND_ID.to_string(),
            trust_root_kid: "vaultcrux-hosted-root-v1".to_string(),
            endpoint_url: Some("https://hosted.vaultcrux.com".to_string()),
            permitted_capabilities: vec![PermittedCapability {
                capability: RCX_HOSTED_RETRIEVE_CAPABILITY.to_string(),
                data_egress_classes: vec![DataEgressClass::Vectors, DataEgressClass::ReceiptHashes],
                required_attestations: vec!["passport_bound".to_string()],
                credit_cost: Some(CreditCost {
                    unit: CreditCostUnit::Call,
                    cost: 1,
                }),
            }],
        }];
        token.credits = Credits {
            balance,
            refill: CreditRefill {
                period: RefillPeriod::None,
                amount: None,
            },
            overdraft: OverdraftPolicy::Forbid,
            overdraft_limit: None,
        };
        token.fallback = FallbackPolicy {
            on_backend_unreachable: fallback,
            on_credits_exhausted: FallbackAction::Refuse,
            on_expiry: FallbackAction::Refuse,
            queue_ttl_seconds: Some(120),
        };
        RcxRouter::new(token)
    }

    fn hosted_call(cost: u64) -> CallContext {
        CallContext {
            capability: RCX_HOSTED_RETRIEVE_CAPABILITY.to_string(),
            preferred_backend: Some(RCX_HOSTED_BACKEND_ID.to_string()),
            data_egress_classes: vec![DataEgressClass::Vectors, DataEgressClass::ReceiptHashes],
            present_attestations: vec!["passport_bound".to_string()],
            estimated_credit_cost: cost,
            backend_reachable: true,
        }
    }

    #[test]
    fn hosted_bridge_debits_and_calls_mock_after_authorization() {
        let router = hosted_router(Some(5), FallbackAction::Refuse);
        let ledger = CreditLedger::from_token(router.token(), 1_776_989_600);
        let client = MockHostedClient {
            reachable: true,
            calls: Vec::new(),
        };
        let mut bridge = HostedBridge::new(client, ledger);

        let outcome = bridge.call(&router, hosted_call(2), 1_776_989_601, b"{}".to_vec());

        assert!(outcome.decision.authorised);
        assert_eq!(outcome.decision.mode, RouterMode::Hosted);
        assert!(outcome.client_called);
        assert_eq!(bridge.ledger().balance(), Some(3));
        assert_eq!(bridge.client().calls.len(), 1);
        assert_eq!(bridge.client().calls[0].capability, RCX_HOSTED_RETRIEVE_CAPABILITY);
    }

    #[test]
    fn hosted_bridge_debits_token_capability_cost_when_estimate_is_zero() {
        let router = hosted_router(Some(5), FallbackAction::Refuse);
        let ledger = CreditLedger::from_token(router.token(), 1_776_989_600);
        let client = MockHostedClient {
            reachable: true,
            calls: Vec::new(),
        };
        let mut bridge = HostedBridge::new(client, ledger);

        let outcome = bridge.call(&router, hosted_call(0), 1_776_989_601, b"{}".to_vec());

        assert!(outcome.client_called);
        assert_eq!(outcome.debit.as_ref().unwrap().cost, 1);
        assert_eq!(bridge.ledger().balance(), Some(4));
        assert_eq!(bridge.client().calls[0].estimated_credit_cost, 1);
    }

    #[test]
    fn hosted_bridge_refuses_without_authorized_token_and_does_not_call_client() {
        let router = RcxRouter::new(mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec!["corecrux.query.local".to_string()],
            1_776_989_600,
            1_780_143_200,
            [0x11; RCX_CT_SIGNATURE_LEN],
        ));
        let ledger = CreditLedger::from_token(router.token(), 1_776_989_600);
        let client = MockHostedClient {
            reachable: true,
            calls: Vec::new(),
        };
        let mut bridge = HostedBridge::new(client, ledger);

        let outcome = bridge.call(&router, hosted_call(1), 1_776_989_601, b"{}".to_vec());

        assert!(!outcome.decision.authorised);
        assert_eq!(
            outcome.decision.reason_code.as_deref(),
            Some("denied:capability_not_permitted")
        );
        assert!(!outcome.client_called);
        assert!(bridge.client().calls.is_empty());
        assert_eq!(bridge.ledger().balance(), None);
    }

    #[test]
    fn hosted_bridge_applies_refill_before_debit() {
        let router = hosted_router(Some(0), FallbackAction::Refuse);
        let mut ledger = CreditLedger::from_token(router.token(), 1_776_989_600);
        ledger.refill = CreditRefill {
            period: RefillPeriod::Daily,
            amount: Some(10),
        };
        let client = MockHostedClient {
            reachable: true,
            calls: Vec::new(),
        };
        let mut bridge = HostedBridge::new(client, ledger);

        let outcome = bridge.call(&router, hosted_call(2), 1_777_076_000, b"{}".to_vec());

        assert!(outcome.refill.is_some());
        assert!(outcome.client_called);
        assert_eq!(bridge.ledger().balance(), Some(8));
    }

    #[test]
    fn hosted_bridge_uses_unreachable_fallback_without_calling_client() {
        let router = hosted_router(Some(5), FallbackAction::Queue);
        let ledger = CreditLedger::from_token(router.token(), 1_776_989_600);
        let client = MockHostedClient {
            reachable: false,
            calls: Vec::new(),
        };
        let mut bridge = HostedBridge::new(client, ledger);

        let outcome = bridge.call(&router, hosted_call(2), 1_776_989_601, b"{}".to_vec());

        assert!(outcome.decision.authorised);
        assert_eq!(outcome.decision.mode, RouterMode::DegradedQueued);
        assert_eq!(outcome.decision.stamp.queue_ttl_seconds, Some(120));
        assert!(!outcome.client_called);
        assert_eq!(bridge.ledger().balance(), Some(5));
        assert!(bridge.client().calls.is_empty());
    }

    #[test]
    fn credit_ledger_allows_configured_overdraft_and_tracks_usage() {
        let router = hosted_router(Some(1), FallbackAction::Refuse);
        let mut ledger = CreditLedger::from_token(router.token(), 1_776_989_600);
        ledger.overdraft = OverdraftPolicy::AllowToLimit;
        ledger.overdraft_limit = Some(3);

        let debit = ledger.try_debit(3).unwrap();

        assert!(debit.used_overdraft);
        assert_eq!(ledger.balance(), Some(0));
        assert_eq!(ledger.overdraft_used(), 2);
    }
}
