// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Append-only comped-wallet meter primitive for the credit-burn rail.
//!
//! The default-off admin spend rail and metered rerank path share this
//! crash-replayable, idempotent reserve/spend state machine and deterministic
//! signed spend-receipt format.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_V1: &str = "crux.credit_meter.event.v1";
const QUOTE_SCHEMA_V1: &str = "crux.credit_quote.v1";
const SPEND_RECEIPT_SCHEMA_V1: &str = "crux.credit_spend_receipt.v1";
const DEFAULT_RESERVATION_TTL_SECS: u64 = 3_600;
const STALE_RESERVATION_GC_REASON: &str = "stale_reservation_gc";

#[derive(Debug, Error)]
pub(crate) enum CreditMeterError {
    #[error("credit meter io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("credit meter json error at line {line}: {source}")]
    Json {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("insufficient credit for tenant {tenant_id}: need {cost}, available {available}")]
    InsufficientCredit {
        tenant_id: String,
        cost: u64,
        available: u64,
    },
    #[error("reservation {reservation_id} not found")]
    ReservationNotFound { reservation_id: String },
    #[error("reservation {reservation_id} belongs to tenant {actual}, not {tenant_id}")]
    TenantMismatch {
        reservation_id: String,
        tenant_id: String,
        actual: String,
    },
    #[error(
        "operation {operation_id} for tenant {tenant_id} was already reserved at cost {existing_cost}, not {requested_cost}"
    )]
    OperationConflict {
        tenant_id: String,
        operation_id: String,
        existing_cost: u64,
        requested_cost: u64,
    },
    #[error(
        "operation {operation_id} for tenant {tenant_id} is reserved for payload {existing_payload_hash}, not {requested_payload_hash}"
    )]
    OperationPayloadMismatch {
        tenant_id: String,
        operation_id: String,
        existing_payload_hash: String,
        requested_payload_hash: String,
    },
    #[error("operation {operation_id} for tenant {tenant_id} was already spent with receipt {spend_receipt}")]
    OperationAlreadySpent {
        tenant_id: String,
        operation_id: String,
        spend_receipt: String,
    },
    #[error("reservation {reservation_id} was voided: {reason}")]
    ReservationVoided { reservation_id: String, reason: String },
    #[error("invalid credit quote: {reason}")]
    InvalidQuote { reason: String },
    #[error("credit quote does not match reservation: {reason}")]
    QuoteReservationMismatch { reason: String },
    #[error("credit spend receipt build failed: {0}")]
    ReceiptBuild(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CreditReservation {
    pub tenant_id: String,
    pub operation_id: String,
    pub reservation_id: String,
    pub cost: u64,
    pub balance_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CreditSpend {
    pub tenant_id: String,
    pub operation_id: String,
    pub reservation_id: String,
    pub cost: u64,
    pub spend_receipt: String,
    pub balance_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PinnedCreditQuote {
    pub schema: String,
    pub quote_id: String,
    pub tenant_id: String,
    pub operation_id: String,
    pub capability: String,
    pub credits: u64,
    pub price_list_hash: String,
}

impl PinnedCreditQuote {
    pub(crate) fn new(
        quote_id: impl Into<String>,
        tenant_id: impl Into<String>,
        operation_id: impl Into<String>,
        capability: impl Into<String>,
        credits: u64,
        price_list_hash: impl Into<String>,
    ) -> Self {
        Self {
            schema: QUOTE_SCHEMA_V1.to_string(),
            quote_id: quote_id.into(),
            tenant_id: tenant_id.into(),
            operation_id: operation_id.into(),
            capability: capability.into(),
            credits,
            price_list_hash: price_list_hash.into(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), CreditMeterError> {
        if self.schema != QUOTE_SCHEMA_V1 {
            return Err(CreditMeterError::InvalidQuote {
                reason: format!("schema must be {QUOTE_SCHEMA_V1}"),
            });
        }
        for (name, value) in [
            ("quote_id", &self.quote_id),
            ("tenant_id", &self.tenant_id),
            ("operation_id", &self.operation_id),
            ("capability", &self.capability),
        ] {
            if value.trim().is_empty() {
                return Err(CreditMeterError::InvalidQuote {
                    reason: format!("{name} must not be empty"),
                });
            }
        }
        if self.credits == 0 {
            return Err(CreditMeterError::InvalidQuote {
                reason: "credits must be > 0".to_string(),
            });
        }
        if !is_blake3_hash_ref(&self.price_list_hash) {
            return Err(CreditMeterError::InvalidQuote {
                reason: "price_list_hash must be blake3:<64-hex>".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CreditSpendReceiptBodyV1 {
    pub schema: String,
    pub receipt_id: String,
    pub tenant_id: String,
    pub operation_id: String,
    pub reservation_id: String,
    pub quote_id: String,
    pub capability: String,
    pub credits: u64,
    pub price_list_hash: String,
    pub balance_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CreditSpendReceiptSignatureV1 {
    pub alg: String,
    pub signed_by: String,
    pub body_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CreditSpendReceiptEnvelopeV1 {
    pub body: CreditSpendReceiptBodyV1,
    pub receipt: CreditSpendReceiptSignatureV1,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct WalletState {
    balance: u64,
    reserved: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReservationState {
    tenant_id: String,
    operation_id: String,
    reservation_id: String,
    cost: u64,
    balance_after: u64,
    payload_hash: Option<String>,
    created_at_unix: Option<u64>,
    spent_receipt: Option<String>,
    voided_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event")]
enum CreditMeterEvent {
    SeedCompedWallet {
        schema: String,
        event_id: String,
        tenant_id: String,
        amount: u64,
    },
    Reserve {
        schema: String,
        tenant_id: String,
        operation_id: String,
        reservation_id: String,
        cost: u64,
        balance_after: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        payload_hash: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        created_at_unix: Option<u64>,
    },
    Spend {
        schema: String,
        tenant_id: String,
        operation_id: String,
        reservation_id: String,
        spend_receipt: String,
    },
    Void {
        schema: String,
        tenant_id: String,
        operation_id: String,
        reservation_id: String,
        reason: String,
    },
}

#[derive(Debug)]
pub(crate) struct CreditMeterStore {
    path: PathBuf,
    wallets: BTreeMap<String, WalletState>,
    seed_events: BTreeMap<(String, String), u64>,
    reservations_by_operation: BTreeMap<(String, String), String>,
    reservations: BTreeMap<String, ReservationState>,
}

impl CreditMeterStore {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, CreditMeterError> {
        Self::open_with_reservation_ttl(path, DEFAULT_RESERVATION_TTL_SECS)
    }

    pub(crate) fn open_with_reservation_ttl(
        path: impl AsRef<Path>,
        reservation_ttl_secs: u64,
    ) -> Result<Self, CreditMeterError> {
        let path = path.as_ref().to_path_buf();
        let mut store = Self {
            path,
            wallets: BTreeMap::new(),
            seed_events: BTreeMap::new(),
            reservations_by_operation: BTreeMap::new(),
            reservations: BTreeMap::new(),
        };
        store.replay()?;
        store.gc_stale_reservations(reservation_ttl_secs)?;
        Ok(store)
    }

    pub(crate) fn available_balance(&self, tenant_id: &str) -> u64 {
        self.wallets
            .get(tenant_id)
            .map_or(0, |wallet| wallet.balance.saturating_sub(wallet.reserved))
    }

    pub(crate) fn seed_comped_wallet(
        &mut self,
        tenant_id: &str,
        amount: u64,
        event_id: &str,
    ) -> Result<u64, CreditMeterError> {
        if self
            .seed_events
            .contains_key(&(tenant_id.to_string(), event_id.to_string()))
        {
            return Ok(self.available_balance(tenant_id));
        }
        let event = CreditMeterEvent::SeedCompedWallet {
            schema: SCHEMA_V1.to_string(),
            event_id: event_id.to_string(),
            tenant_id: tenant_id.to_string(),
            amount,
        };
        self.append_and_apply(&event)?;
        Ok(self.available_balance(tenant_id))
    }

    pub(crate) fn reserve(
        &mut self,
        tenant_id: &str,
        operation_id: &str,
        cost: u64,
        payload_hash: &str,
    ) -> Result<CreditReservation, CreditMeterError> {
        let key = (tenant_id.to_string(), operation_id.to_string());
        if let Some(existing_id) = self.reservations_by_operation.get(&key) {
            if let Some(existing) = self.reservations.get(existing_id) {
                if existing.voided_reason.is_some() {
                    // A failed attempt released its hold. Fall through and bind a
                    // distinct fresh reservation to this retry's payload.
                } else if let Some(spend_receipt) = existing.spent_receipt.clone() {
                    return Err(CreditMeterError::OperationAlreadySpent {
                        tenant_id: tenant_id.to_string(),
                        operation_id: operation_id.to_string(),
                        spend_receipt,
                    });
                } else {
                    if existing.cost != cost {
                        return Err(CreditMeterError::OperationConflict {
                            tenant_id: tenant_id.to_string(),
                            operation_id: operation_id.to_string(),
                            existing_cost: existing.cost,
                            requested_cost: cost,
                        });
                    }
                    if existing.payload_hash.as_deref() != Some(payload_hash) {
                        return Err(CreditMeterError::OperationPayloadMismatch {
                            tenant_id: tenant_id.to_string(),
                            operation_id: operation_id.to_string(),
                            existing_payload_hash: existing
                                .payload_hash
                                .clone()
                                .unwrap_or_else(|| "unbound:legacy".to_string()),
                            requested_payload_hash: payload_hash.to_string(),
                        });
                    }
                    return Ok(reservation_view(existing));
                }
            }
        }

        let available = self.available_balance(tenant_id);
        if available < cost {
            return Err(CreditMeterError::InsufficientCredit {
                tenant_id: tenant_id.to_string(),
                cost,
                available,
            });
        }

        let reservation_id = self.fresh_reservation_id(tenant_id, operation_id, cost, payload_hash);
        let balance_after = available.saturating_sub(cost);
        let event = CreditMeterEvent::Reserve {
            schema: SCHEMA_V1.to_string(),
            tenant_id: tenant_id.to_string(),
            operation_id: operation_id.to_string(),
            reservation_id: reservation_id.clone(),
            cost,
            balance_after,
            payload_hash: Some(payload_hash.to_string()),
            created_at_unix: Some(current_unix_seconds()),
        };
        self.append_and_apply(&event)?;
        self.reservations
            .get(&reservation_id)
            .map(reservation_view)
            .ok_or(CreditMeterError::ReservationNotFound { reservation_id })
    }

    pub(crate) fn spend(
        &mut self,
        tenant_id: &str,
        reservation_id: &str,
        spend_receipt: &str,
    ) -> Result<CreditSpend, CreditMeterError> {
        let existing = self
            .reservations
            .get(reservation_id)
            .ok_or_else(|| CreditMeterError::ReservationNotFound {
                reservation_id: reservation_id.to_string(),
            })?;
        if existing.tenant_id != tenant_id {
            return Err(CreditMeterError::TenantMismatch {
                reservation_id: reservation_id.to_string(),
                tenant_id: tenant_id.to_string(),
                actual: existing.tenant_id.clone(),
            });
        }
        if let Some(reason) = existing.voided_reason.clone() {
            return Err(CreditMeterError::ReservationVoided {
                reservation_id: reservation_id.to_string(),
                reason,
            });
        }
        if let Some(receipt) = existing.spent_receipt.clone() {
            return Ok(spend_view(existing, &receipt));
        }
        let event = CreditMeterEvent::Spend {
            schema: SCHEMA_V1.to_string(),
            tenant_id: existing.tenant_id.clone(),
            operation_id: existing.operation_id.clone(),
            reservation_id: reservation_id.to_string(),
            spend_receipt: spend_receipt.to_string(),
        };
        self.append_and_apply(&event)?;
        self.reservations
            .get(reservation_id)
            .and_then(|reservation| {
                reservation
                    .spent_receipt
                    .as_deref()
                    .map(|receipt| spend_view(reservation, receipt))
            })
            .ok_or_else(|| CreditMeterError::ReservationNotFound {
                reservation_id: reservation_id.to_string(),
            })
    }

    pub(crate) fn void_reservation(
        &mut self,
        tenant_id: &str,
        reservation_id: &str,
        reason: &str,
    ) -> Result<CreditReservation, CreditMeterError> {
        let existing = self
            .reservations
            .get(reservation_id)
            .ok_or_else(|| CreditMeterError::ReservationNotFound {
                reservation_id: reservation_id.to_string(),
            })?;
        if existing.tenant_id != tenant_id {
            return Err(CreditMeterError::TenantMismatch {
                reservation_id: reservation_id.to_string(),
                tenant_id: tenant_id.to_string(),
                actual: existing.tenant_id.clone(),
            });
        }
        if existing.spent_receipt.is_some() {
            return Ok(reservation_view(existing));
        }
        if let Some(existing_reason) = existing.voided_reason.clone() {
            return Err(CreditMeterError::ReservationVoided {
                reservation_id: reservation_id.to_string(),
                reason: existing_reason,
            });
        }
        let event = CreditMeterEvent::Void {
            schema: SCHEMA_V1.to_string(),
            tenant_id: existing.tenant_id.clone(),
            operation_id: existing.operation_id.clone(),
            reservation_id: reservation_id.to_string(),
            reason: reason.to_string(),
        };
        self.append_and_apply(&event)?;
        self.reservations
            .get(reservation_id)
            .map(reservation_view)
            .ok_or_else(|| CreditMeterError::ReservationNotFound {
                reservation_id: reservation_id.to_string(),
            })
    }

    fn replay(&mut self) -> Result<(), CreditMeterError> {
        if !self.path.exists() {
            return Ok(());
        }
        let file = OpenOptions::new().read(true).open(&self.path)?;
        for (idx, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event: CreditMeterEvent =
                serde_json::from_str(&line).map_err(|source| CreditMeterError::Json { line: idx + 1, source })?;
            self.apply(&event);
        }
        Ok(())
    }

    fn gc_stale_reservations(&mut self, reservation_ttl_secs: u64) -> Result<(), CreditMeterError> {
        let now = current_unix_seconds();
        let stale = self
            .reservations
            .values()
            .filter(|reservation| {
                reservation.spent_receipt.is_none()
                    && reservation.voided_reason.is_none()
                    && reservation
                        .created_at_unix
                        .is_none_or(|created_at| now.saturating_sub(created_at) > reservation_ttl_secs)
            })
            .map(|reservation| {
                (
                    reservation.tenant_id.clone(),
                    reservation.operation_id.clone(),
                    reservation.reservation_id.clone(),
                )
            })
            .collect::<Vec<_>>();

        for (tenant_id, operation_id, reservation_id) in stale {
            self.append_and_apply(&CreditMeterEvent::Void {
                schema: SCHEMA_V1.to_string(),
                tenant_id,
                operation_id,
                reservation_id,
                reason: STALE_RESERVATION_GC_REASON.to_string(),
            })?;
        }
        Ok(())
    }

    fn fresh_reservation_id(&self, tenant_id: &str, operation_id: &str, cost: u64, payload_hash: &str) -> String {
        let mut attempt = self
            .reservations
            .values()
            .filter(|reservation| reservation.tenant_id == tenant_id && reservation.operation_id == operation_id)
            .count() as u64;
        loop {
            let reservation_id = reservation_id_for(tenant_id, operation_id, cost, payload_hash, attempt);
            if !self.reservations.contains_key(&reservation_id) {
                return reservation_id;
            }
            attempt = attempt.saturating_add(1);
        }
    }

    fn append_and_apply(&mut self, event: &CreditMeterEvent) -> Result<(), CreditMeterError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        serde_json::to_writer(&mut file, event).map_err(|source| CreditMeterError::Json { line: 0, source })?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        self.apply(event);
        Ok(())
    }

    fn apply(&mut self, event: &CreditMeterEvent) {
        match event {
            CreditMeterEvent::SeedCompedWallet {
                event_id,
                tenant_id,
                amount,
                ..
            } => {
                if self
                    .seed_events
                    .insert((tenant_id.clone(), event_id.clone()), *amount)
                    .is_none()
                {
                    let wallet = self.wallets.entry(tenant_id.clone()).or_default();
                    wallet.balance = wallet.balance.saturating_add(*amount);
                }
            }
            CreditMeterEvent::Reserve {
                tenant_id,
                operation_id,
                reservation_id,
                cost,
                balance_after,
                payload_hash,
                created_at_unix,
                ..
            } => {
                if self.reservations.contains_key(reservation_id) {
                    return;
                }
                let wallet = self.wallets.entry(tenant_id.clone()).or_default();
                wallet.reserved = wallet.reserved.saturating_add(*cost);
                let reservation = ReservationState {
                    tenant_id: tenant_id.clone(),
                    operation_id: operation_id.clone(),
                    reservation_id: reservation_id.clone(),
                    cost: *cost,
                    balance_after: *balance_after,
                    payload_hash: payload_hash.clone(),
                    created_at_unix: *created_at_unix,
                    spent_receipt: None,
                    voided_reason: None,
                };
                self.reservations_by_operation
                    .insert((tenant_id.clone(), operation_id.clone()), reservation_id.clone());
                self.reservations.insert(reservation_id.clone(), reservation);
            }
            CreditMeterEvent::Spend {
                reservation_id,
                spend_receipt,
                ..
            } => {
                if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                    if reservation.spent_receipt.is_none() {
                        reservation.spent_receipt = Some(spend_receipt.clone());
                    }
                }
            }
            CreditMeterEvent::Void {
                reservation_id, reason, ..
            } => {
                if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                    if reservation.spent_receipt.is_none() && reservation.voided_reason.is_none() {
                        reservation.voided_reason = Some(reason.clone());
                        if let Some(wallet) = self.wallets.get_mut(&reservation.tenant_id) {
                            wallet.reserved = wallet.reserved.saturating_sub(reservation.cost);
                        }
                    }
                }
            }
        }
    }
}

fn reservation_view(reservation: &ReservationState) -> CreditReservation {
    CreditReservation {
        tenant_id: reservation.tenant_id.clone(),
        operation_id: reservation.operation_id.clone(),
        reservation_id: reservation.reservation_id.clone(),
        cost: reservation.cost,
        balance_after: reservation.balance_after,
    }
}

fn spend_view(reservation: &ReservationState, spend_receipt: &str) -> CreditSpend {
    CreditSpend {
        tenant_id: reservation.tenant_id.clone(),
        operation_id: reservation.operation_id.clone(),
        reservation_id: reservation.reservation_id.clone(),
        cost: reservation.cost,
        spend_receipt: spend_receipt.to_string(),
        balance_after: reservation.balance_after,
    }
}

fn reservation_id_for(tenant_id: &str, operation_id: &str, cost: u64, payload_hash: &str, attempt: u64) -> String {
    let hash = blake3::hash(format!("{tenant_id}\n{operation_id}\n{cost}\n{payload_hash}\n{attempt}").as_bytes());
    format!("crxres_{}", hash.to_hex())
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn mint_spend_receipt(
    quote: &PinnedCreditQuote,
    reservation: &CreditReservation,
    key: &crux_session::LocalPassportKey,
) -> Result<CreditSpendReceiptEnvelopeV1, CreditMeterError> {
    quote.validate()?;
    if quote.tenant_id != reservation.tenant_id {
        return Err(CreditMeterError::QuoteReservationMismatch {
            reason: format!(
                "quote tenant {} != reservation tenant {}",
                quote.tenant_id, reservation.tenant_id
            ),
        });
    }
    if quote.operation_id != reservation.operation_id {
        return Err(CreditMeterError::QuoteReservationMismatch {
            reason: format!(
                "quote operation {} != reservation operation {}",
                quote.operation_id, reservation.operation_id
            ),
        });
    }
    if quote.credits != reservation.cost {
        return Err(CreditMeterError::QuoteReservationMismatch {
            reason: format!(
                "quote credits {} != reservation cost {}",
                quote.credits, reservation.cost
            ),
        });
    }

    let receipt_id = spend_receipt_id_for(quote, &reservation.reservation_id);
    let body = CreditSpendReceiptBodyV1 {
        schema: SPEND_RECEIPT_SCHEMA_V1.to_string(),
        receipt_id,
        tenant_id: quote.tenant_id.clone(),
        operation_id: quote.operation_id.clone(),
        reservation_id: reservation.reservation_id.clone(),
        quote_id: quote.quote_id.clone(),
        capability: quote.capability.clone(),
        credits: quote.credits,
        price_list_hash: quote.price_list_hash.clone(),
        balance_after: reservation.balance_after,
    };
    let body_bytes = serde_json::to_vec(&body).map_err(|err| CreditMeterError::ReceiptBuild(err.to_string()))?;
    let hash = blake3::hash(&body_bytes);
    let signature = key.sign_hash(hash.as_bytes());
    Ok(CreditSpendReceiptEnvelopeV1 {
        body,
        receipt: CreditSpendReceiptSignatureV1 {
            alg: "ed25519".to_string(),
            signed_by: key.passport_fpr().to_string(),
            body_hash: format!("blake3:{}", hex::encode(hash.as_bytes())),
            signature: hex::encode(signature),
        },
    })
}

fn spend_receipt_id_for(quote: &PinnedCreditQuote, reservation_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SPEND_RECEIPT_SCHEMA_V1.as_bytes());
    hasher.update(b"\n");
    hasher.update(quote.quote_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(quote.tenant_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(quote.operation_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(quote.capability.as_bytes());
    hasher.update(b"\n");
    hasher.update(&quote.credits.to_le_bytes());
    hasher.update(b"\n");
    hasher.update(quote.price_list_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(reservation_id.as_bytes());
    format!("crxspend_{}", hasher.finalize().to_hex())
}

fn is_blake3_hash_ref(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn reserve_and_spend_survive_reopen_and_spent_reserve_is_refused() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let mut meter = CreditMeterStore::open(&path)?;
        assert_eq!(meter.seed_comped_wallet("tenant-a", 10, "seed-1")?, 10);
        let reserved = meter.reserve("tenant-a", "op-1", 4, &blake3_ref("payload-1"))?;
        assert_eq!(reserved.balance_after, 6);
        let spent = meter.spend("tenant-a", &reserved.reservation_id, "crown:r_1")?;
        assert_eq!(spent.spend_receipt, "crown:r_1");
        drop(meter);

        let mut reopened = CreditMeterStore::open(&path)?;
        assert_eq!(reopened.available_balance("tenant-a"), 6);
        assert!(matches!(
            reopened.reserve("tenant-a", "op-1", 4, &blake3_ref("payload-1")),
            Err(CreditMeterError::OperationAlreadySpent {
                ref spend_receipt,
                ..
            }) if spend_receipt == "crown:r_1"
        ));
        assert!(matches!(
            reopened.reserve("tenant-a", "op-1", 4, &blake3_ref("payload-2")),
            Err(CreditMeterError::OperationAlreadySpent { .. })
        ));
        let spend_retry = reopened.spend("tenant-a", &reserved.reservation_id, "crown:r_2")?;
        assert_eq!(spend_retry.spend_receipt, "crown:r_1");
        Ok(())
    }

    #[test]
    fn insufficient_credit_does_not_debit() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let mut meter = CreditMeterStore::open(&path)?;
        meter.seed_comped_wallet("tenant-a", 2, "seed-1")?;
        let denied = meter.reserve("tenant-a", "op-1", 3, &blake3_ref("payload-1"));
        assert!(matches!(
            denied,
            Err(CreditMeterError::InsufficientCredit {
                cost: 3,
                available: 2,
                ..
            })
        ));
        assert_eq!(meter.available_balance("tenant-a"), 2);
        Ok(())
    }

    #[test]
    fn duplicate_seed_event_is_idempotent() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let mut meter = CreditMeterStore::open(&path)?;
        assert_eq!(meter.seed_comped_wallet("tenant-a", 10, "seed-1")?, 10);
        assert_eq!(meter.seed_comped_wallet("tenant-a", 10, "seed-1")?, 10);
        assert_eq!(meter.seed_comped_wallet("tenant-b", 7, "seed-1")?, 7);
        Ok(())
    }

    #[test]
    fn same_operation_with_different_cost_conflicts() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let mut meter = CreditMeterStore::open(&path)?;
        meter.seed_comped_wallet("tenant-a", 10, "seed-1")?;
        let payload_hash = blake3_ref("payload-1");
        let reserved = meter.reserve("tenant-a", "op-1", 4, &payload_hash)?;
        let conflict = meter.reserve("tenant-a", "op-1", 5, &payload_hash);
        assert!(matches!(
            conflict,
            Err(CreditMeterError::OperationConflict {
                existing_cost: 4,
                requested_cost: 5,
                ..
            })
        ));
        assert_eq!(meter.available_balance("tenant-a"), 6);
        assert_eq!(
            meter.reserve("tenant-a", "op-1", 4, &payload_hash)?.reservation_id,
            reserved.reservation_id
        );
        Ok(())
    }

    #[test]
    fn active_same_payload_is_an_idempotent_retry() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let mut meter = CreditMeterStore::open(&path)?;
        meter.seed_comped_wallet("tenant-a", 10, "seed-1")?;
        let payload_hash = blake3_ref("payload-1");

        let first = meter.reserve("tenant-a", "op-1", 4, &payload_hash)?;
        let retry = meter.reserve("tenant-a", "op-1", 4, &payload_hash)?;

        assert_eq!(retry, first);
        assert_eq!(meter.available_balance("tenant-a"), 6);
        let log = std::fs::read_to_string(path)?;
        assert_eq!(log.matches("\"event\":\"Reserve\"").count(), 1);
        Ok(())
    }

    #[test]
    fn active_different_payload_is_rejected() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let mut meter = CreditMeterStore::open(&path)?;
        meter.seed_comped_wallet("tenant-a", 10, "seed-1")?;
        let existing_payload_hash = blake3_ref("payload-1");
        let requested_payload_hash = blake3_ref("payload-2");
        meter.reserve("tenant-a", "op-1", 4, &existing_payload_hash)?;

        assert!(matches!(
            meter.reserve("tenant-a", "op-1", 4, &requested_payload_hash),
            Err(CreditMeterError::OperationPayloadMismatch {
                existing_payload_hash: ref existing,
                requested_payload_hash: ref requested,
                ..
            }) if existing == &existing_payload_hash && requested == &requested_payload_hash
        ));
        assert_eq!(meter.available_balance("tenant-a"), 6);
        Ok(())
    }

    #[test]
    fn voided_reservation_releases_credit_and_survives_reopen() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let mut meter = CreditMeterStore::open(&path)?;
        meter.seed_comped_wallet("tenant-a", 10, "seed-1")?;
        let reserved = meter.reserve("tenant-a", "op-1", 4, &blake3_ref("payload-1"))?;
        assert_eq!(meter.available_balance("tenant-a"), 6);
        meter.void_reservation("tenant-a", &reserved.reservation_id, "remote_failed")?;
        assert_eq!(meter.available_balance("tenant-a"), 10);
        assert!(matches!(
            meter.spend("tenant-a", &reserved.reservation_id, "crown:r_1"),
            Err(CreditMeterError::ReservationVoided { .. })
        ));
        let retried = meter.reserve("tenant-a", "op-1", 4, &blake3_ref("payload-2"))?;
        assert_ne!(retried.reservation_id, reserved.reservation_id);
        assert_eq!(meter.available_balance("tenant-a"), 6);
        let retried_state = meter
            .reservations
            .get(&retried.reservation_id)
            .expect("retried reservation");
        assert_eq!(
            retried_state.payload_hash.as_deref(),
            Some(blake3_ref("payload-2").as_str())
        );
        drop(meter);

        let reopened = CreditMeterStore::open(&path)?;
        assert_eq!(reopened.available_balance("tenant-a"), 6);
        Ok(())
    }

    #[test]
    fn legacy_reserve_event_line_replays_without_binding_fields() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let events = [
            json!({
                "event": "SeedCompedWallet",
                "schema": SCHEMA_V1,
                "event_id": "legacy-seed",
                "tenant_id": "tenant-a",
                "amount": 10,
            }),
            json!({
                "event": "Reserve",
                "schema": SCHEMA_V1,
                "tenant_id": "tenant-a",
                "operation_id": "legacy-op",
                "reservation_id": "legacy-reservation",
                "cost": 4,
                "balance_after": 6,
            }),
            json!({
                "event": "Spend",
                "schema": SCHEMA_V1,
                "tenant_id": "tenant-a",
                "operation_id": "legacy-op",
                "reservation_id": "legacy-reservation",
                "spend_receipt": "legacy-spend-receipt",
            }),
        ];
        let log = events
            .iter()
            .map(|event| serde_json::to_string(event).expect("serialize legacy meter event"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, format!("{log}\n"))?;

        let meter = CreditMeterStore::open(&path)?;

        assert_eq!(meter.available_balance("tenant-a"), 6);
        let legacy = meter
            .reservations
            .get("legacy-reservation")
            .expect("legacy reservation");
        assert_eq!(legacy.payload_hash, None);
        assert_eq!(legacy.created_at_unix, None);
        assert_eq!(legacy.spent_receipt.as_deref(), Some("legacy-spend-receipt"));
        Ok(())
    }

    #[test]
    fn open_gc_voids_legacy_and_stale_active_reservations_but_keeps_recent() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let now = current_unix_seconds();
        let events = [
            json!({
                "event": "SeedCompedWallet",
                "schema": SCHEMA_V1,
                "event_id": "seed-1",
                "tenant_id": "tenant-a",
                "amount": 20,
            }),
            json!({
                "event": "Reserve",
                "schema": SCHEMA_V1,
                "tenant_id": "tenant-a",
                "operation_id": "legacy-op",
                "reservation_id": "legacy-reservation",
                "cost": 2,
                "balance_after": 18,
            }),
            json!({
                "event": "Reserve",
                "schema": SCHEMA_V1,
                "tenant_id": "tenant-a",
                "operation_id": "stale-op",
                "reservation_id": "stale-reservation",
                "cost": 3,
                "balance_after": 15,
                "payload_hash": blake3_ref("stale-payload"),
                "created_at_unix": now.saturating_sub(61),
            }),
            json!({
                "event": "Reserve",
                "schema": SCHEMA_V1,
                "tenant_id": "tenant-a",
                "operation_id": "recent-op",
                "reservation_id": "recent-reservation",
                "cost": 4,
                "balance_after": 11,
                "payload_hash": blake3_ref("recent-payload"),
                "created_at_unix": now,
            }),
        ];
        let log = events
            .iter()
            .map(|event| serde_json::to_string(event).expect("serialize meter event"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, format!("{log}\n"))?;

        let meter = CreditMeterStore::open_with_reservation_ttl(&path, 60)?;

        assert_eq!(meter.available_balance("tenant-a"), 16);
        for reservation_id in ["legacy-reservation", "stale-reservation"] {
            assert_eq!(
                meter
                    .reservations
                    .get(reservation_id)
                    .and_then(|reservation| reservation.voided_reason.as_deref()),
                Some(STALE_RESERVATION_GC_REASON)
            );
        }
        assert_eq!(
            meter
                .reservations
                .get("recent-reservation")
                .and_then(|reservation| reservation.voided_reason.as_deref()),
            None
        );
        let replayed_log = std::fs::read_to_string(path)?;
        assert_eq!(replayed_log.matches(STALE_RESERVATION_GC_REASON).count(), 2);
        Ok(())
    }

    #[test]
    fn concurrent_reserves_never_overspend() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let meter = Arc::new(Mutex::new(CreditMeterStore::open(&path)?));
        {
            let mut guard = meter.lock().map_err(|_| std::io::Error::other("poisoned meter"))?;
            guard.seed_comped_wallet("tenant-a", 10, "seed-1")?;
        }

        let mut handles = Vec::new();
        for i in 0..10 {
            let meter = Arc::clone(&meter);
            handles.push(thread::spawn(move || {
                let mut guard = match meter.lock() {
                    Ok(guard) => guard,
                    Err(_) => return false,
                };
                guard
                    .reserve("tenant-a", &format!("op-{i}"), 3, &blake3_ref(&format!("payload-{i}")))
                    .is_ok()
            }));
        }

        let mut successes = 0;
        for handle in handles {
            match handle.join() {
                Ok(true) => successes += 1,
                Ok(false) => {}
                Err(_) => return Err(std::io::Error::other("thread panicked").into()),
            }
        }
        let guard = meter.lock().map_err(|_| std::io::Error::other("poisoned meter"))?;
        assert_eq!(successes, 3);
        assert_eq!(guard.available_balance("tenant-a"), 1);
        Ok(())
    }

    #[test]
    fn quote_validation_requires_pinned_price_list_hash() {
        let quote = PinnedCreditQuote::new("q-1", "tenant-a", "op-1", "capability", 1, "not-a-hash");
        assert!(matches!(quote.validate(), Err(CreditMeterError::InvalidQuote { .. })));

        let quote = PinnedCreditQuote::new("q-1", "tenant-a", "op-1", "capability", 1, blake3_ref("price-list"));
        assert!(quote.validate().is_ok());
    }

    #[test]
    fn spend_receipt_is_signed_and_bound_to_quote() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let mut meter = CreditMeterStore::open(&path)?;
        meter.seed_comped_wallet("tenant-a", 10, "seed-1")?;
        let quote = PinnedCreditQuote::new(
            "quote-1",
            "tenant-a",
            "op-1",
            "context.attestation",
            4,
            blake3_ref("price-list"),
        );
        let reservation = meter.reserve("tenant-a", "op-1", quote.credits, &blake3_ref("payload-1"))?;
        let key = crux_session::LocalPassportKey::from_seed([7_u8; 32])
            .map_err(|err| std::io::Error::other(err.to_string()))?;

        let receipt = mint_spend_receipt(&quote, &reservation, &key)?;
        assert_eq!(receipt.body.schema, SPEND_RECEIPT_SCHEMA_V1);
        assert_eq!(receipt.body.quote_id, "quote-1");
        assert_eq!(receipt.body.reservation_id, reservation.reservation_id);
        assert_eq!(receipt.receipt.alg, "ed25519");
        assert_eq!(receipt.receipt.signed_by, key.passport_fpr());
        assert!(receipt.receipt.body_hash.starts_with("blake3:"));
        assert_eq!(receipt.receipt.signature.len(), 128);

        let spend = meter.spend("tenant-a", &reservation.reservation_id, &receipt.body.receipt_id)?;
        assert_eq!(spend.spend_receipt, receipt.body.receipt_id);
        let retry = meter.spend("tenant-a", &reservation.reservation_id, "crxspend_wrong")?;
        assert_eq!(retry.spend_receipt, receipt.body.receipt_id);
        Ok(())
    }

    #[test]
    fn spend_receipt_refuses_quote_reservation_mismatch() -> Result<(), CreditMeterError> {
        let reservation = CreditReservation {
            tenant_id: "tenant-a".to_string(),
            operation_id: "op-1".to_string(),
            reservation_id: "res-1".to_string(),
            cost: 4,
            balance_after: 6,
        };
        let quote = PinnedCreditQuote::new(
            "quote-1",
            "tenant-a",
            "op-1",
            "context.attestation",
            5,
            blake3_ref("price-list"),
        );
        let key = crux_session::LocalPassportKey::from_seed([7_u8; 32])
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        assert!(matches!(
            mint_spend_receipt(&quote, &reservation, &key),
            Err(CreditMeterError::QuoteReservationMismatch { .. })
        ));
        Ok(())
    }

    fn blake3_ref(input: &str) -> String {
        format!("blake3:{}", blake3::hash(input.as_bytes()).to_hex())
    }
}
