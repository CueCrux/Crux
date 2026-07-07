// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Append-only comped-wallet meter primitive for the credit-burn rail.
//!
//! This is deliberately not wired into request paths yet. It provides the
//! crash-replayable, idempotent reserve/spend state machine M1 needs before a
//! handler can safely burn credits.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_V1: &str = "crux.credit_meter.event.v1";

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
    #[error("reservation {reservation_id} was voided: {reason}")]
    ReservationVoided { reservation_id: String, reason: String },
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
        let path = path.as_ref().to_path_buf();
        let mut store = Self {
            path,
            wallets: BTreeMap::new(),
            seed_events: BTreeMap::new(),
            reservations_by_operation: BTreeMap::new(),
            reservations: BTreeMap::new(),
        };
        store.replay()?;
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
    ) -> Result<CreditReservation, CreditMeterError> {
        let key = (tenant_id.to_string(), operation_id.to_string());
        if let Some(existing_id) = self.reservations_by_operation.get(&key) {
            if let Some(existing) = self.reservations.get(existing_id) {
                if let Some(reason) = existing.voided_reason.clone() {
                    return Err(CreditMeterError::ReservationVoided {
                        reservation_id: existing.reservation_id.clone(),
                        reason,
                    });
                }
                if existing.cost != cost {
                    return Err(CreditMeterError::OperationConflict {
                        tenant_id: tenant_id.to_string(),
                        operation_id: operation_id.to_string(),
                        existing_cost: existing.cost,
                        requested_cost: cost,
                    });
                }
                return Ok(reservation_view(existing));
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

        let reservation_id = reservation_id_for(tenant_id, operation_id, cost);
        let balance_after = available.saturating_sub(cost);
        let event = CreditMeterEvent::Reserve {
            schema: SCHEMA_V1.to_string(),
            tenant_id: tenant_id.to_string(),
            operation_id: operation_id.to_string(),
            reservation_id: reservation_id.clone(),
            cost,
            balance_after,
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

fn reservation_id_for(tenant_id: &str, operation_id: &str, cost: u64) -> String {
    let hash = blake3::hash(format!("{tenant_id}\n{operation_id}\n{cost}").as_bytes());
    format!("crxres_{}", hash.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn reserve_and_spend_survive_reopen() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let mut meter = CreditMeterStore::open(&path)?;
        assert_eq!(meter.seed_comped_wallet("tenant-a", 10, "seed-1")?, 10);
        let reserved = meter.reserve("tenant-a", "op-1", 4)?;
        assert_eq!(reserved.balance_after, 6);
        let spent = meter.spend("tenant-a", &reserved.reservation_id, "crown:r_1")?;
        assert_eq!(spent.spend_receipt, "crown:r_1");
        drop(meter);

        let mut reopened = CreditMeterStore::open(&path)?;
        assert_eq!(reopened.available_balance("tenant-a"), 6);
        let retry = reopened.reserve("tenant-a", "op-1", 4)?;
        assert_eq!(retry.reservation_id, reserved.reservation_id);
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
        let denied = meter.reserve("tenant-a", "op-1", 3);
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
        let reserved = meter.reserve("tenant-a", "op-1", 4)?;
        let conflict = meter.reserve("tenant-a", "op-1", 5);
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
            meter.reserve("tenant-a", "op-1", 4)?.reservation_id,
            reserved.reservation_id
        );
        Ok(())
    }

    #[test]
    fn voided_reservation_releases_credit_and_survives_reopen() -> Result<(), CreditMeterError> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("credit-meter.jsonl");
        let mut meter = CreditMeterStore::open(&path)?;
        meter.seed_comped_wallet("tenant-a", 10, "seed-1")?;
        let reserved = meter.reserve("tenant-a", "op-1", 4)?;
        assert_eq!(meter.available_balance("tenant-a"), 6);
        meter.void_reservation("tenant-a", &reserved.reservation_id, "remote_failed")?;
        assert_eq!(meter.available_balance("tenant-a"), 10);
        assert!(matches!(
            meter.spend("tenant-a", &reserved.reservation_id, "crown:r_1"),
            Err(CreditMeterError::ReservationVoided { .. })
        ));
        drop(meter);

        let reopened = CreditMeterStore::open(&path)?;
        assert_eq!(reopened.available_balance("tenant-a"), 10);
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
                guard.reserve("tenant-a", &format!("op-{i}"), 3).is_ok()
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
}
