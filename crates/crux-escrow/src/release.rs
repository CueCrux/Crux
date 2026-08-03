// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Release of the custodian share (share C) as an **operation, not a read**.
//!
//! Possession of the account is not possession of the share. A release is delayed, is
//! announced to every registered device at request time, can be cancelled by any of them
//! during the window, and every step is an event the caller writes to the customer's own
//! CROWN timeline.
//!
//! This module is pure state transition. It deliberately does **not** own a device
//! registry, a clock, or a receipt writer: the caller passes the registered devices and
//! `now`, and receipts the returned [`ReleaseEvent`]s. The relay plan's device-identity
//! plane is not built yet, and inventing a device registry here would pin a protocol that
//! plan has not finished freezing.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The mandatory wait between requesting the custodian share and receiving it.
///
/// A constant, not configuration. It is the whole anti-account-takeover control: a value
/// an operator can lower under support pressure is a value an attacker can have lowered.
/// Changing it is a product decision with a threat-model review, not an ops lever.
pub const RELEASE_DELAY: Duration = Duration::hours(72);

/// Why a release operation was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReleaseError {
    /// The requester's passport is not the account holder's. Support cannot initiate a
    /// release on a customer's behalf, by construction.
    #[error("only the account holder may request release of the custodian share")]
    NotAccountHolder,
    /// A release for this vault is already pending. Replaying the request does not open a
    /// second window or restart the clock.
    #[error("a release is already pending for this vault")]
    AlreadyPending,
    /// The delay has not elapsed.
    #[error("release is not available until {available_at}")]
    TooSoon {
        /// When the pending request becomes completable.
        available_at: DateTime<Utc>,
    },
    /// The request was already cancelled or already released. Terminal either way.
    #[error("this release is no longer pending")]
    NotPending,
    /// A device that was not notified tried to cancel.
    #[error("device is not registered against this release")]
    UnknownDevice,
    /// The event stream did not describe a coherent request.
    #[error("release events could not be replayed: {0}")]
    Unreplayable(String),
}

/// Lifecycle of a single release request. Both non-pending states are terminal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ReleaseState {
    /// Waiting out [`RELEASE_DELAY`]; cancellable by any notified device.
    Pending,
    /// Cancelled from a device during the window. The share was never handed over.
    Cancelled {
        /// Device that cancelled.
        by: String,
        /// When.
        at: DateTime<Utc>,
    },
    /// The share was handed to the account holder.
    Released {
        /// When.
        at: DateTime<Utc>,
    },
}

/// What happened, in the customer's own timeline. Each of these is written as a CROWN
/// receipt by the caller; together they reconstruct the request exactly ([`ReleaseRequest::replay`]).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseEvent {
    /// Request this event belongs to.
    pub request_id: Uuid,
    /// Vault whose custodian share is at stake.
    pub vault_id: String,
    /// Passport or device that caused the event.
    pub actor: String,
    /// When it happened, per the caller's clock.
    pub at: DateTime<Utc>,
    /// What happened.
    pub kind: ReleaseEventKind,
}

/// The four things that can appear in a release timeline.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ReleaseEventKind {
    /// The account holder asked for the custodian share.
    Requested {
        /// When the share becomes releasable.
        available_at: DateTime<Utc>,
        /// Every device that will be notified.
        devices: Vec<String>,
    },
    /// One device was told a release is pending. Emitted per device so a missing
    /// notification is visible in the timeline rather than assumed.
    Notified {
        /// Device notified.
        device: String,
    },
    /// A device stopped it.
    Cancelled,
    /// The share was handed over.
    Released,
}

/// A pending or settled request for the custodian share.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseRequest {
    /// Stable id, used to correlate the receipt timeline.
    pub id: Uuid,
    /// Vault whose share C is requested.
    pub vault_id: String,
    /// Passport that owns the account.
    pub account_holder: String,
    /// When the request was opened.
    pub requested_at: DateTime<Utc>,
    /// `requested_at + RELEASE_DELAY`.
    pub available_at: DateTime<Utc>,
    /// Devices notified at request time. Any of them may cancel; a device registered
    /// later cannot, because it was not there to be told.
    pub notified_devices: Vec<String>,
    /// Current state.
    pub state: ReleaseState,
}

impl ReleaseRequest {
    /// Open a release request.
    ///
    /// `previous` is the vault's most recent request, if any — passing it is what makes a
    /// replayed request idempotent instead of a second window.
    ///
    /// A vault with no registered devices produces an empty `Notified` set. That is
    /// recorded rather than rejected: refusing would lock out a customer whose only device
    /// was the one they lost, which is the case this whole plan exists to serve. The
    /// timeline shows nobody could have cancelled.
    ///
    /// # Errors
    /// [`ReleaseError::NotAccountHolder`] if `requested_by` is not the account holder;
    /// [`ReleaseError::AlreadyPending`] if `previous` is still pending.
    pub fn open(
        previous: Option<&Self>,
        vault_id: &str,
        account_holder: &str,
        requested_by: &str,
        registered_devices: &[String],
        now: DateTime<Utc>,
    ) -> Result<(Self, Vec<ReleaseEvent>), ReleaseError> {
        if requested_by != account_holder {
            return Err(ReleaseError::NotAccountHolder);
        }
        if previous.is_some_and(|p| p.state == ReleaseState::Pending) {
            return Err(ReleaseError::AlreadyPending);
        }
        let request = Self {
            id: Uuid::new_v4(),
            vault_id: vault_id.to_string(),
            account_holder: account_holder.to_string(),
            requested_at: now,
            available_at: now + RELEASE_DELAY,
            notified_devices: registered_devices.to_vec(),
            state: ReleaseState::Pending,
        };
        let mut events = vec![request.event(
            requested_by,
            now,
            ReleaseEventKind::Requested {
                available_at: request.available_at,
                devices: registered_devices.to_vec(),
            },
        )];
        events.extend(
            registered_devices
                .iter()
                .map(|device| request.event(device, now, ReleaseEventKind::Notified { device: device.clone() })),
        );
        Ok((request, events))
    }

    /// Cancel from a notified device.
    ///
    /// # Errors
    /// [`ReleaseError::NotPending`] if already settled; [`ReleaseError::UnknownDevice`] if
    /// the device was not notified when the request opened.
    pub fn cancel(&mut self, device: &str, now: DateTime<Utc>) -> Result<ReleaseEvent, ReleaseError> {
        if self.state != ReleaseState::Pending {
            return Err(ReleaseError::NotPending);
        }
        if !self.notified_devices.iter().any(|d| d == device) {
            return Err(ReleaseError::UnknownDevice);
        }
        self.state = ReleaseState::Cancelled {
            by: device.to_string(),
            at: now,
        };
        Ok(self.event(device, now, ReleaseEventKind::Cancelled))
    }

    /// Complete the release, once the window has elapsed.
    ///
    /// # Errors
    /// [`ReleaseError::NotPending`] if cancelled or already released;
    /// [`ReleaseError::TooSoon`] before `available_at`. There is no override.
    pub fn complete(&mut self, now: DateTime<Utc>) -> Result<ReleaseEvent, ReleaseError> {
        if self.state != ReleaseState::Pending {
            return Err(ReleaseError::NotPending);
        }
        if now < self.available_at {
            return Err(ReleaseError::TooSoon {
                available_at: self.available_at,
            });
        }
        self.state = ReleaseState::Released { at: now };
        let holder = self.account_holder.clone();
        Ok(self.event(&holder, now, ReleaseEventKind::Released))
    }

    /// Rebuild a request from its receipted events, proving the timeline is a complete
    /// record rather than a summary of one.
    ///
    /// # Errors
    /// [`ReleaseError::Unreplayable`] if the stream does not start with a `Requested`
    /// event, mixes request ids, or settles twice.
    pub fn replay(events: &[ReleaseEvent]) -> Result<Self, ReleaseError> {
        let Some(first) = events.first() else {
            return Err(ReleaseError::Unreplayable("empty event stream".into()));
        };
        let ReleaseEventKind::Requested { available_at, devices } = &first.kind else {
            return Err(ReleaseError::Unreplayable("stream does not open with a request".into()));
        };
        let mut request = Self {
            id: first.request_id,
            vault_id: first.vault_id.clone(),
            account_holder: first.actor.clone(),
            requested_at: first.at,
            available_at: *available_at,
            notified_devices: devices.clone(),
            state: ReleaseState::Pending,
        };
        for event in &events[1..] {
            if event.request_id != request.id {
                return Err(ReleaseError::Unreplayable("stream mixes request ids".into()));
            }
            match &event.kind {
                ReleaseEventKind::Notified { .. } => {}
                ReleaseEventKind::Requested { .. } => {
                    return Err(ReleaseError::Unreplayable("two requests in one stream".into()));
                }
                ReleaseEventKind::Cancelled => {
                    request.cancel(&event.actor, event.at).map_err(replay_failed)?;
                }
                ReleaseEventKind::Released => {
                    request.complete(event.at).map_err(replay_failed)?;
                }
            }
        }
        Ok(request)
    }

    fn event(&self, actor: &str, at: DateTime<Utc>, kind: ReleaseEventKind) -> ReleaseEvent {
        ReleaseEvent {
            request_id: self.id,
            vault_id: self.vault_id.clone(),
            actor: actor.to_string(),
            at,
            kind,
        }
    }
}

fn replay_failed(e: ReleaseError) -> ReleaseError {
    ReleaseError::Unreplayable(e.to_string())
}

#[cfg(test)]
mod tests {
    // Tests assert on exact outcomes; an unexpected `Err` here should fail loudly.
    #![allow(clippy::unwrap_used)]

    use super::*;

    const VAULT: &str = "vault-01HTEST";
    const OWNER: &str = "passport:owner";
    const THIEF: &str = "passport:thief";

    fn devices() -> Vec<String> {
        vec!["device:laptop".into(), "device:phone".into()]
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_775_000_000, 0).unwrap_or_default()
    }

    fn open() -> (ReleaseRequest, Vec<ReleaseEvent>) {
        ReleaseRequest::open(None, VAULT, OWNER, OWNER, &devices(), now()).unwrap()
    }

    #[test]
    fn release_cannot_complete_before_the_delay_elapses() {
        let (mut request, _) = open();
        for offset in [
            Duration::zero(),
            Duration::hours(1),
            RELEASE_DELAY - Duration::seconds(1),
        ] {
            assert_eq!(
                request.complete(now() + offset),
                Err(ReleaseError::TooSoon {
                    available_at: request.available_at
                }),
                "completed {offset} in"
            );
        }
        assert!(request.complete(now() + RELEASE_DELAY).is_ok());
    }

    #[test]
    fn every_registered_device_is_notified_at_request_time() {
        let (_, events) = open();
        let notified: Vec<&str> = events
            .iter()
            .filter_map(|e| match &e.kind {
                ReleaseEventKind::Notified { device } => Some(device.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(notified, devices(), "a registered device was not told");
        assert_eq!(events[0].at, now(), "notification must not lag the request");
    }

    #[test]
    fn any_device_can_cancel() {
        for device in devices() {
            let (mut request, _) = open();
            let event = request.cancel(&device, now() + Duration::hours(1)).unwrap();
            assert_eq!(event.kind, ReleaseEventKind::Cancelled);
            assert!(matches!(request.state, ReleaseState::Cancelled { .. }));
        }
    }

    #[test]
    fn a_cancelled_release_can_never_be_retried() {
        let (mut request, _) = open();
        request.cancel("device:phone", now() + Duration::hours(1)).unwrap();
        // Not at the boundary, not long after, not ever.
        assert_eq!(request.complete(now() + RELEASE_DELAY), Err(ReleaseError::NotPending));
        assert_eq!(
            request.complete(now() + Duration::days(365)),
            Err(ReleaseError::NotPending)
        );
        assert_eq!(
            request.cancel("device:laptop", now() + Duration::hours(2)),
            Err(ReleaseError::NotPending)
        );
    }

    #[test]
    fn a_non_holder_passport_is_refused() {
        assert_eq!(
            ReleaseRequest::open(None, VAULT, OWNER, THIEF, &devices(), now()).unwrap_err(),
            ReleaseError::NotAccountHolder
        );
    }

    #[test]
    fn an_unnotified_device_cannot_cancel() {
        let (mut request, _) = open();
        assert_eq!(
            request.cancel("device:attacker", now()),
            Err(ReleaseError::UnknownDevice)
        );
    }

    #[test]
    fn a_replayed_request_does_not_open_a_second_window() {
        let (request, _) = open();
        // An hour later, the same request arrives again.
        assert_eq!(
            ReleaseRequest::open(
                Some(&request),
                VAULT,
                OWNER,
                OWNER,
                &devices(),
                now() + Duration::hours(1)
            )
            .unwrap_err(),
            ReleaseError::AlreadyPending
        );
    }

    #[test]
    fn cancelling_resets_the_clock_for_the_next_attempt() {
        let (mut first, _) = open();
        first.cancel("device:phone", now() + Duration::hours(1)).unwrap();
        let later = now() + Duration::hours(2);
        let (second, _) = ReleaseRequest::open(Some(&first), VAULT, OWNER, OWNER, &devices(), later).unwrap();
        assert_eq!(second.available_at, later + RELEASE_DELAY);
        assert_ne!(second.id, first.id);
    }

    #[test]
    fn the_whole_sequence_is_reconstructable_from_receipts() {
        let (mut request, mut events) = open();
        events.push(request.complete(now() + RELEASE_DELAY).unwrap());
        assert_eq!(ReleaseRequest::replay(&events).unwrap(), request);

        let (mut cancelled, mut events) = open();
        events.push(cancelled.cancel("device:phone", now() + Duration::hours(3)).unwrap());
        assert_eq!(ReleaseRequest::replay(&events).unwrap(), cancelled);
    }

    #[test]
    fn a_doctored_receipt_stream_does_not_replay() {
        let (mut request, mut events) = open();
        events.push(request.complete(now() + RELEASE_DELAY).unwrap());

        // Drop the request event: the stream no longer explains itself.
        assert!(ReleaseRequest::replay(&events[1..]).is_err());

        // Splice a release from a different request in.
        let (other, _) = ReleaseRequest::open(None, VAULT, OWNER, OWNER, &devices(), now()).unwrap();
        let mut spliced = events.clone();
        spliced[1].request_id = other.id;
        assert!(ReleaseRequest::replay(&spliced).is_err());

        // Try to shorten the wait by back-dating the release event.
        let mut early = events.clone();
        if let Some(last) = early.last_mut() {
            last.at = now() + Duration::hours(1);
        }
        assert!(ReleaseRequest::replay(&early).is_err());
    }

    #[test]
    fn the_delay_is_seventy_two_hours() {
        // R2: decide the number once, defend it forever. Changing it should require
        // changing this test, and thereby reading why.
        assert_eq!(RELEASE_DELAY, Duration::hours(72));
    }
}
