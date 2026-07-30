// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Metering and billing state for the Crux daemon.
//!
//! Currently the persistent comped-wallet credit ledger
//! ([`credit_meter::CreditMeterStore`]) — an append-only journal of wallet seeds,
//! reservations and spends.
//!
//! Scope boundary — this crate is *not* [`crux_cost`]. `crux-cost` analyses
//! transcripts and produces cost *reports* (what a session appears to have cost);
//! `corecrux-billing` owns the *ledger* (what a tenant has actually been granted
//! and debited).
//!
//! **This crate holds ledger state only — it makes no policy decision about what
//! to do when that state is unavailable.** In particular, the fail-closed
//! response to a poisoned meter mutex lives with the caller that owns the lock
//! (the daemon's `/v1/credits/spend` handler), not here. A store that recovered
//! its own poisoned state would risk an untracked debit; keeping the decision at
//! the lock owner keeps that choice explicit and testable.

pub mod credit_meter;
