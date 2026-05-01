// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `crux-sync` — Outbox sync client for VaultCrux Crux Daemon.
//!
//! Implements the offline-first sync pattern: contributions are written to a
//! local outbox, then pushed to VaultCrux API on connectivity. The sync client
//! handles authentication, retry with exponential backoff, and cursor tracking.

pub mod auth;
pub mod outbox;
pub mod sync_client;
