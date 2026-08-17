// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `crux-sync` — Outbox sync client for VaultCrux Crux Daemon.
//!
//! Implements the offline-first sync pattern: contributions are written to a
//! local outbox, then pushed to VaultCrux API on connectivity. The sync client
//! handles authentication, retry with exponential backoff, and cursor tracking.

pub mod auth;
pub mod outbox;
pub mod peer_handshake;
pub mod sync_client;
