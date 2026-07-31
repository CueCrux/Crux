// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Third-party **provider** integrations for the Crux daemon: credential storage,
//! credential verification, and provider→fact sync.
//!
//! Scope boundary — this crate is *not* `crux-integrations` (not linked: it is
//! deliberately not a dependency). The two are easy to confuse by name:
//!
//! - `crux-integrations` owns integration **packs**: manifests, trust tiers, C2PA /
//!   Ed25519 signing, the Studio index.
//! - `corecrux-providers` (this crate) owns **provider accounts**: the GitHub PAT and
//!   OpenAI API key a daemon operator connects, and the GitHub commit / PR / issue sync
//!   that lands those repos in the fact store.
//!
//! Secrets are never written to disk in plaintext. Credentials are held as
//! [`corecrux_secrets::EncryptedEnvelope`] values sealed under a 32-byte key the caller
//! derives from the daemon-root passport; this crate takes that key as a parameter and
//! never sources or persists it itself.

pub mod github;
pub mod github_sync;
pub mod openai;
