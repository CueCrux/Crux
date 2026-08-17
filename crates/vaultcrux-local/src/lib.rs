// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Local VaultCrux layer for the Crux daemon.
//!
//! This crate owns daemon-local VaultCrux classification and content loading
//! policy so transport crates do not need to duplicate tier-boundary rules.

pub mod content;
pub mod tool_surface;
