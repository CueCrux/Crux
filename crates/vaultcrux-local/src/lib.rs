// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Local VaultCrux layer for the Crux daemon.
//!
//! This crate owns daemon-local VaultCrux classification and content loading
//! policy so transport crates do not need to duplicate tier-boundary rules.

pub mod content;
pub mod tool_surface;
