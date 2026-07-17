// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Cross-module helpers for the everything-as-facts modules (passports,
//! projects, work, session bindings, relations).
//!
//! `dedup_latest` moved to `corecrux_memory::fact_store` so the MCP surface
//! and the engram catalog can share it; re-exported here so existing
//! `crate::fact_helpers::dedup_latest` call sites are unchanged.

pub use corecrux_memory::fact_store::dedup_latest;
