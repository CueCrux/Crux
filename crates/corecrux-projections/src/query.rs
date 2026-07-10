// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Query modules for CoreCrux v4.2: graph traversal and temporal range scans.
//!
//! Both modules operate purely on in-memory `ProjectionState` (BTreeMaps).
//! No segment IO, no async, no locks — callers acquire the projection snapshot
//! before invoking these functions.

pub mod graph_expand;
pub mod time_range;
