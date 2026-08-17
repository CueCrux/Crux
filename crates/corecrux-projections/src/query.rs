// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Query modules for CoreCrux v4.2: graph traversal and temporal range scans.
//!
//! Both modules operate purely on in-memory `ProjectionState` (BTreeMaps).
//! No segment IO, no async, no locks — callers acquire the projection snapshot
//! before invoking these functions.

pub mod graph_expand;
pub mod time_range;
