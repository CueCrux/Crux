// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `crux-lens-features` — the Feature Registry lens for the Crux substrate.
//!
//! This crate is the first concrete lens built on the substrate from
//! `corecrux-memory` (entities + edges + kind_registry). It ports PlanCrux's
//! Feature Registry (formerly `plancrux-api/src/routes/capabilities.ts`) onto
//! the substrate, registering two entity kinds (`capability`, `repo`) and
//! providing analytics functions (gaps, promise coverage, coverage report).
//!
//! Consumers: `corecruxd` mounts the lens's `bootstrap_kinds()` at startup
//! and wires the analytics functions into both HTTP routes
//! (`/v1/features/*`) and the MCP `feature_*` tool surface.

pub mod analytics;
pub mod kinds;

pub use analytics::{
    compute_coverage_report, compute_gaps, compute_promise_coverage, CoverageReport, Gap, GapsReport, PromiseCoverage,
    PromiseEntry,
};
pub use kinds::{bootstrap_kinds, CAPABILITY_KIND, REPO_KIND};
