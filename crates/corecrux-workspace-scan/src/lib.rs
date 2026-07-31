// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Repository **workspace scanning**: walk a checkout, parse its sources and
//! manifests, and emit the structural facts the daemon builds its code lenses on.
//!
//! Four layers, in dependency order:
//!
//! - [`workspace_scan`] — the walk itself, plus the Rust-side `syn` analysis and
//!   the scan-result types the rest of the daemon consumes.
//! - [`workspace_scan_ast`] — Rust AST extraction (`syn`): items, signatures,
//!   call edges.
//! - [`workspace_scan_manifests`] — dependency manifests across ecosystems
//!   (`Cargo.toml`, `package.json`, `pyproject.toml`, `pom.xml`, …) into a
//!   common [`workspace_scan_manifests::ExternalDep`] shape.
//! - [`workspace_scan_polyglot`] — tree-sitter extraction for the ten
//!   non-Rust languages, behind one grammar-dispatch surface.
//!
//! Pure analysis: this crate reads a checkout and returns data. It holds no
//! daemon state, opens no sockets, and writes nothing back — persistence and
//! HTTP are the caller's concern. That is what lets it build standalone.
//!
//! Module names keep their `workspace_scan_*` prefix rather than being shortened
//! to `ast` / `manifests` / `polyglot`. The four files carry a large number of
//! intra-group `crate::workspace_scan_*` paths, and preserving the names kept
//! this extraction a pure file move with no path churn across ~15k lines.

pub mod workspace_scan;
pub mod workspace_scan_ast;
pub mod workspace_scan_manifests;
pub mod workspace_scan_polyglot;

#[cfg(test)]
mod test_support;
