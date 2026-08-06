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
//! And, underneath all four:
//!
//! - [`repo_scan_policy`] — the containment envelope every scan runs inside:
//!   deadlines, depth and byte budgets, work charging, and authorised
//!   file/directory opens. Scanning walks untrusted checkouts, so this is a
//!   security boundary, not a tuning knob.
//!
//! Pure analysis: this crate reads a checkout and returns data. It holds no
//! daemon state, opens no sockets, and writes nothing back — persistence and
//! HTTP are the caller's concern. That is what lets it build standalone.
//!
//! `repo_scan_policy` lives here rather than in `corecruxd` because it and
//! `workspace_scan` are **mutually recursive** — the scanners call
//! `check_deadline` / `charge_*` on essentially every loop iteration, and the
//! policy calls back into `walk_dir`, `read_scan_bytes` and
//! `run_repo_scan_at_with_policy`. Splitting them across a crate boundary is not
//! expressible; keeping the policy in `corecruxd` would have meant either a
//! dependency cycle or unpicking the containment from the code it contains.
//! `corecruxd` re-exports it, so its own call sites are unchanged.
//!
//! Module names keep their `workspace_scan_*` prefix rather than being shortened
//! to `ast` / `manifests` / `polyglot`. The four files carry a large number of
//! intra-group `crate::workspace_scan_*` paths, and preserving the names kept
//! this extraction a pure file move with no path churn across ~15k lines.

pub mod repo_scan_policy;
pub mod workspace_scan;
pub mod workspace_scan_ast;
pub mod workspace_scan_manifests;
pub mod workspace_scan_polyglot;

#[cfg(test)]
mod test_support;
