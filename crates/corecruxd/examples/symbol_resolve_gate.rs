// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! M1 gate harness — measures the symbol resolver against the *real* collision
//! set in this workspace, not a fixture.
//!
//! ExecPlan `crux-runtime-codemap-and-agent-query-api-2026-07-27`, milestone M1.
//!
//! # What is measured
//!
//! `(file, name)` resolves uniquely for ~98% of symbols; that part is free. The
//! gate targets the residue — the keys where several symbols compete, which for
//! the Crux workspace is 134 clusters covering 358 symbols (2.02%).
//!
//! For every member of every cluster we simulate what `tracing` would report at
//! that symbol's callsite. `#[tracing::instrument]` sits *above* the `fn` it
//! decorates, so `Metadata::line()` is the attribute line, a little before the
//! declaration. We therefore probe at the true line and at several plausible
//! attribute offsets above it, and ask whether the resolver recovers the symbol.
//!
//! # The two outcomes that matter
//!
//! * **`mis_attributed`** — the resolver confidently returned the *wrong*
//!   symbol. This must be **zero**. A wrong join is worse than no join: it
//!   silently attributes runtime behaviour to code that never ran.
//! * **`resolved`** — confidently and correctly resolved. Target ≥90% of probes.
//!
//! `ambiguous` is not a failure. It is the resolver declining to guess, which is
//! the designed behaviour when two candidates are equidistant.
//!
//! Run: `cargo run --release --example symbol_resolve_gate`

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;

// symbol_resolve.rs still lives in corecruxd/src, so it is still inlined here
// (bin crate, no lib target to `use`). The workspace-scan modules it reaches for
// via `crate::workspace_scan` now come from their own crate — a root-level `use`
// is what makes that `crate::` path resolve inside this example binary.
// `repo_scan_policy` moved there too, and this gate runs its scan through it.
// The local no-op `fact_helpers::dedup_latest` stub is gone: it existed only to
// satisfy the inlined workspace_scan, which now calls corecrux-memory directly.
#[path = "../src/symbol_resolve.rs"]
mod symbol_resolve;

use corecrux_workspace_scan::{repo_scan_policy, workspace_scan, workspace_scan_ast};

use symbol_resolve::{Resolution, SymbolResolver};

/// Attribute-line offsets to simulate. 0 = the declaration itself; 1..=3 cover
/// `#[tracing::instrument]`, possibly with doc comments or derives above it.
const OFFSETS: [usize; 4] = [0, 1, 2, 3];

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    println!("root: {}", root.display());

    let policy = repo_scan_policy::RepoScanPolicy::for_exact_root(root).expect("scan policy");
    let scan = policy
        .execute(root, workspace_scan_ast::run_scan_ast_at)
        .expect("ast scan");
    let resolver = SymbolResolver::from_scan(&scan);
    println!("symbols indexed: {}", resolver.len());

    // Rebuild the collision map from the scan so we know ground truth: which
    // (file, name) keys have several symbols, and what line each really sits on.
    let mut by_key: HashMap<(String, String), Vec<&workspace_scan::SymbolInfo>> = HashMap::new();
    for s in &scan.symbols {
        by_key
            .entry((s.file_rel_path.clone(), s.name.clone()))
            .or_default()
            .push(s);
    }
    let clusters: Vec<_> = by_key.iter().filter(|(_, v)| v.len() > 1).collect();
    let colliding_symbols: usize = clusters.iter().map(|(_, v)| v.len()).sum();

    println!(
        "collision clusters: {}  covering {} symbols ({:.2}% of {})",
        clusters.len(),
        colliding_symbols,
        100.0 * colliding_symbols as f64 / scan.symbols.len() as f64,
        scan.symbols.len()
    );

    let mut probes = 0usize;
    let mut resolved = 0usize;
    let mut ambiguous = 0usize;
    let mut mis_attributed: Vec<String> = Vec::new();

    for ((file, name), members) in &clusters {
        for truth in members.iter() {
            for off in OFFSETS {
                // A probe line above the file start is not representable.
                let Some(probe_line) = truth.line.checked_sub(off) else {
                    continue;
                };
                probes += 1;

                match resolver.resolve(file, name, Some(probe_line), None) {
                    None => mis_attributed.push(format!(
                        "{file}:{} {name} -> MISS (probe line {probe_line}, off {off})",
                        truth.line
                    )),
                    Some(Resolution::Ambiguous { .. }) => ambiguous += 1,
                    Some(res) => {
                        let got = res.symbol_id().expect("non-ambiguous carries an id");
                        let got_sym = resolver.get(got).expect("id is indexed");
                        // Ground truth is the line: within a cluster, the member
                        // we probed for is the one whose line matches.
                        if got_sym.line == truth.line
                            && got_sym.name == truth.name
                            && got_sym.file_rel_path == truth.file_rel_path
                        {
                            resolved += 1;
                        } else {
                            mis_attributed.push(format!(
                                "{file}:{} {name} -> WRONG: got line {} (probe {probe_line}, off {off})",
                                truth.line, got_sym.line
                            ));
                        }
                    }
                }
            }
        }
    }

    let pct = |n: usize| 100.0 * n as f64 / probes.max(1) as f64;
    println!();
    println!("probes,{probes}");
    println!("resolved,{resolved},{:.2}%", pct(resolved));
    println!("ambiguous,{ambiguous},{:.2}%", pct(ambiguous));
    println!(
        "mis_attributed,{},{:.2}%",
        mis_attributed.len(),
        pct(mis_attributed.len())
    );

    if !mis_attributed.is_empty() {
        println!("\n-- MIS-ATTRIBUTIONS (gate failure) --");
        for m in mis_attributed.iter().take(25) {
            println!("  {m}");
        }
    }

    // Exact-line probes are the floor: if the resolver cannot recover a symbol
    // when handed its own line, nothing downstream can be trusted.
    let mut exact_probes = 0usize;
    let mut exact_ok = 0usize;
    for ((file, name), members) in &clusters {
        for truth in members.iter() {
            exact_probes += 1;
            if let Some(res) = resolver.resolve(file, name, Some(truth.line), None) {
                if res
                    .symbol_id()
                    .and_then(|id| resolver.get(id))
                    .is_some_and(|s| s.line == truth.line)
                {
                    exact_ok += 1;
                }
            }
        }
    }
    println!(
        "\nexact_line_probes,{exact_probes},correct,{exact_ok},{:.2}%",
        100.0 * exact_ok as f64 / exact_probes.max(1) as f64
    );

    println!();
    let gate_zero_misattrib = mis_attributed.is_empty();
    let gate_90 = pct(resolved) >= 90.0;
    println!(
        "GATE zero_mis_attribution: {}",
        if gate_zero_misattrib { "PASS" } else { "FAIL" }
    );
    println!("GATE resolved_ge_90pct:    {}", if gate_90 { "PASS" } else { "FAIL" });
    if !(gate_zero_misattrib && gate_90) {
        std::process::exit(1);
    }
}
