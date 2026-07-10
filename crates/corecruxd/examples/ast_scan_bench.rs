// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

mod fact_helpers {
    pub fn dedup_latest(facts: Vec<corecrux_memory::fact_store::Fact>) -> Vec<corecrux_memory::fact_store::Fact> {
        facts
    }
}

#[path = "../src/workspace_scan.rs"]
mod workspace_scan;
#[path = "../src/workspace_scan_ast.rs"]
mod workspace_scan_ast;

use workspace_scan::WorkspaceScan;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root");
    let iterations = 10usize;

    println!("root: {}", root.display());
    println!("iterations: {iterations}");

    let (regex_cold, regex_scan) = timed_scan(|| workspace_scan::run_scan_regex_at(root).expect("regex scan"));
    let (ast_cold, ast_scan) = timed_scan(|| workspace_scan_ast::run_scan_ast_at(root).expect("ast scan"));

    let mut regex_times = Vec::with_capacity(iterations);
    let mut ast_times = Vec::with_capacity(iterations);
    let mut latest_regex = regex_scan;
    let mut latest_ast = ast_scan;

    for _ in 0..iterations {
        let (dur, scan) = timed_scan(|| workspace_scan::run_scan_regex_at(root).expect("regex scan"));
        regex_times.push(dur);
        latest_regex = scan;

        let (dur, scan) = timed_scan(|| workspace_scan_ast::run_scan_ast_at(root).expect("ast scan"));
        ast_times.push(dur);
        latest_ast = scan;
    }

    println!();
    println!("walltime_ms");
    println!("backend,cold,p50,p95");
    println!(
        "regex,{},{},{}",
        ms(regex_cold),
        ms(percentile(regex_times.clone(), 50)),
        ms(percentile(regex_times, 95))
    );
    println!(
        "ast,{},{},{}",
        ms(ast_cold),
        ms(percentile(ast_times.clone(), 50)),
        ms(percentile(ast_times, 95))
    );

    println!();
    println!("stats_diff");
    println!("field,regex,ast,diff_ast_minus_regex");
    print_stat(
        "crate_count",
        latest_regex.stats.crate_count,
        latest_ast.stats.crate_count,
    );
    print_stat("file_count", latest_regex.stats.file_count, latest_ast.stats.file_count);
    print_stat(
        "route_count",
        latest_regex.stats.route_count,
        latest_ast.stats.route_count,
    );
    print_stat(
        "file_reference_count",
        latest_regex.stats.file_reference_count,
        latest_ast.stats.file_reference_count,
    );
    print_stat(
        "dead_code_count",
        latest_regex.stats.dead_code_count,
        latest_ast.stats.dead_code_count,
    );
    print_stat(
        "symbol_count",
        latest_regex.stats.symbol_count,
        latest_ast.stats.symbol_count,
    );

    let regex_edges = edge_set(&latest_regex);
    let ast_edges = edge_set(&latest_ast);
    let regex_absent_ast = regex_edges.difference(&ast_edges).count();
    let ast_absent_regex = ast_edges.difference(&regex_edges).count();

    println!();
    println!("edge_delta");
    println!("regex_present_ast_absent,{regex_absent_ast}");
    println!("ast_present_regex_absent,{ast_absent_regex}");
}

fn timed_scan<F>(f: F) -> (Duration, WorkspaceScan)
where
    F: FnOnce() -> WorkspaceScan,
{
    let start = Instant::now();
    let scan = f();
    (start.elapsed(), scan)
}

fn percentile(mut values: Vec<Duration>, pct: u32) -> Duration {
    values.sort();
    let len = values.len();
    if len == 0 {
        return Duration::ZERO;
    }
    let rank = ((pct as usize * len).div_ceil(100)).saturating_sub(1);
    values[rank.min(len - 1)]
}

fn ms(duration: Duration) -> u128 {
    duration.as_millis()
}

fn print_stat(name: &str, regex: usize, ast: usize) {
    println!("{name},{regex},{ast},{}", ast as isize - regex as isize);
}

fn edge_set(scan: &WorkspaceScan) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for file in &scan.files {
        for edge in &file.references {
            out.insert(format!(
                "{}>{}>{}>{}",
                file.rel_path,
                edge.to_file,
                edge.to_symbol,
                edge.from_symbol.as_deref().unwrap_or("")
            ));
        }
    }
    out
}
