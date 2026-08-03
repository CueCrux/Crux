// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `repo_aggregate` — one code graph spanning every repo an account registers.
//!
//! ExecPlan `crux-code-intel-pro-hosted-surface-2026-07-28`, milestone M3 (P1).
//!
//! # What this is for
//!
//! The free tier answers within one repo because that is all a local daemon can
//! see. Pro's first rung is the arithmetic a local daemon *cannot* do: "who calls
//! this symbol" answered across service boundaries, where the caller lives in a
//! repo the callee's checkout has never heard of.
//!
//! # Why paths are qualified
//!
//! `WorkspaceScan` paths are relative to one workspace root, so two repos both
//! containing `src/main.rs` would collide on merge and the answer would name a
//! file without saying whose. Every path is therefore prefixed with its
//! `repo_id`, which keeps attribution in the answer rather than in a lookup the
//! caller has to perform.
//!
//! # The accuracy limit, stated rather than hidden
//!
//! References resolve by **symbol name**. Across repos that is the point — a
//! shared crate's symbol referenced from two services is exactly the edge the
//! free tier cannot see. It also means two unrelated symbols that share a name
//! (`handle`, `new`, `run`) merge into one blast radius. The aggregated answer
//! is therefore a **superset**: sound for "what might break", not precise enough
//! to delete from without reading. Single-repo answers are unaffected — this
//! only applies when aggregation is requested.

use crate::workspace_scan::WorkspaceScan;

/// One repo's contribution to the aggregate.
pub struct RepoScan {
    pub repo_id: String,
    pub scan: WorkspaceScan,
}

/// Prefix a workspace-relative path with the repo that owns it.
///
/// `/` rather than `::` so the result still reads as a path and still matches on
/// the file extension for anything downstream that cares.
fn qualify(repo_id: &str, rel_path: &str) -> String {
    format!("{repo_id}/{rel_path}")
}

/// Merge per-repo scans into one graph with repo-qualified paths.
///
/// Deterministic: inputs are merged in the order given, and callers obtain that
/// order from the registry, which sorts by `repo_id`. Two identical calls must
/// not disagree about what the graph contains.
pub fn aggregate(inputs: Vec<RepoScan>) -> WorkspaceScan {
    let mut out = WorkspaceScan {
        scan_id: format!("aggregate:{}", inputs.len()),
        root_path: String::new(),
        started_at_unix_ms: inputs.iter().map(|i| i.scan.started_at_unix_ms).min().unwrap_or(0),
        finished_at_unix_ms: inputs.iter().map(|i| i.scan.finished_at_unix_ms).max().unwrap_or(0),
        duration_ms: inputs.iter().map(|i| i.scan.duration_ms).sum(),
        crates: Vec::new(),
        files: Vec::new(),
        symbols: Vec::new(),
        deps: Vec::new(),
        stubs: Vec::new(),
        dead_code: Vec::new(),
        ..Default::default()
    };

    for RepoScan { repo_id, scan } in inputs {
        for mut f in scan.files {
            f.rel_path = qualify(&repo_id, &f.rel_path);
            out.files.push(f);
        }
        for mut s in scan.symbols {
            s.file_rel_path = qualify(&repo_id, &s.file_rel_path);
            out.symbols.push(s);
        }
        out.crates.extend(scan.crates);
        out.deps.extend(scan.deps);
        out.stubs.extend(scan.stubs);
        out.dead_code.extend(scan.dead_code);
    }

    // Each repo's `dead_code` was computed against that repo alone, so a symbol
    // defined in repo A and called only from repo B arrives here still flagged.
    // Carrying those verdicts forward verbatim would emit a *wrong* answer under
    // an `aggregate: true` badge, which is worse than the single-repo answer that
    // at least does not claim to have looked across the estate. Someone acting on
    // it deletes live code.
    //
    // Aggregation can only ever add callers, so it can only ever make a symbol
    // less dead — the filter is one-directional by construction and can never
    // introduce a new dead verdict.
    let referenced: std::collections::HashSet<&str> = out
        .files
        .iter()
        .flat_map(|f| f.references.iter())
        .map(|r| r.to_symbol.as_str())
        .collect();
    let live_after_aggregation: Vec<String> = out
        .dead_code
        .iter()
        .filter(|d| referenced.contains(d.name.as_str()))
        .map(|d| d.name.clone())
        .collect();
    out.dead_code.retain(|d| !referenced.contains(d.name.as_str()));
    if !live_after_aggregation.is_empty() {
        tracing::debug!(
            cleared = live_after_aggregation.len(),
            "aggregation cleared dead-code verdicts that a sibling repo references"
        );
    }

    out
}

/// Load and aggregate every **enabled** repo registered to `tenant_id`.
///
/// Disabled repos are excluded for the same reason M1 does not charge for them:
/// they are not being aggregated, so they must not appear in an aggregated
/// answer either. A repo the user has switched off should not resurface as a
/// caller.
///
/// Repos with no stored scan are skipped rather than failing the whole request —
/// a newly registered repo that has not been scanned yet must not break the
/// answer for the ones that have.
pub async fn aggregate_tenant(
    state: &crate::http::AppState,
    scope: &crate::auth::TenantScope,
) -> (WorkspaceScan, Vec<String>) {
    let tenant_id = scope.as_str();
    let store = state.fact_store.read().await;
    let repos = crate::repo_registry::list_repos(&store, tenant_id);
    let mut inputs = Vec::new();
    let mut included = Vec::new();
    for repo in repos.into_iter().filter(|r| r.enabled) {
        if let Some(json) = crate::repo_registry::load_scan_json(&store, scope, &repo.repo_id) {
            if let Ok(scan) = serde_json::from_str::<WorkspaceScan>(&json) {
                included.push(repo.repo_id.clone());
                inputs.push(RepoScan {
                    repo_id: repo.repo_id,
                    scan,
                });
            }
        }
    }
    drop(store);
    (aggregate(inputs), included)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_scan::{FileInfo, FileReference, SymbolInfo};

    fn sym(file: &str, name: &str) -> SymbolInfo {
        SymbolInfo {
            crate_name: "c".into(),
            module_path: "m".into(),
            file_rel_path: file.into(),
            line: 1,
            kind: "fn".into(),
            name: name.into(),
            is_pub: true,
        }
    }

    fn file_with_ref(path: &str, to_symbol: &str, from: &str) -> FileInfo {
        FileInfo {
            rel_path: path.into(),
            crate_name: "c".into(),
            module_path: "m".into(),
            loc: 10,
            symbol_count: 1,
            stub_count: 0,
            doc_summary: None,
            doc_full: None,
            defines: Vec::new(),
            references: vec![FileReference {
                to_file: path.into(),
                to_symbol: to_symbol.into(),
                call_count: 1,
                same_file: false,
                from_symbol: Some(from.into()),
            }],
            referenced_by: Vec::new(),
            is_test_file: false,
        }
    }

    fn scan_with(files: Vec<FileInfo>, symbols: Vec<SymbolInfo>) -> WorkspaceScan {
        WorkspaceScan {
            files,
            symbols,
            ..Default::default()
        }
    }

    #[test]
    fn paths_are_qualified_so_two_repos_cannot_collide() {
        // Both repos have src/main.rs. Without qualification the merged graph
        // would name a file without saying whose.
        let a = scan_with(
            vec![file_with_ref("src/main.rs", "x", "a_caller")],
            vec![sym("src/main.rs", "a_thing")],
        );
        let b = scan_with(
            vec![file_with_ref("src/main.rs", "x", "b_caller")],
            vec![sym("src/main.rs", "b_thing")],
        );
        let agg = aggregate(vec![
            RepoScan {
                repo_id: "repo-a".into(),
                scan: a,
            },
            RepoScan {
                repo_id: "repo-b".into(),
                scan: b,
            },
        ]);

        let paths: Vec<&str> = agg.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(paths, vec!["repo-a/src/main.rs", "repo-b/src/main.rs"]);
        assert_eq!(agg.files.len(), 2, "identical rel_paths must not collapse");

        let sym_paths: Vec<&str> = agg.symbols.iter().map(|s| s.file_rel_path.as_str()).collect();
        assert_eq!(sym_paths, vec!["repo-a/src/main.rs", "repo-b/src/main.rs"]);
    }

    #[test]
    fn blast_radius_crosses_a_repo_boundary_the_single_repo_answer_cannot() {
        // The M3 gate. repo-a defines `shared_fn`; repo-b calls it. A single-repo
        // answer over repo-a alone cannot see repo-b's call — that is the whole
        // capability being sold.
        let a = scan_with(vec![], vec![sym("src/lib.rs", "shared_fn")]);
        let b = scan_with(vec![file_with_ref("src/service.rs", "shared_fn", "b_handler")], vec![]);

        let alone = crate::code_intel::blast_radius(&a, &[], "shared_fn", 4000);
        let agg = aggregate(vec![
            RepoScan {
                repo_id: "repo-a".into(),
                scan: a,
            },
            RepoScan {
                repo_id: "repo-b".into(),
                scan: b,
            },
        ]);
        let crossed = crate::code_intel::blast_radius(&agg, &[], "shared_fn", 4000);

        let alone_json = serde_json::to_string(&alone).unwrap();
        let crossed_json = serde_json::to_string(&crossed).unwrap();
        assert!(
            !alone_json.contains("b_handler"),
            "single-repo answer must not know about repo-b: {alone_json}"
        );
        assert!(
            crossed_json.contains("b_handler"),
            "aggregated answer must name the cross-repo caller: {crossed_json}"
        );
        assert!(
            crossed_json.contains("repo-b/src/service.rs"),
            "and must say which repo it is in: {crossed_json}"
        );
    }

    fn dead(file: &str, name: &str) -> crate::workspace_scan::DeadSymbol {
        crate::workspace_scan::DeadSymbol {
            crate_name: "c".into(),
            module_path: "m".into(),
            file_rel_path: file.into(),
            line: 1,
            kind: "fn".into(),
            name: name.into(),
            confidence: 0.9,
            note: "no internal references".into(),
        }
    }

    /// The highest-stakes aggregate on this surface, and the one #564 got wrong.
    ///
    /// repo-a defines `shared_fn` and, seeing no caller of its own, its scanner
    /// flags it dead. repo-b calls it. `aggregate` used to `extend` the dead lists
    /// verbatim, so the verdict survived aggregation and the API returned "dead"
    /// under an `aggregate: true` badge — a wrong answer that reads as more
    /// authoritative than the single-repo one. Someone acting on it deletes live
    /// code.
    #[test]
    fn aggregation_clears_a_dead_verdict_a_sibling_repo_disproves() {
        let a = scan_with(vec![], vec![sym("src/lib.rs", "shared_fn")]);
        let mut a = a;
        a.dead_code = vec![dead("src/lib.rs", "shared_fn")];
        let b = scan_with(vec![file_with_ref("src/service.rs", "shared_fn", "b_handler")], vec![]);

        // Single-repo: the verdict stands, because repo-a genuinely has no caller.
        assert_eq!(a.dead_code.len(), 1, "precondition: repo-a flags it dead alone");

        let agg = aggregate(vec![
            RepoScan {
                repo_id: "repo-a".into(),
                scan: a,
            },
            RepoScan {
                repo_id: "repo-b".into(),
                scan: b,
            },
        ]);
        assert!(
            agg.dead_code.iter().all(|d| d.name != "shared_fn"),
            "aggregation must clear a dead verdict that a sibling repo disproves, got {:?}",
            agg.dead_code.iter().map(|d| &d.name).collect::<Vec<_>>()
        );
    }

    /// The filter is one-directional: a symbol nothing references stays dead.
    /// Without this, the test above would pass against an `aggregate` that simply
    /// dropped every dead verdict.
    #[test]
    fn aggregation_keeps_a_dead_verdict_no_repo_disproves() {
        let mut a = scan_with(vec![], vec![sym("src/lib.rs", "truly_dead")]);
        a.dead_code = vec![dead("src/lib.rs", "truly_dead")];
        let b = scan_with(
            vec![file_with_ref("src/service.rs", "something_else", "b_handler")],
            vec![],
        );

        let agg = aggregate(vec![
            RepoScan {
                repo_id: "repo-a".into(),
                scan: a,
            },
            RepoScan {
                repo_id: "repo-b".into(),
                scan: b,
            },
        ]);
        assert!(
            agg.dead_code.iter().any(|d| d.name == "truly_dead"),
            "aggregation must not launder a genuine dead verdict into life"
        );
    }

    #[test]
    fn an_empty_aggregate_is_valid_not_an_error() {
        // An account with no scanned repos yet asks a legitimate question and
        // gets an empty answer, not a failure.
        let agg = aggregate(Vec::new());
        assert!(agg.files.is_empty());
        assert!(agg.symbols.is_empty());
    }

    #[test]
    fn aggregation_is_deterministic_for_the_same_input_order() {
        let mk = || {
            vec![
                RepoScan {
                    repo_id: "repo-a".into(),
                    scan: scan_with(vec![file_with_ref("f.rs", "x", "ca")], vec![sym("f.rs", "sa")]),
                },
                RepoScan {
                    repo_id: "repo-b".into(),
                    scan: scan_with(vec![file_with_ref("f.rs", "x", "cb")], vec![sym("f.rs", "sb")]),
                },
            ]
        };
        let one = serde_json::to_string(&aggregate(mk())).unwrap();
        let two = serde_json::to_string(&aggregate(mk())).unwrap();
        assert_eq!(one, two, "two identical calls must not disagree about the graph");
    }
}
