// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `symbol_resolve` — stable symbol identity and the runtime→static join.
//!
//! This is the bridge M2's span layer needs: given what `tracing::Metadata`
//! reports at a callsite (`file()`, `line()`, and the span name, which for
//! `#[tracing::instrument]` is the function name), return the [`SymbolInfo`]
//! it refers to, with an honest confidence.
//!
//! # Why the key is `(file, name)` and not the line
//!
//! Measured over the Crux workspace at 93b41a7 (17,725 symbols — see
//! `PlanCrux/artifacts/codemap-baseline-2026-07-27.md`):
//!
//! * `line == 0` never occurs (0.00%), so scanner line numbers *are* reliable;
//! * but `(file, name)` alone leaves **2.02%** of symbols ambiguous — 134 keys
//!   collide, e.g. `decode_bin` appears 11× in one `events.rs`;
//! * adding `kind` to the key improves this by exactly nothing, because the
//!   collisions are same-kind trait impls.
//!
//! And the line cannot be the *primary* key either: `#[tracing::instrument]`
//! reports the line of the attribute, which sits above the `fn` it decorates.
//!
//! So: `(file, name)` selects a candidate set, and `line` disambiguates within
//! it by proximity. A collision that cannot be separated returns
//! [`Confidence::Ambiguous`] — never a confident wrong answer. Mis-attributing
//! a trace to the wrong symbol is silently corrupting, so this module treats
//! "I don't know" as the correct output rather than a failure.

use std::collections::HashMap;

use serde::Serialize;

use crate::workspace_scan::{SymbolInfo, WorkspaceScan};

/// How the resolver arrived at a match.
///
/// Mirrors `context_graph::Confidence` in spirit, but carries the concrete
/// signal a caller needs to decide whether to trust the join.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "confidence", rename_all = "snake_case")]
pub enum Resolution {
    /// Exactly one symbol named `name` in `file`. No ambiguity to resolve.
    Extracted { symbol_id: String },
    /// Several candidates; a line was supplied and one was nearest. `distance`
    /// is the line delta, `runner_up_distance` the next-nearest — a caller can
    /// treat a narrow gap as weak evidence.
    Inferred {
        symbol_id: String,
        score: f32,
        distance: usize,
        runner_up_distance: usize,
    },
    /// Several candidates and no way to choose: either no line was supplied, or
    /// two candidates are equidistant. Carries every candidate so the caller can
    /// decide, but commits to none.
    Ambiguous { candidates: Vec<String> },
}

impl Resolution {
    /// The chosen symbol, or `None` when ambiguous. Deliberately returns `None`
    /// rather than a best guess — see the module docs.
    pub fn symbol_id(&self) -> Option<&str> {
        match self {
            Self::Extracted { symbol_id } | Self::Inferred { symbol_id, .. } => Some(symbol_id),
            Self::Ambiguous { .. } => None,
        }
    }
}

/// Build a stable, content-addressed id for a symbol.
///
/// Stability requirements, in order of importance:
/// 1. **Unchanged across rescans of an unchanged tree** — so traces recorded
///    yesterday still resolve today.
/// 2. **Unaffected by edits elsewhere in the file** — so adding a function at
///    the top of a file does not renumber every symbol below it.
///
/// (2) is why the line number is *not* part of the id. Duplicate `(file, name,
/// kind)` triples are separated by `ordinal`: their index in line order among
/// their own collision cluster. That is stable unless the duplicates themselves
/// are reordered, which is the best available without true `syn` spans.
pub fn symbol_id(sym: &SymbolInfo, ordinal: usize) -> String {
    let digest = blake3::hash(
        format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            sym.crate_name, sym.file_rel_path, sym.kind, sym.name, ordinal
        )
        .as_bytes(),
    );
    format!("sym_{}", &digest.to_hex()[..16])
}

/// An index over a [`WorkspaceScan`] supporting `(file, name) [+ line]` lookup.
pub struct SymbolResolver {
    /// `(file_rel_path, name)` → candidates, held in ascending line order.
    by_file_name: HashMap<(String, String), Vec<Candidate>>,
    /// `symbol_id` → the symbol it names, for reverse lookup.
    by_id: HashMap<String, SymbolInfo>,
}

/// One symbol competing for a `(file, name)` key.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub symbol_id: String,
    pub line: usize,
    pub kind: String,
}

impl SymbolResolver {
    /// Index a scan. Cost is one pass plus a sort per collision cluster.
    pub fn from_scan(scan: &WorkspaceScan) -> Self {
        // Group first so `ordinal` can be assigned in line order, making ids
        // independent of the scanner's emission order.
        let mut grouped: HashMap<(String, String, String), Vec<&SymbolInfo>> = HashMap::new();
        for sym in &scan.symbols {
            grouped
                .entry((sym.file_rel_path.clone(), sym.name.clone(), sym.kind.clone()))
                .or_default()
                .push(sym);
        }

        let mut by_file_name: HashMap<(String, String), Vec<Candidate>> = HashMap::new();
        let mut by_id: HashMap<String, SymbolInfo> = HashMap::new();

        for (_, mut syms) in grouped {
            syms.sort_by_key(|s| s.line);
            for (ordinal, sym) in syms.iter().enumerate() {
                let id = symbol_id(sym, ordinal);
                by_file_name
                    .entry((sym.file_rel_path.clone(), sym.name.clone()))
                    .or_default()
                    .push(Candidate {
                        symbol_id: id.clone(),
                        line: sym.line,
                        kind: sym.kind.clone(),
                    });
                by_id.insert(id, (*sym).clone());
            }
        }

        for candidates in by_file_name.values_mut() {
            candidates.sort_by_key(|c| c.line);
        }

        Self { by_file_name, by_id }
    }

    /// Number of indexed symbols.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Look a symbol up by id.
    pub fn get(&self, symbol_id: &str) -> Option<&SymbolInfo> {
        self.by_id.get(symbol_id)
    }

    /// Resolve `(file, name)`, optionally narrowed by `line` and `kind`.
    ///
    /// Returns `None` only when nothing in `file` is called `name` — a genuine
    /// miss, distinct from [`Resolution::Ambiguous`], which means "found several
    /// and will not guess".
    pub fn resolve(&self, file: &str, name: &str, line: Option<usize>, kind: Option<&str>) -> Option<Resolution> {
        let candidates = self.by_file_name.get(&(file.to_string(), name.to_string()))?;

        // `kind` is a cheap pre-filter. It rarely helps (collisions are
        // same-kind in practice) but costs nothing and is correct when a caller
        // does know the kind.
        let filtered: Vec<&Candidate> = match kind {
            Some(k) => candidates.iter().filter(|c| c.kind == k).collect(),
            None => candidates.iter().collect(),
        };

        match filtered.len() {
            0 => None,
            1 => Some(Resolution::Extracted {
                symbol_id: filtered[0].symbol_id.clone(),
            }),
            _ => Some(Self::disambiguate(&filtered, line)),
        }
    }

    /// Choose among several candidates using line proximity.
    ///
    /// `tracing` reports the `#[instrument]` attribute line, which precedes the
    /// declaration, so the reported line is typically *just above* the true
    /// symbol. Absolute distance handles that without assuming a fixed offset,
    /// and an exact tie is reported as ambiguous rather than broken by
    /// arbitrary ordering.
    fn disambiguate(candidates: &[&Candidate], line: Option<usize>) -> Resolution {
        let Some(line) = line else {
            return Resolution::Ambiguous {
                candidates: candidates.iter().map(|c| c.symbol_id.clone()).collect(),
            };
        };

        let mut scored: Vec<(usize, &Candidate)> = candidates.iter().map(|c| (c.line.abs_diff(line), *c)).collect();
        scored.sort_by_key(|(d, _)| *d);

        let (best_distance, best) = scored[0];
        let runner_up_distance = scored[1].0;

        // A near-tie is unresolvable, not merely close.
        //
        // `tracing` reports the `#[instrument]` attribute line, which floats a
        // few lines from the declaration depending on doc comments, derives and
        // other attributes. So when two candidates sit within a few lines of
        // each other, whichever happens to be nearer the probe is *noise*, not
        // evidence — the offset alone can flip the winner.
        //
        // Measured on this workspace (M1 gate, `examples/symbol_resolve_gate.rs`):
        // both mis-attributions were separation-1 pairs about 5 lines apart
        // (`replace_profile_file` 334/339, `rerank_endpoint_configured` 426/431).
        // Requiring a margin wider than a plausible attribute block converts
        // those from confident-and-wrong into honestly ambiguous.
        //
        // A wrong join silently attributes runtime behaviour to code that never
        // ran; declining to answer is strictly better.
        const MIN_SEPARATION: usize = 4;
        if runner_up_distance.saturating_sub(best_distance) < MIN_SEPARATION {
            return Resolution::Ambiguous {
                candidates: candidates.iter().map(|c| c.symbol_id.clone()).collect(),
            };
        }

        // Score decays with distance and rises with the margin over the runner
        // up. Bounded to (0, 1]; an exact line hit with a distant runner-up
        // approaches 1.
        let separation = (runner_up_distance - best_distance) as f32;
        let score = (separation / (separation + best_distance as f32 + 1.0)).clamp(0.01, 1.0);

        Resolution::Inferred {
            symbol_id: best.symbol_id.clone(),
            score,
            distance: best_distance,
            runner_up_distance,
        }
    }

    /// Every `(file, name)` key with more than one symbol behind it. This is the
    /// 2.02% the M1 gate is measured against.
    pub fn collision_clusters(&self) -> Vec<(&(String, String), &Vec<Candidate>)> {
        self.by_file_name.iter().filter(|(_, v)| v.len() > 1).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(file: &str, name: &str, kind: &str, line: usize) -> SymbolInfo {
        SymbolInfo {
            crate_name: "testcrate".into(),
            module_path: "testcrate::m".into(),
            file_rel_path: file.into(),
            line,
            kind: kind.into(),
            name: name.into(),
            is_pub: true,
        }
    }

    fn scan_of(symbols: Vec<SymbolInfo>) -> WorkspaceScan {
        WorkspaceScan {
            symbols,
            ..Default::default()
        }
    }

    #[test]
    fn unique_name_resolves_extracted() {
        let r = SymbolResolver::from_scan(&scan_of(vec![
            sym("a.rs", "alpha", "fn", 10),
            sym("a.rs", "beta", "fn", 20),
        ]));
        let res = r.resolve("a.rs", "alpha", None, None).expect("found");
        assert!(matches!(res, Resolution::Extracted { .. }), "got {res:?}");
        // A unique name needs no line, which is what makes the common case cheap.
        assert!(r.get(res.symbol_id().unwrap()).is_some());
    }

    #[test]
    fn miss_returns_none_not_ambiguous() {
        let r = SymbolResolver::from_scan(&scan_of(vec![sym("a.rs", "alpha", "fn", 10)]));
        assert!(r.resolve("a.rs", "nope", None, None).is_none());
        assert!(r.resolve("other.rs", "alpha", None, None).is_none());
    }

    #[test]
    fn same_kind_collision_without_line_is_ambiguous_never_guessed() {
        // The real shape: `decode_bin` x11 in one events.rs, all `fn`.
        let r = SymbolResolver::from_scan(&scan_of(vec![
            sym("events.rs", "decode_bin", "fn", 10),
            sym("events.rs", "decode_bin", "fn", 50),
            sym("events.rs", "decode_bin", "fn", 90),
        ]));
        let res = r.resolve("events.rs", "decode_bin", None, None).expect("found");
        match res {
            Resolution::Ambiguous { ref candidates } => assert_eq!(candidates.len(), 3),
            other => panic!("must not guess without a line, got {other:?}"),
        }
        assert_eq!(res.symbol_id(), None, "ambiguous must not yield a symbol_id");
    }

    #[test]
    fn line_disambiguates_collision() {
        let r = SymbolResolver::from_scan(&scan_of(vec![
            sym("events.rs", "decode_bin", "fn", 10),
            sym("events.rs", "decode_bin", "fn", 50),
            sym("events.rs", "decode_bin", "fn", 90),
        ]));
        // tracing reports the #[instrument] line, just above the fn.
        let res = r.resolve("events.rs", "decode_bin", Some(48), None).expect("found");
        let Resolution::Inferred {
            symbol_id,
            distance,
            runner_up_distance,
            ..
        } = res
        else {
            panic!("expected Inferred, got {res:?}")
        };
        assert_eq!(distance, 2);
        assert_eq!(runner_up_distance, 38);
        assert_eq!(r.get(&symbol_id).unwrap().line, 50);
    }

    #[test]
    fn equidistant_candidates_are_ambiguous_not_arbitrary() {
        let r = SymbolResolver::from_scan(&scan_of(vec![
            sym("a.rs", "dup", "fn", 10),
            sym("a.rs", "dup", "fn", 20),
        ]));
        // Exactly between the two: nothing justifies a choice.
        let res = r.resolve("a.rs", "dup", Some(15), None).expect("found");
        assert!(matches!(res, Resolution::Ambiguous { .. }), "got {res:?}");
    }

    #[test]
    fn near_tie_is_ambiguous_rather_than_confidently_wrong() {
        // The exact shape that failed the first M1 gate run: two same-named
        // symbols ~5 lines apart. `rerank_endpoint_configured` at 426 and 431 in
        // http/health.rs. Probing at 428 (an attribute 3 lines above the 431
        // declaration) is nearer to 426 — so nearest-line alone would confidently
        // return the wrong symbol.
        let r = SymbolResolver::from_scan(&scan_of(vec![
            sym("health.rs", "rerank_endpoint_configured", "fn", 426),
            sym("health.rs", "rerank_endpoint_configured", "fn", 431),
        ]));
        let res = r
            .resolve("health.rs", "rerank_endpoint_configured", Some(428), None)
            .expect("found");
        assert!(
            matches!(res, Resolution::Ambiguous { .. }),
            "a 1-line margin is noise, not evidence; got {res:?}"
        );
        assert_eq!(res.symbol_id(), None);
    }

    #[test]
    fn wide_separation_still_resolves_confidently() {
        // The guard must not swallow genuine matches: a clear winner survives.
        let r = SymbolResolver::from_scan(&scan_of(vec![
            sym("a.rs", "dup", "fn", 10),
            sym("a.rs", "dup", "fn", 200),
        ]));
        let res = r.resolve("a.rs", "dup", Some(198), None).expect("found");
        let Resolution::Inferred { symbol_id, .. } = res else {
            panic!("expected Inferred, got {res:?}")
        };
        assert_eq!(r.get(&symbol_id).unwrap().line, 200);
    }

    #[test]
    fn kind_filter_narrows_to_a_unique_match() {
        let r = SymbolResolver::from_scan(&scan_of(vec![
            sym("a.rs", "Thing", "struct", 10),
            sym("a.rs", "Thing", "fn", 40),
        ]));
        let res = r.resolve("a.rs", "Thing", None, Some("struct")).expect("found");
        assert!(matches!(res, Resolution::Extracted { .. }), "got {res:?}");
        assert_eq!(r.get(res.symbol_id().unwrap()).unwrap().line, 10);
    }

    #[test]
    fn ids_are_stable_across_rescans() {
        let a = SymbolResolver::from_scan(&scan_of(vec![
            sym("a.rs", "alpha", "fn", 10),
            sym("a.rs", "dup", "fn", 20),
            sym("a.rs", "dup", "fn", 60),
        ]));
        // Same tree, different emission order — ids must not move.
        let b = SymbolResolver::from_scan(&scan_of(vec![
            sym("a.rs", "dup", "fn", 60),
            sym("a.rs", "alpha", "fn", 10),
            sym("a.rs", "dup", "fn", 20),
        ]));
        let ida = a
            .resolve("a.rs", "alpha", None, None)
            .unwrap()
            .symbol_id()
            .unwrap()
            .to_string();
        let idb = b
            .resolve("a.rs", "alpha", None, None)
            .unwrap()
            .symbol_id()
            .unwrap()
            .to_string();
        assert_eq!(ida, idb);

        let da = a
            .resolve("a.rs", "dup", Some(20), None)
            .unwrap()
            .symbol_id()
            .unwrap()
            .to_string();
        let db = b
            .resolve("a.rs", "dup", Some(20), None)
            .unwrap()
            .symbol_id()
            .unwrap()
            .to_string();
        assert_eq!(da, db, "ordinal must follow line order, not emission order");
    }

    #[test]
    fn unrelated_edits_do_not_renumber_ids() {
        let before = SymbolResolver::from_scan(&scan_of(vec![
            sym("a.rs", "alpha", "fn", 10),
            sym("a.rs", "beta", "fn", 20),
        ]));
        // A function was inserted above, shifting `beta` down 30 lines.
        let after = SymbolResolver::from_scan(&scan_of(vec![
            sym("a.rs", "inserted", "fn", 5),
            sym("a.rs", "alpha", "fn", 40),
            sym("a.rs", "beta", "fn", 50),
        ]));
        let b1 = before
            .resolve("a.rs", "beta", None, None)
            .unwrap()
            .symbol_id()
            .unwrap()
            .to_string();
        let b2 = after
            .resolve("a.rs", "beta", None, None)
            .unwrap()
            .symbol_id()
            .unwrap()
            .to_string();
        assert_eq!(b1, b2, "line must not be part of the id");
    }

    #[test]
    fn zero_line_symbols_still_resolve() {
        // Belt and braces: the scanner emits 0 lines nowhere in Crux today, but
        // `LineLookup::take` can still return 0 via its `unwrap_or(0)` fallback.
        let r = SymbolResolver::from_scan(&scan_of(vec![
            sym("a.rs", "dup", "fn", 0),
            sym("a.rs", "dup", "fn", 80),
        ]));
        let res = r.resolve("a.rs", "dup", Some(78), None).expect("found");
        let Resolution::Inferred { symbol_id, .. } = res else {
            panic!("expected Inferred, got {res:?}")
        };
        assert_eq!(r.get(&symbol_id).unwrap().line, 80);
    }

    #[test]
    fn collision_clusters_reports_only_multis() {
        let r = SymbolResolver::from_scan(&scan_of(vec![
            sym("a.rs", "alpha", "fn", 10),
            sym("a.rs", "dup", "fn", 20),
            sym("a.rs", "dup", "fn", 60),
        ]));
        let clusters = r.collision_clusters();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].1.len(), 2);
    }
}
