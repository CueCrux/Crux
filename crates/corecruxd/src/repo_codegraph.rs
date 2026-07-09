// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Emit repository workspace scans into the tenant-scoped relation graph.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use corecrux_projections::{ProjectionState, RelationTypeV1};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::workspace_scan::{DepEdge, FileInfo, WorkspaceScan};

pub const CODEGRAPH_IDS_PREFIX: &str = "__repo_codegraph_ids__";
const CODEGRAPH_IDS_KEY: &str = "content";
const CODEGRAPH_ENV: &str = "CORECRUXD_CODEGRAPH_EDGES";

#[derive(Debug, thiserror::Error)]
pub(crate) enum CodeGraphError {
    #[error(transparent)]
    Relations(#[from] crate::relations::RelationsError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct CodeGraphIdStore {
    pub next_id: u32,
    pub map: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CodeGraphEmitReport {
    pub defines: usize,
    pub calls: usize,
    pub imports: usize,
    pub depends_on: usize,
    pub ids_by_key: BTreeMap<String, u32>,
}

pub(crate) fn ids_entity(tenant_id: &str, repo_id: &str) -> String {
    format!("{CODEGRAPH_IDS_PREFIX}::{tenant_id}::{repo_id}")
}

pub(crate) fn enabled_from_env() -> bool {
    std::env::var(CODEGRAPH_ENV).ok().is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        !(v.is_empty() || v == "0" || v == "false" || v == "off" || v == "no")
    })
}

pub(crate) async fn maybe_emit_codegraph_edges(
    fact_store: &Arc<RwLock<FactStore>>,
    projection_state: &Arc<RwLock<ProjectionState>>,
    data_dir: &Path,
    tenant_id: &str,
    repo_id: &str,
    scan: &WorkspaceScan,
) -> Result<Option<CodeGraphEmitReport>, CodeGraphError> {
    if !enabled_from_env() {
        return Ok(None);
    }
    let mut store = fact_store.write().await;
    let mut projection = projection_state.write().await;
    emit_codegraph_edges(&mut store, &mut projection, data_dir, tenant_id, repo_id, scan).map(Some)
}

pub(crate) fn emit_codegraph_edges(
    store: &mut FactStore,
    projection: &mut ProjectionState,
    data_dir: &Path,
    tenant_id: &str,
    repo_id: &str,
    scan: &WorkspaceScan,
) -> Result<CodeGraphEmitReport, CodeGraphError> {
    let mut id_store = load_id_store(store, tenant_id, repo_id)?;
    if id_store.next_id == 0 {
        id_store.next_id = seeded_next_id(tenant_id, repo_id);
    }
    let mut used_ids = tenant_used_ids(store, tenant_id);
    let mut file_ids = BTreeMap::new();
    let mut symbol_ids = BTreeMap::new();

    for file in &scan.files {
        let key = file_key(&file.rel_path);
        let id = allocate_id(&mut id_store, &mut used_ids, key.clone());
        file_ids.insert(file.rel_path.clone(), id);
    }
    for symbol in &scan.symbols {
        let key = symbol_key(&symbol.file_rel_path, &symbol.name);
        let id = allocate_id(&mut id_store, &mut used_ids, key.clone());
        symbol_ids.insert((symbol.file_rel_path.clone(), symbol.name.clone()), id);
    }
    store_id_store(store, tenant_id, repo_id, &id_store)?;

    let now = current_micros();
    let mut report = CodeGraphEmitReport {
        ids_by_key: id_store.map.clone(),
        ..CodeGraphEmitReport::default()
    };
    let file_by_rel: BTreeMap<&str, &FileInfo> = scan.files.iter().map(|file| (file.rel_path.as_str(), file)).collect();

    for symbol in &scan.symbols {
        let Some(from_id) = file_ids.get(&symbol.file_rel_path).copied() else {
            continue;
        };
        let Some(to_id) = symbol_ids
            .get(&(symbol.file_rel_path.clone(), symbol.name.clone()))
            .copied()
        else {
            continue;
        };
        apply_and_append(
            projection,
            data_dir,
            relation_record(tenant_id, from_id, to_id, RelationTypeV1::Defines, 10_000, now),
        )?;
        report.defines += 1;
    }

    for file in &scan.files {
        let Some(from_file_id) = file_ids.get(&file.rel_path).copied() else {
            continue;
        };
        for reference in &file.references {
            let Some(to_id) = symbol_ids
                .get(&(reference.to_file.clone(), reference.to_symbol.clone()))
                .copied()
            else {
                continue;
            };
            let from_id = reference
                .from_symbol
                .as_ref()
                .and_then(|name| symbol_ids.get(&(file.rel_path.clone(), name.clone())).copied())
                .unwrap_or(from_file_id);
            apply_and_append(
                projection,
                data_dir,
                relation_record(
                    tenant_id,
                    from_id,
                    to_id,
                    RelationTypeV1::Calls,
                    call_confidence_bp(reference.call_count),
                    now,
                ),
            )?;
            report.calls += 1;
        }
    }

    for dep in &scan.deps {
        let Some(from_id) = file_ids.get(&dep.from_file).copied() else {
            continue;
        };
        let Some(to_id) = resolve_dep_target_file(dep, &file_ids, &file_by_rel) else {
            continue;
        };
        apply_and_append(
            projection,
            data_dir,
            relation_record(tenant_id, from_id, to_id, RelationTypeV1::Imports, 8_000, now),
        )?;
        report.imports += 1;
    }

    let crate_roots = crate_root_files(scan, &file_ids);
    for krate in &scan.crates {
        let Some(from_id) = crate_roots.get(&krate.name).copied() else {
            continue;
        };
        for dep_name in &krate.internal_deps {
            let Some(to_id) = crate_roots.get(dep_name).copied() else {
                continue;
            };
            apply_and_append(
                projection,
                data_dir,
                relation_record(tenant_id, from_id, to_id, RelationTypeV1::DependsOn, 7_000, now),
            )?;
            report.depends_on += 1;
        }
    }

    Ok(report)
}

fn load_id_store(store: &FactStore, tenant_id: &str, repo_id: &str) -> Result<CodeGraphIdStore, CodeGraphError> {
    let result = store.query(&FactQuery {
        query: None,
        entity: Some(ids_entity(tenant_id, repo_id)),
        entity_prefix: None,
        top_k: 10,
        token_budget: None,
    });
    let Some(fact) = crate::fact_helpers::dedup_latest(result.facts)
        .into_iter()
        .find(|fact| fact.key == CODEGRAPH_IDS_KEY)
    else {
        return Ok(CodeGraphIdStore::default());
    };
    Ok(serde_json::from_str::<CodeGraphIdStore>(&fact.value)?)
}

fn store_id_store(
    store: &mut FactStore,
    tenant_id: &str,
    repo_id: &str,
    id_store: &CodeGraphIdStore,
) -> Result<(), CodeGraphError> {
    store.store(StoreFact {
        entity: ids_entity(tenant_id, repo_id),
        key: CODEGRAPH_IDS_KEY.to_string(),
        value: serde_json::to_string(id_store)?,
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    });
    Ok(())
}

fn tenant_used_ids(store: &FactStore, tenant_id: &str) -> BTreeSet<u32> {
    let result = store.query(&FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some(format!("{CODEGRAPH_IDS_PREFIX}::{tenant_id}::")),
        top_k: 10_000,
        token_budget: None,
    });
    let mut used = BTreeSet::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != CODEGRAPH_IDS_KEY {
            continue;
        }
        if let Ok(store) = serde_json::from_str::<CodeGraphIdStore>(&fact.value) {
            used.extend(store.map.values().copied().filter(|id| *id != 0));
        }
    }
    used
}

fn allocate_id(id_store: &mut CodeGraphIdStore, used_ids: &mut BTreeSet<u32>, key: String) -> u32 {
    if let Some(id) = id_store.map.get(&key).copied() {
        used_ids.insert(id);
        return id;
    }
    loop {
        let candidate = id_store.next_id.max(1);
        id_store.next_id = id_store.next_id.wrapping_add(1).max(1);
        if used_ids.insert(candidate) {
            id_store.map.insert(key, candidate);
            return candidate;
        }
    }
}

fn seeded_next_id(tenant_id: &str, repo_id: &str) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tenant_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(repo_id.as_bytes());
    let bytes = hasher.finalize();
    let mut seed = u32::from_le_bytes(bytes.as_bytes()[0..4].try_into().unwrap_or([0; 4]));
    if seed == 0 {
        seed = 1;
    }
    seed
}

fn file_key(rel_path: &str) -> String {
    format!("file:{}", normalize_rel(rel_path))
}

fn symbol_key(rel_path: &str, name: &str) -> String {
    format!("sym:{}#{name}", normalize_rel(rel_path))
}

fn normalize_rel(path: &str) -> String {
    path.replace('\\', "/")
}

fn apply_and_append(
    projection: &mut ProjectionState,
    data_dir: &Path,
    record: crate::relations::RelationRecord,
) -> Result<(), CodeGraphError> {
    crate::relations::apply_record(projection, &record)?;
    crate::relations::append_record(data_dir, &record)?;
    Ok(())
}

fn relation_record(
    tenant_id: &str,
    from_id: u32,
    to_id: u32,
    edge_type: RelationTypeV1,
    confidence_bp: u16,
    now: i64,
) -> crate::relations::RelationRecord {
    crate::relations::RelationRecord {
        tenant_id: tenant_id.to_string(),
        from_id,
        to_id,
        edge_type: edge_type.as_engine_str().to_string(),
        confidence_bp,
        created_at_micros: now,
        updated_at_micros: now,
    }
}

fn current_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

fn call_confidence_bp(call_count: usize) -> u16 {
    (6_000usize.saturating_add(call_count.saturating_mul(1_000)).min(10_000)) as u16
}

fn resolve_dep_target_file(
    dep: &DepEdge,
    file_ids: &BTreeMap<String, u32>,
    file_by_rel: &BTreeMap<&str, &FileInfo>,
) -> Option<u32> {
    for (rel_path, file) in file_by_rel {
        if file.module_path == dep.to_module || *rel_path == dep.to_module {
            return file_ids.get(*rel_path).copied();
        }
    }

    let normalized = dep.to_module.replace('\\', "/");
    if normalized.starts_with('.') {
        let base = Path::new(&dep.from_file).parent().unwrap_or_else(|| Path::new(""));
        let joined = normalize_path(base.join(&normalized));
        for candidate in path_candidates(&joined) {
            if let Some(id) = file_ids.get(&candidate).copied() {
                return Some(id);
            }
        }
    }

    let module_path = normalized.replace("::", "/").replace('.', "/");
    for candidate in path_candidates(&module_path) {
        if let Some(id) = file_ids.get(&candidate).copied() {
            return Some(id);
        }
    }
    file_ids
        .iter()
        .find(|(rel_path, _)| rel_path.trim_end_matches(".rs").ends_with(&module_path))
        .map(|(_, id)| *id)
}

fn normalize_path(path: PathBuf) -> String {
    let mut out = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(part) => out.push(part.to_string_lossy().to_string()),
            _ => {}
        }
    }
    out.join("/")
}

fn path_candidates(base: &str) -> Vec<String> {
    let base = base.trim_start_matches("./").trim_start_matches('/');
    let mut out = vec![base.to_string()];
    if !has_supported_extension(base) {
        out.extend([
            format!("{base}.rs"),
            format!("{base}.ts"),
            format!("{base}.tsx"),
            format!("{base}.py"),
            format!("{base}.vue"),
            format!("{base}/mod.rs"),
            format!("{base}/index.ts"),
            format!("{base}/index.tsx"),
            format!("{base}/__init__.py"),
        ]);
    }
    out
}

fn has_supported_extension(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "rs" | "ts" | "tsx" | "py" | "vue"))
}

fn crate_root_files(scan: &WorkspaceScan, file_ids: &BTreeMap<String, u32>) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    for krate in &scan.crates {
        let mut candidates: Vec<_> = scan.files.iter().filter(|file| file.crate_name == krate.name).collect();
        candidates.sort_by_key(|file| {
            let rel = file.rel_path.as_str();
            (
                !(rel.ends_with("src/lib.rs") || rel.ends_with("src/main.rs") || rel.ends_with("lib.rs")),
                rel.len(),
                rel,
            )
        });
        if let Some(file) = candidates.first() {
            if let Some(id) = file_ids.get(&file.rel_path).copied() {
                out.insert(krate.name.clone(), id);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_projections::query::graph_expand::{graph_expand, GraphExpandRequest};
    use corecrux_projections::tenant_hash_xxhash64;

    fn sample_scan() -> WorkspaceScan {
        WorkspaceScan {
            scan_id: "scan-1".to_string(),
            root_path: "/tmp/repo".to_string(),
            crates: vec![crate::workspace_scan::CrateInfo {
                name: "sample".to_string(),
                rel_path: ".".to_string(),
                internal_deps: Vec::new(),
                file_count: 2,
                total_loc: 4,
            }],
            files: vec![
                FileInfo {
                    rel_path: "src/lib.rs".to_string(),
                    crate_name: "sample".to_string(),
                    module_path: "sample".to_string(),
                    loc: 2,
                    symbol_count: 1,
                    stub_count: 0,
                    doc_summary: None,
                    doc_full: None,
                    defines: vec!["caller".to_string()],
                    references: vec![crate::workspace_scan::FileReference {
                        to_file: "src/target.rs".to_string(),
                        to_symbol: "target".to_string(),
                        call_count: 2,
                        same_file: false,
                        from_symbol: Some("caller".to_string()),
                    }],
                    referenced_by: Vec::new(),
                    is_test_file: false,
                },
                FileInfo {
                    rel_path: "src/target.rs".to_string(),
                    crate_name: "sample".to_string(),
                    module_path: "sample::target".to_string(),
                    loc: 2,
                    symbol_count: 1,
                    stub_count: 0,
                    doc_summary: None,
                    doc_full: None,
                    defines: vec!["target".to_string()],
                    references: Vec::new(),
                    referenced_by: vec!["src/lib.rs".to_string()],
                    is_test_file: false,
                },
            ],
            symbols: vec![
                crate::workspace_scan::SymbolInfo {
                    crate_name: "sample".to_string(),
                    module_path: "sample".to_string(),
                    file_rel_path: "src/lib.rs".to_string(),
                    line: 1,
                    kind: "fn".to_string(),
                    name: "caller".to_string(),
                    is_pub: true,
                },
                crate::workspace_scan::SymbolInfo {
                    crate_name: "sample".to_string(),
                    module_path: "sample::target".to_string(),
                    file_rel_path: "src/target.rs".to_string(),
                    line: 1,
                    kind: "fn".to_string(),
                    name: "target".to_string(),
                    is_pub: true,
                },
            ],
            deps: vec![DepEdge {
                from_crate: "sample".to_string(),
                from_file: "src/lib.rs".to_string(),
                to_module: "sample::target".to_string(),
                raw: "use crate::target".to_string(),
            }],
            ..WorkspaceScan::default()
        }
    }

    #[test]
    fn emits_defines_and_calls_into_graph_expand() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let mut projection = ProjectionState::default();
        let report = emit_codegraph_edges(
            &mut store,
            &mut projection,
            tmp.path(),
            "tenant-t",
            "repo-a",
            &sample_scan(),
        )
        .expect("emit");
        assert_eq!(report.defines, 2);
        assert_eq!(report.calls, 1);
        assert_eq!(report.imports, 1);

        let file_id = report.ids_by_key[&file_key("src/lib.rs")];
        let caller_id = report.ids_by_key[&symbol_key("src/lib.rs", "caller")];
        let target_id = report.ids_by_key[&symbol_key("src/target.rs", "target")];
        let resp = graph_expand(
            &projection,
            &GraphExpandRequest {
                tenant_hash: tenant_hash_xxhash64("tenant-t"),
                seed_artifact_ids: vec![file_id],
                max_hops: 2,
                ..GraphExpandRequest::default()
            },
        );
        assert!(resp.artifacts.iter().any(|artifact| artifact.artifact_id == caller_id
            && artifact.hop_distance == 1
            && artifact.edge_types_used.contains(&RelationTypeV1::Defines)));
        assert!(resp.artifacts.iter().any(|artifact| artifact.artifact_id == target_id
            && artifact.hop_distance == 2
            && artifact.edge_types_used.contains(&RelationTypeV1::Calls)));

        let calls_only = graph_expand(
            &projection,
            &GraphExpandRequest {
                tenant_hash: tenant_hash_xxhash64("tenant-t"),
                seed_artifact_ids: vec![caller_id],
                edge_types: vec![RelationTypeV1::Calls],
                max_hops: 1,
                ..GraphExpandRequest::default()
            },
        );
        assert_eq!(calls_only.artifacts.len(), 1);
        assert_eq!(calls_only.artifacts[0].artifact_id, target_id);
        assert_eq!(calls_only.artifacts[0].hop_distance, 1);
        assert_eq!(calls_only.artifacts[0].edge_types_used, vec![RelationTypeV1::Calls]);
    }

    #[test]
    fn interner_reuses_ids_across_scans() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let mut projection = ProjectionState::default();
        let first = emit_codegraph_edges(
            &mut store,
            &mut projection,
            tmp.path(),
            "tenant-t",
            "repo-a",
            &sample_scan(),
        )
        .expect("first emit");
        let second = emit_codegraph_edges(
            &mut store,
            &mut projection,
            tmp.path(),
            "tenant-t",
            "repo-a",
            &sample_scan(),
        )
        .expect("second emit");
        assert_eq!(
            first.ids_by_key[&symbol_key("src/lib.rs", "caller")],
            second.ids_by_key[&symbol_key("src/lib.rs", "caller")]
        );
    }

    #[test]
    fn new_edge_types_replay_from_relations_jsonl() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let mut projection = ProjectionState::default();
        let report = emit_codegraph_edges(
            &mut store,
            &mut projection,
            tmp.path(),
            "tenant-t",
            "repo-a",
            &sample_scan(),
        )
        .expect("emit");

        let mut reloaded = ProjectionState::default();
        let loaded = crate::relations::load_into_state(tmp.path(), &mut reloaded).expect("reload");
        assert_eq!(
            loaded,
            report.defines + report.calls + report.imports + report.depends_on
        );
        let caller_id = report.ids_by_key[&symbol_key("src/lib.rs", "caller")];
        let target_id = report.ids_by_key[&symbol_key("src/target.rs", "target")];
        let tenant_hash = tenant_hash_xxhash64("tenant-t");
        assert!(reloaded
            .relations
            .contains_key(&(tenant_hash, caller_id, target_id, RelationTypeV1::Calls.to_u8())));
    }

    #[tokio::test]
    async fn flag_off_maybe_emit_does_not_emit_edges() {
        std::env::remove_var(CODEGRAPH_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        let fact_store = Arc::new(RwLock::new(FactStore::new()));
        let projection = Arc::new(RwLock::new(ProjectionState::default()));
        let report = maybe_emit_codegraph_edges(
            &fact_store,
            &projection,
            tmp.path(),
            "tenant-t",
            "repo-a",
            &sample_scan(),
        )
        .await
        .expect("maybe emit");
        assert!(report.is_none());
        assert!(projection.read().await.relations.is_empty());
        let store = fact_store.read().await;
        assert!(store.get_by_entity(&ids_entity("tenant-t", "repo-a")).is_empty());
    }
}
