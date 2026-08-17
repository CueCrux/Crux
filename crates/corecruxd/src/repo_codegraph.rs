// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
pub const REPO_EXTDEPS_PREFIX: &str = "__repo_extdeps__";
pub(crate) const CODEGRAPH_IDS_KEY: &str = "content";
const CODEGRAPH_ENV: &str = "CORECRUXD_CODEGRAPH_EDGES";
const CODEGRAPH_EXTERNAL_ENV: &str = "CORECRUXD_CODEGRAPH_EXTERNAL";
const SHARED_IDS_REPO_ID: &str = "__shared__";
const SHARED_ID_START: u32 = u32::MAX;
#[cfg(test)]
const SHARED_ID_RESERVED_BAND_START: u32 = 0xF000_0000;
const PER_REPO_ID_SEED_MASK: u32 = 0x3FFF_FFFF;
const PER_REPO_ID_SEED_FLOOR: u32 = 0x0000_0100;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CodeGraphError {
    #[error(transparent)]
    Relations(#[from] crate::relations::RelationsError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("shared codegraph id allocator exhausted")]
    SharedIdsExhausted,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct CodeGraphIdStore {
    pub next_id: u32,
    /// Distinguishes an uninitialized shared allocator from an exhausted one
    /// when `next_id == 0`. Older persisted stores deserialize to `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub initialized: bool,
    pub map: BTreeMap<String, u32>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalDepVersionRow {
    pub version_req: Option<String>,
    pub version_locked: Option<String>,
    pub kind: String,
    pub source_manifest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CodeGraphEmitReport {
    pub defines: usize,
    pub calls: usize,
    pub imports: usize,
    pub depends_on: usize,
    pub repo_roots: usize,
    pub external_pkgs: usize,
    pub external_edges: usize,
    pub ids_by_key: BTreeMap<String, u32>,
}

pub(crate) fn ids_entity(tenant_id: &str, repo_id: &str) -> String {
    format!("{CODEGRAPH_IDS_PREFIX}::{tenant_id}::{repo_id}")
}

pub(crate) fn shared_ids_entity(tenant_id: &str) -> String {
    ids_entity(tenant_id, SHARED_IDS_REPO_ID)
}

pub(crate) fn extdeps_entity(tenant_id: &str, repo_id: &str) -> String {
    format!("{REPO_EXTDEPS_PREFIX}::{tenant_id}::{repo_id}::latest")
}

pub(crate) fn enabled_from_env() -> bool {
    crate::workspace_scan_manifests::env_flag_enabled(CODEGRAPH_ENV)
}

pub(crate) fn external_enabled_from_env() -> bool {
    crate::workspace_scan_manifests::env_flag_enabled(CODEGRAPH_EXTERNAL_ENV)
}

pub(crate) async fn maybe_emit_codegraph_edges(
    fact_store: &Arc<RwLock<FactStore>>,
    projection_state: &Arc<RwLock<ProjectionState>>,
    data_dir: &Path,
    tenant_id: &str,
    repo_id: &str,
    scan: &WorkspaceScan,
) -> Result<Option<CodeGraphEmitReport>, CodeGraphError> {
    if !enabled_from_env() && !external_enabled_from_env() {
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
    let intra_enabled = enabled_from_env();
    let external_enabled = external_enabled_from_env();
    let mut id_store = load_id_store(store, tenant_id, repo_id)?;
    if id_store.next_id == 0 {
        id_store.next_id = seeded_next_id(tenant_id, repo_id);
    }
    let mut shared_id_store = if external_enabled {
        let mut shared = load_shared_id_store(store, tenant_id)?;
        initialize_shared_id_store(&mut shared);
        Some(shared)
    } else {
        None
    };

    let mut used_ids = tenant_used_ids(store, tenant_id);
    let repo_root_id = if let Some(shared) = shared_id_store.as_mut() {
        Some(allocate_shared_id(shared, &mut used_ids, repo_key(repo_id))?)
    } else {
        None
    };
    let mut file_ids = BTreeMap::new();
    let mut symbol_ids = BTreeMap::new();

    if intra_enabled {
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
    } else if external_enabled {
        for rel_path in crate_root_file_paths(scan).values() {
            let key = file_key(rel_path);
            let id = allocate_id(&mut id_store, &mut used_ids, key.clone());
            file_ids.insert(rel_path.clone(), id);
        }
    }

    let external_deps = if external_enabled {
        external_dep_versions(scan)
    } else {
        BTreeMap::new()
    };
    let mut external_pkg_ids = BTreeMap::new();
    if let Some(shared) = shared_id_store.as_mut() {
        for (ecosystem, name) in external_deps.keys() {
            let key = pkg_key(ecosystem, name);
            let id = allocate_shared_id(shared, &mut used_ids, key)?;
            external_pkg_ids.insert((ecosystem.clone(), name.clone()), id);
        }
    }

    store_id_store(store, tenant_id, repo_id, &id_store)?;
    if let Some(shared) = shared_id_store.as_ref() {
        store_shared_id_store(store, tenant_id, shared)?;
    }
    if external_enabled {
        store_extdeps(store, tenant_id, repo_id, &external_deps)?;
    }

    let now = current_micros();
    let mut ids_by_key = id_store.map.clone();
    if let Some(shared) = shared_id_store.as_ref() {
        ids_by_key.extend(shared.map.clone());
    }
    let mut report = CodeGraphEmitReport {
        repo_roots: usize::from(repo_root_id.is_some()),
        external_pkgs: external_deps.len(),
        ids_by_key,
        ..CodeGraphEmitReport::default()
    };
    let mut records = Vec::new();

    if intra_enabled {
        let file_by_rel: BTreeMap<&str, &FileInfo> =
            scan.files.iter().map(|file| (file.rel_path.as_str(), file)).collect();
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
            records.push(relation_record(
                tenant_id,
                from_id,
                to_id,
                RelationTypeV1::Defines,
                10_000,
                now,
            ));
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
                records.push(relation_record(
                    tenant_id,
                    from_id,
                    to_id,
                    RelationTypeV1::Calls,
                    call_confidence_bp(reference.call_count),
                    now,
                ));
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
            records.push(relation_record(
                tenant_id,
                from_id,
                to_id,
                RelationTypeV1::Imports,
                8_000,
                now,
            ));
            report.imports += 1;
        }
    }

    let crate_roots = crate_root_files(scan, &file_ids);
    if intra_enabled {
        for krate in &scan.crates {
            let Some(from_id) = crate_roots.get(&krate.name).copied() else {
                continue;
            };
            for dep_name in &krate.internal_deps {
                let Some(to_id) = crate_roots.get(dep_name).copied() else {
                    continue;
                };
                records.push(relation_record(
                    tenant_id,
                    from_id,
                    to_id,
                    RelationTypeV1::DependsOn,
                    7_000,
                    now,
                ));
                report.depends_on += 1;
            }
        }
    }

    if let Some(repo_root_id) = repo_root_id {
        let mut root_file_ids = BTreeSet::new();
        for crate_root_id in crate_roots.values().copied() {
            if root_file_ids.insert(crate_root_id) {
                records.push(relation_record(
                    tenant_id,
                    repo_root_id,
                    crate_root_id,
                    RelationTypeV1::Defines,
                    10_000,
                    now,
                ));
                report.defines += 1;
            }
        }
        for pkg_id in external_pkg_ids.values().copied() {
            records.push(relation_record(
                tenant_id,
                repo_root_id,
                pkg_id,
                RelationTypeV1::DependsOn,
                7_000,
                now,
            ));
            report.external_edges += 1;
        }
    }

    crate::relations::append_records(data_dir, &records)?;
    for record in &records {
        crate::relations::apply_record(projection, record)?;
    }

    Ok(report)
}

fn load_id_store(store: &FactStore, tenant_id: &str, repo_id: &str) -> Result<CodeGraphIdStore, CodeGraphError> {
    load_id_store_entity(store, ids_entity(tenant_id, repo_id))
}

pub(crate) fn load_shared_id_store(store: &FactStore, tenant_id: &str) -> Result<CodeGraphIdStore, CodeGraphError> {
    load_id_store_entity(store, shared_ids_entity(tenant_id))
}

fn load_id_store_entity(store: &FactStore, entity: String) -> Result<CodeGraphIdStore, CodeGraphError> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(entity),
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
    store_id_store_entity(store, ids_entity(tenant_id, repo_id), id_store)
}

fn store_shared_id_store(
    store: &mut FactStore,
    tenant_id: &str,
    id_store: &CodeGraphIdStore,
) -> Result<(), CodeGraphError> {
    store_id_store_entity(store, shared_ids_entity(tenant_id), id_store)
}

fn store_id_store_entity(
    store: &mut FactStore,
    entity: String,
    id_store: &CodeGraphIdStore,
) -> Result<(), CodeGraphError> {
    store.store(StoreFact {
        tenant_hash: "default".to_string(),
        entity,
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

fn store_extdeps(
    store: &mut FactStore,
    tenant_id: &str,
    repo_id: &str,
    deps: &BTreeMap<(String, String), ExternalDepVersionRow>,
) -> Result<(), CodeGraphError> {
    let by_pkg: BTreeMap<String, ExternalDepVersionRow> = deps
        .iter()
        .map(|((ecosystem, name), dep)| (external_dep_map_key(ecosystem, name), dep.clone()))
        .collect();
    store.store(StoreFact {
        tenant_hash: "default".to_string(),
        entity: extdeps_entity(tenant_id, repo_id),
        key: CODEGRAPH_IDS_KEY.to_string(),
        value: serde_json::to_string(&by_pkg)?,
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    });
    Ok(())
}

pub(crate) fn load_extdeps(
    store: &FactStore,
    tenant_id: &str,
    repo_id: &str,
) -> Result<BTreeMap<String, ExternalDepVersionRow>, CodeGraphError> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(extdeps_entity(tenant_id, repo_id)),
        entity_prefix: None,
        top_k: 10,
        token_budget: None,
    });
    let Some(fact) = crate::fact_helpers::dedup_latest(result.facts)
        .into_iter()
        .find(|fact| fact.key == CODEGRAPH_IDS_KEY)
    else {
        return Ok(BTreeMap::new());
    };
    Ok(serde_json::from_str::<BTreeMap<String, ExternalDepVersionRow>>(
        &fact.value,
    )?)
}

fn tenant_used_ids(store: &FactStore, tenant_id: &str) -> BTreeSet<u32> {
    let entity_prefix = format!("{CODEGRAPH_IDS_PREFIX}::{tenant_id}::");
    let facts: Vec<_> = store
        .entities()
        .into_iter()
        .filter(|entity| entity.starts_with(&entity_prefix))
        .flat_map(|entity| store.get_by_entity(&entity).into_iter().cloned())
        .collect();
    let mut used = BTreeSet::new();
    for fact in crate::fact_helpers::dedup_latest(facts) {
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

fn initialize_shared_id_store(id_store: &mut CodeGraphIdStore) {
    if id_store.initialized {
        return;
    }
    if id_store.next_id == 0 {
        id_store.next_id = SHARED_ID_START;
    }
    id_store.initialized = true;
}

fn allocate_shared_id(
    id_store: &mut CodeGraphIdStore,
    used_ids: &mut BTreeSet<u32>,
    key: String,
) -> Result<u32, CodeGraphError> {
    if let Some(id) = id_store.map.get(&key).copied() {
        used_ids.insert(id);
        return Ok(id);
    }

    // This is not a hard ID partition for historical per-repo stores: old
    // hash-seeded IDs may already live in the high band. Collision safety comes
    // from the exhaustive tenant-used-ID scan, while new per-repo seeds are
    // masked below the shared allocator's reserved high band.
    loop {
        if id_store.next_id == 0 && id_store.initialized {
            tracing::error!(key = %key, "shared codegraph id allocator exhausted");
            return Err(CodeGraphError::SharedIdsExhausted);
        }
        let candidate = if id_store.next_id == 0 {
            SHARED_ID_START
        } else {
            id_store.next_id
        };
        id_store.next_id = candidate.saturating_sub(1);
        if candidate != 0 && used_ids.insert(candidate) {
            id_store.map.insert(key, candidate);
            return Ok(candidate);
        }
    }
}

fn seeded_next_id(tenant_id: &str, repo_id: &str) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tenant_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(repo_id.as_bytes());
    let bytes = hasher.finalize();
    let seed = u32::from_le_bytes(bytes.as_bytes()[0..4].try_into().unwrap_or([0; 4]));
    (seed & PER_REPO_ID_SEED_MASK) | PER_REPO_ID_SEED_FLOOR
}

fn file_key(rel_path: &str) -> String {
    format!("file:{}", normalize_rel(rel_path))
}

fn symbol_key(rel_path: &str, name: &str) -> String {
    format!("sym:{}#{name}", normalize_rel(rel_path))
}

pub(crate) fn repo_key(repo_id: &str) -> String {
    format!("repo:{}", repo_id.trim())
}

pub(crate) fn pkg_key(ecosystem: &str, name: &str) -> String {
    format!("pkg:{}", external_dep_map_key(ecosystem, name))
}

pub(crate) fn external_dep_map_key(ecosystem: &str, name: &str) -> String {
    format!(
        "{}/{}",
        normalize_external_part(ecosystem),
        normalize_external_part(name)
    )
}

fn normalize_external_part(value: &str) -> String {
    value.trim().replace('\\', "/")
}

fn external_dep_versions(scan: &WorkspaceScan) -> BTreeMap<(String, String), ExternalDepVersionRow> {
    let mut deps = scan.external_deps.clone();
    deps.sort_by(|a, b| {
        normalize_external_part(&a.ecosystem)
            .cmp(&normalize_external_part(&b.ecosystem))
            .then_with(|| normalize_external_part(&a.name).cmp(&normalize_external_part(&b.name)))
            .then_with(|| a.source_manifest.cmp(&b.source_manifest))
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.version_req.cmp(&b.version_req))
            .then_with(|| a.version_locked.cmp(&b.version_locked))
    });

    let mut by_pkg = BTreeMap::new();
    for dep in deps {
        let ecosystem = normalize_external_part(&dep.ecosystem);
        let name = normalize_external_part(&dep.name);
        if ecosystem.is_empty() || name.is_empty() {
            continue;
        }
        by_pkg
            .entry((ecosystem, name))
            .or_insert_with(|| ExternalDepVersionRow {
                version_req: dep.version_req,
                version_locked: dep.version_locked,
                kind: dep.kind,
                source_manifest: dep.source_manifest,
            });
    }
    by_pkg
}

fn normalize_rel(path: &str) -> String {
    path.replace('\\', "/")
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

fn crate_root_file_paths(scan: &WorkspaceScan) -> BTreeMap<String, String> {
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
            out.insert(krate.name.clone(), file.rel_path.clone());
        }
    }
    out
}

fn crate_root_files(scan: &WorkspaceScan, file_ids: &BTreeMap<String, u32>) -> BTreeMap<String, u32> {
    crate_root_file_paths(scan)
        .into_iter()
        .filter_map(|(name, rel_path)| file_ids.get(&rel_path).copied().map(|id| (name, id)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvVarGuard;
    use crate::workspace_scan_manifests::ExternalDep;
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

    fn external_dep(ecosystem: &str, name: &str, source_manifest: &str) -> ExternalDep {
        ExternalDep {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version_req: Some("^4.18.0".to_string()),
            version_locked: Some("4.18.2".to_string()),
            source_manifest: source_manifest.to_string(),
            kind: "runtime".to_string(),
        }
    }

    fn scan_with_external_dep(ecosystem: &str, name: &str) -> WorkspaceScan {
        let mut scan = sample_scan();
        scan.external_deps = vec![external_dep(ecosystem, name, "package.json")];
        scan.stats.external_dep_count = scan.external_deps.len();
        scan
    }

    #[test]
    #[serial_test::serial]
    fn emits_defines_and_calls_into_graph_expand() {
        let _edges = EnvVarGuard::set(CODEGRAPH_ENV, "1");
        let _external = EnvVarGuard::unset(CODEGRAPH_EXTERNAL_ENV);
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
    #[serial_test::serial]
    fn interner_reuses_ids_across_scans() {
        let _edges = EnvVarGuard::set(CODEGRAPH_ENV, "1");
        let _external = EnvVarGuard::unset(CODEGRAPH_EXTERNAL_ENV);
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
    #[serial_test::serial]
    fn new_edge_types_replay_from_relations_jsonl() {
        let _edges = EnvVarGuard::set(CODEGRAPH_ENV, "1");
        let _external = EnvVarGuard::unset(CODEGRAPH_EXTERNAL_ENV);
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

    #[test]
    #[serial_test::serial]
    fn shared_pkg_id_reaches_both_repos_through_reverse_expand() {
        let _edges = EnvVarGuard::unset(CODEGRAPH_ENV);
        let _external = EnvVarGuard::set(CODEGRAPH_EXTERNAL_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let mut projection = ProjectionState::default();
        let scan = scan_with_external_dep("npm", "express");

        let first = emit_codegraph_edges(&mut store, &mut projection, tmp.path(), "tenant-t", "repo-a", &scan)
            .expect("emit repo a");
        let second = emit_codegraph_edges(&mut store, &mut projection, tmp.path(), "tenant-t", "repo-b", &scan)
            .expect("emit repo b");

        let pkg = pkg_key("npm", "express");
        let pkg_id = first.ids_by_key[&pkg];
        assert_eq!(pkg_id, second.ids_by_key[&pkg]);
        assert_eq!(first.repo_roots, 1);
        assert_eq!(first.external_pkgs, 1);
        assert_eq!(first.external_edges, 1);

        let repo_a_id = first.ids_by_key[&repo_key("repo-a")];
        let repo_b_id = second.ids_by_key[&repo_key("repo-b")];
        let resp = graph_expand(
            &projection,
            &GraphExpandRequest {
                tenant_hash: tenant_hash_xxhash64("tenant-t"),
                seed_artifact_ids: vec![pkg_id],
                edge_types: vec![RelationTypeV1::DependsOn],
                max_hops: 1,
                budget: 10,
                ..GraphExpandRequest::default()
            },
        );
        let reached: BTreeSet<u32> = resp.artifacts.iter().map(|artifact| artifact.artifact_id).collect();
        assert!(reached.contains(&repo_a_id), "repo-a root reached from shared pkg id");
        assert!(reached.contains(&repo_b_id), "repo-b root reached from shared pkg id");
    }

    #[test]
    #[serial_test::serial]
    fn shared_pkg_id_persists_across_fresh_store_load() {
        let _external = EnvVarGuard::set(CODEGRAPH_EXTERNAL_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let mut projection = ProjectionState::default();
        let scan = scan_with_external_dep("npm", "express");
        let first = emit_codegraph_edges(&mut store, &mut projection, tmp.path(), "tenant-t", "repo-a", &scan)
            .expect("emit repo a");
        let pkg_id = first.ids_by_key[&pkg_key("npm", "express")];

        let shared_value = store
            .get_by_entity(&shared_ids_entity("tenant-t"))
            .into_iter()
            .max_by_key(|fact| fact.version)
            .expect("shared id fact")
            .value
            .clone();
        let mut restarted = FactStore::new();
        restarted.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: shared_ids_entity("tenant-t"),
            key: CODEGRAPH_IDS_KEY.to_string(),
            value: shared_value,
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });

        let mut restarted_projection = ProjectionState::default();
        let second = emit_codegraph_edges(
            &mut restarted,
            &mut restarted_projection,
            tmp.path(),
            "tenant-t",
            "repo-b",
            &scan,
        )
        .expect("emit repo b");
        assert_eq!(second.ids_by_key[&pkg_key("npm", "express")], pkg_id);
    }

    #[test]
    #[serial_test::serial]
    fn shared_ids_skip_pre_existing_per_repo_ids() {
        let _external = EnvVarGuard::set(CODEGRAPH_EXTERNAL_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let old_store = CodeGraphIdStore {
            next_id: 1,
            map: BTreeMap::from([(file_key("legacy.rs"), SHARED_ID_START)]),
            ..CodeGraphIdStore::default()
        };
        store_id_store(&mut store, "tenant-t", "legacy-repo", &old_store).expect("seed old id store");
        let mut projection = ProjectionState::default();

        let report = emit_codegraph_edges(
            &mut store,
            &mut projection,
            tmp.path(),
            "tenant-t",
            "repo-a",
            &scan_with_external_dep("npm", "express"),
        )
        .expect("emit");

        let repo_id = report.ids_by_key[&repo_key("repo-a")];
        let pkg_id = report.ids_by_key[&pkg_key("npm", "express")];
        assert_ne!(repo_id, SHARED_ID_START);
        assert_ne!(pkg_id, SHARED_ID_START);
        assert_ne!(repo_id, pkg_id);
        assert_ne!(report.ids_by_key[&file_key("src/lib.rs")], repo_id);
        assert_ne!(report.ids_by_key[&file_key("src/lib.rs")], pkg_id);
    }

    #[test]
    fn tenant_used_ids_enumerates_all_id_store_entities() {
        let mut store = FactStore::new();
        for id in 1u32..=10_050 {
            let id_store = CodeGraphIdStore {
                next_id: id.saturating_add(1),
                map: BTreeMap::from([(format!("file:legacy-{id}.rs"), id)]),
                ..CodeGraphIdStore::default()
            };
            store_id_store(&mut store, "tenant-t", &format!("repo-{id}"), &id_store).expect("store id entity");
        }

        let used = tenant_used_ids(&store, "tenant-t");
        assert_eq!(used.len(), 10_050);
        assert!(used.contains(&1), "oldest ID must not fall off a query cap");
        assert!(used.contains(&10_050), "newest ID should still be present");
    }

    #[test]
    fn new_per_repo_seed_stays_below_shared_reserved_band() {
        for repo_id in ["repo-a", "repo-b", "repo-c", "repo-d"] {
            let seed = seeded_next_id("tenant-t", repo_id);
            assert!(seed >= PER_REPO_ID_SEED_FLOOR);
            assert!(seed < SHARED_ID_RESERVED_BAND_START);
        }
    }

    #[test]
    #[serial_test::serial]
    fn shared_allocator_next_id_zero_initialized_errors_without_wrap() {
        let _external = EnvVarGuard::set(CODEGRAPH_EXTERNAL_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        let exhausted = CodeGraphIdStore {
            next_id: 0,
            initialized: true,
            map: BTreeMap::new(),
        };
        store_shared_id_store(&mut store, "tenant-t", &exhausted).expect("store exhausted shared ids");
        let mut projection = ProjectionState::default();

        let err = emit_codegraph_edges(
            &mut store,
            &mut projection,
            tmp.path(),
            "tenant-t",
            "repo-a",
            &scan_with_external_dep("npm", "express"),
        )
        .expect_err("shared allocator should not wrap after exhaustion");

        assert!(matches!(err, CodeGraphError::SharedIdsExhausted));
        assert!(projection.relations.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn emit_appends_records_before_applying_projection_edges() {
        let _edges = EnvVarGuard::set(CODEGRAPH_ENV, "1");
        let _external = EnvVarGuard::unset(CODEGRAPH_EXTERNAL_ENV);
        let data_file = tempfile::NamedTempFile::new().expect("data file");
        let mut store = FactStore::new();
        let mut projection = ProjectionState::default();

        let err = emit_codegraph_edges(
            &mut store,
            &mut projection,
            data_file.path(),
            "tenant-t",
            "repo-a",
            &sample_scan(),
        )
        .expect_err("append should fail when data_dir is a file");

        assert!(matches!(
            err,
            CodeGraphError::Relations(crate::relations::RelationsError::Io(_))
        ));
        assert!(projection.relations.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn external_graph_emission_uses_scan_external_deps_sequence() {
        let _external_emit = EnvVarGuard::set(CODEGRAPH_EXTERNAL_ENV, "1");
        let fixture = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            fixture.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .expect("package json");
        let tmp = tempfile::tempdir().expect("data dir");
        let mut store = FactStore::new();
        let mut projection = ProjectionState::default();

        let _scan_off = EnvVarGuard::unset("CORECRUXD_EXTERNAL_DEPS");
        let mut scan_without = sample_scan();
        crate::workspace_scan_manifests::attach_external_deps_if_enabled(fixture.path(), &mut scan_without);
        assert!(scan_without.external_deps.is_empty());
        let without = emit_codegraph_edges(
            &mut store,
            &mut projection,
            tmp.path(),
            "tenant-t",
            "repo-off",
            &scan_without,
        )
        .expect("emit without deps");
        assert_eq!(without.external_pkgs, 0);
        assert_eq!(without.external_edges, 0);

        drop(_scan_off);
        let _scan_on = EnvVarGuard::set("CORECRUXD_EXTERNAL_DEPS", "1");
        let mut scan_with = sample_scan();
        crate::workspace_scan_manifests::attach_external_deps_if_enabled(fixture.path(), &mut scan_with);
        assert!(!scan_with.external_deps.is_empty());
        let with = emit_codegraph_edges(
            &mut store,
            &mut projection,
            tmp.path(),
            "tenant-t",
            "repo-on",
            &scan_with,
        )
        .expect("emit with deps");
        assert_eq!(with.external_pkgs, 1);
        assert_eq!(with.external_edges, 1);
        assert!(with.ids_by_key.contains_key(&pkg_key("npm", "express")));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn external_only_maybe_emit_emits_only_repo_and_pkg_edges() {
        let _edges = EnvVarGuard::unset(CODEGRAPH_ENV);
        let _external_emit = EnvVarGuard::set(CODEGRAPH_EXTERNAL_ENV, "1");
        let _scan_deps = EnvVarGuard::set("CORECRUXD_EXTERNAL_DEPS", "1");
        let fixture = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            fixture.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .expect("package json");
        let mut scan = sample_scan();
        crate::workspace_scan_manifests::attach_external_deps_if_enabled(fixture.path(), &mut scan);
        assert!(!scan.external_deps.is_empty());

        let tmp = tempfile::tempdir().expect("data dir");
        let fact_store = Arc::new(RwLock::new(FactStore::new()));
        let projection = Arc::new(RwLock::new(ProjectionState::default()));
        let report =
            maybe_emit_codegraph_edges(&fact_store, &projection, tmp.path(), "tenant-t", "repo-external", &scan)
                .await
                .expect("maybe emit")
                .expect("external enabled");

        assert_eq!(report.defines, 1);
        assert_eq!(report.calls, 0);
        assert_eq!(report.imports, 0);
        assert_eq!(report.depends_on, 0);
        assert_eq!(report.repo_roots, 1);
        assert_eq!(report.external_pkgs, 1);
        assert_eq!(report.external_edges, 1);
        assert!(!report.ids_by_key.contains_key(&file_key("src/target.rs")));
        assert!(!report.ids_by_key.contains_key(&symbol_key("src/lib.rs", "caller")));
        assert!(!report.ids_by_key.contains_key(&symbol_key("src/target.rs", "target")));

        let repo_root_id = report.ids_by_key[&repo_key("repo-external")];
        let crate_root_id = report.ids_by_key[&file_key("src/lib.rs")];
        let pkg_id = report.ids_by_key[&pkg_key("npm", "express")];
        let records_jsonl = std::fs::read_to_string(tmp.path().join("relations.jsonl")).expect("relations jsonl");
        let records: Vec<crate::relations::RelationRecord> = records_jsonl
            .lines()
            .map(|line| serde_json::from_str(line).expect("relation record"))
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(projection.read().await.relations.len(), 2);
        assert!(records.iter().any(|record| {
            record.from_id == repo_root_id
                && record.to_id == crate_root_id
                && record.edge_type == RelationTypeV1::Defines.as_engine_str()
        }));
        assert!(records.iter().any(|record| {
            record.from_id == repo_root_id
                && record.to_id == pkg_id
                && record.edge_type == RelationTypeV1::DependsOn.as_engine_str()
        }));
        assert!(records.iter().all(|record| {
            record.from_id == repo_root_id
                && ((record.to_id == crate_root_id && record.edge_type == RelationTypeV1::Defines.as_engine_str())
                    || (record.to_id == pkg_id && record.edge_type == RelationTypeV1::DependsOn.as_engine_str()))
        }));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn external_flag_off_preserves_existing_emit_shape() {
        let _external = EnvVarGuard::unset(CODEGRAPH_EXTERNAL_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        let fact_store = Arc::new(RwLock::new(FactStore::new()));
        let projection = Arc::new(RwLock::new(ProjectionState::default()));
        let _edges = EnvVarGuard::set(CODEGRAPH_ENV, "1");

        let report = maybe_emit_codegraph_edges(
            &fact_store,
            &projection,
            tmp.path(),
            "tenant-t",
            "repo-a",
            &scan_with_external_dep("npm", "express"),
        )
        .await
        .expect("maybe emit")
        .expect("enabled");
        assert_eq!(report.repo_roots, 0);
        assert_eq!(report.external_pkgs, 0);
        assert_eq!(report.external_edges, 0);
        assert!(!report.ids_by_key.contains_key(&repo_key("repo-a")));
        assert!(!report.ids_by_key.contains_key(&pkg_key("npm", "express")));

        let store = fact_store.read().await;
        assert!(store.get_by_entity(&shared_ids_entity("tenant-t")).is_empty());
        assert!(store.get_by_entity(&extdeps_entity("tenant-t", "repo-a")).is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn version_side_table_content_and_delete_repo_cleanup() {
        let _external = EnvVarGuard::set(CODEGRAPH_EXTERNAL_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        crate::repo_registry::store_repo(
            &mut store,
            &crate::repo_registry::RepoRegistration {
                repo_id: "repo-a".to_string(),
                tenant_id: "tenant-t".to_string(),
                root_path: None,
                clone_url: Some("https://example.invalid/repo-a.git".to_string()),
                languages: vec!["typescript".to_string()],
                enabled: true,
                added_at_unix_ms: 1,
                last_scan_id: None,
                scan_status: None,
                scan_error: None,
                scan_queued_at_unix_ms: None,
                scan_finished_at_unix_ms: None,
            },
        )
        .expect("store repo");
        let mut projection = ProjectionState::default();
        emit_codegraph_edges(
            &mut store,
            &mut projection,
            tmp.path(),
            "tenant-t",
            "repo-a",
            &scan_with_external_dep("npm", "express"),
        )
        .expect("emit");

        let fact = store
            .get_by_entity(&extdeps_entity("tenant-t", "repo-a"))
            .into_iter()
            .max_by_key(|fact| fact.version)
            .expect("extdeps fact");
        let versions: BTreeMap<String, ExternalDepVersionRow> =
            serde_json::from_str(&fact.value).expect("version map json");
        let row = versions.get("npm/express").expect("express row");
        assert_eq!(row.version_req.as_deref(), Some("^4.18.0"));
        assert_eq!(row.version_locked.as_deref(), Some("4.18.2"));
        assert_eq!(row.kind, "runtime");
        assert_eq!(row.source_manifest, "package.json");

        crate::repo_registry::delete_repo(&mut store, "tenant-t", "repo-a").expect("delete repo");
        assert!(store.get_by_entity(&extdeps_entity("tenant-t", "repo-a")).is_empty());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn flag_off_maybe_emit_does_not_emit_edges() {
        let _edges = EnvVarGuard::unset(CODEGRAPH_ENV);
        let _external = EnvVarGuard::unset(CODEGRAPH_EXTERNAL_ENV);
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
