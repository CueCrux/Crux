// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Manifest and lockfile extraction for external dependencies.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const EXTERNAL_DEPS_ENV: &str = "CORECRUXD_EXTERNAL_DEPS";
const MAX_DEPTH: usize = 12;
const MAX_MANIFESTS: usize = 2000;
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_LOCKFILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalDep {
    pub name: String,
    pub ecosystem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_req: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_locked: Option<String>,
    pub source_manifest: String,
    pub kind: String,
}

pub(crate) fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        !(v.is_empty() || v == "0" || v == "false" || v == "off" || v == "no")
    })
}

pub(crate) fn external_deps_enabled_from_env() -> bool {
    env_flag_enabled(EXTERNAL_DEPS_ENV)
}

pub(crate) fn attach_external_deps_if_enabled(root: &Path, scan: &mut crate::workspace_scan::WorkspaceScan) {
    if external_deps_enabled_from_env() {
        scan.external_deps = scan_external_deps(root);
        scan.stats.external_dep_count = scan.external_deps.len();
    }
}

pub fn scan_external_deps(root: &Path) -> Vec<ExternalDep> {
    let manifests = discover_manifests(root);
    let mut deps = Vec::new();
    for (idx, manifest) in manifests.iter().enumerate() {
        if idx >= MAX_MANIFESTS {
            tracing::warn!(
                root = %root.display(),
                max_manifests = MAX_MANIFESTS,
                "external dependency manifest cap reached"
            );
            break;
        }
        let Some(name) = manifest.file_name().and_then(|n| n.to_str()) else {
            tracing::warn!(path = %manifest.display(), "skipping non-UTF-8 manifest path");
            continue;
        };
        match name {
            "Cargo.toml" => parse_cargo_manifest(root, manifest, &mut deps),
            "package.json" => parse_package_json(root, manifest, &mut deps),
            "pyproject.toml" => parse_pyproject_toml(root, manifest, &mut deps),
            "go.mod" => parse_go_mod(root, manifest, &mut deps),
            _ if is_requirements_file(name) || is_requirements_path(manifest) => {
                parse_requirements_txt(root, manifest, &mut deps);
            }
            _ => {}
        }
    }
    dedup_and_sort(deps)
}

fn discover_manifests(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::warn!(path = %dir.display(), ?err, "failed to read directory for external dependency scan");
                continue;
            }
        };
        let mut entries = Vec::new();
        for entry in read_dir {
            match entry {
                Ok(entry) => entries.push(entry),
                Err(err) => tracing::warn!(path = %dir.display(), ?err, "failed to read directory entry"),
            }
        }
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(err) => {
                    tracing::warn!(path = %path.display(), ?err, "failed to read file type");
                    continue;
                }
            };
            if file_type.is_symlink() {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if file_type.is_dir() {
                if should_skip_dir(name) {
                    continue;
                }
                if depth >= MAX_DEPTH {
                    tracing::warn!(path = %path.display(), max_depth = MAX_DEPTH, "external dependency scan depth cap reached");
                    continue;
                }
                stack.push((path, depth + 1));
            } else if file_type.is_file() && is_manifest_path(&path) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        "node_modules" | "target" | "vendor" | ".git" | "dist" | "build" | ".venv" | "venv" | "__pycache__"
    )
}

fn is_manifest_name(name: &str) -> bool {
    matches!(name, "Cargo.toml" | "package.json" | "pyproject.toml" | "go.mod") || is_requirements_file(name)
}

fn is_requirements_file(name: &str) -> bool {
    name.starts_with("requirements") && Path::new(name).extension().and_then(|ext| ext.to_str()) == Some("txt")
}

fn is_manifest_path(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    is_manifest_name(name) || is_requirements_path(path)
}

fn is_requirements_path(path: &Path) -> bool {
    if path.extension().and_then(|ext| ext.to_str()) != Some("txt") {
        return false;
    }
    let parent_name = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    parent_name.starts_with("requirements")
}

fn read_utf8_file(path: &Path, label: &str) -> Option<String> {
    read_utf8_file_with_cap(path, label, MAX_FILE_BYTES)
}

fn read_utf8_lockfile(path: &Path, label: &str) -> Option<String> {
    read_utf8_file_with_cap(path, label, MAX_LOCKFILE_BYTES)
}

fn read_utf8_file_with_cap(path: &Path, label: &str, max_bytes: u64) -> Option<String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            tracing::warn!(path = %path.display(), ?err, file_kind = %label, "failed to stat external dependency file");
            return None;
        }
    };
    if metadata.file_type().is_symlink() {
        tracing::warn!(path = %path.display(), file_kind = %label, "skipping symlinked external dependency file");
        return None;
    }
    if metadata.len() > max_bytes {
        tracing::warn!(
            path = %path.display(),
            file_kind = %label,
            bytes = metadata.len(),
            max_bytes,
            "external dependency file exceeds size cap"
        );
        return None;
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(path = %path.display(), ?err, file_kind = %label, "failed to read external dependency file");
            return None;
        }
    };
    match String::from_utf8(bytes) {
        Ok(contents) => Some(contents),
        Err(err) => {
            tracing::warn!(path = %path.display(), ?err, file_kind = %label, "external dependency file is not UTF-8");
            None
        }
    }
}

fn rel_path(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok().unwrap_or(path);
    rel.to_str().map(|s| s.replace('\\', "/")).or_else(|| {
        tracing::warn!(path = %path.display(), "skipping non-UTF-8 manifest path");
        None
    })
}

fn dedup_and_sort(deps: Vec<ExternalDep>) -> Vec<ExternalDep> {
    let mut by_key: BTreeMap<(String, String, String), ExternalDep> = BTreeMap::new();
    for dep in deps {
        let key = (dep.source_manifest.clone(), dep.ecosystem.clone(), dep.name.clone());
        by_key.entry(key).or_insert(dep);
    }
    by_key.into_values().collect()
}

fn find_nearest_file(start_dir: &Path, root: &Path, file_name: &str) -> Option<PathBuf> {
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        let candidate = dir.join(file_name);
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir == root {
            break;
        }
        current = dir.parent();
    }
    None
}

fn parse_toml(contents: &str, path: &Path, label: &str) -> Option<toml::Value> {
    // toml 1.x: `Value: FromStr` parses a single TOML value expression, not a
    // document — documents must go through `Table: FromStr`.
    match contents.parse::<toml::Table>() {
        Ok(table) => Some(toml::Value::Table(table)),
        Err(err) => {
            tracing::warn!(path = %path.display(), ?err, file_kind = %label, "failed to parse toml external dependency file");
            None
        }
    }
}

fn table_at<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Table> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_table()
}

fn parse_cargo_manifest(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "Cargo.toml") else {
        return;
    };
    let Some(value) = parse_toml(&contents, manifest, "Cargo.toml") else {
        return;
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    let manifest_dir = manifest.parent().unwrap_or(root);
    let workspace_deps = nearest_workspace_cargo_deps(root, manifest_dir);
    let lock_versions = find_nearest_file(manifest_dir, root, "Cargo.lock").and_then(|lock| parse_cargo_lock(&lock));

    add_cargo_section(
        table_at(&value, &["dependencies"]),
        "normal",
        &source_manifest,
        workspace_deps.as_ref(),
        lock_versions.as_ref(),
        deps,
    );
    add_cargo_section(
        table_at(&value, &["dev-dependencies"]),
        "dev",
        &source_manifest,
        workspace_deps.as_ref(),
        lock_versions.as_ref(),
        deps,
    );
    add_cargo_section(
        table_at(&value, &["build-dependencies"]),
        "build",
        &source_manifest,
        workspace_deps.as_ref(),
        lock_versions.as_ref(),
        deps,
    );
    if let Some(targets) = table_at(&value, &["target"]) {
        for target in targets.values() {
            let Some(target_table) = target.as_table() else {
                continue;
            };
            add_cargo_section(
                target_table.get("dependencies").and_then(toml::Value::as_table),
                "normal",
                &source_manifest,
                workspace_deps.as_ref(),
                lock_versions.as_ref(),
                deps,
            );
            add_cargo_section(
                target_table.get("dev-dependencies").and_then(toml::Value::as_table),
                "dev",
                &source_manifest,
                workspace_deps.as_ref(),
                lock_versions.as_ref(),
                deps,
            );
            add_cargo_section(
                target_table.get("build-dependencies").and_then(toml::Value::as_table),
                "build",
                &source_manifest,
                workspace_deps.as_ref(),
                lock_versions.as_ref(),
                deps,
            );
        }
    }
}

fn nearest_workspace_cargo_deps(root: &Path, start_dir: &Path) -> Option<toml::Table> {
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() {
            let workspace_table = read_utf8_file(&manifest, "Cargo.toml")
                .and_then(|contents| parse_toml(&contents, &manifest, "Cargo.toml"))
                .and_then(|value| table_at(&value, &["workspace", "dependencies"]).cloned());
            if let Some(table) = workspace_table {
                return Some(table);
            }
        }
        if dir == root {
            break;
        }
        current = dir.parent();
    }
    None
}

fn parse_cargo_lock(lock: &Path) -> Option<BTreeMap<String, Option<String>>> {
    let contents = read_utf8_lockfile(lock, "Cargo.lock")?;
    let value = parse_toml(&contents, lock, "Cargo.lock")?;
    let mut versions: BTreeMap<String, Option<String>> = BTreeMap::new();
    let Some(packages) = value.get("package").and_then(toml::Value::as_array) else {
        return Some(versions);
    };
    for package in packages {
        let Some(table) = package.as_table() else {
            continue;
        };
        let (Some(name), Some(version)) = (
            table.get("name").and_then(toml::Value::as_str),
            table.get("version").and_then(toml::Value::as_str),
        ) else {
            continue;
        };
        versions
            .entry(name.to_string())
            .and_modify(|existing| *existing = None)
            .or_insert_with(|| Some(version.to_string()));
    }
    Some(versions)
}

fn add_cargo_section(
    table: Option<&toml::Table>,
    base_kind: &str,
    source_manifest: &str,
    workspace_deps: Option<&toml::Table>,
    lock_versions: Option<&BTreeMap<String, Option<String>>>,
    deps: &mut Vec<ExternalDep>,
) {
    let Some(table) = table else {
        return;
    };
    for (name, value) in table {
        let Some(spec) = cargo_dep_spec(name, value, workspace_deps) else {
            continue;
        };
        let kind = if spec.optional { "optional" } else { base_kind };
        let version_locked = lock_versions.and_then(|versions| versions.get(&spec.lock_name).cloned().flatten());
        deps.push(ExternalDep {
            name: name.clone(),
            ecosystem: "cargo".to_string(),
            version_req: spec.version_req,
            version_locked,
            source_manifest: source_manifest.to_string(),
            kind: kind.to_string(),
        });
    }
}

#[derive(Debug, Clone)]
struct CargoDepSpec {
    version_req: Option<String>,
    lock_name: String,
    optional: bool,
}

fn cargo_dep_spec(name: &str, value: &toml::Value, workspace_deps: Option<&toml::Table>) -> Option<CargoDepSpec> {
    if let Some(version) = value.as_str() {
        return Some(CargoDepSpec {
            version_req: Some(version.to_string()),
            lock_name: name.to_string(),
            optional: false,
        });
    }
    let Some(table) = value.as_table() else {
        tracing::warn!(dependency = %name, "skipping unsupported cargo dependency value");
        return None;
    };
    let is_workspace = table.get("workspace").and_then(toml::Value::as_bool).unwrap_or(false);
    let has_path = table.contains_key("path");
    let has_git = table.contains_key("git");
    let mut version_req = table
        .get("version")
        .and_then(toml::Value::as_str)
        .map(ToString::to_string);
    let mut lock_name = table
        .get("package")
        .and_then(toml::Value::as_str)
        .map_or_else(|| name.to_string(), ToString::to_string);
    let mut optional = table.get("optional").and_then(toml::Value::as_bool).unwrap_or(false);

    if is_workspace && version_req.is_none() {
        if let Some(workspace_spec) = workspace_dep_spec(name, workspace_deps) {
            version_req = workspace_spec.version_req;
            lock_name = workspace_spec.lock_name;
            optional |= workspace_spec.optional;
        }
    }
    if has_path && !has_git && version_req.is_none() && !is_workspace {
        return None;
    }
    Some(CargoDepSpec {
        version_req,
        lock_name,
        optional,
    })
}

fn workspace_dep_spec(name: &str, workspace_deps: Option<&toml::Table>) -> Option<CargoDepSpec> {
    let value = workspace_deps?.get(name)?;
    if let Some(version) = value.as_str() {
        return Some(CargoDepSpec {
            version_req: Some(version.to_string()),
            lock_name: name.to_string(),
            optional: false,
        });
    }
    let table = value.as_table()?;
    Some(CargoDepSpec {
        version_req: table
            .get("version")
            .and_then(toml::Value::as_str)
            .map(ToString::to_string),
        lock_name: table
            .get("package")
            .and_then(toml::Value::as_str)
            .map_or_else(|| name.to_string(), ToString::to_string),
        optional: table.get("optional").and_then(toml::Value::as_bool).unwrap_or(false),
    })
}

fn parse_package_json(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "package.json") else {
        return;
    };
    let value = match serde_json::from_str::<serde_json::Value>(&contents) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(path = %manifest.display(), ?err, "failed to parse package.json for external dependency scan");
            return;
        }
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    let manifest_dir = manifest.parent().unwrap_or(root);
    let lock_versions = npm_lock_versions(root, manifest_dir);
    add_package_json_section(
        value.get("dependencies").and_then(serde_json::Value::as_object),
        "normal",
        &source_manifest,
        lock_versions.as_ref(),
        deps,
    );
    add_package_json_section(
        value.get("devDependencies").and_then(serde_json::Value::as_object),
        "dev",
        &source_manifest,
        lock_versions.as_ref(),
        deps,
    );
    add_package_json_section(
        value.get("optionalDependencies").and_then(serde_json::Value::as_object),
        "optional",
        &source_manifest,
        lock_versions.as_ref(),
        deps,
    );
}

fn add_package_json_section(
    section: Option<&serde_json::Map<String, serde_json::Value>>,
    kind: &str,
    source_manifest: &str,
    lock_versions: Option<&BTreeMap<String, String>>,
    deps: &mut Vec<ExternalDep>,
) {
    let Some(section) = section else {
        return;
    };
    for (name, value) in section {
        let Some(version_req) = value.as_str() else {
            tracing::warn!(dependency = %name, "skipping unsupported package.json dependency value");
            continue;
        };
        // workspace:/link:/file:/portal: specs are intra-repo packages, not
        // external dependencies — mirror the cargo path-dep exclusion.
        if version_req.starts_with("workspace:")
            || version_req.starts_with("link:")
            || version_req.starts_with("file:")
            || version_req.starts_with("portal:")
        {
            continue;
        }
        deps.push(ExternalDep {
            name: name.clone(),
            ecosystem: "npm".to_string(),
            version_req: Some(version_req.to_string()),
            version_locked: lock_versions.and_then(|versions| versions.get(name).cloned()),
            source_manifest: source_manifest.to_string(),
            kind: kind.to_string(),
        });
    }
}

fn npm_lock_versions(root: &Path, manifest_dir: &Path) -> Option<BTreeMap<String, String>> {
    if let Some(lock) = find_nearest_file(manifest_dir, root, "package-lock.json") {
        return package_lock_versions(&lock);
    }
    find_nearest_file(manifest_dir, root, "pnpm-lock.yaml").and_then(|lock| pnpm_lock_versions(&lock, manifest_dir))
}

fn package_lock_versions(lock: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_lockfile(lock, "package-lock.json")?;
    let value = match serde_json::from_str::<serde_json::Value>(&contents) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(path = %lock.display(), ?err, "failed to parse package-lock.json for external dependency scan");
            return None;
        }
    };
    let mut versions = BTreeMap::new();
    let Some(packages) = value.get("packages").and_then(serde_json::Value::as_object) else {
        if let Some(dependencies) = value.get("dependencies").and_then(serde_json::Value::as_object) {
            for (name, package) in dependencies {
                let Some(version) = package.get("version").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                versions.insert(name.to_string(), version.to_string());
            }
        }
        return Some(versions);
    };
    for (path, package) in packages {
        let Some(name) = path.strip_prefix("node_modules/") else {
            continue;
        };
        let Some(version) = package.get("version").and_then(serde_json::Value::as_str) else {
            continue;
        };
        versions.insert(name.to_string(), version.to_string());
    }
    Some(versions)
}

fn pnpm_lock_versions(lock: &Path, manifest_dir: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_lockfile(lock, "pnpm-lock.yaml")?;
    let value = match serde_yaml::from_str::<serde_yaml::Value>(&contents) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(path = %lock.display(), ?err, "failed to parse pnpm-lock.yaml for external dependency scan");
            return None;
        }
    };
    let lock_dir = lock.parent().unwrap_or(manifest_dir);
    let importer_key = pnpm_importer_key(lock_dir, manifest_dir);
    let Some(importers) = yaml_get(&value, "importers").and_then(serde_yaml::Value::as_mapping) else {
        return Some(BTreeMap::new());
    };
    let importer_lookup = serde_yaml::Value::String(importer_key);
    let Some(importer) = importers.get(&importer_lookup) else {
        return Some(BTreeMap::new());
    };
    let mut versions = BTreeMap::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(section_map) = yaml_get(importer, section).and_then(serde_yaml::Value::as_mapping) else {
            continue;
        };
        for (name_value, dep_value) in section_map {
            let Some(name) = name_value.as_str() else {
                continue;
            };
            let version = dep_value
                .as_mapping()
                .and_then(|mapping| {
                    mapping
                        .get(serde_yaml::Value::String("version".to_string()))
                        .and_then(serde_yaml::Value::as_str)
                })
                .or_else(|| dep_value.as_str());
            if let Some(version) = version {
                versions.insert(name.to_string(), strip_pnpm_peer_suffix(version).to_string());
            }
        }
    }
    Some(versions)
}

fn yaml_get<'a>(value: &'a serde_yaml::Value, key: &str) -> Option<&'a serde_yaml::Value> {
    value.as_mapping()?.get(serde_yaml::Value::String(key.to_string()))
}

fn pnpm_importer_key(lock_dir: &Path, manifest_dir: &Path) -> String {
    manifest_dir
        .strip_prefix(lock_dir)
        .ok()
        .and_then(Path::to_str)
        .filter(|s| !s.is_empty())
        .map_or_else(|| ".".to_string(), |s| s.replace('\\', "/"))
}

fn strip_pnpm_peer_suffix(version: &str) -> &str {
    let paren = version.find('(');
    let underscore = version.find('_');
    match (paren, underscore) {
        (Some(paren), Some(underscore)) => &version[..paren.min(underscore)],
        (Some(idx), None) | (None, Some(idx)) => &version[..idx],
        (None, None) => version,
    }
}

fn parse_requirements_txt(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "requirements.txt") else {
        return;
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    for line in contents.lines() {
        let Some((name, version_req)) = parse_requirement_line(line, manifest) else {
            continue;
        };
        deps.push(ExternalDep {
            name,
            ecosystem: "pypi".to_string(),
            version_req,
            version_locked: None,
            source_manifest: source_manifest.clone(),
            kind: "normal".to_string(),
        });
    }
}

fn parse_pyproject_toml(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "pyproject.toml") else {
        return;
    };
    let Some(value) = parse_toml(&contents, manifest, "pyproject.toml") else {
        return;
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    if let Some(project_deps) = table_at(&value, &["project"])
        .and_then(|project| project.get("dependencies"))
        .and_then(toml::Value::as_array)
    {
        for dep in project_deps {
            let Some(raw) = dep.as_str() else {
                continue;
            };
            if let Some((name, version_req)) = parse_requirement_line(raw, manifest) {
                deps.push(ExternalDep {
                    name,
                    ecosystem: "pypi".to_string(),
                    version_req,
                    version_locked: None,
                    source_manifest: source_manifest.clone(),
                    kind: "normal".to_string(),
                });
            }
        }
    }
    if let Some(optional) = table_at(&value, &["project", "optional-dependencies"]) {
        for dep_group in optional.values() {
            let Some(dep_group) = dep_group.as_array() else {
                continue;
            };
            for dep in dep_group {
                let Some(raw) = dep.as_str() else {
                    continue;
                };
                if let Some((name, version_req)) = parse_requirement_line(raw, manifest) {
                    deps.push(ExternalDep {
                        name,
                        ecosystem: "pypi".to_string(),
                        version_req,
                        version_locked: None,
                        source_manifest: source_manifest.clone(),
                        kind: "optional".to_string(),
                    });
                }
            }
        }
    }
    if let Some(poetry_deps) = table_at(&value, &["tool", "poetry", "dependencies"]) {
        for (name, value) in poetry_deps {
            if name == "python" {
                continue;
            }
            let (version_req, optional) = poetry_dep_spec(value);
            if version_req.is_none() {
                tracing::warn!(dependency = %name, "skipping unsupported poetry dependency value");
                continue;
            }
            deps.push(ExternalDep {
                name: name.clone(),
                ecosystem: "pypi".to_string(),
                version_req,
                version_locked: None,
                source_manifest: source_manifest.clone(),
                kind: if optional { "optional" } else { "normal" }.to_string(),
            });
        }
    }
}

fn poetry_dep_spec(value: &toml::Value) -> (Option<String>, bool) {
    if let Some(version) = value.as_str() {
        return (Some(version.to_string()), false);
    }
    let Some(table) = value.as_table() else {
        return (None, false);
    };
    (
        table
            .get("version")
            .and_then(toml::Value::as_str)
            .map(ToString::to_string),
        table.get("optional").and_then(toml::Value::as_bool).unwrap_or(false),
    )
}

fn parse_requirement_line(raw: &str, source: &Path) -> Option<(String, Option<String>)> {
    let without_comment = raw.split_once('#').map_or(raw, |(line, _)| line).trim();
    let without_options = without_comment
        .split_once(" --")
        .map_or(without_comment, |(requirement, _)| requirement)
        .trim_end();
    let requirement = without_options.strip_suffix('\\').unwrap_or(without_options).trim_end();
    if requirement.is_empty() {
        return None;
    }
    let lower = requirement.to_ascii_lowercase();
    if lower.starts_with("-r ")
        || lower == "-r"
        || lower.starts_with("--requirement ")
        || lower.starts_with("-e ")
        || lower == "-e"
        || lower.starts_with("--editable ")
    {
        tracing::warn!(path = %source.display(), line = %requirement, "skipping referenced or editable python requirement");
        return None;
    }
    if requirement.starts_with('-') || looks_like_url_or_local_path(requirement) || requirement.contains(" @ ") {
        tracing::warn!(path = %source.display(), line = %requirement, "skipping unsupported python requirement");
        return None;
    }
    let without_marker = requirement
        .split_once(';')
        .map_or(requirement, |(requirement, _)| requirement)
        .trim();
    let mut name_end = 0usize;
    for (idx, ch) in without_marker.char_indices() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            name_end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    if name_end == 0 {
        tracing::warn!(path = %source.display(), line = %requirement, "skipping malformed python requirement");
        return None;
    }
    let name = without_marker[..name_end].to_string();
    let mut suffix = without_marker[name_end..].trim_start();
    if let Some(after_extras) = suffix.strip_prefix('[') {
        let Some((_, rest)) = after_extras.split_once(']') else {
            tracing::warn!(path = %source.display(), line = %requirement, "skipping malformed python requirement extras");
            return None;
        };
        suffix = rest.trim_start();
    }
    let version_req = version_req_from_python_suffix(suffix);
    Some((name, version_req))
}

fn looks_like_url_or_local_path(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    line.contains("://")
        || line.starts_with('/')
        || line.starts_with("./")
        || line.starts_with("../")
        || [".whl", ".tar.gz", ".zip"].iter().any(|suffix| lower.ends_with(suffix))
}

fn version_req_from_python_suffix(suffix: &str) -> Option<String> {
    let suffix = suffix.trim();
    if suffix.is_empty() {
        return None;
    }
    for op in ["===", "==", ">=", "<=", "~=", "!=", ">", "<"] {
        if suffix.starts_with(op) {
            return Some(suffix.to_string());
        }
    }
    None
}

fn parse_go_mod(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "go.mod") else {
        return;
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    let mut in_require_block = false;
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if in_require_block {
            if line.starts_with(')') {
                in_require_block = false;
                continue;
            }
            parse_go_require_line(line, &source_manifest, deps);
            continue;
        }
        if go_require_block_start(line) {
            in_require_block = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("require ") {
            parse_go_require_line(rest.trim(), &source_manifest, deps);
        }
    }
}

fn go_require_block_start(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("require") else {
        return false;
    };
    rest.trim_start().starts_with('(')
}

fn parse_go_require_line(line: &str, source_manifest: &str, deps: &mut Vec<ExternalDep>) {
    if line.starts_with("replace ") || line.starts_with("exclude ") {
        return;
    }
    let indirect = line.contains("// indirect");
    let without_comment = line
        .split_once("//")
        .map_or(line, |(requirement, _)| requirement)
        .trim();
    let mut parts = without_comment.split_whitespace();
    let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
        return;
    };
    deps.push(ExternalDep {
        name: name.to_string(),
        ecosystem: "go".to_string(),
        version_req: Some(version.to_string()),
        version_locked: None,
        source_manifest: source_manifest.to_string(),
        kind: if indirect { "indirect" } else { "normal" }.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvVarGuard;

    fn dep<'a>(deps: &'a [ExternalDep], ecosystem: &str, source_manifest: &str, name: &str) -> &'a ExternalDep {
        deps.iter()
            .find(|dep| dep.ecosystem == ecosystem && dep.source_manifest == source_manifest && dep.name == name)
            .expect("dependency")
    }

    #[test]
    fn cargo_manifest_extracts_direct_deps_and_lock_versions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("crates/app")).expect("crate dir");
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            r#"[workspace]
members = ["crates/app"]

[workspace.dependencies]
serde = "1.0"
"#,
        )
        .expect("workspace manifest");
        std::fs::write(
            tmp.path().join("crates/app/Cargo.toml"),
            r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
serde = { workspace = true }
tokio = { version = "1", optional = true }
local = { path = "../local" }
gitdep = { git = "https://example.invalid/repo.git" }
dup = ">=1"

[dev-dependencies]
pretty_assertions = "1"

[build-dependencies]
cc = "1"
"#,
        )
        .expect("member manifest");
        std::fs::write(
            tmp.path().join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "anyhow"
version = "1.0.99"

[[package]]
name = "serde"
version = "1.0.200"

[[package]]
name = "tokio"
version = "1.40.0"

[[package]]
name = "pretty_assertions"
version = "1.4.0"

[[package]]
name = "cc"
version = "1.0.90"

[[package]]
name = "dup"
version = "1.0.0"

[[package]]
name = "dup"
version = "2.0.0"
"#,
        )
        .expect("lock");

        let deps = scan_external_deps(tmp.path());
        let anyhow = dep(&deps, "cargo", "crates/app/Cargo.toml", "anyhow");
        assert_eq!(anyhow.kind, "normal");
        assert_eq!(anyhow.version_req.as_deref(), Some("1"));
        assert_eq!(anyhow.version_locked.as_deref(), Some("1.0.99"));
        let serde = dep(&deps, "cargo", "crates/app/Cargo.toml", "serde");
        assert_eq!(serde.version_req.as_deref(), Some("1.0"));
        assert_eq!(serde.version_locked.as_deref(), Some("1.0.200"));
        assert!(deps
            .iter()
            .all(|dep| dep.source_manifest != "Cargo.toml" || dep.name != "serde"));
        assert_eq!(dep(&deps, "cargo", "crates/app/Cargo.toml", "tokio").kind, "optional");
        assert_eq!(
            dep(&deps, "cargo", "crates/app/Cargo.toml", "pretty_assertions").kind,
            "dev"
        );
        assert_eq!(dep(&deps, "cargo", "crates/app/Cargo.toml", "cc").kind, "build");
        assert!(deps.iter().all(|dep| dep.name != "local"));
        assert!(dep(&deps, "cargo", "crates/app/Cargo.toml", "gitdep")
            .version_req
            .is_none());
        assert!(dep(&deps, "cargo", "crates/app/Cargo.toml", "dup")
            .version_locked
            .is_none());
    }

    #[test]
    fn cargo_manifest_extracts_target_specific_deps() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            r#"[package]
name = "targeted"
version = "0.1.0"
edition = "2021"

[target.'cfg(windows)'.dependencies]
winapi = "0.3"

[target.'cfg(unix)'.dev-dependencies]
nix = "0.29"

[target.'cfg(target_os = "linux")'.build-dependencies]
cc = "1"
"#,
        )
        .expect("manifest");
        std::fs::write(
            tmp.path().join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "winapi"
version = "0.3.9"

[[package]]
name = "nix"
version = "0.29.0"

[[package]]
name = "cc"
version = "1.1.0"
"#,
        )
        .expect("lock");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "cargo", "Cargo.toml", "winapi").version_locked.as_deref(),
            Some("0.3.9")
        );
        assert_eq!(dep(&deps, "cargo", "Cargo.toml", "nix").kind, "dev");
        assert_eq!(dep(&deps, "cargo", "Cargo.toml", "cc").kind, "build");
    }

    #[test]
    fn npm_package_lock_v3_extracts_locked_versions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{
  "dependencies": { "express": "^4.18", "@acme/internal": "workspace:*" },
  "devDependencies": { "mocha": "^10" },
  "optionalDependencies": { "fsevents": "^2" }
}"#,
        )
        .expect("package");
        std::fs::write(
            tmp.path().join("package-lock.json"),
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/express": { "version": "4.18.3" },
    "node_modules/mocha": { "version": "10.7.0" },
    "node_modules/fsevents": { "version": "2.3.3" },
    "node_modules/transitive": { "version": "1.0.0" }
  }
}"#,
        )
        .expect("package lock");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "npm", "package.json", "express").version_locked.as_deref(),
            Some("4.18.3")
        );
        assert_eq!(dep(&deps, "npm", "package.json", "mocha").kind, "dev");
        assert_eq!(dep(&deps, "npm", "package.json", "fsevents").kind, "optional");
        assert!(deps.iter().all(|dep| dep.name != "transitive"));
        assert!(
            deps.iter().all(|dep| dep.name != "@acme/internal"),
            "workspace: deps are intra-repo packages and must be excluded"
        );
    }

    #[test]
    fn npm_package_lock_v1_extracts_top_level_dependency_versions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18"},"devDependencies":{"mocha":"^10"}}"#,
        )
        .expect("package");
        std::fs::write(
            tmp.path().join("package-lock.json"),
            r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.18.3",
      "dependencies": {
        "body-parser": { "version": "1.20.3" }
      }
    },
    "mocha": { "version": "10.7.0" }
  }
}"#,
        )
        .expect("package lock");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "npm", "package.json", "express").version_locked.as_deref(),
            Some("4.18.3")
        );
        assert_eq!(
            dep(&deps, "npm", "package.json", "mocha").version_locked.as_deref(),
            Some("10.7.0")
        );
        assert!(deps.iter().all(|dep| dep.name != "body-parser"));
    }

    #[test]
    fn package_lock_over_manifest_size_cap_still_extracts_locked_versions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18"}}"#,
        )
        .expect("package");
        let padding = " ".repeat((MAX_FILE_BYTES as usize) + 1);
        std::fs::write(
            tmp.path().join("package-lock.json"),
            format!(
                r#"{{
  "lockfileVersion": 3,
  "packages": {{
    "node_modules/express": {{ "version": "4.18.3" }}
  }}
{padding}
}}"#
            ),
        )
        .expect("package lock");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "npm", "package.json", "express").version_locked.as_deref(),
            Some("4.18.3")
        );
    }

    #[test]
    fn npm_pnpm_lock_9_extracts_importer_versions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"react":"^18","next":"^13"},"devDependencies":{"vite":"^5"}}"#,
        )
        .expect("package");
        std::fs::write(
            tmp.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18
        version: 18.3.1(@types/react@18.3.0)
      next:
        specifier: ^13
        version: 13.4.0_react@18.2.0
    devDependencies:
      vite:
        specifier: ^5
        version: 5.4.0
"#,
        )
        .expect("pnpm lock");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "npm", "package.json", "react").version_locked.as_deref(),
            Some("18.3.1")
        );
        assert_eq!(
            dep(&deps, "npm", "package.json", "next").version_locked.as_deref(),
            Some("13.4.0")
        );
        assert_eq!(
            dep(&deps, "npm", "package.json", "vite").version_locked.as_deref(),
            Some("5.4.0")
        );
    }

    #[test]
    fn python_requirements_extracts_pep508_lite_and_skips_references() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("requirements.txt"),
            r#"# comment
requests[security]>=2.31.0; python_version >= "3.10"
urllib3>=1,<2 # inline comment
-r other.txt
-e .
https://example.invalid/pkg.whl
./localpkg
"#,
        )
        .expect("requirements");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "pypi", "requirements.txt", "requests")
                .version_req
                .as_deref(),
            Some(">=2.31.0")
        );
        assert_eq!(
            dep(&deps, "pypi", "requirements.txt", "urllib3").version_req.as_deref(),
            Some(">=1,<2")
        );
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn python_requirements_directory_files_and_inline_options_are_parsed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("requirements")).expect("requirements dir");
        std::fs::write(
            tmp.path().join("requirements/base.txt"),
            r#"requests==2.31.0 --hash=sha256:aaaaaaaa \
urllib3>=1,<2 \
"#,
        )
        .expect("requirements");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "pypi", "requirements/base.txt", "requests")
                .version_req
                .as_deref(),
            Some("==2.31.0")
        );
        assert_eq!(
            dep(&deps, "pypi", "requirements/base.txt", "urllib3")
                .version_req
                .as_deref(),
            Some(">=1,<2")
        );
    }

    #[test]
    fn pyproject_extracts_pep621_and_poetry_deps() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("pyproject.toml"),
            r#"[project]
dependencies = ["requests>=2", "flask[async]==3.0.0; python_version >= '3.10'"]

[project.optional-dependencies]
dev = ["pytest>=8"]

[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"
click = { version = ">=8,<9", optional = true }
"#,
        )
        .expect("pyproject");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "pypi", "pyproject.toml", "requests").version_req.as_deref(),
            Some(">=2")
        );
        assert_eq!(
            dep(&deps, "pypi", "pyproject.toml", "flask").version_req.as_deref(),
            Some("==3.0.0")
        );
        assert_eq!(dep(&deps, "pypi", "pyproject.toml", "pytest").kind, "optional");
        assert_eq!(
            dep(&deps, "pypi", "pyproject.toml", "httpx").version_req.as_deref(),
            Some("^0.27")
        );
        assert_eq!(dep(&deps, "pypi", "pyproject.toml", "click").kind, "optional");
        assert!(deps.iter().all(|dep| dep.name != "python"));
    }

    #[test]
    fn go_mod_extracts_block_single_and_indirect_requirements() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("go.mod"),
            r#"module example.com/app

require ( // core deps
  github.com/a/b v1.2.3
  github.com/indirect/lib v0.1.0 // indirect
)

require(
  github.com/tight/block v1.1.0
)

require golang.org/x/sync v0.7.0
replace github.com/a/b => ../b
exclude github.com/old/pkg v1.0.0
"#,
        )
        .expect("go mod");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "go", "go.mod", "github.com/a/b").version_req.as_deref(),
            Some("v1.2.3")
        );
        assert_eq!(dep(&deps, "go", "go.mod", "github.com/indirect/lib").kind, "indirect");
        assert_eq!(
            dep(&deps, "go", "go.mod", "golang.org/x/sync").version_req.as_deref(),
            Some("v0.7.0")
        );
        assert_eq!(
            dep(&deps, "go", "go.mod", "github.com/tight/block")
                .version_req
                .as_deref(),
            Some("v1.1.0")
        );
        assert!(deps.iter().all(|dep| dep.name != "github.com/old/pkg"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_loop_is_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a/b");
        std::fs::create_dir_all(&nested).expect("nested dirs");
        std::os::unix::fs::symlink(tmp.path(), nested.join("loop")).expect("symlink");
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"left-pad":"1"}}"#).expect("package");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "left-pad");
    }

    #[test]
    fn manifest_cap_allows_more_than_legacy_limit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for idx in 0..=500 {
            let package_dir = tmp.path().join(format!("pkg{idx:04}"));
            std::fs::create_dir_all(&package_dir).expect("package dir");
            std::fs::write(package_dir.join("package.json"), r#"{"dependencies":{"dep":"1"}}"#).expect("package");
        }

        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 501);
        assert_eq!(
            dep(&deps, "npm", "pkg0500/package.json", "dep").version_req.as_deref(),
            Some("1")
        );
    }

    #[test]
    fn manifest_scan_order_is_deterministic() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("b")).expect("b dir");
        std::fs::create_dir_all(tmp.path().join("a")).expect("a dir");
        std::fs::write(
            tmp.path().join("b/package.json"),
            r#"{"dependencies":{"zeta":"1","alpha":"1"}}"#,
        )
        .expect("b package");
        std::fs::write(tmp.path().join("a/go.mod"), "module a\nrequire example.com/a v1.0.0\n").expect("a go");

        let first = scan_external_deps(tmp.path());
        let second = scan_external_deps(tmp.path());
        assert_eq!(first, second);
        let keys: Vec<_> = first
            .iter()
            .map(|dep| (dep.source_manifest.as_str(), dep.ecosystem.as_str(), dep.name.as_str()))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted);
    }

    #[test]
    #[serial_test::serial]
    fn flag_off_scan_serializes_without_external_dependency_fields() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"express":"^4"}}"#).expect("package");
        std::fs::write(tmp.path().join("main.ts"), "export function main() {}\n").expect("ts");

        let _env = EnvVarGuard::unset(EXTERNAL_DEPS_ENV);
        let scan = crate::workspace_scan_polyglot::run_repo_scan_at(tmp.path()).expect("scan");
        let json = serde_json::to_string(&scan).expect("scan json");
        assert!(!json.contains("external_deps"));
        assert!(!json.contains("external_dep_count"));
    }

    #[test]
    fn old_scan_json_without_external_dependency_fields_decodes() {
        let json = r#"{
  "scan_id": "old",
  "root_path": "/tmp/repo",
  "started_at_unix_ms": 1,
  "finished_at_unix_ms": 2,
  "duration_ms": 1,
  "crates": [],
  "files": [],
  "symbols": [],
  "deps": [],
  "stubs": [],
  "dead_code": [],
  "stats": {
    "crate_count": 0,
    "file_count": 0,
    "total_loc": 0,
    "symbol_count": 0,
    "dep_count": 0,
    "stub_count": 0,
    "dead_code_count": 0
  }
}"#;
        let scan: crate::workspace_scan::WorkspaceScan = serde_json::from_str(json).expect("old scan");
        assert!(scan.external_deps.is_empty());
        assert_eq!(scan.stats.external_dep_count, 0);
    }
}
