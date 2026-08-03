// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Manifest and lockfile extraction for external dependencies.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

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

pub fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        !(v.is_empty() || v == "0" || v == "false" || v == "off" || v == "no")
    })
}

pub fn external_deps_enabled_from_env() -> bool {
    env_flag_enabled(EXTERNAL_DEPS_ENV)
}

pub fn attach_external_deps_if_enabled(root: &Path, scan: &mut crate::workspace_scan::WorkspaceScan) {
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
            "pom.xml" => parse_maven_pom(root, manifest, &mut deps),
            "build.gradle" | "build.gradle.kts" => parse_gradle_manifest(root, manifest, &mut deps),
            "Gemfile" => parse_gemfile(root, manifest, &mut deps),
            "Package.swift" => parse_swift_package(root, manifest, &mut deps),
            "composer.json" => parse_composer_manifest(root, manifest, &mut deps),
            _ if manifest.extension().and_then(|ext| ext.to_str()) == Some("csproj") => {
                parse_csproj(root, manifest, &mut deps);
            }
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
    // Preserve the pre-M2 cap surface: manifests supported before this
    // milestone always claim slots before newly supported ecosystems.
    let (mut pre_m2, later): (Vec<_>, Vec<_>) = out.into_iter().partition(|path| is_pre_m2_manifest_path(path));
    let (m2, m4): (Vec<_>, Vec<_>) = later.into_iter().partition(|path| is_m2_manifest_path(path));
    pre_m2.extend(m2);
    pre_m2.extend(m4);
    pre_m2
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        "node_modules" | "target" | "vendor" | ".git" | "dist" | "build" | ".venv" | "venv" | "__pycache__"
    )
}

fn is_manifest_name(name: &str) -> bool {
    matches!(
        name,
        "Cargo.toml"
            | "package.json"
            | "pyproject.toml"
            | "go.mod"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "Gemfile"
            | "Package.swift"
            | "composer.json"
    ) || is_requirements_file(name)
}

fn is_requirements_file(name: &str) -> bool {
    name.starts_with("requirements") && Path::new(name).extension().and_then(|ext| ext.to_str()) == Some("txt")
}

fn is_manifest_path(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    is_manifest_name(name)
        || is_requirements_path(path)
        || path.extension().and_then(|ext| ext.to_str()) == Some("csproj")
}

fn is_pre_m2_manifest_path(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    matches!(name, "Cargo.toml" | "package.json" | "pyproject.toml" | "go.mod")
        || is_requirements_file(name)
        || is_requirements_path(path)
}

fn is_m2_manifest_path(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    matches!(name, "pom.xml" | "build.gradle" | "build.gradle.kts" | "Gemfile")
        || path.extension().and_then(|ext| ext.to_str()) == Some("csproj")
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
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
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
    let lock_versions = pypi_lock_versions(root, manifest.parent().unwrap_or(root));
    for line in contents.lines() {
        let Some((name, version_req)) = parse_requirement_line(line, manifest) else {
            continue;
        };
        deps.push(ExternalDep {
            name: name.clone(),
            ecosystem: "pypi".to_string(),
            version_req,
            version_locked: lock_versions
                .as_ref()
                .and_then(|versions| versions.get(&normalize_pypi_name(&name)).cloned()),
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
    let lock_versions = pypi_lock_versions(root, manifest.parent().unwrap_or(root));
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
                    name: name.clone(),
                    ecosystem: "pypi".to_string(),
                    version_req,
                    version_locked: lock_versions
                        .as_ref()
                        .and_then(|versions| versions.get(&normalize_pypi_name(&name)).cloned()),
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
                        name: name.clone(),
                        ecosystem: "pypi".to_string(),
                        version_req,
                        version_locked: lock_versions
                            .as_ref()
                            .and_then(|versions| versions.get(&normalize_pypi_name(&name)).cloned()),
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
                version_locked: lock_versions
                    .as_ref()
                    .and_then(|versions| versions.get(&normalize_pypi_name(name)).cloned()),
                source_manifest: source_manifest.clone(),
                kind: if optional { "optional" } else { "normal" }.to_string(),
            });
        }
    }
}

fn pypi_lock_versions(root: &Path, manifest_dir: &Path) -> Option<BTreeMap<String, String>> {
    for file_name in ["poetry.lock", "uv.lock"] {
        if let Some(lock) = find_nearest_file(manifest_dir, root, file_name) {
            return parse_pypi_toml_lock(&lock, file_name);
        }
    }
    None
}

fn parse_pypi_toml_lock(lock: &Path, label: &str) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_lockfile(lock, label)?;
    let value = parse_toml(&contents, lock, label)?;
    let mut versions = BTreeMap::new();
    let Some(packages) = value.get("package").and_then(toml::Value::as_array) else {
        return Some(versions);
    };
    for package in packages {
        let Some(package) = package.as_table() else {
            continue;
        };
        let (Some(name), Some(version)) = (
            package.get("name").and_then(toml::Value::as_str),
            package.get("version").and_then(toml::Value::as_str),
        ) else {
            continue;
        };
        versions.insert(normalize_pypi_name(name), version.to_string());
    }
    Some(versions)
}

fn normalize_pypi_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut separator = false;
    for ch in name.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !separator {
                normalized.push('-');
            }
            separator = true;
        } else {
            normalized.extend(ch.to_lowercase());
            separator = false;
        }
    }
    normalized
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
    let mut suffix = suffix.trim();
    // PEP 508 allows a parenthesized version specifier: `build (>=1.2.1,<2.0.0)`.
    // Unwrap one level so those declarations keep their version_req.
    if let Some(inner) = suffix.strip_prefix('(').and_then(|rest| rest.strip_suffix(')')) {
        suffix = inner.trim();
    }
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
    let lock_versions =
        find_nearest_file(manifest.parent().unwrap_or(root), root, "go.sum").and_then(|lock| parse_go_sum(&lock));
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
            parse_go_require_line(line, &source_manifest, lock_versions.as_ref(), deps);
            continue;
        }
        if go_require_block_start(line) {
            in_require_block = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("require ") {
            parse_go_require_line(rest.trim(), &source_manifest, lock_versions.as_ref(), deps);
        }
    }
}

fn go_require_block_start(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("require") else {
        return false;
    };
    rest.trim_start().starts_with('(')
}

fn parse_go_require_line(
    line: &str,
    source_manifest: &str,
    lock_versions: Option<&BTreeMap<String, BTreeSet<String>>>,
    deps: &mut Vec<ExternalDep>,
) {
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
        version_locked: lock_versions
            .and_then(|versions| versions.get(name))
            .and_then(|versions| versions.contains(version).then(|| version.to_string())),
        source_manifest: source_manifest.to_string(),
        kind: if indirect { "indirect" } else { "normal" }.to_string(),
    });
}

fn parse_go_sum(lock: &Path) -> Option<BTreeMap<String, BTreeSet<String>>> {
    let contents = read_utf8_lockfile(lock, "go.sum")?;
    let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(raw_version), Some(_hash)) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        if raw_version.ends_with("/go.mod") {
            continue;
        }
        let version = raw_version;
        versions
            .entry(name.to_string())
            .or_default()
            .insert(version.to_string());
    }
    Some(versions)
}

fn parse_maven_pom(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "pom.xml") else {
        return;
    };
    let document = match roxmltree::Document::parse(&contents) {
        Ok(document) => document,
        Err(err) => {
            tracing::warn!(path = %manifest.display(), ?err, "failed to parse pom.xml for external dependency scan");
            return;
        }
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    let project = document.root_element();
    let mut properties = BTreeMap::new();
    if let Some(property_node) = xml_child(project, "properties") {
        for property in property_node.children().filter(roxmltree::Node::is_element) {
            if let Some(value) = property.text() {
                properties.insert(property.tag_name().name().to_string(), value.trim().to_string());
            }
        }
    }
    for dependency in project.descendants().filter(|node| xml_is(*node, "dependency")) {
        let Some(parent) = dependency.parent() else {
            continue;
        };
        if !xml_is(parent, "dependencies")
            || dependency.ancestors().any(|ancestor| {
                xml_is(ancestor, "dependencyManagement") || xml_is(ancestor, "plugin") || xml_is(ancestor, "profile")
            })
        {
            continue;
        }
        let (Some(group), Some(artifact)) = (
            xml_child_text(dependency, "groupId"),
            xml_child_text(dependency, "artifactId"),
        ) else {
            continue;
        };
        let group = interpolate_maven_properties(&group, &properties);
        let artifact = interpolate_maven_properties(&artifact, &properties);
        let version_req =
            xml_child_text(dependency, "version").map(|version| interpolate_maven_properties(&version, &properties));
        let kind = if xml_child_text(dependency, "scope").as_deref() == Some("test") {
            "dev"
        } else {
            "normal"
        };
        deps.push(ExternalDep {
            name: format!("{group}:{artifact}"),
            ecosystem: "maven".to_string(),
            version_req,
            version_locked: None,
            source_manifest: source_manifest.clone(),
            kind: kind.to_string(),
        });
    }
}

fn xml_is(node: roxmltree::Node<'_, '_>, name: &str) -> bool {
    node.is_element() && node.tag_name().name() == name
}

fn xml_child<'a, 'input>(node: roxmltree::Node<'a, 'input>, name: &str) -> Option<roxmltree::Node<'a, 'input>> {
    node.children().find(|child| xml_is(*child, name))
}

fn xml_child_text(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    xml_child(node, name)?.text().map(|text| text.trim().to_string())
}

fn interpolate_maven_properties(value: &str, properties: &BTreeMap<String, String>) -> String {
    let mut interpolated = value.to_string();
    let mut search_from = 0usize;
    for _ in 0..16 {
        let Some(relative_start) = interpolated[search_from..].find("${") else {
            break;
        };
        let start = search_from + relative_start;
        let Some(relative_end) = interpolated[start + 2..].find('}') else {
            break;
        };
        let end = start + 2 + relative_end;
        let key = &interpolated[start + 2..end];
        if let Some(replacement) = properties.get(key) {
            interpolated.replace_range(start..=end, replacement);
            search_from = start;
        } else {
            search_from = end + 1;
        }
    }
    interpolated
}

static GRADLE_DEP_RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
    regex::Regex::new(
        r#"^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly|androidTestImplementation|debugImplementation|releaseImplementation)\s*(?:\(\s*)?[\"']([^\"']+)[\"']"#,
    )
    .ok()
});

fn parse_gradle_manifest(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "Gradle build file") else {
        return;
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    let Some(pattern) = GRADLE_DEP_RE.as_ref() else {
        tracing::warn!("failed to initialize Gradle dependency pattern");
        return;
    };
    let mut in_block_comment = false;
    for raw_line in contents.lines() {
        let uncommented = strip_gradle_comments(raw_line, &mut in_block_comment);
        let Some(captures) = pattern.captures(&uncommented) else {
            continue;
        };
        let (Some(configuration), Some(coordinates)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let parts: Vec<_> = coordinates.as_str().split(':').collect();
        if parts.len() != 3
            || parts.iter().any(|part| part.is_empty())
            || parts
                .iter()
                .any(|part| part.chars().any(|ch| matches!(ch, '$' | '{' | '}')))
            || gradle_version_is_dynamic(parts[2])
        {
            continue;
        }
        deps.push(ExternalDep {
            name: format!("{}:{}", parts[0], parts[1]),
            ecosystem: "maven".to_string(),
            version_req: Some(parts[2].to_string()),
            version_locked: None,
            source_manifest: source_manifest.clone(),
            kind: if configuration.as_str().to_ascii_lowercase().contains("test") {
                "dev"
            } else {
                "normal"
            }
            .to_string(),
        });
    }
}

fn strip_gradle_comments(line: &str, in_block_comment: &mut bool) -> String {
    let mut output = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut quote = None;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if *in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                *in_block_comment = false;
            }
            continue;
        }
        if let Some(active_quote) = quote {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
            output.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            break;
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            *in_block_comment = true;
        } else {
            output.push(ch);
        }
    }
    output
}

fn gradle_version_is_dynamic(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    version
        .chars()
        .any(|ch| matches!(ch, '$' | '{' | '}' | '+' | '[' | ']' | '(' | ')'))
        || lower.starts_with("latest.")
}

static GEM_SPEC_RE: LazyLock<Option<regex::Regex>> =
    LazyLock::new(|| regex::Regex::new(r"^    ([A-Za-z0-9_.-]+) \(([^ )]+)").ok());

fn parse_gemfile(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "Gemfile") else {
        return;
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    let lock_versions = find_nearest_file(manifest.parent().unwrap_or(root), root, "Gemfile.lock")
        .and_then(|lock| parse_gemfile_lock(&lock));
    let mut block_stack = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.split_once('#').map_or(raw_line, |(before, _)| before).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("group ") || line.starts_with("group(") {
            block_stack.push(line.contains(":test") || line.contains(":development"));
            continue;
        }
        if line == "end" {
            block_stack.pop();
            continue;
        }
        if line.ends_with(" do") {
            block_stack.push(false);
        }
        let Some(rest) = line
            .strip_prefix("gem")
            .filter(|rest| rest.starts_with(char::is_whitespace) || rest.starts_with('('))
        else {
            continue;
        };
        let quoted = ruby_quoted_literals(rest);
        let Some(name) = quoted.first() else {
            continue;
        };
        let version_req = gem_version_req(rest, &quoted);
        deps.push(ExternalDep {
            name: name.value.clone(),
            ecosystem: "rubygems".to_string(),
            version_req,
            version_locked: lock_versions
                .as_ref()
                .and_then(|versions| versions.get(&name.value).cloned()),
            source_manifest: source_manifest.clone(),
            kind: if block_stack.iter().any(|is_dev| *is_dev) {
                "dev"
            } else {
                "normal"
            }
            .to_string(),
        });
    }
}

#[derive(Debug)]
struct RubyQuotedLiteral {
    value: String,
    start: usize,
}

fn ruby_quoted_literals(value: &str) -> Vec<RubyQuotedLiteral> {
    let mut values = Vec::new();
    let mut chars = value.char_indices().peekable();
    while let Some((start, ch)) = chars.next() {
        if ch != '\'' && ch != '"' {
            continue;
        }
        let quote = ch;
        let mut literal = String::new();
        let mut escaped = false;
        for (_, next) in chars.by_ref() {
            if escaped {
                literal.push(next);
                escaped = false;
            } else if next == '\\' {
                escaped = true;
            } else if next == quote {
                values.push(RubyQuotedLiteral { value: literal, start });
                break;
            } else {
                literal.push(next);
            }
        }
    }
    values
}

fn gem_version_req(rest: &str, quoted: &[RubyQuotedLiteral]) -> Option<String> {
    let name = quoted.first()?;
    let option_start = gem_option_start(rest).unwrap_or(rest.len());
    let constraints: Vec<_> = quoted
        .iter()
        .skip(1)
        .take_while(|literal| literal.start < option_start)
        .map(|literal| literal.value.as_str())
        .filter(|literal| gem_version_shaped(literal))
        .collect();
    if name.start >= option_start || constraints.is_empty() {
        None
    } else {
        Some(constraints.join(", "))
    }
}

fn gem_option_start(value: &str) -> Option<usize> {
    static GEM_OPTION_RE: LazyLock<Option<regex::Regex>> =
        LazyLock::new(|| regex::Regex::new(r"(?:\b[A-Za-z_][A-Za-z0-9_]*\s*:|:[A-Za-z_][A-Za-z0-9_]*\s*=>)").ok());
    GEM_OPTION_RE.as_ref()?.find(value).map(|matched| matched.start())
}

fn gem_version_shaped(value: &str) -> bool {
    value.starts_with(|ch: char| ch.is_ascii_digit())
        || ["~>", ">=", "<=", "!=", ">", "<", "="]
            .iter()
            .any(|prefix| value.starts_with(prefix))
}

fn parse_gemfile_lock(lock: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_lockfile(lock, "Gemfile.lock")?;
    let pattern = GEM_SPEC_RE.as_ref()?;
    let mut in_gem = false;
    let mut in_specs = false;
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for line in contents.lines() {
        if !line.starts_with(' ') {
            in_gem = line == "GEM";
            in_specs = false;
            continue;
        }
        if in_gem && line.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        if !in_specs {
            continue;
        }
        let Some(captures) = pattern.captures(line) else {
            continue;
        };
        let (Some(name), Some(version)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let name = name.as_str();
        let version = version.as_str();
        versions
            .entry(name.to_string())
            .and_modify(|existing| {
                if gem_version_is_platform_specific(existing) && !gem_version_is_platform_specific(version) {
                    *existing = version.to_string();
                }
            })
            .or_insert_with(|| version.to_string());
    }
    Some(versions)
}

fn gem_version_is_platform_specific(version: &str) -> bool {
    version.split_once('-').is_some_and(|(_, suffix)| {
        [
            "linux", "darwin", "mingw", "java", "x86", "arm", "aarch", "mswin", "musl",
        ]
        .iter()
        .any(|platform| suffix.contains(platform))
    })
}

fn parse_csproj(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "csproj") else {
        return;
    };
    let document = match roxmltree::Document::parse(&contents) {
        Ok(document) => document,
        Err(err) => {
            tracing::warn!(path = %manifest.display(), ?err, "failed to parse csproj for external dependency scan");
            return;
        }
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    let manifest_dir = manifest.parent().unwrap_or(root);
    let central_versions = find_nearest_file(manifest_dir, root, "Directory.Packages.props")
        .and_then(|props| parse_nuget_central_versions(&props));
    let lock_versions =
        find_nearest_file(manifest_dir, root, "packages.lock.json").and_then(|lock| parse_nuget_lock(&lock));
    for reference in document.descendants().filter(|node| xml_is(*node, "PackageReference")) {
        let Some(name) = reference.attribute("Include") else {
            continue;
        };
        if reference.attribute("Remove").is_some() {
            continue;
        }
        let key = name.to_ascii_lowercase();
        let version_req = reference
            .attribute("Version")
            .map(ToString::to_string)
            .or_else(|| xml_child_text(reference, "Version"))
            .or_else(|| {
                central_versions
                    .as_ref()
                    .and_then(|versions| versions.get(&key).cloned())
            });
        deps.push(ExternalDep {
            name: name.to_string(),
            ecosystem: "nuget".to_string(),
            version_req,
            version_locked: lock_versions.as_ref().and_then(|versions| versions.get(&key).cloned()),
            source_manifest: source_manifest.clone(),
            kind: "normal".to_string(),
        });
    }
}

fn parse_nuget_central_versions(props: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_file(props, "Directory.Packages.props")?;
    let document = match roxmltree::Document::parse(&contents) {
        Ok(document) => document,
        Err(err) => {
            tracing::warn!(path = %props.display(), ?err, "failed to parse Directory.Packages.props");
            return None;
        }
    };
    let mut versions = BTreeMap::new();
    for package in document.descendants().filter(|node| xml_is(*node, "PackageVersion")) {
        let Some(name) = package.attribute("Include").or_else(|| package.attribute("Update")) else {
            continue;
        };
        let version = package
            .attribute("Version")
            .map(ToString::to_string)
            .or_else(|| xml_child_text(package, "Version"));
        if let Some(version) = version {
            versions.insert(name.to_ascii_lowercase(), version);
        }
    }
    Some(versions)
}

fn parse_nuget_lock(lock: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_lockfile(lock, "packages.lock.json")?;
    let value = match serde_json::from_str::<serde_json::Value>(&contents) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(path = %lock.display(), ?err, "failed to parse packages.lock.json");
            return None;
        }
    };
    let mut versions = BTreeMap::new();
    let Some(frameworks) = value.get("dependencies").and_then(serde_json::Value::as_object) else {
        return Some(versions);
    };
    for packages in frameworks.values().filter_map(serde_json::Value::as_object) {
        for (name, package) in packages {
            if package.get("type").and_then(serde_json::Value::as_str) != Some("Direct") {
                continue;
            }
            let Some(version) = package.get("resolved").and_then(serde_json::Value::as_str) else {
                continue;
            };
            versions.insert(name.to_ascii_lowercase(), version.to_string());
        }
    }
    Some(versions)
}

static SWIFTPM_PACKAGE_RE: LazyLock<Option<regex::Regex>> =
    LazyLock::new(|| regex::Regex::new(r"(?s)\.package\s*\((.*?)\)").ok());
static SWIFTPM_URL_RE: LazyLock<Option<regex::Regex>> =
    LazyLock::new(|| regex::Regex::new(r#"url\s*:\s*\"([^\"]+)\""#).ok());
static SWIFTPM_REQUIREMENT_RE: LazyLock<Option<regex::Regex>> =
    LazyLock::new(|| regex::Regex::new(r#"\b(from|exact|branch|revision)\s*:\s*\"([^\"]+)\""#).ok());

fn parse_swift_package(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "Package.swift") else {
        return;
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    let Some(package_pattern) = SWIFTPM_PACKAGE_RE.as_ref() else {
        tracing::warn!("failed to initialize SwiftPM package pattern");
        return;
    };
    let Some(url_pattern) = SWIFTPM_URL_RE.as_ref() else {
        tracing::warn!("failed to initialize SwiftPM URL pattern");
        return;
    };
    let lock_versions = find_nearest_file(manifest.parent().unwrap_or(root), root, "Package.resolved")
        .and_then(|lock| parse_swift_package_resolved(&lock));
    for capture in package_pattern.captures_iter(&contents) {
        let Some(arguments) = capture.get(1).map(|matched| matched.as_str()) else {
            continue;
        };
        let Some(url) = url_pattern
            .captures(arguments)
            .and_then(|captures| captures.get(1))
            .map(|matched| matched.as_str())
        else {
            continue;
        };
        let Some(name) = package_name_from_url(url) else {
            continue;
        };
        let version_req = SWIFTPM_REQUIREMENT_RE.as_ref().and_then(|pattern| {
            pattern.captures(arguments).and_then(|captures| {
                let label = captures.get(1)?.as_str();
                let value = captures.get(2)?.as_str();
                Some(format!("{label}: {value}"))
            })
        });
        deps.push(ExternalDep {
            name: name.clone(),
            ecosystem: "swiftpm".to_string(),
            version_req,
            version_locked: lock_versions
                .as_ref()
                .and_then(|versions| versions.get(&name.to_ascii_lowercase()).cloned()),
            source_manifest: source_manifest.clone(),
            kind: "normal".to_string(),
        });
    }
}

fn package_name_from_url(url: &str) -> Option<String> {
    let trimmed = url.trim_end_matches('/');
    let name = trimmed.rsplit('/').next()?.trim_end_matches(".git");
    (!name.is_empty()).then(|| name.to_string())
}

fn parse_swift_package_resolved(lock: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_lockfile(lock, "Package.resolved")?;
    let value = match serde_json::from_str::<serde_json::Value>(&contents) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(path = %lock.display(), ?err, "failed to parse Package.resolved");
            return None;
        }
    };
    let mut versions = BTreeMap::new();
    let pins = value
        .get("pins")
        .or_else(|| value.get("object").and_then(|object| object.get("pins")))
        .and_then(serde_json::Value::as_array);
    let Some(pins) = pins else {
        return Some(versions);
    };
    for pin in pins {
        let name = pin
            .get("identity")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                pin.get("package")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
            })
            .or_else(|| {
                pin.get("location")
                    .or_else(|| pin.get("repositoryURL"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(package_name_from_url)
            });
        let version = pin
            .get("state")
            .and_then(|state| state.get("version"))
            .and_then(serde_json::Value::as_str);
        if let (Some(name), Some(version)) = (name, version) {
            versions.insert(name.to_ascii_lowercase(), version.to_string());
        }
    }
    Some(versions)
}

fn parse_composer_manifest(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "composer.json") else {
        return;
    };
    let value = match serde_json::from_str::<serde_json::Value>(&contents) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(path = %manifest.display(), ?err, "failed to parse composer.json");
            return;
        }
    };
    let Some(source_manifest) = rel_path(root, manifest) else {
        return;
    };
    let lock_versions = find_nearest_file(manifest.parent().unwrap_or(root), root, "composer.lock")
        .and_then(|lock| parse_composer_lock(&lock));
    for (section, kind) in [("require", "normal"), ("require-dev", "dev")] {
        let Some(requirements) = value.get(section).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (name, requirement) in requirements {
            let lower = name.to_ascii_lowercase();
            if is_composer_platform_package(&lower) {
                continue;
            }
            let Some(version_req) = requirement.as_str() else {
                tracing::warn!(path = %manifest.display(), dependency = %name, "skipping non-string Composer requirement");
                continue;
            };
            deps.push(ExternalDep {
                name: name.clone(),
                ecosystem: "composer".to_string(),
                version_req: Some(version_req.to_string()),
                version_locked: lock_versions
                    .as_ref()
                    .and_then(|versions| versions.get(&lower).cloned()),
                source_manifest: source_manifest.clone(),
                kind: kind.to_string(),
            });
        }
    }
}

fn is_composer_platform_package(name: &str) -> bool {
    matches!(
        name,
        "php"
            | "php-64bit"
            | "php-ipv6"
            | "php-zts"
            | "php-debug"
            | "hhvm"
            | "composer"
            | "composer-plugin-api"
            | "composer-runtime-api"
    ) || name.starts_with("ext-")
        || name.starts_with("lib-")
}

fn parse_composer_lock(lock: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_lockfile(lock, "composer.lock")?;
    let value = match serde_json::from_str::<serde_json::Value>(&contents) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(path = %lock.display(), ?err, "failed to parse composer.lock");
            return None;
        }
    };
    let mut versions = BTreeMap::new();
    for section in ["packages", "packages-dev"] {
        let Some(packages) = value.get(section).and_then(serde_json::Value::as_array) else {
            continue;
        };
        for package in packages {
            let (Some(name), Some(version)) = (
                package.get("name").and_then(serde_json::Value::as_str),
                package.get("version").and_then(serde_json::Value::as_str),
            ) else {
                continue;
            };
            versions.insert(name.to_ascii_lowercase(), version.to_string());
        }
    }
    Some(versions)
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
    fn python_parenthesized_pep508_specifiers_keep_version_req() {
        // poetry's own pyproject declares deps as `build (>=1.2.1,<2.0.0)`.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("requirements.txt"),
            "build (>=1.2.1,<2.0.0)\nnoversion ()\n",
        )
        .expect("requirements");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "pypi", "requirements.txt", "build").version_req.as_deref(),
            Some(">=1.2.1,<2.0.0")
        );
        assert_eq!(dep(&deps, "pypi", "requirements.txt", "noversion").version_req, None);
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

    #[test]
    fn maven_pom_extracts_properties_and_test_scope() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("pom.xml"),
            r#"<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties>
    <junit.version>5.11.0</junit.version>
    <lib.group>org.example</lib.group>
  </properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>managed</groupId><artifactId>only</artifactId><version>1</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>${lib.group}</groupId><artifactId>core</artifactId><version>2.4.0</version></dependency>
    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>${junit.version}</version><scope>test</scope></dependency>
    <dependency><groupId>org.example</groupId><artifactId>inherited</artifactId><version>${unresolved.version}-${junit.version}</version></dependency>
  </dependencies>
  <profiles><profile><dependencies>
    <dependency><groupId>profile</groupId><artifactId>only</artifactId><version>1</version></dependency>
  </dependencies></profile></profiles>
</project>"#,
        )
        .expect("pom");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "maven", "pom.xml", "org.example:core")
                .version_req
                .as_deref(),
            Some("2.4.0")
        );
        let junit = dep(&deps, "maven", "pom.xml", "org.junit.jupiter:junit-jupiter");
        assert_eq!(junit.version_req.as_deref(), Some("5.11.0"));
        assert_eq!(junit.kind, "dev");
        assert_eq!(
            dep(&deps, "maven", "pom.xml", "org.example:inherited")
                .version_req
                .as_deref(),
            Some("${unresolved.version}-5.11.0")
        );
        assert!(deps
            .iter()
            .all(|dep| dep.name != "managed:only" && dep.name != "profile:only"));
        assert_eq!(
            serde_json::to_value(&deps).expect("deps json"),
            serde_json::json!([
                {
                    "name": "org.example:core",
                    "ecosystem": "maven",
                    "version_req": "2.4.0",
                    "source_manifest": "pom.xml",
                    "kind": "normal"
                },
                {
                    "name": "org.example:inherited",
                    "ecosystem": "maven",
                    "version_req": "${unresolved.version}-5.11.0",
                    "source_manifest": "pom.xml",
                    "kind": "normal"
                },
                {
                    "name": "org.junit.jupiter:junit-jupiter",
                    "ecosystem": "maven",
                    "version_req": "5.11.0",
                    "source_manifest": "pom.xml",
                    "kind": "dev"
                }
            ])
        );
    }

    #[test]
    fn gradle_groovy_and_kotlin_extract_static_string_coordinates_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("kotlin")).expect("kotlin dir");
        std::fs::write(
            tmp.path().join("build.gradle"),
            r#"dependencies {
  implementation "com.google.guava:guava:33.3.0-jre"
  testImplementation('org.junit.jupiter:junit-jupiter:5.11.0')
  implementation "org.dynamic:plus:1.+"
  implementation libs.bundles.testing
  implementation "org.variable:dep:$version"
  implementation "$group:guava:33.0"
  // implementation "commented:out:1.0"
  println("x") /*
  implementation "ghost:lib:9.9.9"
  */
}"#,
        )
        .expect("gradle");
        std::fs::write(
            tmp.path().join("kotlin/build.gradle.kts"),
            r#"dependencies {
  api("org.jetbrains.kotlin:kotlin-stdlib:2.0.20")
  testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.0")
  implementation("org.range:dep:[1,2)")
}"#,
        )
        .expect("gradle kts");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "maven", "build.gradle", "com.google.guava:guava")
                .version_req
                .as_deref(),
            Some("33.3.0-jre")
        );
        assert_eq!(
            dep(&deps, "maven", "build.gradle", "org.junit.jupiter:junit-jupiter").kind,
            "dev"
        );
        assert_eq!(
            dep(
                &deps,
                "maven",
                "kotlin/build.gradle.kts",
                "org.jetbrains.kotlin:kotlin-stdlib"
            )
            .kind,
            "normal"
        );
        assert_eq!(
            dep(
                &deps,
                "maven",
                "kotlin/build.gradle.kts",
                "org.junit.platform:junit-platform-launcher"
            )
            .kind,
            "dev"
        );
        assert_eq!(deps.len(), 4);
        assert_eq!(
            serde_json::to_value(&deps).expect("deps json"),
            serde_json::json!([
                {
                    "name": "com.google.guava:guava",
                    "ecosystem": "maven",
                    "version_req": "33.3.0-jre",
                    "source_manifest": "build.gradle",
                    "kind": "normal"
                },
                {
                    "name": "org.junit.jupiter:junit-jupiter",
                    "ecosystem": "maven",
                    "version_req": "5.11.0",
                    "source_manifest": "build.gradle",
                    "kind": "dev"
                },
                {
                    "name": "org.jetbrains.kotlin:kotlin-stdlib",
                    "ecosystem": "maven",
                    "version_req": "2.0.20",
                    "source_manifest": "kotlin/build.gradle.kts",
                    "kind": "normal"
                },
                {
                    "name": "org.junit.platform:junit-platform-launcher",
                    "ecosystem": "maven",
                    "version_req": "1.11.0",
                    "source_manifest": "kotlin/build.gradle.kts",
                    "kind": "dev"
                }
            ])
        );
    }

    #[test]
    fn gemfile_extracts_group_kind_and_closes_from_gemfile_lock() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Gemfile"),
            r#"source "https://rubygems.org"
gem "rails", "~> 7.2"
gem('puma', '>= 6.4')
group :development, :test do
  gem "rspec", "~> 3.13"
end
"#,
        )
        .expect("Gemfile");
        std::fs::write(
            tmp.path().join("Gemfile.lock"),
            r#"GEM
  remote: https://rubygems.org/
  specs:
    puma (6.4.3)
    rails (7.2.1)
      rack (>= 2.2.4)
    rack (3.1.8)
    rspec (3.13.0)

DEPENDENCIES
  puma (>= 6.4)
  rails (~> 7.2)
  rspec (~> 3.13)
"#,
        )
        .expect("Gemfile.lock");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "rubygems", "Gemfile", "rails").version_locked.as_deref(),
            Some("7.2.1")
        );
        assert_eq!(
            dep(&deps, "rubygems", "Gemfile", "puma").version_req.as_deref(),
            Some(">= 6.4")
        );
        assert_eq!(dep(&deps, "rubygems", "Gemfile", "rspec").kind, "dev");
        assert!(deps.iter().all(|dep| dep.name != "rack"));
        assert_eq!(
            serde_json::to_value(&deps).expect("deps json"),
            serde_json::json!([
                {
                    "name": "puma",
                    "ecosystem": "rubygems",
                    "version_req": ">= 6.4",
                    "version_locked": "6.4.3",
                    "source_manifest": "Gemfile",
                    "kind": "normal"
                },
                {
                    "name": "rails",
                    "ecosystem": "rubygems",
                    "version_req": "~> 7.2",
                    "version_locked": "7.2.1",
                    "source_manifest": "Gemfile",
                    "kind": "normal"
                },
                {
                    "name": "rspec",
                    "ecosystem": "rubygems",
                    "version_req": "~> 3.13",
                    "version_locked": "3.13.0",
                    "source_manifest": "Gemfile",
                    "kind": "dev"
                }
            ])
        );
    }

    #[test]
    fn gemfile_options_nested_groups_constraints_and_platform_locks_are_precise() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Gemfile"),
            r#"gem "elasticsearch-model", require: "elasticsearch/model"
gem "source-only", source: "https://gems.example.invalid"
gem "git-only", :git => "https://git.example.invalid/repo.git"
gem "rails", ">= 5.0", "< 7", require: false
gem "nokogiri", ">= 1"
group :test do
  group :development do
    gem "inner"
  end
  gem "after-nested"
end
"#,
        )
        .expect("Gemfile");
        std::fs::write(
            tmp.path().join("Gemfile.lock"),
            r#"GEM
  specs:
    nokogiri (1.16.5)
    nokogiri (1.16.5-x86_64-linux)
"#,
        )
        .expect("Gemfile.lock");

        let deps = scan_external_deps(tmp.path());
        for name in ["elasticsearch-model", "source-only", "git-only"] {
            assert!(dep(&deps, "rubygems", "Gemfile", name).version_req.is_none());
        }
        assert_eq!(
            dep(&deps, "rubygems", "Gemfile", "rails").version_req.as_deref(),
            Some(">= 5.0, < 7")
        );
        assert_eq!(dep(&deps, "rubygems", "Gemfile", "inner").kind, "dev");
        assert_eq!(dep(&deps, "rubygems", "Gemfile", "after-nested").kind, "dev");
        assert_eq!(
            dep(&deps, "rubygems", "Gemfile", "nokogiri").version_locked.as_deref(),
            Some("1.16.5")
        );
    }

    #[test]
    fn nuget_csproj_uses_central_versions_and_direct_lock_entries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("src/App")).expect("app dir");
        std::fs::write(
            tmp.path().join("Directory.Packages.props"),
            r#"<Project><ItemGroup>
  <PackageVersion Include="Serilog" Version="4.0.2" />
</ItemGroup></Project>"#,
        )
        .expect("central props");
        std::fs::write(
            tmp.path().join("src/App/App.csproj"),
            r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
  <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  <PackageReference Include="Serilog" />
  <PackageReference Include="xunit"><Version>2.9.2</Version></PackageReference>
  <PackageReference Update="Not.A.Direct.Dependency" Version="9.9.9" />
</ItemGroup></Project>"#,
        )
        .expect("csproj");
        std::fs::write(
            tmp.path().join("packages.lock.json"),
            r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3" },
      "Serilog": { "type": "Direct", "requested": "[4.0.2, )", "resolved": "4.0.2" },
      "xunit": { "type": "Direct", "requested": "[2.9.2, )", "resolved": "2.9.2" },
      "System.Memory": { "type": "Transitive", "resolved": "4.5.5" }
    }
  }
}"#,
        )
        .expect("packages lock");

        let deps = scan_external_deps(tmp.path());
        let source = "src/App/App.csproj";
        assert_eq!(
            dep(&deps, "nuget", source, "Serilog").version_req.as_deref(),
            Some("4.0.2")
        );
        assert_eq!(
            dep(&deps, "nuget", source, "Newtonsoft.Json").version_locked.as_deref(),
            Some("13.0.3")
        );
        assert_eq!(
            dep(&deps, "nuget", source, "xunit").version_req.as_deref(),
            Some("2.9.2")
        );
        assert!(deps
            .iter()
            .all(|dep| dep.name != "System.Memory" && dep.name != "Not.A.Direct.Dependency"));
        assert_eq!(
            serde_json::to_value(&deps).expect("deps json"),
            serde_json::json!([
                {
                    "name": "Newtonsoft.Json",
                    "ecosystem": "nuget",
                    "version_req": "13.0.3",
                    "version_locked": "13.0.3",
                    "source_manifest": "src/App/App.csproj",
                    "kind": "normal"
                },
                {
                    "name": "Serilog",
                    "ecosystem": "nuget",
                    "version_req": "4.0.2",
                    "version_locked": "4.0.2",
                    "source_manifest": "src/App/App.csproj",
                    "kind": "normal"
                },
                {
                    "name": "xunit",
                    "ecosystem": "nuget",
                    "version_req": "2.9.2",
                    "version_locked": "2.9.2",
                    "source_manifest": "src/App/App.csproj",
                    "kind": "normal"
                }
            ])
        );
    }

    #[test]
    fn swiftpm_extracts_url_requirements_and_v2_v3_lock_versions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Package.swift"),
            r#"// swift-tools-version: 5.9
import PackageDescription
let package = Package(
  name: "Demo",
  dependencies: [
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.70.0"),
    .package(url: "https://github.com/pointfreeco/swift-composable-architecture", exact: "1.15.0"),
    .package(url: "https://github.com/acme/BranchKit.git", branch: "main"),
    .package(url: "https://github.com/acme/RevisionKit.git", revision: "abc123")
  ]
)
"#,
        )
        .expect("Package.swift");
        std::fs::write(
            tmp.path().join("Package.resolved"),
            r#"{"version":3,"pins":[
{"identity":"swift-nio","location":"https://github.com/apple/swift-nio.git","state":{"version":"2.70.1"}},
{"identity":"swift-composable-architecture","location":"https://github.com/pointfreeco/swift-composable-architecture","state":{"version":"1.15.0"}},
{"identity":"transitive","location":"https://example.invalid/transitive.git","state":{"version":"9.9.9"}}
]}"#,
        )
        .expect("Package.resolved");
        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 4);
        assert_eq!(
            dep(&deps, "swiftpm", "Package.swift", "swift-nio")
                .version_req
                .as_deref(),
            Some("from: 2.70.0")
        );
        assert_eq!(
            dep(&deps, "swiftpm", "Package.swift", "swift-nio")
                .version_locked
                .as_deref(),
            Some("2.70.1")
        );
        assert_eq!(
            dep(&deps, "swiftpm", "Package.swift", "BranchKit")
                .version_req
                .as_deref(),
            Some("branch: main")
        );
        assert!(deps.iter().all(|dep| dep.name != "transitive"));
    }

    #[test]
    fn composer_extracts_require_kinds_skips_platform_and_closes_direct_locks() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("composer.json"),
            r#"{"require":{"php":"^8.3","ext-json":"*","Composer-Plugin-API":"^2","lib-openssl":"*","laravel/framework":"^12.0","guzzlehttp/guzzle":"^7.9"},"require-dev":{"phpunit/phpunit":"^11.0"}}"#,
        )
        .expect("composer.json");
        std::fs::write(
            tmp.path().join("composer.lock"),
            r#"{"packages":[{"name":"laravel/framework","version":"v12.1.2"},{"name":"guzzlehttp/guzzle","version":"7.9.2"},{"name":"psr/http-message","version":"2.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"11.5.0"}]}"#,
        )
        .expect("composer.lock");
        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 3);
        assert_eq!(dep(&deps, "composer", "composer.json", "phpunit/phpunit").kind, "dev");
        assert_eq!(
            dep(&deps, "composer", "composer.json", "laravel/framework")
                .version_locked
                .as_deref(),
            Some("v12.1.2")
        );
        assert!(deps.iter().all(|dep| !matches!(
            dep.name.as_str(),
            "php" | "ext-json" | "Composer-Plugin-API" | "lib-openssl" | "psr/http-message"
        )));
    }

    #[test]
    fn malformed_and_oversized_m4_ecosystem_files_are_skipped_without_panics() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("composer.json"), "{").expect("malformed composer");
        std::fs::write(tmp.path().join("composer.lock"), b"\0\xFF").expect("binary composer lock");
        std::fs::write(
            tmp.path().join("Package.swift"),
            ".package(url: \"https://example.invalid/Good.git\", from: \"1\")\n",
        )
        .expect("Package.swift");
        std::fs::write(tmp.path().join("Package.resolved"), "{").expect("malformed resolved");
        let oversized = std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path().join("Package.swift"))
            .expect("open Package.swift");
        oversized.set_len(MAX_FILE_BYTES + 1).expect("oversize Package.swift");
        assert!(scan_external_deps(tmp.path()).is_empty());
    }

    #[test]
    fn poetry_and_uv_locks_close_declared_python_deps_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("poetry")).expect("poetry dir");
        std::fs::create_dir_all(tmp.path().join("uv")).expect("uv dir");
        std::fs::write(
            tmp.path().join("poetry/pyproject.toml"),
            "[tool.poetry.dependencies]\npython = \"^3.11\"\nRequests = \"^2.32\"\n",
        )
        .expect("poetry project");
        std::fs::write(
            tmp.path().join("poetry/poetry.lock"),
            "[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.2.3\"\n",
        )
        .expect("poetry lock");
        std::fs::write(tmp.path().join("uv/requirements.txt"), "httpx>=0.27\n").expect("requirements");
        std::fs::write(
            tmp.path().join("uv/uv.lock"),
            "version = 1\n\n[[package]]\nname = \"httpx\"\nversion = \"0.27.2\"\n\n[[package]]\nname = \"anyio\"\nversion = \"4.6.0\"\n",
        )
        .expect("uv lock");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "pypi", "poetry/pyproject.toml", "Requests")
                .version_locked
                .as_deref(),
            Some("2.32.3")
        );
        assert_eq!(
            dep(&deps, "pypi", "uv/requirements.txt", "httpx")
                .version_locked
                .as_deref(),
            Some("0.27.2")
        );
        assert!(deps.iter().all(|dep| dep.name != "urllib3" && dep.name != "anyio"));
    }

    #[test]
    fn go_sum_closes_exact_direct_versions_without_transitive_leakage() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("go.mod"),
            "module example.com/app\n\nrequire example.com/direct v1.2.3\nrequire example.com/missing v2.0.0\nrequire example.com/metadata-only v1.0.0\n",
        )
        .expect("go mod");
        std::fs::write(
            tmp.path().join("go.sum"),
            "example.com/direct v1.2.3 h1:direct\nexample.com/direct v1.2.3/go.mod h1:mod\nexample.com/direct v1.1.0 h1:old\nexample.com/metadata-only v1.0.0/go.mod h1:metadata\nexample.com/transitive v9.9.9 h1:transitive\n",
        )
        .expect("go sum");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "go", "go.mod", "example.com/direct")
                .version_locked
                .as_deref(),
            Some("v1.2.3")
        );
        assert!(dep(&deps, "go", "go.mod", "example.com/missing")
            .version_locked
            .is_none());
        assert!(dep(&deps, "go", "go.mod", "example.com/metadata-only")
            .version_locked
            .is_none());
        assert!(deps.iter().all(|dep| dep.name != "example.com/transitive"));
    }

    #[test]
    fn repos_without_new_manifest_types_keep_existing_dependency_golden() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("requirements.txt"), "requests>=2\n").expect("requirements");
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"express":"^4"}}"#).expect("package");
        std::fs::write(
            tmp.path().join("go.mod"),
            "module example.com/app\nrequire golang.org/x/sync v0.7.0\n",
        )
        .expect("go mod");

        let json = serde_json::to_string(&scan_external_deps(tmp.path())).expect("deps json");
        assert_eq!(
            json,
            r#"[{"name":"golang.org/x/sync","ecosystem":"go","version_req":"v0.7.0","source_manifest":"go.mod","kind":"normal"},{"name":"express","ecosystem":"npm","version_req":"^4","source_manifest":"package.json","kind":"normal"},{"name":"requests","ecosystem":"pypi","version_req":">=2","source_manifest":"requirements.txt","kind":"normal"}]"#
        );
    }

    #[test]
    fn repos_without_m4_manifest_types_keep_m2_dependency_golden_byte_identical() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("Gemfile"), "gem \"rails\", \"~> 7.2\"\n").expect("Gemfile");
        std::fs::write(
            tmp.path().join("App.csproj"),
            "<Project><ItemGroup><PackageReference Include=\"Serilog\" Version=\"4\" /></ItemGroup></Project>",
        )
        .expect("csproj");
        let json = serde_json::to_string(&scan_external_deps(tmp.path())).expect("deps json");
        assert_eq!(
            json,
            r#"[{"name":"Serilog","ecosystem":"nuget","version_req":"4","source_manifest":"App.csproj","kind":"normal"},{"name":"rails","ecosystem":"rubygems","version_req":"~> 7.2","source_manifest":"Gemfile","kind":"normal"}]"#
        );
    }

    #[test]
    fn malformed_and_oversized_new_ecosystem_files_are_skipped_without_panics() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("pom.xml"), "<project><dependencies>").expect("truncated pom");
        std::fs::write(
            tmp.path().join("App.csproj"),
            "<Project><ItemGroup><PackageReference Include=\"Example.Package\" Version=\"1\" /></ItemGroup></Project>",
        )
        .expect("csproj");
        std::fs::write(tmp.path().join("Broken.csproj"), b"\0\xFF\xFE").expect("binary csproj");
        std::fs::write(tmp.path().join("Gemfile"), "gem \"rack\", \"~> 3\"\n").expect("Gemfile");
        std::fs::write(tmp.path().join("Gemfile.lock"), b"GEM\n\xFF\xFE\0").expect("binary lock");
        std::fs::write(tmp.path().join("build.gradle"), "implementation \"a:b:1\"\n").expect("gradle");
        let oversized = std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path().join("build.gradle"))
            .expect("open gradle");
        oversized.set_len(MAX_FILE_BYTES + 1).expect("oversize gradle");
        std::fs::write(tmp.path().join("packages.lock.json"), r#"{"dependencies":{}}"#).expect("lock");
        let oversized_lock = std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path().join("packages.lock.json"))
            .expect("open lock");
        oversized_lock.set_len(MAX_LOCKFILE_BYTES + 1).expect("oversize lock");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 2);
        assert!(dep(&deps, "nuget", "App.csproj", "Example.Package")
            .version_locked
            .is_none());
        assert!(dep(&deps, "rubygems", "Gemfile", "rack").version_locked.is_none());
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
    fn pre_m2_manifests_claim_cap_slots_before_alphabetically_earlier_m2_manifests() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for idx in 0..=MAX_MANIFESTS {
            std::fs::write(tmp.path().join(format!("A{idx:04}.csproj")), "<Project />").expect("csproj");
        }
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"must-survive":"1.2.3"}}"#,
        )
        .expect("package");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "must-survive");
        assert_eq!(deps[0].source_manifest, "package.json");
    }

    #[test]
    fn pre_m4_manifest_tiers_claim_cap_slots_before_m4_manifests() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for idx in 0..=MAX_MANIFESTS {
            let dir = tmp.path().join(format!("a{idx:04}"));
            std::fs::create_dir_all(&dir).expect("composer dir");
            std::fs::write(dir.join("composer.json"), r#"{"require":{"acme/m4":"1"}}"#).expect("composer");
        }
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"pre-m2-must-survive":"1"}}"#,
        )
        .expect("package");
        std::fs::write(tmp.path().join("Gemfile"), "gem \"m2-must-survive\", \"1\"\n").expect("Gemfile");

        let deps = scan_external_deps(tmp.path());
        assert!(deps.iter().any(|dep| dep.name == "pre-m2-must-survive"));
        assert!(deps.iter().any(|dep| dep.name == "m2-must-survive"));
        assert_eq!(
            deps.iter().filter(|dep| dep.ecosystem == "composer").count(),
            MAX_MANIFESTS - 2
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
        std::fs::write(
            tmp.path().join("pom.xml"),
            "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>new</artifactId><version>1</version></dependency></dependencies></project>",
        )
        .expect("pom");
        std::fs::write(tmp.path().join("Gemfile"), "gem \"rack\", \"~> 3\"\n").expect("Gemfile");
        std::fs::write(tmp.path().join("main.ts"), "export function main() {}\n").expect("ts");

        let _env = EnvVarGuard::unset(EXTERNAL_DEPS_ENV);
        let scan = crate::workspace_scan_polyglot::run_repo_scan_at(tmp.path()).expect("scan");
        let json = serde_json::to_string(&scan).expect("scan json");
        assert!(!json.contains("external_deps"));
        assert!(!json.contains("external_dep_count"));
    }

    #[test]
    #[serial_test::serial]
    fn flag_off_full_scan_bytes_are_identical_with_all_m2_manifests_and_locks_present() {
        fn stable_bytes(mut scan: crate::workspace_scan::WorkspaceScan) -> Vec<u8> {
            scan.scan_id = "stable".to_string();
            scan.started_at_unix_ms = 1;
            scan.finished_at_unix_ms = 2;
            scan.duration_ms = 1;
            serde_json::to_vec(&scan).expect("scan json")
        }

        let tmp = tempfile::tempdir().expect("tempdir");
        let _external_deps = EnvVarGuard::unset(EXTERNAL_DEPS_ENV);
        let _polyglot = EnvVarGuard::unset("CORECRUXD_POLYGLOT_V2");
        let baseline =
            stable_bytes(crate::workspace_scan_polyglot::run_repo_scan_at(tmp.path()).expect("baseline scan"));

        std::fs::write(tmp.path().join("pom.xml"), "<project />").expect("pom");
        std::fs::write(
            tmp.path().join("build.gradle"),
            "implementation \"org.example:core:1\"\n",
        )
        .expect("gradle");
        std::fs::write(tmp.path().join("Gemfile"), "gem \"rack\", \"~> 3\"\n").expect("Gemfile");
        std::fs::write(tmp.path().join("Gemfile.lock"), "GEM\n  specs:\n    rack (3.1.0)\n").expect("Gemfile.lock");
        std::fs::write(
            tmp.path().join("App.csproj"),
            "<Project><ItemGroup><PackageReference Include=\"Example.Package\" Version=\"1\" /></ItemGroup></Project>",
        )
        .expect("csproj");
        std::fs::write(tmp.path().join("packages.lock.json"), r#"{"dependencies":{}}"#).expect("NuGet lock");
        std::fs::write(
            tmp.path().join("poetry.lock"),
            "[[package]]\nname = \"requests\"\nversion = \"2\"\n",
        )
        .expect("poetry lock");
        std::fs::write(tmp.path().join("uv.lock"), "version = 1\n").expect("uv lock");
        std::fs::write(tmp.path().join("go.sum"), "example.com/mod v1.0.0 h1:hash\n").expect("go sum");
        std::fs::write(tmp.path().join("Package.swift"), "// swift manifest\n").expect("Package.swift");
        std::fs::write(tmp.path().join("Package.resolved"), r#"{"version":3,"pins":[]}"#).expect("Package.resolved");
        std::fs::write(tmp.path().join("composer.json"), r#"{"require":{"acme/package":"1"}}"#).expect("composer.json");
        std::fs::write(tmp.path().join("composer.lock"), r#"{"packages":[]}"#).expect("composer.lock");

        let with_m2_files =
            stable_bytes(crate::workspace_scan_polyglot::run_repo_scan_at(tmp.path()).expect("M2 files scan"));
        assert_eq!(baseline, with_m2_files);
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

    // ---------------------------------------------------------------------
    // Flag plumbing
    // ---------------------------------------------------------------------

    #[test]
    #[serial_test::serial]
    fn env_flag_reads_falsey_words_as_off_and_everything_else_as_on() {
        for off in ["", "  ", "0", "false", "FALSE", "off", "No", " no "] {
            let _env = EnvVarGuard::set(EXTERNAL_DEPS_ENV, off);
            assert!(!external_deps_enabled_from_env(), "expected {off:?} to read as off");
        }
        for on in ["1", "true", "YES", "on", "enabled", "00"] {
            let _env = EnvVarGuard::set(EXTERNAL_DEPS_ENV, on);
            assert!(external_deps_enabled_from_env(), "expected {on:?} to read as on");
        }
        let _unset = EnvVarGuard::unset(EXTERNAL_DEPS_ENV);
        assert!(!external_deps_enabled_from_env());
    }

    #[test]
    #[serial_test::serial]
    fn attach_external_deps_populates_scan_and_stats_only_when_enabled() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"express":"^4"}}"#).expect("package");

        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        {
            let _env = EnvVarGuard::unset(EXTERNAL_DEPS_ENV);
            attach_external_deps_if_enabled(tmp.path(), &mut scan);
            assert!(scan.external_deps.is_empty());
            assert_eq!(scan.stats.external_dep_count, 0);
        }
        let _env = EnvVarGuard::set(EXTERNAL_DEPS_ENV, "1");
        attach_external_deps_if_enabled(tmp.path(), &mut scan);
        assert_eq!(scan.external_deps.len(), 1);
        assert_eq!(scan.stats.external_dep_count, 1);
    }

    // ---------------------------------------------------------------------
    // Discovery: skipped directories, depth cap, path classification
    // ---------------------------------------------------------------------

    #[test]
    fn manifests_inside_build_and_vendor_directories_are_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for skipped in [
            "node_modules",
            "target",
            "vendor",
            ".git",
            "dist",
            "build",
            ".venv",
            "venv",
            "__pycache__",
        ] {
            assert!(should_skip_dir(skipped), "{skipped} must be skipped");
            let dir = tmp.path().join(skipped).join("inner");
            std::fs::create_dir_all(&dir).expect("skipped dir");
            std::fs::write(dir.join("package.json"), r#"{"dependencies":{"ghost":"1"}}"#).expect("ghost manifest");
        }
        assert!(!should_skip_dir("src"));
        assert!(!should_skip_dir("packages"));
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"real":"1"}}"#).expect("real manifest");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 1, "vendored manifests leaked: {deps:?}");
        assert_eq!(deps[0].name, "real");
    }

    #[test]
    fn manifests_below_the_depth_cap_are_scanned_and_deeper_ones_are_not() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut at_cap = tmp.path().to_path_buf();
        for level in 1..=MAX_DEPTH {
            at_cap = at_cap.join(format!("d{level}"));
        }
        let past_cap = at_cap.join("deeper");
        std::fs::create_dir_all(&past_cap).expect("nested dirs");
        std::fs::write(at_cap.join("package.json"), r#"{"dependencies":{"at-cap":"1"}}"#).expect("at cap");
        std::fs::write(past_cap.join("package.json"), r#"{"dependencies":{"past-cap":"1"}}"#).expect("past cap");

        let deps = scan_external_deps(tmp.path());
        assert!(deps.iter().any(|dep| dep.name == "at-cap"));
        assert!(
            deps.iter().all(|dep| dep.name != "past-cap"),
            "the depth cap must stop the walk"
        );
    }

    #[test]
    fn manifest_path_classification_covers_every_supported_name() {
        for name in [
            "Cargo.toml",
            "package.json",
            "pyproject.toml",
            "go.mod",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "Gemfile",
            "Package.swift",
            "composer.json",
            "requirements.txt",
            "requirements-dev.txt",
        ] {
            assert!(is_manifest_name(name), "{name}");
            assert!(is_manifest_path(Path::new(name)), "{name}");
        }
        for name in ["README.md", "Cargo.lock", "requirements", "requirements.in", "gemfile"] {
            assert!(!is_manifest_name(name), "{name}");
        }
        assert!(is_manifest_path(Path::new("src/App.csproj")));
        assert!(is_manifest_path(Path::new("requirements/base.txt")));
        assert!(!is_manifest_path(Path::new("docs/notes.txt")));
        assert!(!is_manifest_path(Path::new("src/App.vbproj")));
    }

    #[test]
    fn requirements_files_are_recognised_by_name_or_parent_directory() {
        assert!(is_requirements_file("requirements.txt"));
        assert!(is_requirements_file("requirements-dev.txt"));
        assert!(!is_requirements_file("requirements"));
        assert!(!is_requirements_file("dev-requirements.txt"));
        assert!(is_requirements_path(Path::new("requirements/base.txt")));
        assert!(is_requirements_path(Path::new("requirements-ci/base.txt")));
        assert!(!is_requirements_path(Path::new("requirements/base.in")));
        assert!(!is_requirements_path(Path::new("docs/base.txt")));
        assert!(!is_requirements_path(Path::new("base.txt")));
    }

    #[test]
    fn manifest_cap_tiers_partition_pre_m2_m2_and_m4_paths() {
        for path in [
            "Cargo.toml",
            "package.json",
            "pyproject.toml",
            "go.mod",
            "requirements.txt",
        ] {
            assert!(is_pre_m2_manifest_path(Path::new(path)), "{path}");
            assert!(!is_m2_manifest_path(Path::new(path)), "{path}");
        }
        assert!(is_pre_m2_manifest_path(Path::new("requirements/base.txt")));
        for path in ["pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "App.csproj"] {
            assert!(is_m2_manifest_path(Path::new(path)), "{path}");
            assert!(!is_pre_m2_manifest_path(Path::new(path)), "{path}");
        }
        for path in ["Package.swift", "composer.json"] {
            assert!(!is_pre_m2_manifest_path(Path::new(path)), "{path}");
            assert!(!is_m2_manifest_path(Path::new(path)), "{path}");
        }
    }

    // ---------------------------------------------------------------------
    // File reading guards
    // ---------------------------------------------------------------------

    #[test]
    fn unreadable_oversized_and_non_utf8_files_read_as_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(read_utf8_file(&tmp.path().join("absent.toml"), "Cargo.toml").is_none());

        let binary = tmp.path().join("binary.json");
        std::fs::write(&binary, b"\xFF\xFE\0").expect("binary file");
        assert!(read_utf8_file(&binary, "package.json").is_none());

        let big = tmp.path().join("big.json");
        std::fs::write(&big, "{}").expect("big file");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&big)
            .expect("open big")
            .set_len(MAX_FILE_BYTES + 1)
            .expect("oversize");
        assert!(read_utf8_file(&big, "package.json").is_none());
        assert!(
            read_utf8_lockfile(&big, "package-lock.json").is_some(),
            "the lockfile cap is larger than the manifest cap"
        );

        let ok = tmp.path().join("ok.json");
        std::fs::write(&ok, "{}").expect("ok file");
        assert_eq!(read_utf8_file(&ok, "package.json").as_deref(), Some("{}"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_manifests_are_never_read() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real.json");
        std::fs::write(&real, r#"{"dependencies":{"linked":"1"}}"#).expect("real file");
        let link = tmp.path().join("package.json");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(read_utf8_file(&link, "package.json").is_none());
        assert!(
            scan_external_deps(tmp.path()).is_empty(),
            "a symlinked manifest must not be followed"
        );
    }

    #[test]
    fn rel_path_keeps_paths_outside_the_root_verbatim() {
        assert_eq!(
            rel_path(Path::new("/repo"), Path::new("/repo/crates/a/Cargo.toml")).as_deref(),
            Some("crates/a/Cargo.toml")
        );
        assert_eq!(
            rel_path(Path::new("/repo"), Path::new("/elsewhere/Cargo.toml")).as_deref(),
            Some("/elsewhere/Cargo.toml")
        );
    }

    #[test]
    fn find_nearest_file_walks_up_and_stops_at_the_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a/b/c");
        std::fs::create_dir_all(&nested).expect("dirs");
        std::fs::write(tmp.path().join("Cargo.lock"), "").expect("lock");
        assert_eq!(
            find_nearest_file(&nested, tmp.path(), "Cargo.lock"),
            Some(tmp.path().join("Cargo.lock"))
        );
        assert!(find_nearest_file(&nested, tmp.path(), "absent.lock").is_none());
        // A closer file wins over the root one.
        std::fs::write(nested.join("Cargo.lock"), "").expect("nested lock");
        assert_eq!(
            find_nearest_file(&nested, tmp.path(), "Cargo.lock"),
            Some(nested.join("Cargo.lock"))
        );
    }

    #[test]
    fn dedup_and_sort_keeps_the_first_entry_per_manifest_ecosystem_name_key() {
        let make = |name: &str, ecosystem: &str, manifest: &str, version: &str| ExternalDep {
            name: name.to_string(),
            ecosystem: ecosystem.to_string(),
            version_req: Some(version.to_string()),
            version_locked: None,
            source_manifest: manifest.to_string(),
            kind: "normal".to_string(),
        };
        let deduped = dedup_and_sort(vec![
            make("z", "npm", "b/package.json", "1"),
            make("a", "npm", "a/package.json", "1"),
            make("a", "npm", "a/package.json", "2"),
            make("a", "cargo", "a/package.json", "3"),
        ]);
        assert_eq!(deduped.len(), 3);
        assert_eq!(
            deduped
                .iter()
                .map(|dep| (dep.source_manifest.as_str(), dep.ecosystem.as_str(), dep.name.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("a/package.json", "cargo", "a"),
                ("a/package.json", "npm", "a"),
                ("b/package.json", "npm", "z"),
            ]
        );
        assert_eq!(
            deduped
                .iter()
                .find(|dep| dep.ecosystem == "npm" && dep.name == "a")
                .and_then(|dep| dep.version_req.as_deref()),
            Some("1"),
            "the first entry for a key wins"
        );
    }

    #[test]
    fn malformed_toml_and_json_manifests_yield_no_dependencies() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("a")).expect("a dir");
        std::fs::create_dir_all(tmp.path().join("b")).expect("b dir");
        std::fs::write(tmp.path().join("a/Cargo.toml"), "[dependencies\nbroken = ").expect("broken cargo");
        std::fs::write(tmp.path().join("b/pyproject.toml"), "[project\n").expect("broken pyproject");
        std::fs::write(tmp.path().join("package.json"), "{not json").expect("broken package");
        assert!(scan_external_deps(tmp.path()).is_empty());
    }

    #[test]
    fn empty_manifests_and_manifests_without_dependency_sections_yield_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("py")).expect("py dir");
        std::fs::create_dir_all(tmp.path().join("rs")).expect("rs dir");
        std::fs::write(tmp.path().join("package.json"), "{}").expect("package");
        std::fs::write(tmp.path().join("py/pyproject.toml"), "[build-system]\nrequires = []\n").expect("pyproject");
        std::fs::write(
            tmp.path().join("rs/Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .expect("cargo");
        std::fs::write(
            tmp.path().join("go.mod"),
            "module example.com/app\n\n// only a comment\n",
        )
        .expect("go mod");
        std::fs::write(tmp.path().join("requirements.txt"), "\n# nothing but a comment\n").expect("requirements");
        std::fs::write(tmp.path().join("Gemfile"), "source \"https://rubygems.org\"\n").expect("Gemfile");
        assert!(scan_external_deps(tmp.path()).is_empty());
    }

    /// DEFECT PIN — a missing lockfile and an unparsable one are the same
    /// observable outcome: every `version_locked` is simply `None`. Nothing in
    /// the scan distinguishes "this dependency is not pinned" from "the lockfile
    /// that pins it could not be read".
    #[test]
    fn unparsable_lockfile_is_indistinguishable_from_a_missing_one() {
        let with_broken_lock = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            with_broken_lock.path().join("package.json"),
            r#"{"dependencies":{"express":"^4"}}"#,
        )
        .expect("package");
        std::fs::write(with_broken_lock.path().join("package-lock.json"), "{ not json").expect("broken lock");

        let without_lock = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            without_lock.path().join("package.json"),
            r#"{"dependencies":{"express":"^4"}}"#,
        )
        .expect("package");

        let broken = scan_external_deps(with_broken_lock.path());
        let missing = scan_external_deps(without_lock.path());
        assert_eq!(broken, missing);
        assert!(broken[0].version_locked.is_none());
    }

    // ---------------------------------------------------------------------
    // Cargo specifics
    // ---------------------------------------------------------------------

    #[test]
    fn workspace_dependency_inherits_rename_and_optional_from_the_workspace_table() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("crates/app")).expect("crate dir");
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            r#"[workspace]
members = ["crates/app"]

[workspace.dependencies]
renamed = { package = "real-crate", version = "2.1", optional = true }
plain = "3.0"
"#,
        )
        .expect("workspace manifest");
        std::fs::write(
            tmp.path().join("crates/app/Cargo.toml"),
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
renamed = { workspace = true }
plain = { workspace = true }
pinned = { workspace = true, version = "9" }
unknown_in_workspace = { workspace = true }
"#,
        )
        .expect("member manifest");
        std::fs::write(
            tmp.path().join("Cargo.lock"),
            "[[package]]\nname = \"real-crate\"\nversion = \"2.1.4\"\n\n[[package]]\nname = \"plain\"\nversion = \"3.0.1\"\n",
        )
        .expect("lock");

        let deps = scan_external_deps(tmp.path());
        let source = "crates/app/Cargo.toml";
        let renamed = dep(&deps, "cargo", source, "renamed");
        assert_eq!(renamed.version_req.as_deref(), Some("2.1"));
        assert_eq!(renamed.version_locked.as_deref(), Some("2.1.4"));
        assert_eq!(renamed.kind, "optional", "workspace optional propagates");
        assert_eq!(
            dep(&deps, "cargo", source, "plain").version_locked.as_deref(),
            Some("3.0.1")
        );
        assert_eq!(
            dep(&deps, "cargo", source, "pinned").version_req.as_deref(),
            Some("9"),
            "an explicit version wins over the workspace table"
        );
        assert!(dep(&deps, "cargo", source, "unknown_in_workspace")
            .version_req
            .is_none());
    }

    #[test]
    fn path_dependency_with_a_version_or_git_is_kept_and_a_bare_path_dependency_is_dropped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
bare_path = { path = "../bare" }
published_path = { path = "../pub", version = "1.2" }
git_and_path = { path = "../git", git = "https://example.invalid/r.git" }
renamed = { package = "other-name", version = "1" }
not_a_table_or_string = [1, 2]
"#,
        )
        .expect("manifest");

        let deps = scan_external_deps(tmp.path());
        let names: BTreeSet<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
        assert_eq!(
            names,
            BTreeSet::from(["published_path", "git_and_path", "renamed"]),
            "{names:?}"
        );
        assert_eq!(
            dep(&deps, "cargo", "Cargo.toml", "published_path")
                .version_req
                .as_deref(),
            Some("1.2")
        );
    }

    #[test]
    fn cargo_lock_without_packages_or_with_nameless_entries_locks_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nanyhow = \"1\"\n",
        )
        .expect("manifest");
        std::fs::write(
            tmp.path().join("Cargo.lock"),
            "version = 3\n\n[[package]]\nversion = \"1.0.0\"\n\n[[package]]\nname = \"anyhow\"\n",
        )
        .expect("lock");
        assert!(dep(&scan_external_deps(tmp.path()), "cargo", "Cargo.toml", "anyhow")
            .version_locked
            .is_none());
    }

    // ---------------------------------------------------------------------
    // npm / pnpm specifics
    // ---------------------------------------------------------------------

    #[test]
    fn npm_intra_repo_protocol_specs_and_non_string_values_are_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{
              "ws-dep":"workspace:^",
              "link-dep":"link:../a",
              "file-dep":"file:../b",
              "portal-dep":"portal:../c",
              "object-dep":{"version":"1"},
              "real":"^1.2.3"
            }}"#,
        )
        .expect("package");
        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "real");
    }

    #[test]
    fn package_lock_without_packages_or_dependencies_locks_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"express":"^4"}}"#).expect("package");
        std::fs::write(tmp.path().join("package-lock.json"), r#"{"lockfileVersion":3}"#).expect("lock");
        assert!(dep(&scan_external_deps(tmp.path()), "npm", "package.json", "express")
            .version_locked
            .is_none());
    }

    #[test]
    fn pnpm_lock_without_importers_or_without_this_importer_locks_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"react":"^18"}}"#).expect("package");
        std::fs::write(tmp.path().join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").expect("lock");
        assert!(dep(&scan_external_deps(tmp.path()), "npm", "package.json", "react")
            .version_locked
            .is_none());

        std::fs::write(
            tmp.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\nimporters:\n  packages/other:\n    dependencies:\n      react:\n        version: 18.0.0\n",
        )
        .expect("lock");
        assert!(dep(&scan_external_deps(tmp.path()), "npm", "package.json", "react")
            .version_locked
            .is_none());
    }

    #[test]
    fn pnpm_workspace_member_reads_its_own_importer_entry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("packages/web")).expect("member dir");
        std::fs::write(
            tmp.path().join("packages/web/package.json"),
            r#"{"dependencies":{"react":"^18"}}"#,
        )
        .expect("member package");
        std::fs::write(
            tmp.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\nimporters:\n  packages/web:\n    dependencies:\n      react: 18.3.1\n",
        )
        .expect("lock");
        assert_eq!(
            dep(
                &scan_external_deps(tmp.path()),
                "npm",
                "packages/web/package.json",
                "react"
            )
            .version_locked
            .as_deref(),
            Some("18.3.1"),
            "a plain scalar importer entry is a version too"
        );
    }

    #[test]
    fn pnpm_importer_key_is_dot_at_the_lock_root_and_a_relative_path_below_it() {
        assert_eq!(pnpm_importer_key(Path::new("/repo"), Path::new("/repo")), ".");
        assert_eq!(
            pnpm_importer_key(Path::new("/repo"), Path::new("/repo/packages/web")),
            "packages/web"
        );
        assert_eq!(
            pnpm_importer_key(Path::new("/repo"), Path::new("/elsewhere")),
            ".",
            "a manifest outside the lock directory falls back to the root importer"
        );
    }

    #[test]
    fn pnpm_peer_suffixes_are_stripped_at_the_first_marker() {
        assert_eq!(strip_pnpm_peer_suffix("1.2.3"), "1.2.3");
        assert_eq!(strip_pnpm_peer_suffix("1.2.3(peer@1)"), "1.2.3");
        assert_eq!(strip_pnpm_peer_suffix("1.2.3_peer@1"), "1.2.3");
        assert_eq!(strip_pnpm_peer_suffix("1.2.3_a(b)"), "1.2.3");
        assert_eq!(strip_pnpm_peer_suffix("1.2.3(a)_b"), "1.2.3");
    }

    #[test]
    fn yaml_get_returns_none_for_non_mappings() {
        let scalar = serde_yaml::Value::String("x".to_string());
        assert!(yaml_get(&scalar, "anything").is_none());
    }

    // ---------------------------------------------------------------------
    // Python specifics
    // ---------------------------------------------------------------------

    #[test]
    fn requirement_lines_cover_markers_extras_options_and_every_rejection() {
        let source = Path::new("requirements.txt");
        let parse = |line: &str| parse_requirement_line(line, source);
        assert_eq!(parse("requests"), Some(("requests".to_string(), None)));
        assert_eq!(
            parse("requests[security,socks] >= 2.31 ; python_version >= '3.10'"),
            Some(("requests".to_string(), Some(">= 2.31".to_string())))
        );
        assert_eq!(
            parse("pkg == 1.0 --hash=sha256:aa"),
            Some(("pkg".to_string(), Some("== 1.0".to_string())))
        );
        assert_eq!(
            parse("pkg===1.0"),
            Some(("pkg".to_string(), Some("===1.0".to_string())))
        );
        assert_eq!(parse("pkg~=1.0"), Some(("pkg".to_string(), Some("~=1.0".to_string()))));
        assert_eq!(parse("pkg!=1.0"), Some(("pkg".to_string(), Some("!=1.0".to_string()))));
        assert_eq!(parse("pkg<2"), Some(("pkg".to_string(), Some("<2".to_string()))));
        assert_eq!(parse("pkg<=2"), Some(("pkg".to_string(), Some("<=2".to_string()))));
        assert_eq!(parse("pkg>2"), Some(("pkg".to_string(), Some(">2".to_string()))));
        assert_eq!(
            parse("pkg (>=1)"),
            Some(("pkg".to_string(), Some(">=1".to_string()))),
            "a PEP 508 parenthesised specifier is unwrapped"
        );
        assert_eq!(
            parse("pkg @ https://example.invalid/pkg.tar.gz"),
            None,
            "direct references are skipped"
        );
        assert_eq!(parse("pkg [unterminated"), None, "malformed extras are skipped");
        assert_eq!(
            parse("pkg ; python_version < '3'  # trailing"),
            Some(("pkg".to_string(), None))
        );
        assert_eq!(
            parse("pkg extra-token"),
            Some(("pkg".to_string(), None)),
            "an unrecognised suffix simply carries no version_req"
        );
        for rejected in [
            "",
            "   ",
            "# comment only",
            "-r other.txt",
            "-r",
            "--requirement other.txt",
            "-e .",
            "-e",
            "--editable .",
            "--index-url https://example.invalid",
            "==1.0",
            "/abs/path",
            "./local",
            "../local",
            "https://example.invalid/pkg.whl",
            "dist/pkg.zip",
            "dist/pkg.tar.gz",
        ] {
            assert_eq!(parse(rejected), None, "expected {rejected:?} to be skipped");
        }
    }

    #[test]
    fn python_version_specifier_unwrapping_rejects_bare_and_unrecognised_suffixes() {
        assert!(version_req_from_python_suffix("").is_none());
        assert!(version_req_from_python_suffix("   ").is_none());
        assert!(version_req_from_python_suffix("()").is_none());
        assert!(version_req_from_python_suffix("1.0").is_none());
        assert_eq!(version_req_from_python_suffix(">=1").as_deref(), Some(">=1"));
        assert_eq!(version_req_from_python_suffix("(>=1,<2)").as_deref(), Some(">=1,<2"));
    }

    #[test]
    fn url_and_local_path_requirements_are_recognised() {
        for line in [
            "https://example.invalid/x.whl",
            "git+ssh://example.invalid/x",
            "/abs",
            "./rel",
            "../rel",
            "PKG.WHL",
            "x.tar.gz",
            "x.zip",
        ] {
            assert!(looks_like_url_or_local_path(line), "{line}");
        }
        assert!(!looks_like_url_or_local_path("requests>=2"));
    }

    #[test]
    fn pypi_names_normalize_runs_of_separators_and_case() {
        assert_eq!(normalize_pypi_name("Requests"), "requests");
        assert_eq!(normalize_pypi_name("zope.interface"), "zope-interface");
        assert_eq!(normalize_pypi_name("typing_extensions"), "typing-extensions");
        assert_eq!(normalize_pypi_name("A__b--C..d"), "a-b-c-d");
        assert_eq!(normalize_pypi_name(""), "");
    }

    #[test]
    fn poetry_dependency_values_that_are_not_strings_or_versioned_tables_are_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("pyproject.toml"),
            r#"[tool.poetry.dependencies]
python = "^3.11"
good = "^1"
pathdep = { path = "../local" }
listdep = ["a", "b"]
"#,
        )
        .expect("pyproject");
        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "good");
        assert_eq!(poetry_dep_spec(&toml::Value::Integer(1)), (None, false));
    }

    #[test]
    fn pypi_lock_without_packages_or_with_partial_entries_locks_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("requirements.txt"), "requests>=2\n").expect("requirements");
        std::fs::write(tmp.path().join("poetry.lock"), "lock-version = \"2.0\"\n").expect("poetry lock");
        assert!(
            dep(&scan_external_deps(tmp.path()), "pypi", "requirements.txt", "requests")
                .version_locked
                .is_none()
        );

        std::fs::write(
            tmp.path().join("poetry.lock"),
            "[[package]]\nname = \"requests\"\n\n[[package]]\nversion = \"1\"\n",
        )
        .expect("poetry lock");
        assert!(
            dep(&scan_external_deps(tmp.path()), "pypi", "requirements.txt", "requests")
                .version_locked
                .is_none()
        );
    }

    // ---------------------------------------------------------------------
    // Go specifics
    // ---------------------------------------------------------------------

    #[test]
    fn go_require_block_start_needs_an_opening_paren() {
        assert!(go_require_block_start("require ("));
        assert!(go_require_block_start("require("));
        assert!(!go_require_block_start("require example.com/a v1"));
        assert!(!go_require_block_start("module example.com/app"));
    }

    #[test]
    fn go_require_lines_without_a_version_and_nested_directives_are_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("go.mod"),
            r#"module example.com/app

require (
  example.com/ok v1.0.0
  nameonly
  replace example.com/x => ../x
  exclude example.com/y v1.0.0
)
"#,
        )
        .expect("go mod");
        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "example.com/ok");
    }

    #[test]
    fn go_sum_lines_missing_a_hash_field_are_ignored() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("go.mod"),
            "module example.com/app\nrequire example.com/a v1.0.0\n",
        )
        .expect("go mod");
        std::fs::write(tmp.path().join("go.sum"), "example.com/a v1.0.0\n\n").expect("go sum");
        assert!(dep(&scan_external_deps(tmp.path()), "go", "go.mod", "example.com/a")
            .version_locked
            .is_none());
    }

    // ---------------------------------------------------------------------
    // Maven / Gradle specifics
    // ---------------------------------------------------------------------

    #[test]
    fn maven_property_interpolation_handles_missing_keys_and_unterminated_placeholders() {
        let properties: BTreeMap<String, String> =
            [("a".to_string(), "A".to_string()), ("b".to_string(), "B".to_string())]
                .into_iter()
                .collect();
        assert_eq!(interpolate_maven_properties("plain", &properties), "plain");
        assert_eq!(interpolate_maven_properties("${a}-${b}", &properties), "A-B");
        assert_eq!(
            interpolate_maven_properties("${missing}-${a}", &properties),
            "${missing}-A"
        );
        assert_eq!(
            interpolate_maven_properties("${unterminated", &properties),
            "${unterminated"
        );
        assert_eq!(
            interpolate_maven_properties("no placeholder }", &properties),
            "no placeholder }"
        );
    }

    #[test]
    fn maven_dependencies_missing_a_group_or_artifact_are_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("pom.xml"),
            r#"<project>
  <dependencies>
    <dependency><artifactId>no-group</artifactId></dependency>
    <dependency><groupId>no.artifact</groupId></dependency>
    <dependency><groupId>ok</groupId><artifactId>dep</artifactId></dependency>
  </dependencies>
  <build><plugins><plugin><dependencies>
    <dependency><groupId>plugin</groupId><artifactId>dep</artifactId></dependency>
  </dependencies></plugin></plugins></build>
</project>"#,
        )
        .expect("pom");
        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "ok:dep");
        assert!(deps[0].version_req.is_none());
    }

    #[test]
    fn gradle_dynamic_versions_are_never_reported() {
        for version in ["1.+", "[1,2)", "(1,2]", "latest.release", "LATEST.INTEGRATION", "${v}"] {
            assert!(gradle_version_is_dynamic(version), "{version}");
        }
        assert!(!gradle_version_is_dynamic("1.2.3"));
        assert!(!gradle_version_is_dynamic("33.3.0-jre"));
    }

    #[test]
    fn gradle_comment_stripping_respects_quotes_escapes_and_block_spans() {
        let mut in_block = false;
        assert_eq!(
            strip_gradle_comments("implementation \"a:b:1\"", &mut in_block),
            "implementation \"a:b:1\""
        );
        assert_eq!(strip_gradle_comments("code // trailing", &mut in_block), "code ");
        assert_eq!(
            strip_gradle_comments("keep \"http://not-a-comment\" end", &mut in_block),
            "keep \"http://not-a-comment\" end"
        );
        assert_eq!(strip_gradle_comments("a /* mid */ b", &mut in_block), "a  b");
        assert!(!in_block);
        assert_eq!(strip_gradle_comments("start /* open", &mut in_block), "start ");
        assert!(in_block, "an unterminated block comment carries to the next line");
        assert_eq!(strip_gradle_comments("still inside", &mut in_block), "");
        assert_eq!(strip_gradle_comments("close */ tail", &mut in_block), " tail");
        assert!(!in_block);
        assert_eq!(
            strip_gradle_comments(r#"a "esc\"aped // still string" b"#, &mut in_block),
            r#"a "esc\"aped // still string" b"#
        );
    }

    // ---------------------------------------------------------------------
    // Ruby specifics
    // ---------------------------------------------------------------------

    #[test]
    fn ruby_quoted_literals_track_escapes_and_unterminated_quotes() {
        let literals = ruby_quoted_literals(r#" "first", 'second', "esc\"aped" "#);
        let values: Vec<&str> = literals.iter().map(|literal| literal.value.as_str()).collect();
        assert_eq!(values, vec!["first", "second", "esc\"aped"]);
        assert!(literals[0].start < literals[1].start);
        assert!(
            ruby_quoted_literals("\"unterminated").is_empty(),
            "an unterminated literal is not a value"
        );
    }

    #[test]
    fn gem_version_shapes_and_option_boundaries_are_recognised() {
        for shaped in ["1.2", "~> 3", ">= 1", "<= 1", "!= 1", "> 1", "< 1", "= 1"] {
            assert!(gem_version_shaped(shaped), "{shaped}");
        }
        assert!(!gem_version_shaped("elasticsearch/model"));
        // Both option spellings start at the first option token, not the gem name.
        assert_eq!(gem_option_start("\"rails\", require: false"), Some(9));
        assert_eq!(gem_option_start("\"rails\", \"~> 7\", :git => \"x\""), Some(17));
        assert!(gem_option_start("\"rails\", \"~> 7\"").is_none());
    }

    #[test]
    fn platform_specific_gemfile_lock_versions_lose_to_the_generic_one_in_either_order() {
        for lock in [
            "GEM\n  specs:\n    nokogiri (1.16.5-x86_64-linux)\n    nokogiri (1.16.5)\n",
            "GEM\n  specs:\n    nokogiri (1.16.5)\n    nokogiri (1.16.5-x86_64-linux)\n",
        ] {
            let tmp = tempfile::tempdir().expect("tempdir");
            std::fs::write(tmp.path().join("Gemfile"), "gem \"nokogiri\"\n").expect("Gemfile");
            std::fs::write(tmp.path().join("Gemfile.lock"), lock).expect("Gemfile.lock");
            assert_eq!(
                dep(&scan_external_deps(tmp.path()), "rubygems", "Gemfile", "nokogiri")
                    .version_locked
                    .as_deref(),
                Some("1.16.5"),
                "lock: {lock}"
            );
        }
        assert!(gem_version_is_platform_specific("1.0-x86_64-linux"));
        assert!(gem_version_is_platform_specific("1.0-java"));
        assert!(!gem_version_is_platform_specific("1.0"));
        assert!(!gem_version_is_platform_specific("1.0-rc1"));
    }

    #[test]
    fn gemfile_lock_sections_other_than_gem_specs_are_ignored() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("Gemfile"), "gem \"rails\"\ngem \"other\"\n").expect("Gemfile");
        std::fs::write(
            tmp.path().join("Gemfile.lock"),
            "PATH\n  specs:\n    other (9.9.9)\nGEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.2.1)\n\nDEPENDENCIES\n  rails\n",
        )
        .expect("Gemfile.lock");
        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "rubygems", "Gemfile", "rails").version_locked.as_deref(),
            Some("7.2.1")
        );
        assert!(
            dep(&deps, "rubygems", "Gemfile", "other").version_locked.is_none(),
            "only the GEM section's specs are lock versions"
        );
    }

    // ---------------------------------------------------------------------
    // NuGet / SwiftPM / Composer specifics
    // ---------------------------------------------------------------------

    #[test]
    fn nuget_central_versions_accept_update_attributes_and_child_version_elements() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Directory.Packages.props"),
            r#"<Project><ItemGroup>
  <PackageVersion Update="Updated.Pkg" Version="1.0.0" />
  <PackageVersion Include="Child.Pkg"><Version>2.0.0</Version></PackageVersion>
  <PackageVersion Include="No.Version" />
  <PackageVersion Version="3.0.0" />
</ItemGroup></Project>"#,
        )
        .expect("central props");
        std::fs::write(
            tmp.path().join("App.csproj"),
            r#"<Project><ItemGroup>
  <PackageReference Include="Updated.Pkg" />
  <PackageReference Include="Child.Pkg" />
  <PackageReference Include="No.Version" />
</ItemGroup></Project>"#,
        )
        .expect("csproj");

        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "nuget", "App.csproj", "Updated.Pkg").version_req.as_deref(),
            Some("1.0.0")
        );
        assert_eq!(
            dep(&deps, "nuget", "App.csproj", "Child.Pkg").version_req.as_deref(),
            Some("2.0.0")
        );
        assert!(dep(&deps, "nuget", "App.csproj", "No.Version").version_req.is_none());
    }

    #[test]
    fn nuget_lock_without_dependencies_or_with_transitive_only_entries_locks_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("App.csproj"),
            "<Project><ItemGroup><PackageReference Include=\"Pkg\" Version=\"1\" /></ItemGroup></Project>",
        )
        .expect("csproj");
        std::fs::write(tmp.path().join("packages.lock.json"), r#"{"version":1}"#).expect("lock");
        assert!(dep(&scan_external_deps(tmp.path()), "nuget", "App.csproj", "Pkg")
            .version_locked
            .is_none());

        std::fs::write(
            tmp.path().join("packages.lock.json"),
            r#"{"dependencies":{"net8.0":{"Pkg":{"type":"Transitive","resolved":"1.0.0"},"Other":{"type":"Direct"}}}}"#,
        )
        .expect("lock");
        assert!(dep(&scan_external_deps(tmp.path()), "nuget", "App.csproj", "Pkg")
            .version_locked
            .is_none());
    }

    #[test]
    fn swift_package_names_come_from_the_url_tail() {
        assert_eq!(
            package_name_from_url("https://example.invalid/Repo.git").as_deref(),
            Some("Repo")
        );
        assert_eq!(
            package_name_from_url("https://example.invalid/Repo/").as_deref(),
            Some("Repo")
        );
        assert_eq!(package_name_from_url("Repo").as_deref(), Some("Repo"));
        assert!(package_name_from_url("").is_none());
        assert!(package_name_from_url("https://example.invalid/.git").is_none());
    }

    #[test]
    fn swift_package_resolved_v1_shape_and_pins_without_versions_are_handled() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Package.swift"),
            ".package(url: \"https://github.com/apple/swift-nio.git\", from: \"2.0.0\")\n.package(url: \"https://github.com/acme/NoPin.git\", from: \"1.0.0\")\n",
        )
        .expect("Package.swift");
        std::fs::write(
            tmp.path().join("Package.resolved"),
            r#"{"object":{"pins":[
{"package":"swift-nio","state":{"version":"2.70.1"}},
{"repositoryURL":"https://github.com/acme/NoPin.git","state":{"branch":"main"}}
]}}"#,
        )
        .expect("Package.resolved");
        let deps = scan_external_deps(tmp.path());
        assert_eq!(
            dep(&deps, "swiftpm", "Package.swift", "swift-nio")
                .version_locked
                .as_deref(),
            Some("2.70.1")
        );
        assert!(dep(&deps, "swiftpm", "Package.swift", "NoPin").version_locked.is_none());
    }

    #[test]
    fn swift_package_declarations_without_a_url_are_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Package.swift"),
            ".package(name: \"Local\", path: \"../Local\")\n.package(url: \"https://example.invalid/Real.git\", from: \"1\")\n",
        )
        .expect("Package.swift");
        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Real");
    }

    #[test]
    fn composer_platform_packages_cover_php_variants_and_ext_lib_prefixes() {
        for platform in [
            "php",
            "php-64bit",
            "php-ipv6",
            "php-zts",
            "php-debug",
            "hhvm",
            "composer",
            "composer-plugin-api",
            "composer-runtime-api",
            "ext-json",
            "lib-openssl",
        ] {
            assert!(is_composer_platform_package(platform), "{platform}");
        }
        assert!(!is_composer_platform_package("laravel/framework"));
        assert!(!is_composer_platform_package("phpunit/phpunit"));
    }

    #[test]
    fn composer_lock_sections_missing_or_malformed_lock_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("composer.json"),
            r#"{"require":{"acme/pkg":"^1"},"require-dev":{"nonstring":{"version":"1"}}}"#,
        )
        .expect("composer.json");
        std::fs::write(
            tmp.path().join("composer.lock"),
            r#"{"packages":[{"name":"acme/pkg"},{"version":"1"}]}"#,
        )
        .expect("composer.lock");
        let deps = scan_external_deps(tmp.path());
        assert_eq!(deps.len(), 1);
        assert!(deps[0].version_locked.is_none());
    }
}
