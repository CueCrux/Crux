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

pub(crate) fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        !(v.is_empty() || v == "0" || v == "false" || v == "off" || v == "no")
    })
}

pub(crate) fn external_deps_enabled_from_env() -> bool {
    env_flag_enabled(EXTERNAL_DEPS_ENV)
}

pub(crate) fn attach_external_deps_if_enabled(
    root: &Path,
    scan: &mut crate::workspace_scan::WorkspaceScan,
) -> Result<(), crate::workspace_scan::ScanError> {
    if external_deps_enabled_from_env() {
        scan.external_deps = if crate::repo_scan_policy::active_root().is_some() {
            scan_external_deps_in_context(root)?
        } else {
            let policy = crate::repo_scan_policy::RepoScanPolicy::for_exact_root(root)?;
            policy.execute(root, scan_external_deps_in_context)?
        };
        scan.stats.external_dep_count = scan.external_deps.len();
    }
    Ok(())
}

#[cfg(test)]
pub fn scan_external_deps(root: &Path) -> Vec<ExternalDep> {
    let result = crate::repo_scan_policy::RepoScanPolicy::for_exact_root(root)
        .and_then(|policy| policy.execute(root, scan_external_deps_in_context));
    match result {
        Ok(deps) => deps,
        Err(error) => {
            tracing::warn!(root=%root.display(), ?error, "external dependency scan rejected");
            Vec::new()
        }
    }
}

fn scan_external_deps_in_context(root: &Path) -> Result<Vec<ExternalDep>, crate::workspace_scan::ScanError> {
    let manifests = discover_manifests(root)?;
    let mut deps = Vec::new();
    for (idx, manifest) in manifests.iter().enumerate() {
        crate::repo_scan_policy::check_deadline()?;
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

fn discover_manifests(root: &Path) -> Result<Vec<PathBuf>, crate::workspace_scan::ScanError> {
    let mut pre_m2 = BTreeSet::new();
    let mut m2 = BTreeSet::new();
    let mut m4 = BTreeSet::new();
    crate::workspace_scan::walk_dir_filtered(root, root, Some(MAX_DEPTH), should_skip_dir, &mut |_rel, path| {
        if !is_manifest_path(path) {
            return;
        }
        let tier = if is_pre_m2_manifest_path(path) {
            &mut pre_m2
        } else if is_m2_manifest_path(path) {
            &mut m2
        } else {
            &mut m4
        };
        insert_bounded_manifest(tier, path.to_path_buf());
    })?;
    // Preserve the pre-M2 cap surface: manifests supported before this
    // milestone always claim slots before newly supported ecosystems.
    Ok(pre_m2.into_iter().chain(m2).chain(m4).collect())
}

fn insert_bounded_manifest(manifests: &mut BTreeSet<PathBuf>, path: PathBuf) {
    if manifests.len() < MAX_MANIFESTS {
        manifests.insert(path);
        return;
    }
    if manifests.last().is_some_and(|last| path < *last) {
        manifests.pop_last();
        manifests.insert(path);
    }
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

pub(crate) fn is_manifest_path(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    is_manifest_name(name)
        || is_requirements_path(path)
        || path.extension().and_then(|ext| ext.to_str()) == Some("csproj")
}

/// Files whose contents can change the external-dependency projection.
///
/// Lock files are deliberately included even though they are not declaration
/// manifests: watcher snapshots must notice a locked-version-only change.
pub(crate) fn is_dependency_input_path(path: &Path) -> bool {
    if is_manifest_path(path) {
        return true;
    }
    matches!(
        path.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
        "Cargo.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "poetry.lock"
            | "uv.lock"
            | "go.sum"
            | "Gemfile.lock"
            | "packages.lock.json"
            | "Package.resolved"
            | "composer.lock"
    )
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
    let effective_max_bytes = max_bytes.min(crate::repo_scan_policy::max_file_bytes());
    let metadata = match crate::repo_scan_policy::scan_file_metadata_for_admission(path) {
        Ok(Some(metadata)) => metadata,
        Ok(None) => {
            tracing::warn!(path = %path.display(), file_kind = %label, "external dependency input is not a regular file");
            return None;
        }
        Err(err) => {
            tracing::warn!(path = %path.display(), ?err, file_kind = %label, "failed to admit external dependency file");
            return None;
        }
    };
    if metadata.len() > effective_max_bytes {
        tracing::warn!(
            path = %path.display(),
            file_kind = %label,
            bytes = metadata.len(),
            max_bytes = effective_max_bytes,
            "external dependency file exceeds its effective read ceiling"
        );
        return None;
    }
    let bytes = match crate::workspace_scan::read_scan_bytes(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(path = %path.display(), ?err, file_kind = %label, "failed to read external dependency file");
            return None;
        }
    };
    if bytes.len() as u64 > effective_max_bytes {
        tracing::warn!(
            path = %path.display(),
            file_kind = %label,
            bytes = bytes.len(),
            max_bytes = effective_max_bytes,
            "external dependency file exceeds size cap"
        );
        return None;
    }
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

fn dedup_and_sort(mut deps: Vec<ExternalDep>) -> Result<Vec<ExternalDep>, crate::workspace_scan::ScanError> {
    crate::repo_scan_policy::check_deadline()?;
    deps.sort_by(|left, right| {
        (&left.source_manifest, &left.ecosystem, &left.name).cmp(&(
            &right.source_manifest,
            &right.ecosystem,
            &right.name,
        ))
    });
    deps.dedup_by(|left, right| {
        left.source_manifest == right.source_manifest && left.ecosystem == right.ecosystem && left.name == right.name
    });
    crate::repo_scan_policy::check_deadline()?;
    Ok(deps)
}

fn push_external_dep(deps: &mut Vec<ExternalDep>, dep: ExternalDep) {
    let generated_bytes = dep
        .name
        .len()
        .saturating_add(dep.ecosystem.len())
        .saturating_add(dep.version_req.as_deref().map_or(0, str::len))
        .saturating_add(dep.version_locked.as_deref().map_or(0, str::len))
        .saturating_add(dep.source_manifest.len())
        .saturating_add(dep.kind.len());
    if crate::repo_scan_policy::charge_generated_work(1, generated_bytes, "external dependency output").is_ok() {
        deps.push(dep);
    }
}

fn find_nearest_file(start_dir: &Path, root: &Path, file_name: &str) -> Option<PathBuf> {
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        let candidate = dir.join(file_name);
        match crate::repo_scan_policy::scan_path_is_file(&candidate) {
            Ok(true) => return Some(candidate),
            Ok(false) => {}
            Err(_) => return None,
        }
        if dir == root {
            break;
        }
        current = dir.parent();
    }
    None
}

fn parse_toml(contents: &str, path: &Path, label: &str) -> Option<toml::Value> {
    if !charge_manifest_document(contents, label) {
        return None;
    }
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

fn charge_manifest_document(contents: &str, label: &str) -> bool {
    let structural_items = contents
        .bytes()
        .filter(|byte| {
            matches!(
                byte,
                b'\n' | b'{' | b'}' | b'[' | b']' | b',' | b':' | b'=' | b'<' | b'>' | b'/' | b'"' | b'\''
            )
        })
        .count()
        .saturating_add(1);
    let estimated_bytes = contents
        .len()
        .saturating_add(structural_items.saturating_mul(std::mem::size_of::<serde_json::Value>()));
    crate::repo_scan_policy::charge_generated_work(
        structural_items,
        estimated_bytes,
        &format!("{label} parser document"),
    )
    .is_ok()
}

fn parse_json(contents: &str, path: &Path, label: &str) -> Option<serde_json::Value> {
    if !charge_manifest_document(contents, label) {
        return None;
    }
    match serde_json::from_str(contents) {
        Ok(value) => Some(value),
        Err(err) => {
            tracing::warn!(path = %path.display(), ?err, file_kind = %label, "failed to parse json external dependency file");
            None
        }
    }
}

fn charge_manifest_index(name: &str, version: &str, label: &str) -> bool {
    crate::repo_scan_policy::charge_generated_work(1, name.len().saturating_add(version.len()), label).is_ok()
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
        match crate::repo_scan_policy::scan_path_is_file(&manifest) {
            Ok(true) => {
                let workspace_table = read_utf8_file(&manifest, "Cargo.toml")
                    .and_then(|contents| parse_toml(&contents, &manifest, "Cargo.toml"))
                    .and_then(|value| table_at(&value, &["workspace", "dependencies"]).cloned());
                if let Some(table) = workspace_table {
                    return Some(table);
                }
            }
            Ok(false) => {}
            Err(_) => return None,
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
        if !charge_manifest_index(name, version, "external dependency lock index") {
            return None;
        }
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
        push_external_dep(
            deps,
            ExternalDep {
                name: name.clone(),
                ecosystem: "cargo".to_string(),
                version_req: spec.version_req,
                version_locked,
                source_manifest: source_manifest.to_string(),
                kind: kind.to_string(),
            },
        );
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
    let Some(value) = parse_json(&contents, manifest, "package.json") else {
        return;
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
        push_external_dep(
            deps,
            ExternalDep {
                name: name.clone(),
                ecosystem: "npm".to_string(),
                version_req: Some(version_req.to_string()),
                version_locked: lock_versions.and_then(|versions| versions.get(name).cloned()),
                source_manifest: source_manifest.to_string(),
                kind: kind.to_string(),
            },
        );
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
    let value = parse_json(&contents, lock, "package-lock.json")?;
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    let Some(packages) = value.get("packages").and_then(serde_json::Value::as_object) else {
        if let Some(dependencies) = value.get("dependencies").and_then(serde_json::Value::as_object) {
            for (name, package) in dependencies {
                let Some(version) = package.get("version").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                if !charge_manifest_index(name, version, "external dependency lock index") {
                    return None;
                }
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
        if !charge_manifest_index(name, version, "external dependency lock index") {
            return None;
        }
        versions.insert(name.to_string(), version.to_string());
    }
    Some(versions)
}

fn pnpm_lock_versions(lock: &Path, manifest_dir: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_lockfile(lock, "pnpm-lock.yaml")?;
    if !charge_manifest_document(&contents, "pnpm-lock.yaml") {
        return None;
    }
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
                let version = strip_pnpm_peer_suffix(version);
                if !charge_manifest_index(name, version, "external dependency lock index") {
                    return None;
                }
                versions.insert(name.to_string(), version.to_string());
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
        push_external_dep(
            deps,
            ExternalDep {
                name: name.clone(),
                ecosystem: "pypi".to_string(),
                version_req,
                version_locked: lock_versions
                    .as_ref()
                    .and_then(|versions| versions.get(&normalize_pypi_name(&name)).cloned()),
                source_manifest: source_manifest.clone(),
                kind: "normal".to_string(),
            },
        );
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
                push_external_dep(
                    deps,
                    ExternalDep {
                        name: name.clone(),
                        ecosystem: "pypi".to_string(),
                        version_req,
                        version_locked: lock_versions
                            .as_ref()
                            .and_then(|versions| versions.get(&normalize_pypi_name(&name)).cloned()),
                        source_manifest: source_manifest.clone(),
                        kind: "normal".to_string(),
                    },
                );
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
                    push_external_dep(
                        deps,
                        ExternalDep {
                            name: name.clone(),
                            ecosystem: "pypi".to_string(),
                            version_req,
                            version_locked: lock_versions
                                .as_ref()
                                .and_then(|versions| versions.get(&normalize_pypi_name(&name)).cloned()),
                            source_manifest: source_manifest.clone(),
                            kind: "optional".to_string(),
                        },
                    );
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
            push_external_dep(
                deps,
                ExternalDep {
                    name: name.clone(),
                    ecosystem: "pypi".to_string(),
                    version_req,
                    version_locked: lock_versions
                        .as_ref()
                        .and_then(|versions| versions.get(&normalize_pypi_name(name)).cloned()),
                    source_manifest: source_manifest.clone(),
                    kind: if optional { "optional" } else { "normal" }.to_string(),
                },
            );
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
        if !charge_manifest_index(name, version, "external dependency lock index") {
            return None;
        }
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
    push_external_dep(
        deps,
        ExternalDep {
            name: name.to_string(),
            ecosystem: "go".to_string(),
            version_req: Some(version.to_string()),
            version_locked: lock_versions
                .and_then(|versions| versions.get(name))
                .and_then(|versions| versions.contains(version).then(|| version.to_string())),
            source_manifest: source_manifest.to_string(),
            kind: if indirect { "indirect" } else { "normal" }.to_string(),
        },
    );
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
        if !charge_manifest_index(name, version, "external dependency lock index") {
            return None;
        }
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
    if !charge_manifest_document(&contents, "pom.xml") {
        return;
    }
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
                let name = property.tag_name().name();
                let value = value.trim();
                if !charge_manifest_index(name, value, "manifest property index") {
                    return;
                }
                properties.insert(name.to_string(), value.to_string());
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
        push_external_dep(
            deps,
            ExternalDep {
                name: format!("{group}:{artifact}"),
                ecosystem: "maven".to_string(),
                version_req,
                version_locked: None,
                source_manifest: source_manifest.clone(),
                kind: kind.to_string(),
            },
        );
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
        push_external_dep(
            deps,
            ExternalDep {
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
            },
        );
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
            if crate::repo_scan_policy::charge_generated_work(1, 1, "Gemfile block stack").is_err() {
                return;
            }
            block_stack.push(line.contains(":test") || line.contains(":development"));
            continue;
        }
        if line == "end" {
            block_stack.pop();
            continue;
        }
        if line.ends_with(" do") {
            if crate::repo_scan_policy::charge_generated_work(1, 1, "Gemfile block stack").is_err() {
                return;
            }
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
        push_external_dep(
            deps,
            ExternalDep {
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
            },
        );
    }
}

#[derive(Debug)]
struct RubyQuotedLiteral {
    value: String,
    start: usize,
}

fn ruby_quoted_literals(value: &str) -> Vec<RubyQuotedLiteral> {
    let mut values = Vec::new();
    let bytes = value.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() && values.len() < 64 {
        let quote = bytes[cursor];
        if quote != b'\'' && quote != b'"' {
            cursor += 1;
            continue;
        }
        let start = cursor;
        let content_start = cursor + 1;
        cursor = content_start;
        let mut escaped = false;
        let mut end = None;
        while cursor < bytes.len() {
            let next = bytes[cursor];
            if escaped {
                escaped = false;
            } else if next == b'\\' {
                escaped = true;
            } else if next == quote {
                end = Some(cursor);
                cursor += 1;
                break;
            }
            cursor += 1;
        }
        let Some(end) = end else {
            break;
        };
        let raw = &value[content_start..end];
        if crate::repo_scan_policy::charge_generated_work(1, raw.len(), "Gemfile quoted literal").is_err() {
            break;
        }
        let mut literal = String::with_capacity(raw.len());
        let mut escaped = false;
        for ch in raw.chars() {
            if escaped {
                literal.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                literal.push(ch);
            }
        }
        values.push(RubyQuotedLiteral { value: literal, start });
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
        if !charge_manifest_index(name, version, "external dependency lock index") {
            return None;
        }
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
    if !charge_manifest_document(&contents, "csproj") {
        return;
    }
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
        push_external_dep(
            deps,
            ExternalDep {
                name: name.to_string(),
                ecosystem: "nuget".to_string(),
                version_req,
                version_locked: lock_versions.as_ref().and_then(|versions| versions.get(&key).cloned()),
                source_manifest: source_manifest.clone(),
                kind: "normal".to_string(),
            },
        );
    }
}

fn parse_nuget_central_versions(props: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_file(props, "Directory.Packages.props")?;
    if !charge_manifest_document(&contents, "Directory.Packages.props") {
        return None;
    }
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
            if !charge_manifest_index(name, &version, "external dependency lock index") {
                return None;
            }
            versions.insert(name.to_ascii_lowercase(), version);
        }
    }
    Some(versions)
}

fn parse_nuget_lock(lock: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_lockfile(lock, "packages.lock.json")?;
    let value = parse_json(&contents, lock, "packages.lock.json")?;
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
            if !charge_manifest_index(name, version, "external dependency lock index") {
                return None;
            }
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
        push_external_dep(
            deps,
            ExternalDep {
                name: name.clone(),
                ecosystem: "swiftpm".to_string(),
                version_req,
                version_locked: lock_versions
                    .as_ref()
                    .and_then(|versions| versions.get(&name.to_ascii_lowercase()).cloned()),
                source_manifest: source_manifest.clone(),
                kind: "normal".to_string(),
            },
        );
    }
}

fn package_name_from_url(url: &str) -> Option<String> {
    let trimmed = url.trim_end_matches('/');
    let name = trimmed.rsplit('/').next()?.trim_end_matches(".git");
    (!name.is_empty()).then(|| name.to_string())
}

fn parse_swift_package_resolved(lock: &Path) -> Option<BTreeMap<String, String>> {
    let contents = read_utf8_lockfile(lock, "Package.resolved")?;
    let value = parse_json(&contents, lock, "Package.resolved")?;
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
            if !charge_manifest_index(&name, version, "external dependency lock index") {
                return None;
            }
            versions.insert(name.to_ascii_lowercase(), version.to_string());
        }
    }
    Some(versions)
}

fn parse_composer_manifest(root: &Path, manifest: &Path, deps: &mut Vec<ExternalDep>) {
    let Some(contents) = read_utf8_file(manifest, "composer.json") else {
        return;
    };
    let Some(value) = parse_json(&contents, manifest, "composer.json") else {
        return;
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
            push_external_dep(
                deps,
                ExternalDep {
                    name: name.clone(),
                    ecosystem: "composer".to_string(),
                    version_req: Some(version_req.to_string()),
                    version_locked: lock_versions
                        .as_ref()
                        .and_then(|versions| versions.get(&lower).cloned()),
                    source_manifest: source_manifest.clone(),
                    kind: kind.to_string(),
                },
            );
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
    let value = parse_json(&contents, lock, "composer.lock")?;
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
            if !charge_manifest_index(name, version, "external dependency lock index") {
                return None;
            }
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
    fn manifest_discovery_uses_the_shared_entry_budget() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for name in ["a.json", "b.json", "c.json"] {
            std::fs::write(tmp.path().join(name), "{}").expect("fixture");
        }
        let canonical = tmp.path().canonicalize().expect("canonical root");
        let policy = crate::repo_scan_policy::RepoScanPolicy::for_test_roots(
            vec![canonical.clone()],
            crate::repo_scan_policy::RepoScanLimits {
                max_files: 2,
                ..crate::repo_scan_policy::RepoScanLimits::default()
            },
        );
        let error = policy
            .execute(&canonical, scan_external_deps_in_context)
            .expect_err("manifest walker entry cap");
        assert!(error.to_string().contains("filesystem entries"));
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
    fn symlink_loop_rejects_the_manifest_scan() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a/b");
        std::fs::create_dir_all(&nested).expect("nested dirs");
        std::os::unix::fs::symlink(tmp.path(), nested.join("loop")).expect("symlink");
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"left-pad":"1"}}"#).expect("package");

        assert!(scan_external_deps(tmp.path()).is_empty());
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
}
