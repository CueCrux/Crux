// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crux_integrations::{EntryKind, IntegrationManifest, ValidationPolicy, FIRST_PARTY_PASSPORT};

const DANGEROUS_CAPABILITIES: &[&str] = &[
    "admin:read",
    "facts:private:read",
    "integrations:grant",
    "integrations:install",
    "sessions:write",
    "tenant:content:preview",
];

#[derive(Debug, serde::Deserialize)]
struct ReviewGate {
    maintainer_approval: bool,
    rationale: String,
}

#[test]
fn community_pack_manifests_are_safe_and_reviewable() -> Result<(), Box<dyn Error>> {
    let community_root = repo_root().join("integrations/community");
    assert!(
        community_root.exists(),
        "integrations/community must exist for public pack PRs"
    );

    let mut manifests = Vec::new();
    collect_manifests(&community_root, &mut manifests)?;
    for manifest_path in manifests {
        validate_manifest_file(&manifest_path)?;
    }
    Ok(())
}

fn validate_manifest_file(manifest_path: &Path) -> Result<(), Box<dyn Error>> {
    let manifest_text = fs::read_to_string(manifest_path)?;
    let manifest: IntegrationManifest = serde_json::from_str(&manifest_text)?;
    manifest.validate(&ValidationPolicy::default())?;

    assert_ne!(
        manifest.publisher_passport_fpr,
        FIRST_PARTY_PASSPORT,
        "{} must not claim first-party publisher identity",
        manifest_path.display()
    );
    assert!(
        manifest.hashes.manifest.is_some(),
        "{} must include hashes.manifest",
        manifest_path.display()
    );
    assert!(
        manifest.signature.is_some(),
        "{} must include an Ed25519 Passport signature",
        manifest_path.display()
    );
    assert!(
        manifest.entry.kind != EntryKind::ExternalHelper,
        "{} uses external_helper; community v1 packs are declarative only",
        manifest_path.display()
    );
    assert!(
        is_safe_relative_path(&manifest.entry.path),
        "{} has unsafe entry.path '{}'",
        manifest_path.display(),
        manifest.entry.path
    );

    let pack_dir = manifest_path.parent().ok_or("manifest path has no parent")?;
    assert!(
        pack_dir.join("README.md").exists(),
        "{} must include README.md with setup and safety notes",
        pack_dir.display()
    );
    if requires_maintainer_review(&manifest) {
        let review_path = pack_dir.join("review.json");
        let review: ReviewGate = serde_json::from_str(&fs::read_to_string(&review_path)?)?;
        assert!(
            review.maintainer_approval,
            "{} must set maintainer_approval=true",
            review_path.display()
        );
        assert!(
            !review.rationale.trim().is_empty(),
            "{} must include a non-empty rationale",
            review_path.display()
        );
    }

    Ok(())
}

fn collect_manifests(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_manifests(&path, out)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("manifest.json") {
            out.push(path);
        }
    }
    Ok(())
}

fn requires_maintainer_review(manifest: &IntegrationManifest) -> bool {
    manifest
        .capabilities
        .iter()
        .any(|capability| DANGEROUS_CAPABILITIES.contains(&capability.as_str()))
}

fn is_safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && !value.is_empty()
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").clone()
}
