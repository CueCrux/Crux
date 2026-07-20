// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::json;

const SCRATCH_PREFIX: char = '_';

/// Hash each top-level ExecPlan's raw bytes using the daemon's BLAKE3 convention.
///
/// A missing root has no local plans. Other directory and file errors are
/// returned so callers do not mistake an unreadable configured root for an
/// authoritative empty directory.
pub fn compute_local_plan_hashes(root: impl AsRef<Path>) -> io::Result<BTreeMap<String, String>> {
    let entries = match fs::read_dir(root.as_ref()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error),
    };

    let mut hashes = BTreeMap::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("md") || !path.metadata()?.is_file() {
            continue;
        }
        let Some(slug) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if slug.starts_with(SCRATCH_PREFIX) {
            continue;
        }
        let bytes = fs::read(&path)?;
        hashes.insert(slug.to_string(), blake3::hash(&bytes).to_hex().to_string());
    }
    Ok(hashes)
}

/// Build the document-start script that exposes an immutable local hash map.
///
/// The map is encoded as JSON twice: the inner object preserves arbitrary
/// UTF-8 slugs as data, including `__proto__`, while the outer JSON string
/// prevents a filename from becoming executable JavaScript. No script is
/// emitted when the active profile has no configured plan root.
pub fn local_plan_hashes_initialization_script(hashes: Option<&BTreeMap<String, String>>) -> String {
    hashes.map_or_else(String::new, |hashes| {
        let expression = json_parse_expression(&hashes_json(hashes));
        format!(
            "(function(){{if(window.top!==window){{return;}}var hashes={expression};Object.defineProperty(window,\"CRUX_LOCAL_PLAN_HASHES\",{{value:Object.freeze(hashes),writable:false,configurable:false}});}})();"
        )
    })
}

fn hashes_json(hashes: &BTreeMap<String, String>) -> String {
    let mut object = String::from("{");
    for (index, (slug, hash)) in hashes.iter().enumerate() {
        if index != 0 {
            object.push(',');
        }
        json::push_string(&mut object, slug);
        object.push(':');
        json::push_string(&mut object, hash);
    }
    object.push('}');
    object
}

fn json_parse_expression(value: &str) -> String {
    format!("JSON.parse({})", javascript_string(value))
}

fn javascript_string(value: &str) -> String {
    let mut encoded_object = String::new();
    json::push_string(&mut encoded_object, value);
    encoded_object
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{compute_local_plan_hashes, local_plan_hashes_initialization_script};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "crux-local-plan-{name}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn hashes_two_plan_fixtures_by_slug() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_dir("two-fixtures");
        fs::create_dir_all(&root)?;
        fs::write(root.join("canonical.md"), b"# Canonical plan\n\nStatus: Planned\n")?;
        fs::write(root.join("beta.md"), b"# Beta\r\n\r\nStatus: In progress\r\n")?;

        let hashes = compute_local_plan_hashes(&root)?;

        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes.get("canonical").map(String::as_str),
            Some("cbeec51693582110c995e0ddfe7c07f61f3ca75a8327ae65ef023f21032564bd")
        );
        assert_eq!(
            hashes.get("beta").map(String::as_str),
            Some("b22a4364d4d9408d0f36ef4871aa66c68c9868f74baa0870ea44de9a9741321c")
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn matches_the_known_blake3_abc_vector() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_dir("known-vector");
        fs::create_dir_all(&root)?;
        fs::write(root.join("vector.md"), b"abc")?;

        let hashes = compute_local_plan_hashes(&root)?;

        assert_eq!(
            hashes.get("vector").map(String::as_str),
            Some("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn changing_one_byte_changes_the_plan_hash() -> Result<(), Box<dyn std::error::Error>> {
        const FIRST: &[u8] = b"# Copy A\n\nStatus: Planned\n";
        const SECOND: &[u8] = b"# Copy B\n\nStatus: Planned\n";
        let root = test_dir("one-byte");
        fs::create_dir_all(&root)?;
        let path = root.join("copy.md");
        fs::write(&path, FIRST)?;
        let first = compute_local_plan_hashes(&root)?;
        fs::write(path, SECOND)?;
        let second = compute_local_plan_hashes(&root)?;

        assert_eq!(FIRST.iter().zip(SECOND).filter(|(a, b)| a != b).count(), 1);
        assert_ne!(first.get("copy"), second.get("copy"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn ignores_non_markdown_subdirectories_and_scratchpads() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_dir("ignored");
        fs::create_dir_all(root.join("nested"))?;
        fs::create_dir_all(root.join("directory.md"))?;
        fs::write(root.join("notes.txt"), b"not a plan")?;
        fs::write(root.join("nested").join("nested.md"), b"# Nested\n")?;
        fs::write(root.join("_scratch.md"), b"# Scratch\n")?;

        let hashes = compute_local_plan_hashes(&root)?;

        assert!(hashes.is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_root_returns_an_empty_map() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_dir("missing");
        let hashes = compute_local_plan_hashes(root)?;
        assert!(hashes.is_empty());
        Ok(())
    }

    #[test]
    fn initialization_script_treats_hostile_slugs_as_json_data() {
        let hashes = BTreeMap::from([
            ("__proto__".to_string(), "aa".to_string()),
            ("quote\"\\\n</script>\u{2028}".to_string(), "bb".to_string()),
        ]);

        let script = local_plan_hashes_initialization_script(Some(&hashes));

        assert!(script.starts_with("(function(){if(window.top!==window){return;}var hashes=JSON.parse("));
        assert!(script.contains("Object.defineProperty(window,\"CRUX_LOCAL_PLAN_HASHES\""));
        assert!(script.contains("Object.freeze(hashes)"));
        assert!(script.contains("\\\\\\\""));
        assert!(!script.contains("quote\"\\\n</script>\u{2028}"));
        assert!(!script.contains('\n'));
        assert!(!script.contains('\u{2028}'));
        assert!(script.contains("writable:false,configurable:false"));
        assert!(script.ends_with("})();"));
    }

    #[test]
    fn no_root_initialization_script_injects_nothing() {
        assert!(local_plan_hashes_initialization_script(None).is_empty());
    }
}
