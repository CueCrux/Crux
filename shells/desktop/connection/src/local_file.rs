// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ConnectionError;

const MARKDOWN_EXTENSION: &str = "md";
const PATH_NOT_ALLOWED: &str = "requested path is not an allowlisted local ExecPlan Markdown file";

/// Authorise an existing local ExecPlan file and return its canonical path.
///
/// Relative requests are resolved from `configured_plan_root`. Both the root
/// and candidate are canonicalised before the containment check, so traversal
/// and symlinks cannot escape the configured root.
pub fn authorize_local_plan_path(
    configured_plan_root: impl AsRef<Path>,
    requested_path: impl AsRef<Path>,
) -> Result<PathBuf, ConnectionError> {
    let canonical_root = fs::canonicalize(configured_plan_root).map_err(|_| path_not_allowed())?;
    if !fs::metadata(&canonical_root).map_err(|_| path_not_allowed())?.is_dir() {
        return Err(path_not_allowed());
    }

    let requested_path = requested_path.as_ref();
    if requested_path.extension() != Some(OsStr::new(MARKDOWN_EXTENSION)) {
        return Err(path_not_allowed());
    }
    let candidate = if requested_path.is_absolute() {
        requested_path.to_path_buf()
    } else {
        canonical_root.join(requested_path)
    };
    let canonical_candidate = fs::canonicalize(candidate).map_err(|_| path_not_allowed())?;
    if canonical_candidate == canonical_root
        || !canonical_candidate.starts_with(&canonical_root)
        || canonical_candidate.extension() != Some(OsStr::new(MARKDOWN_EXTENSION))
        || !fs::metadata(&canonical_candidate)
            .map_err(|_| path_not_allowed())?
            .is_file()
    {
        return Err(path_not_allowed());
    }

    Ok(canonical_candidate)
}

fn path_not_allowed() -> ConnectionError {
    ConnectionError::new(PATH_NOT_ALLOWED)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::authorize_local_plan_path;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "crux-local-file-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn create_fixture(name: &str) -> (PathBuf, PathBuf) {
        let fixture = test_dir(name);
        let root = fixture.join("plans");
        fs::create_dir_all(&root).unwrap();
        (fixture, root)
    }

    fn remove_fixture(fixture: &Path) {
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn allows_existing_markdown_file_strictly_inside_root() {
        let (fixture, root) = create_fixture("allowed");
        let plan = root.join("mission.md");
        fs::write(&plan, b"# Mission\n").unwrap();
        let canonical_plan = fs::canonicalize(&plan).unwrap();

        assert_eq!(authorize_local_plan_path(&root, "mission.md").unwrap(), canonical_plan);
        assert_eq!(authorize_local_plan_path(&root, &plan).unwrap(), canonical_plan);

        remove_fixture(&fixture);
    }

    #[test]
    fn rejects_traversal_and_absolute_outside_paths() {
        let (fixture, root) = create_fixture("outside");
        let outside = fixture.join("outside.md");
        fs::write(&outside, b"# Outside\n").unwrap();

        assert!(authorize_local_plan_path(&root, "../outside.md").is_err());
        assert!(authorize_local_plan_path(&root, &outside).is_err());

        remove_fixture(&fixture);
    }

    #[test]
    fn rejects_non_markdown_missing_and_directory_paths() {
        let (fixture, root) = create_fixture("invalid-kind");
        let text = root.join("notes.txt");
        let uppercase = root.join("notes.MD");
        let markdown_directory = root.join("nested.md");
        fs::write(&text, b"notes\n").unwrap();
        fs::write(&uppercase, b"notes\n").unwrap();
        fs::create_dir(&markdown_directory).unwrap();

        assert!(authorize_local_plan_path(&root, &text).is_err());
        assert!(authorize_local_plan_path(&root, &uppercase).is_err());
        assert!(authorize_local_plan_path(&root, "missing.md").is_err());
        assert!(authorize_local_plan_path(&root, &markdown_directory).is_err());
        assert!(authorize_local_plan_path(&root, ".").is_err());
        assert!(authorize_local_plan_path(&root, &root).is_err());

        remove_fixture(&fixture);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let (fixture, root) = create_fixture("symlink-escape");
        let outside = fixture.join("outside.md");
        let link = root.join("escape.md");
        fs::write(&outside, b"# Outside\n").unwrap();
        symlink(&outside, &link).unwrap();

        assert!(authorize_local_plan_path(&root, &link).is_err());

        remove_fixture(&fixture);
    }
}
