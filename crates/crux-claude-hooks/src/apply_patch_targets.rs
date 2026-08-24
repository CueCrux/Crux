// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Parse the canonical Codex `apply_patch` envelope into punchcard resources.
//!
//! This deliberately parses only the target-bearing envelope. Hunk contents
//! remain opaque and are applied by Codex itself; the hook never executes or
//! shell-expands patch text.

use std::fmt;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

const BEGIN_PATCH: &str = "*** Begin Patch";
const END_PATCH: &str = "*** End Patch";
const ADD_FILE: &str = "*** Add File: ";
const UPDATE_FILE: &str = "*** Update File: ";
const DELETE_FILE: &str = "*** Delete File: ";
const MOVE_TO: &str = "*** Move to: ";
const END_OF_FILE: &str = "*** End of File";
const MAX_TARGETS: usize = 24;

/// One normalized path affected by a canonical patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AffectedPath {
    path: PathBuf,
    must_exist: bool,
}

impl AffectedPath {
    /// Absolute lexical path used as the `file://` punchcard key.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// A bounded, non-secret parser or normalization failure suitable for a hook
/// denial reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetError {
    Malformed(&'static str),
    InvalidCwd,
    InvalidPath(&'static str),
    TooManyTargets,
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(formatter, "malformed apply_patch envelope: {reason}"),
            Self::InvalidCwd => write!(formatter, "apply_patch cwd must be a safe absolute directory"),
            Self::InvalidPath(reason) => write!(formatter, "unsafe apply_patch target: {reason}"),
            Self::TooManyTargets => write!(
                formatter,
                "apply_patch touches more than {MAX_TARGETS} files; split it into smaller patches"
            ),
        }
    }
}

impl std::error::Error for TargetError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionKind {
    Add,
    Update,
    Delete,
}

#[derive(Debug)]
struct RawSection<'a> {
    kind: SectionKind,
    source: &'a str,
    destination: Option<&'a str>,
}

/// Parse and normalize every affected path in `command` against `cwd`.
pub(crate) fn parse(command: &str, cwd: &str) -> Result<Vec<AffectedPath>, TargetError> {
    if command.contains('\0') {
        return Err(TargetError::Malformed("NUL bytes are not permitted"));
    }

    let lines = command
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>();
    let first = lines
        .iter()
        .position(|line| !line.trim().is_empty())
        .ok_or(TargetError::Malformed("patch is empty"))?;
    let last = lines
        .iter()
        .rposition(|line| !line.trim().is_empty())
        .ok_or(TargetError::Malformed("patch is empty"))?;

    if lines[first] != BEGIN_PATCH {
        return Err(TargetError::Malformed("Begin Patch must be first"));
    }
    if lines[last] != END_PATCH {
        return Err(TargetError::Malformed("End Patch must be last"));
    }

    let mut sections = Vec::new();
    let mut index = first + 1;
    while index < last {
        if lines[index].trim().is_empty() {
            index += 1;
            continue;
        }

        let (kind, source) = parse_section_header(lines[index])?;
        index += 1;

        let mut destination = None;
        if kind == SectionKind::Update && index < last {
            if let Some(path) = lines[index].strip_prefix(MOVE_TO) {
                destination = Some(require_path(path)?);
                index += 1;
            }
        }

        let mut has_add_line = false;
        let mut has_update_hunk = false;
        let mut delete_has_body = false;
        while index < last && !is_section_header(lines[index]) {
            let line = lines[index];
            reject_ambiguous_control(line, kind)?;

            if !line.trim().is_empty() {
                match kind {
                    SectionKind::Add => has_add_line |= line.starts_with('+'),
                    SectionKind::Update => {
                        has_update_hunk |= line == "@@" || line.starts_with("@@ ");
                    }
                    SectionKind::Delete => delete_has_body = true,
                }
            }
            index += 1;
        }

        match kind {
            SectionKind::Add if !has_add_line => {
                return Err(TargetError::Malformed("Add File requires a + body line"));
            }
            SectionKind::Update if !has_update_hunk && destination.is_none() => {
                return Err(TargetError::Malformed("Update File requires a hunk or Move to"));
            }
            SectionKind::Delete if delete_has_body => {
                return Err(TargetError::Malformed("Delete File must be header-only"));
            }
            _ => {}
        }

        sections.push(RawSection {
            kind,
            source,
            destination,
        });
    }

    if sections.is_empty() {
        return Err(TargetError::Malformed("patch has no file section"));
    }

    normalize_sections(&sections, cwd)
}

fn parse_section_header(line: &str) -> Result<(SectionKind, &str), TargetError> {
    if let Some(path) = line.strip_prefix(ADD_FILE) {
        return Ok((SectionKind::Add, require_path(path)?));
    }
    if let Some(path) = line.strip_prefix(UPDATE_FILE) {
        return Ok((SectionKind::Update, require_path(path)?));
    }
    if let Some(path) = line.strip_prefix(DELETE_FILE) {
        return Ok((SectionKind::Delete, require_path(path)?));
    }
    if line.starts_with("*** Environment ID:") {
        return Err(TargetError::Malformed("Environment ID is not supported"));
    }
    if line.starts_with("***") {
        return Err(TargetError::Malformed("unknown or misplaced control line"));
    }
    if is_indented_control(line) {
        return Err(TargetError::Malformed("indented operation marker is ambiguous"));
    }
    Err(TargetError::Malformed("expected a file section header"))
}

fn require_path(path: &str) -> Result<&str, TargetError> {
    if path.trim().is_empty() {
        Err(TargetError::Malformed("file path is empty"))
    } else {
        Ok(path)
    }
}

fn is_section_header(line: &str) -> bool {
    line.starts_with(ADD_FILE) || line.starts_with(UPDATE_FILE) || line.starts_with(DELETE_FILE)
}

fn is_indented_control(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed != line
        && (trimmed == BEGIN_PATCH
            || trimmed == END_PATCH
            || trimmed == END_OF_FILE
            || trimmed.starts_with(ADD_FILE)
            || trimmed.starts_with(UPDATE_FILE)
            || trimmed.starts_with(DELETE_FILE)
            || trimmed.starts_with(MOVE_TO)
            || trimmed.starts_with("*** Environment ID:"))
}

fn reject_ambiguous_control(line: &str, kind: SectionKind) -> Result<(), TargetError> {
    if is_indented_control(line) {
        return Err(TargetError::Malformed("indented operation marker is ambiguous"));
    }
    if line.starts_with("*** Environment ID:") {
        return Err(TargetError::Malformed("Environment ID is not supported"));
    }
    if line.starts_with("***") && !(kind == SectionKind::Update && line == END_OF_FILE) {
        return Err(TargetError::Malformed("unknown or misplaced control line"));
    }
    Ok(())
}

fn normalize_sections(sections: &[RawSection<'_>], cwd: &str) -> Result<Vec<AffectedPath>, TargetError> {
    let cwd = normalize_cwd(cwd)?;
    let mut targets = Vec::new();

    for section in sections {
        let source_must_exist = section.kind != SectionKind::Add;
        let source = normalize_target(section.source, &cwd, source_must_exist)?;

        if let Some(destination) = section.destination {
            let destination = normalize_target(destination, &cwd, false)?;
            if destination == source {
                return Err(TargetError::InvalidPath("Move to destination equals its source"));
            }
            push_deduplicated(&mut targets, source, source_must_exist)?;
            push_deduplicated(&mut targets, destination, false)?;
        } else {
            push_deduplicated(&mut targets, source, source_must_exist)?;
        }
    }

    Ok(targets)
}

fn normalize_cwd(cwd: &str) -> Result<PathBuf, TargetError> {
    if cwd.is_empty() || cwd.contains('\0') {
        return Err(TargetError::InvalidCwd);
    }
    let path = Path::new(cwd);
    if !path.is_absolute() || has_parent_component(path) {
        return Err(TargetError::InvalidCwd);
    }
    let normalized = lexical_normalize(path);
    if normalized.as_os_str().is_empty() {
        return Err(TargetError::InvalidCwd);
    }
    inspect_existing_components(&normalized, true).map_err(|_| TargetError::InvalidCwd)?;
    let metadata = std::fs::symlink_metadata(&normalized).map_err(|_| TargetError::InvalidCwd)?;
    if !metadata.is_dir() {
        return Err(TargetError::InvalidCwd);
    }
    Ok(normalized)
}

fn normalize_target(path: &str, cwd: &Path, must_exist: bool) -> Result<PathBuf, TargetError> {
    if path.contains('\0') {
        return Err(TargetError::InvalidPath("NUL bytes are not permitted"));
    }
    let raw = Path::new(path);
    if has_parent_component(raw) {
        return Err(TargetError::InvalidPath("parent traversal is not permitted"));
    }
    let normalized = normalize_target_unchecked(path, cwd);
    if normalized == cwd || !normalized.starts_with(cwd) {
        return Err(TargetError::InvalidPath("target must remain below cwd"));
    }
    inspect_existing_components(&normalized, must_exist)?;
    Ok(normalized)
}

fn normalize_target_unchecked(path: &str, cwd: &Path) -> PathBuf {
    let raw = Path::new(path);
    if raw.is_absolute() {
        lexical_normalize(raw)
    } else {
        lexical_normalize(&cwd.join(raw))
    }
}

fn has_parent_component(path: &Path) -> bool {
    path.components().any(|component| component == Component::ParentDir)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            // Callers reject ParentDir before reaching this helper.
            Component::CurDir | Component::ParentDir => {}
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn inspect_existing_components(path: &Path, must_exist: bool) -> Result<(), TargetError> {
    let mut prefixes = path.ancestors().collect::<Vec<_>>();
    prefixes.reverse();

    for (index, prefix) in prefixes.iter().enumerate() {
        let is_target = index + 1 == prefixes.len();
        match std::fs::symlink_metadata(prefix) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(TargetError::InvalidPath("existing symlink component is not permitted"));
                }
                if !is_target && !metadata.is_dir() {
                    return Err(TargetError::InvalidPath("intermediate component is not a directory"));
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound && !must_exist => break,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(TargetError::InvalidPath("Update/Delete source does not exist"));
            }
            Err(_) => {
                return Err(TargetError::InvalidPath("path metadata could not be inspected"));
            }
        }
    }
    Ok(())
}

fn push_deduplicated(targets: &mut Vec<AffectedPath>, path: PathBuf, must_exist: bool) -> Result<(), TargetError> {
    if let Some(existing) = targets.iter_mut().find(|target| target.path == path) {
        existing.must_exist |= must_exist;
        return Ok(());
    }
    if targets.len() == MAX_TARGETS {
        return Err(TargetError::TooManyTargets);
    }
    targets.push(AffectedPath { path, must_exist });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    use std::fs;

    fn root() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn names(targets: &[AffectedPath]) -> Vec<String> {
        targets
            .iter()
            .map(|target| target.path().file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn add_update_delete_and_dedup_are_ordered() {
        let root = root();
        fs::write(root.path().join("update.rs"), "old").unwrap();
        fs::write(root.path().join("delete.rs"), "old").unwrap();
        let patch = "*** Begin Patch\n*** Add File: add.rs\n+new\n*** Update File: ./update.rs\n@@\n-old\n+new\n*** Delete File: delete.rs\n*** Add File: ./add.rs\n+again\n*** End Patch\n";
        let targets = parse(patch, root.path().to_str().unwrap()).unwrap();
        assert_eq!(names(&targets), ["add.rs", "update.rs", "delete.rs"]);
    }

    #[test]
    fn update_move_includes_both_endpoints() {
        let root = root();
        fs::write(root.path().join("old name.rs"), "old").unwrap();
        let patch = "*** Begin Patch\n*** Update File: old name.rs\n*** Move to: new 名.rs\n*** End Patch";
        let targets = parse(patch, root.path().to_str().unwrap()).unwrap();
        assert_eq!(names(&targets), ["old name.rs", "new 名.rs"]);
    }

    #[test]
    fn header_only_delete_and_move_only_update_are_valid() {
        let root = root();
        fs::write(root.path().join("delete.rs"), "old").unwrap();
        fs::write(root.path().join("move.rs"), "old").unwrap();
        let patch = "*** Begin Patch\n*** Delete File: delete.rs\n*** Update File: move.rs\n*** Move to: moved.rs\n*** End Patch";
        assert_eq!(parse(patch, root.path().to_str().unwrap()).unwrap().len(), 3);
    }

    #[test]
    fn add_needs_plus_and_update_needs_hunk_or_move() {
        let root = root();
        fs::write(root.path().join("x"), "old").unwrap();
        let add = "*** Begin Patch\n*** Add File: a\nplain\n*** End Patch";
        let update = "*** Begin Patch\n*** Update File: x\n-old\n+new\n*** End Patch";
        assert!(parse(add, root.path().to_str().unwrap()).is_err());
        assert!(parse(update, root.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn accepts_twenty_four_unique_targets_and_rejects_twenty_five() {
        let root = root();
        let patch = |count| {
            let mut sections = String::new();
            for index in 0..count {
                writeln!(&mut sections, "*** Add File: {index}.rs\n+{index}").unwrap();
            }
            format!("*** Begin Patch\n{sections}*** End Patch")
        };
        assert_eq!(parse(&patch(24), root.path().to_str().unwrap()).unwrap().len(), 24);
        assert_eq!(
            parse(&patch(25), root.path().to_str().unwrap()).unwrap_err(),
            TargetError::TooManyTargets
        );
    }

    #[test]
    fn crlf_and_update_end_marker_are_valid() {
        let root = root();
        fs::write(root.path().join("x"), "old").unwrap();
        let patch =
            "*** Begin Patch\r\n*** Update File: x\r\n@@\r\n-old\r\n+new\r\n*** End of File\r\n*** End Patch\r\n";
        assert_eq!(parse(patch, root.path().to_str().unwrap()).unwrap().len(), 1);
    }

    #[test]
    fn malformed_envelopes_and_controls_are_rejected() {
        let root = root();
        let cwd = root.path().to_str().unwrap();
        let cases = [
            "*** Add File: a\n+x\n*** End Patch",
            "*** Begin Patch\n*** Add File: a\n+x",
            "*** Begin Patch\n*** End Patch",
            "*** Begin Patch\n*** Add File: \n+x\n*** End Patch",
            "*** Begin Patch\n*** Move to: b\n*** End Patch",
            "*** Begin Patch\n*** Add File: a\n+x\n*** Mystery: b\n*** End Patch",
            "*** Begin Patch\n*** Environment ID: prod\n*** Add File: a\n+x\n*** End Patch",
            "*** Begin Patch\n *** Add File: a\n+x\n*** End Patch",
            "*** Begin Patch\n*** Add File: a\n+x\n*** End Patch\ntrailing",
            "*** Begin Patch\n*** Begin Patch\n*** Add File: a\n+x\n*** End Patch",
        ];
        for patch in cases {
            assert!(parse(patch, cwd).is_err(), "accepted malformed patch: {patch:?}");
        }
    }

    #[test]
    fn duplicate_and_stray_moves_are_rejected() {
        let root = root();
        fs::write(root.path().join("x"), "old").unwrap();
        let duplicate = "*** Begin Patch\n*** Update File: x\n*** Move to: y\n*** Move to: z\n*** End Patch";
        let late = "*** Begin Patch\n*** Update File: x\n@@\n-old\n+new\n*** Move to: y\n*** End Patch";
        assert!(parse(duplicate, root.path().to_str().unwrap()).is_err());
        assert!(parse(late, root.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn parent_traversal_absolute_escape_and_missing_source_are_rejected() {
        let root = root();
        let cwd = root.path().to_str().unwrap();
        let parent = "*** Begin Patch\n*** Add File: link/../victim\n+x\n*** End Patch";
        let outside = "*** Begin Patch\n*** Add File: /tmp/outside-crux-hook-test\n+x\n*** End Patch";
        let missing = "*** Begin Patch\n*** Update File: missing\n@@\n-old\n+new\n*** End Patch";
        assert!(parse(parent, cwd).is_err());
        assert!(parse(outside, cwd).is_err());
        assert!(parse(missing, cwd).is_err());
    }

    #[test]
    fn add_below_safe_parent_is_valid_and_non_directory_prefix_is_rejected() {
        let root = root();
        fs::create_dir(root.path().join("safe")).unwrap();
        fs::write(root.path().join("file"), "not a directory").unwrap();
        let valid = "*** Begin Patch\n*** Add File: safe/new/nested.rs\n+x\n*** End Patch";
        let invalid = "*** Begin Patch\n*** Add File: file/child.rs\n+x\n*** End Patch";
        assert!(parse(valid, root.path().to_str().unwrap()).is_ok());
        assert!(parse(invalid, root.path().to_str().unwrap()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_component_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = root();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("link")).unwrap();
        let patch = "*** Begin Patch\n*** Add File: link/new.rs\n+x\n*** End Patch";
        assert!(parse(patch, root.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn move_destination_must_not_equal_source() {
        let root = root();
        fs::write(root.path().join("x"), "old").unwrap();
        let patch = "*** Begin Patch\n*** Update File: x\n*** Move to: ./x\n*** End Patch";
        assert!(parse(patch, root.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn nul_and_relative_cwd_are_rejected() {
        let root = root();
        let nul = "*** Begin Patch\n*** Add File: a\0b\n+x\n*** End Patch";
        let valid = "*** Begin Patch\n*** Add File: a\n+x\n*** End Patch";
        assert!(parse(nul, root.path().to_str().unwrap()).is_err());
        assert!(parse(valid, "relative/cwd").is_err());
    }
}
