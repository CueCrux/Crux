// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Managed-section composer.
//!
//! The composer is line-oriented (no markdown AST). It scans the existing
//! file for `<!-- BEGIN-CRUX-MANAGED:<name> v<n> -->` / `<!-- END-CRUX-MANAGED:<name> -->`
//! marker pairs, replaces only the spans inside matched pairs, and
//! appends any missing managed spans at the end of the file (in `order`).
//! Text outside markers is preserved verbatim.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use crate::profile::ProfileFragment;
use crate::Target;

#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error("io error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("unbalanced markers in {path}: {reason}")]
    UnbalancedMarkers { path: String, reason: String },
    #[error("manual edit detected inside managed section '{profile}' in {path}; refuse to overwrite without --force")]
    Drift { path: String, profile: String },
}

#[derive(Debug, Clone)]
pub struct ComposeReport {
    pub wrote: bool,
    pub managed_sections_updated: usize,
    pub managed_sections_added: usize,
    pub drift_detected: Vec<String>,
}

/// Compose `target` (CLAUDE.md or AGENTS.md) by replacing managed sections
/// with content rendered from `fragments`. Only fragments whose `targets`
/// includes the given Target are considered. Returns a report; `wrote` is
/// false in dry-run mode.
pub fn compose_file(
    workspace_root: &Path,
    target: Target,
    fragments: &[ProfileFragment],
    force: bool,
    dry_run: bool,
) -> Result<ComposeReport, ComposeError> {
    let relevant: Vec<&ProfileFragment> = fragments
        .iter()
        .filter(|f| f.frontmatter.targets.contains(&target))
        .collect();

    let path = workspace_root.join(target.filename());
    let existing = if path.exists() {
        fs::read_to_string(&path).map_err(|e| ComposeError::Io {
            path: path.display().to_string(),
            source: e,
        })?
    } else {
        String::new()
    };

    let spans = parse_spans(&existing).map_err(|reason| ComposeError::UnbalancedMarkers {
        path: path.display().to_string(),
        reason,
    })?;

    // Index managed sections by name from the existing file.
    let mut existing_managed: std::collections::HashMap<String, (usize, ManagedSpan)> =
        std::collections::HashMap::new();
    for (idx, span) in spans.iter().enumerate() {
        if let Span::Managed(m) = span {
            existing_managed.insert(m.name.clone(), (idx, m.clone()));
        }
    }

    // Detect drift: compare the body of every existing managed span against
    // the bundled fragment body. If different, refuse unless --force.
    let mut drift = Vec::new();
    for (name, (_idx, m)) in &existing_managed {
        let frag = relevant.iter().find(|f| &f.frontmatter.name == name);
        if let Some(f) = frag {
            let expected = render_managed_body(f);
            if normalise(&m.body) != normalise(&expected) && !force {
                drift.push(name.clone());
            }
        }
    }
    if !drift.is_empty() && !force {
        return Err(ComposeError::Drift {
            path: path.display().to_string(),
            profile: drift.join(", "),
        });
    }

    // Build the new file. For each span: if Managed and we have an updated
    // fragment, replace; else preserve. Then append any fragment we haven't
    // emitted yet, in `order`.
    let mut emitted = std::collections::HashSet::<String>::new();
    let mut new_text = String::new();
    let mut updated = 0usize;

    for span in &spans {
        match span {
            Span::Free(text) => {
                new_text.push_str(text);
            }
            Span::Managed(m) => {
                if let Some(f) = relevant.iter().find(|f| f.frontmatter.name == m.name) {
                    new_text.push_str(&render_full_section(f));
                    emitted.insert(m.name.clone());
                    updated += 1;
                } else {
                    // Profile no longer enabled — drop the section entirely.
                    // (Add/remove flow handles this.)
                }
            }
        }
    }

    // Append fragments not yet emitted, in order.
    let mut to_append: Vec<&&ProfileFragment> = relevant
        .iter()
        .filter(|f| !emitted.contains(&f.frontmatter.name))
        .collect();
    to_append.sort_by_key(|f| f.frontmatter.order);
    let mut added = 0usize;
    for f in &to_append {
        if !new_text.is_empty() && !new_text.ends_with("\n\n") {
            if new_text.ends_with('\n') {
                new_text.push('\n');
            } else {
                new_text.push_str("\n\n");
            }
        }
        new_text.push_str(&render_full_section(f));
        added += 1;
    }

    let wrote = if !dry_run && new_text != existing {
        write_atomic(&path, &new_text).map_err(|e| ComposeError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        true
    } else {
        false
    };

    Ok(ComposeReport {
        wrote,
        managed_sections_updated: updated,
        managed_sections_added: added,
        drift_detected: drift,
    })
}

fn render_full_section(f: &ProfileFragment) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    writeln!(
        s,
        "<!-- BEGIN-CRUX-MANAGED:{} v{} -->",
        f.frontmatter.name, f.frontmatter.version
    )
    .expect("write to String cannot fail");
    s.push_str(&render_managed_body(f));
    if !s.ends_with('\n') {
        s.push('\n');
    }
    writeln!(s, "<!-- END-CRUX-MANAGED:{} -->", f.frontmatter.name).expect("write to String cannot fail");
    s
}

fn render_managed_body(f: &ProfileFragment) -> String {
    // The body comes from the fragment file verbatim (post-frontmatter). The
    // composer doesn't transform it; the file is the contract.
    let mut body = f.body.clone();
    if !body.ends_with('\n') {
        body.push('\n');
    }
    body
}

fn normalise(text: &str) -> String {
    text.lines()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[derive(Debug, Clone)]
enum Span {
    Free(String),
    Managed(ManagedSpan),
}

#[derive(Debug, Clone)]
struct ManagedSpan {
    name: String,
    #[allow(dead_code)]
    version: u32,
    body: String,
}

fn parse_spans(text: &str) -> Result<Vec<Span>, String> {
    let mut spans = Vec::new();
    let mut buf = String::new();
    let mut in_managed: Option<(String, u32, String)> = None;
    for (lineno, line) in text.split_inclusive('\n').enumerate() {
        if let Some((begin_name, begin_ver)) = parse_begin_marker(line) {
            if in_managed.is_some() {
                return Err(format!("nested BEGIN marker at line {}", lineno + 1));
            }
            if !buf.is_empty() {
                spans.push(Span::Free(std::mem::take(&mut buf)));
            }
            in_managed = Some((begin_name, begin_ver, String::new()));
        } else if let Some(end_name) = parse_end_marker(line) {
            match in_managed.take() {
                Some((name, ver, body)) if name == end_name => {
                    spans.push(Span::Managed(ManagedSpan {
                        name,
                        version: ver,
                        body,
                    }));
                }
                Some((name, _, _)) => {
                    return Err(format!(
                        "mismatched END marker at line {}: opened '{}', closed '{}'",
                        lineno + 1,
                        name,
                        end_name
                    ));
                }
                None => {
                    return Err(format!("END marker without BEGIN at line {}", lineno + 1));
                }
            }
        } else if let Some((_, _, ref mut body)) = in_managed {
            body.push_str(line);
        } else {
            buf.push_str(line);
        }
    }
    if let Some((name, _, _)) = in_managed {
        return Err(format!("unclosed BEGIN marker for '{name}'"));
    }
    if !buf.is_empty() {
        spans.push(Span::Free(buf));
    }
    Ok(spans)
}

fn parse_begin_marker(line: &str) -> Option<(String, u32)> {
    let s = line.trim();
    let prefix = "<!-- BEGIN-CRUX-MANAGED:";
    let suffix = "-->";
    let inner = s.strip_prefix(prefix)?.strip_suffix(suffix)?.trim();
    let mut parts = inner.split_whitespace();
    let name = parts.next()?.to_string();
    let ver_token = parts.next()?;
    let ver: u32 = ver_token.strip_prefix('v').and_then(|n| n.parse().ok())?;
    Some((name, ver))
}

fn parse_end_marker(line: &str) -> Option<String> {
    let s = line.trim();
    let prefix = "<!-- END-CRUX-MANAGED:";
    let suffix = "-->";
    let inner = s.strip_prefix(prefix)?.strip_suffix(suffix)?.trim();
    Some(inner.to_string())
}

fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("md.tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileFragment;
    use tempfile::TempDir;

    fn frag(name: &str, ver: u32, order: u32, body: &str) -> ProfileFragment {
        let raw = format!(
            "+++\nname = \"{name}\"\nversion = {ver}\ndescription = \"d\"\ntargets = [\"claude_md\"]\norder = {order}\n+++\n\n{body}\n"
        );
        ProfileFragment::parse(name, &raw).unwrap()
    }

    #[test]
    fn fresh_file_gets_all_sections_appended() {
        let dir = TempDir::new().unwrap();
        let fragments = vec![frag("a", 1, 10, "## A body"), frag("b", 1, 20, "## B body")];
        let r = compose_file(dir.path(), Target::ClaudeMd, &fragments, false, false).unwrap();
        assert!(r.wrote);
        assert_eq!(r.managed_sections_added, 2);
        let txt = std::fs::read_to_string(dir.path().join("CLAUDE.md")).unwrap();
        assert!(txt.contains("BEGIN-CRUX-MANAGED:a v1"));
        assert!(txt.contains("BEGIN-CRUX-MANAGED:b v1"));
        assert!(txt.find("a v1").unwrap() < txt.find("b v1").unwrap());
    }

    #[test]
    fn idempotent_regenerate_byte_identical() {
        let dir = TempDir::new().unwrap();
        let fragments = vec![frag("a", 1, 10, "## A body"), frag("b", 1, 20, "## B body")];
        compose_file(dir.path(), Target::ClaudeMd, &fragments, false, false).unwrap();
        let first = std::fs::read_to_string(dir.path().join("CLAUDE.md")).unwrap();
        let r = compose_file(dir.path(), Target::ClaudeMd, &fragments, false, false).unwrap();
        let second = std::fs::read_to_string(dir.path().join("CLAUDE.md")).unwrap();
        assert_eq!(first, second);
        assert!(!r.wrote, "second regenerate must be a no-op");
    }

    #[test]
    fn manual_content_outside_markers_preserved() {
        let dir = TempDir::new().unwrap();
        let fragments = vec![frag("a", 1, 10, "## A body")];
        compose_file(dir.path(), Target::ClaudeMd, &fragments, false, false).unwrap();
        let path = dir.path().join("CLAUDE.md");
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("\n## My own section\nKeep me!\n");
        std::fs::write(&path, &text).unwrap();
        compose_file(dir.path(), Target::ClaudeMd, &fragments, false, false).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("## My own section"));
        assert!(after.contains("Keep me!"));
    }

    #[test]
    fn drift_refused_without_force() {
        let dir = TempDir::new().unwrap();
        let fragments = vec![frag("a", 1, 10, "## A body")];
        compose_file(dir.path(), Target::ClaudeMd, &fragments, false, false).unwrap();
        let path = dir.path().join("CLAUDE.md");
        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replace("## A body", "## A body\nMANUAL EDIT");
        std::fs::write(&path, tampered).unwrap();
        let err = compose_file(dir.path(), Target::ClaudeMd, &fragments, false, false).unwrap_err();
        assert!(matches!(err, ComposeError::Drift { .. }));
        // With --force it succeeds.
        let r = compose_file(dir.path(), Target::ClaudeMd, &fragments, true, false).unwrap();
        assert!(r.wrote);
    }

    #[test]
    fn disabled_profile_section_removed_on_recompose() {
        let dir = TempDir::new().unwrap();
        let fragments_2 = vec![frag("a", 1, 10, "## A body"), frag("b", 1, 20, "## B body")];
        compose_file(dir.path(), Target::ClaudeMd, &fragments_2, false, false).unwrap();
        let fragments_1 = vec![frag("a", 1, 10, "## A body")];
        compose_file(dir.path(), Target::ClaudeMd, &fragments_1, false, false).unwrap();
        let txt = std::fs::read_to_string(dir.path().join("CLAUDE.md")).unwrap();
        assert!(txt.contains("BEGIN-CRUX-MANAGED:a"));
        assert!(!txt.contains("BEGIN-CRUX-MANAGED:b"));
    }

    #[test]
    fn unbalanced_markers_rejected() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "<!-- BEGIN-CRUX-MANAGED:a v1 -->\nbody\n").unwrap();
        let fragments = vec![frag("a", 1, 10, "## A body")];
        let err = compose_file(dir.path(), Target::ClaudeMd, &fragments, false, false).unwrap_err();
        assert!(matches!(err, ComposeError::UnbalancedMarkers { .. }));
    }
}
