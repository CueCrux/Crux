// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Plane-layer sync — Phase 2B of the context graph.
//!
//! Walks `<source_path>/<plane_id>/` for each plane in a project, picks the
//! most-likely "main doc" markdown file by filename heuristic, and writes
//! its leading content as the plane's vision (or goals) layer. This gives
//! the storybook keyword-overlap mapper enough text to actually match
//! crates to planes — without the operator having to copy/paste docs.
//!
//! ## Heuristics
//!
//! For `vision`:
//! 1. `*Master*Plan*.md`            (highest priority — these are the canonical "what is this plane" docs in PlanCrux)
//! 2. `*-vision*.md` / `Vision*.md`
//! 3. `INDEX.md`
//! 4. The first `.md` file alphabetically (lowest priority)
//!
//! For `goals`:
//! 1. `*Goals*.md` / `*-goals*.md`
//! 2. `*Roadmap*.md`
//! 3. `*Master*Plan*.md` (fallback — usually has a "Goals" section)
//!
//! ## Safety
//!
//! `source_path` MUST start with one of the prefixes in `CORECRUXD_SOURCE_ROOTS`
//! (default `/sources,/src`). Anything outside is rejected. There is no
//! file-write side: this module only reads.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("source path '{0}' is not under any allowed root ({1})")]
    NotAllowed(String, String),
    #[error("source path '{0}' does not exist")]
    PathMissing(String),
    #[error("layer must be 'vision' or 'goals'; got '{0}'")]
    InvalidLayer(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncReport {
    pub project_id: String,
    pub source_path: String,
    pub layer: String,
    pub max_bytes: usize,
    pub mode: String, // "preview" | "applied"
    pub planes: Vec<PlaneSyncOutcome>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PlaneSyncOutcome {
    pub plane_id: String,
    pub status: String, // "would_apply" | "applied" | "skipped" | "no_match"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_extracted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

/// Resolve allowed roots from env. Defaults to `/sources,/src`.
pub fn allowed_roots() -> Vec<String> {
    std::env::var("CORECRUXD_SOURCE_ROOTS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/sources,/src".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn validate_layer(layer: &str) -> Result<(), SyncError> {
    if layer == "vision" || layer == "goals" {
        Ok(())
    } else {
        Err(SyncError::InvalidLayer(layer.to_string()))
    }
}

fn validate_source_path(p: &str) -> Result<PathBuf, SyncError> {
    let roots = allowed_roots();
    let p_norm = Path::new(p);
    let allowed = roots.iter().any(|r| {
        let r_path = Path::new(r);
        p_norm.starts_with(r_path)
    });
    if !allowed {
        return Err(SyncError::NotAllowed(p.to_string(), roots.join(",")));
    }
    if !p_norm.exists() {
        return Err(SyncError::PathMissing(p.to_string()));
    }
    Ok(p_norm.to_path_buf())
}

/// Walk an immediate-child dir of `base` for the most likely "main doc"
/// markdown file matching the chosen layer's heuristic. Returns the absolute
/// path or `None` if nothing matches.
pub fn pick_main_doc(plane_dir: &Path, layer: &str) -> Option<PathBuf> {
    if !plane_dir.is_dir() {
        return None;
    }
    let entries = std::fs::read_dir(plane_dir).ok()?;
    let mut md_files: Vec<PathBuf> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.is_file() && p.extension().and_then(|x| x.to_str()) == Some("md") {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    if md_files.is_empty() {
        return None;
    }
    md_files.sort();

    let lower = |p: &Path| -> String { p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase() };
    if layer == "vision" {
        // Priority 1: *Master*Plan*.md (PlanCrux convention).
        if let Some(p) = md_files.iter().find(|p| {
            let l = lower(p);
            l.contains("master") && l.contains("plan")
        }) {
            return Some(p.clone());
        }
        // Priority 2: vision-named files.
        if let Some(p) = md_files.iter().find(|p| {
            let l = lower(p);
            l.contains("vision") || l.starts_with("vision")
        }) {
            return Some(p.clone());
        }
        // Priority 3: INDEX.md
        if let Some(p) = md_files.iter().find(|p| lower(p) == "index.md") {
            return Some(p.clone());
        }
        // Fallback: first .md alphabetically.
        return md_files.into_iter().next();
    }
    // layer == "goals"
    if let Some(p) = md_files.iter().find(|p| {
        let l = lower(p);
        l.contains("goals") || l.contains("roadmap")
    }) {
        return Some(p.clone());
    }
    if let Some(p) = md_files.iter().find(|p| {
        let l = lower(p);
        l.contains("master") && l.contains("plan")
    }) {
        return Some(p.clone());
    }
    if let Some(p) = md_files.iter().find(|p| lower(p) == "index.md") {
        return Some(p.clone());
    }
    md_files.into_iter().next()
}

fn read_truncated(path: &Path, max_bytes: usize) -> Result<String, SyncError> {
    let raw = std::fs::read_to_string(path)?;
    if raw.len() <= max_bytes {
        Ok(raw)
    } else {
        // Cut on a line boundary if possible to avoid mid-character / mid-block truncation.
        let mut cut = max_bytes;
        while cut > 0 && !raw.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut out = raw[..cut].to_string();
        if let Some(last_newline) = out.rfind('\n') {
            if last_newline > max_bytes / 2 {
                out.truncate(last_newline);
            }
        }
        out.push_str("\n\n…(truncated)");
        Ok(out)
    }
}

/// Run the sync. With `confirm=false`, returns a preview (`status="would_apply"`)
/// of what would change. With `confirm=true`, writes plane layer facts using
/// the project's existing layer-storage convention.
pub fn run_sync(
    store: &mut corecrux_memory::FactStore,
    project_id: &str,
    source_path: &str,
    layer: &str,
    max_bytes: usize,
    confirm: bool,
) -> Result<SyncReport, SyncError> {
    validate_layer(layer)?;
    let base = validate_source_path(source_path)?;
    let planes = crate::planes::list_planes(store, project_id);
    let mut report = SyncReport {
        project_id: project_id.to_string(),
        source_path: base.display().to_string(),
        layer: layer.to_string(),
        max_bytes,
        mode: if confirm { "applied".into() } else { "preview".into() },
        planes: Vec::new(),
    };
    // Pre-list immediate children of base so we can match plane ids to
    // directory names case-insensitively (PlanCrux uses `RCX/` for the rcx
    // plane, etc.).
    let base_entries: Vec<PathBuf> = std::fs::read_dir(&base)
        .map(|it| {
            it.flatten()
                .filter_map(|e| {
                    let p = e.path();
                    if p.is_dir() {
                        Some(p)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    for plane in &planes {
        let plane_id_lower = plane.id.to_lowercase();
        let plane_dir = base_entries
            .iter()
            .find(|p| {
                p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.to_lowercase() == plane_id_lower)
            })
            .cloned()
            .unwrap_or_else(|| base.join(&plane.id));
        if !plane_dir.exists() {
            report.planes.push(PlaneSyncOutcome {
                plane_id: plane.id.clone(),
                status: "skipped".into(),
                source_file: None,
                bytes_extracted: None,
                note: Some(format!(
                    "no directory matching '{}' (case-insensitive) under {}",
                    plane.id,
                    base.display()
                )),
                preview: None,
            });
            continue;
        }
        let chosen = pick_main_doc(&plane_dir, layer);
        let Some(file) = chosen else {
            report.planes.push(PlaneSyncOutcome {
                plane_id: plane.id.clone(),
                status: "no_match".into(),
                source_file: None,
                bytes_extracted: None,
                note: Some(format!("no .md file under {}", plane_dir.display())),
                preview: None,
            });
            continue;
        };
        let raw = match read_truncated(&file, max_bytes) {
            Ok(s) => s,
            Err(e) => {
                report.planes.push(PlaneSyncOutcome {
                    plane_id: plane.id.clone(),
                    status: "skipped".into(),
                    source_file: Some(file.display().to_string()),
                    bytes_extracted: None,
                    note: Some(format!("read failed: {e}")),
                    preview: None,
                });
                continue;
            }
        };
        let header = format!(
            "# {layer} (synced from PlanCrux)\n\n*Source*: `{}`\n*Synced at*: {}\n\n---\n\n",
            file.display(),
            chrono::Utc::now().to_rfc3339(),
        );
        let payload = format!("{header}{raw}");
        let preview = first_lines(&raw, 6);

        if confirm {
            let entity = format!("__plane_layer__::{}::{}::{}", project_id, plane.id, layer);
            let mut sf = corecrux_memory::fact_store::StoreFact {
                entity,
                key: "content".to_string(),
                value: payload.clone(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            horizon_class: None,
            };
            crate::fact_privacy::enforce_global(&mut sf);
            store.store(sf);
        }
        report.planes.push(PlaneSyncOutcome {
            plane_id: plane.id.clone(),
            status: if confirm {
                "applied".into()
            } else {
                "would_apply".into()
            },
            source_file: Some(file.display().to_string()),
            bytes_extracted: Some(payload.len()),
            note: None,
            preview: Some(preview),
        });
    }
    Ok(report)
}

fn first_lines(s: &str, n: usize) -> String {
    s.lines().take(n).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn validate_layer_accepts_vision_and_goals() {
        assert!(validate_layer("vision").is_ok());
        assert!(validate_layer("goals").is_ok());
        assert!(validate_layer("manifesto").is_err());
    }

    #[test]
    fn pick_main_doc_prefers_master_plan_for_vision() {
        let dir = tmpdir();
        fs::write(dir.path().join("Crux-Daemon-Master-Plan-v2_0.md"), "# Master plan\n").unwrap();
        fs::write(dir.path().join("INDEX.md"), "# Index\n").unwrap();
        fs::write(dir.path().join("README.md"), "# Readme\n").unwrap();
        let pick = pick_main_doc(dir.path(), "vision").unwrap();
        let name = pick.file_name().unwrap().to_str().unwrap();
        assert!(name.contains("Master") && name.contains("Plan"));
    }

    #[test]
    fn pick_main_doc_prefers_goals_for_goals() {
        let dir = tmpdir();
        fs::write(dir.path().join("Crux-Daemon-Master-Plan-v2_0.md"), "# Master plan\n").unwrap();
        fs::write(dir.path().join("Goals-2026.md"), "# Goals\n").unwrap();
        let pick = pick_main_doc(dir.path(), "goals").unwrap();
        let name = pick.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("Goals"));
    }

    #[test]
    fn pick_main_doc_falls_back_to_first_md() {
        let dir = tmpdir();
        fs::write(dir.path().join("notes.md"), "# notes\n").unwrap();
        let pick = pick_main_doc(dir.path(), "vision").unwrap();
        assert!(pick.file_name().unwrap().to_str().unwrap().ends_with("notes.md"));
    }

    #[test]
    fn pick_main_doc_returns_none_for_dir_with_no_md() {
        let dir = tmpdir();
        fs::write(dir.path().join("README.txt"), "x").unwrap();
        assert!(pick_main_doc(dir.path(), "vision").is_none());
    }

    #[test]
    fn read_truncated_caps_at_max_bytes() {
        let dir = tmpdir();
        let p = dir.path().join("big.md");
        let body = "x".repeat(10_000);
        fs::write(&p, &body).unwrap();
        let out = read_truncated(&p, 1000).unwrap();
        assert!(out.len() <= 1100); // body cut + truncation marker
        assert!(out.contains("(truncated)"));
    }

    #[test]
    fn validate_source_path_blocks_non_allowed() {
        std::env::set_var("CORECRUXD_SOURCE_ROOTS", "/sources,/tmp");
        let err = validate_source_path("/etc/passwd").unwrap_err();
        assert!(matches!(err, SyncError::NotAllowed(_, _)));
        std::env::remove_var("CORECRUXD_SOURCE_ROOTS");
    }

    #[test]
    fn allowed_roots_default_when_unset() {
        std::env::remove_var("CORECRUXD_SOURCE_ROOTS");
        let r = allowed_roots();
        assert!(r.contains(&"/sources".to_string()));
        assert!(r.contains(&"/src".to_string()));
    }
}
