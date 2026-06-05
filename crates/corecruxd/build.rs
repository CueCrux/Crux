// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::process::Command;

#[allow(clippy::unnecessary_wraps)] // anyhow::Result keeps build.rs consistent across crates
fn main() -> anyhow::Result<()> {
    // Resolve the build sha, in priority order:
    //   1. An explicit `CORECRUX_GIT_SHA` env var (set by the Docker build via
    //      `ARG GIT_SHA` → `ENV`). The Docker builder stage copies only the
    //      crate sources, NOT `.git`, so the git fallback below cannot work in a
    //      container build — without this the published image reported
    //      `(unknown)`.
    //   2. `git rev-parse --short HEAD` against the repo root (local/CI builds
    //      that have a `.git`).
    //   3. `"unknown"` as a last resort.
    // A full 40-char CI sha is normalised to the 7-char short form so the
    // `--version` string is consistent regardless of build environment.
    let sha = std::env::var("CORECRUX_GIT_SHA")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(7).collect::<String>())
        .or_else(git_short_sha)
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=CORECRUX_GIT_SHA={sha}");
    println!("cargo:rerun-if-env-changed=CORECRUX_GIT_SHA");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    Ok(())
}

/// `git rev-parse --short HEAD` against the repo root, or `None` when git or
/// the `.git` directory is unavailable (e.g. a Docker build context).
fn git_short_sha() -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo_root())
        .output()
        .ok()
        .and_then(|o| if o.status.success() { Some(o.stdout) } else { None })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}
