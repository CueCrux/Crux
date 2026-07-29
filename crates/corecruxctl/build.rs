// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

use std::process::Command;

#[allow(clippy::unnecessary_wraps)] // anyhow::Result keeps build.rs consistent across crates
fn main() -> anyhow::Result<()> {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo_root())
        .output()
        .ok()
        .and_then(|o| if o.status.success() { Some(o.stdout) } else { None })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=CORECRUX_GIT_SHA={sha}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    Ok(())
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}
