// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![deny(clippy::unwrap_used, clippy::expect_used)]

//! Generate archive-level Audit Bundle v1 vectors from the unpacked fixtures.
//!
//! The JSON/CBOR files under `vectors/audit-bundle-v1/*/` remain the reviewable
//! source of truth. This example packages them into deterministic `tar.zst`
//! bundles so external verifiers can test the production archive shape.

use std::fs;
use std::path::{Path, PathBuf};

const VECTOR_NAMES: &[&str] = &[
    "valid-minimal",
    "invalid-events-hash",
    "valid-minimal-v2",
    "valid-minimal-v3",
];
const BUNDLE_MEMBERS: &[&str] = &["manifest.json", "events.jsonl", "receipts.cbor"];

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let root = std::env::current_dir()?;
    let vectors_root = root.join("crates/corecrux-receipts/vectors/audit-bundle-v1");
    for name in VECTOR_NAMES {
        write_archive_vector(&vectors_root.join(name))?;
    }
    Ok(())
}

fn write_archive_vector(dir: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let out_path = dir.join("audit-bundle.tar.zst");
    let tmp_path = temp_path(&out_path);

    let file = fs::File::create(&tmp_path)?;
    let encoder = zstd::stream::write::Encoder::new(file, 3)?.auto_finish();
    let mut builder = tar::Builder::new(encoder);
    builder.mode(tar::HeaderMode::Deterministic);

    for member in BUNDLE_MEMBERS {
        let bytes = fs::read(dir.join(member))?;
        let mut header = tar::Header::new_gnu();
        header.set_path(member)?;
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder.append(&header, bytes.as_slice())?;
    }

    builder.finish()?;
    drop(builder);
    fs::rename(tmp_path, out_path)?;
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    tmp.set_extension("tar.zst.tmp");
    tmp
}
