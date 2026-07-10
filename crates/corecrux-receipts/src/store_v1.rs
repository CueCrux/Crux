// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Receipt-store v1 — append-only on-disk record + subject-indexed lookup; produces `VerificationReportV1`.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::verify_v1::VerificationReportV1;

#[derive(Debug, Error)]
pub enum ReceiptStoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid stored report: {msg}")]
    Invalid { msg: String },
}

pub fn verification_report_path_v1(shard_dir: &Path, tenant_id: &str, receipt_id: &str) -> PathBuf {
    let tenant_dir = tenant_dir_name_v1(tenant_id);
    shard_dir
        .join("receipts")
        .join("verification")
        .join(tenant_dir)
        .join(format!("{receipt_id}.json"))
}

pub fn store_verification_report_v1(
    shard_dir: &Path,
    report: &VerificationReportV1,
) -> Result<PathBuf, ReceiptStoreError> {
    let path = verification_report_path_v1(shard_dir, &report.tenant_id, &report.receipt_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Deterministic serialization.
    let bytes = serde_json::to_vec_pretty(report)?;
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    std::fs::write(&tmp, &bytes)?;

    // Cross-platform-ish atomic replace:
    // - On Unix, rename over existing is atomic.
    // - On Windows, rename fails if destination exists, so remove then rename.
    if std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&path);
        std::fs::rename(&tmp, &path)?;
    }

    Ok(path)
}

pub fn load_verification_report_v1(
    shard_dir: &Path,
    tenant_id: &str,
    receipt_id: &str,
) -> Result<Option<VerificationReportV1>, ReceiptStoreError> {
    let path = verification_report_path_v1(shard_dir, tenant_id, receipt_id);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    let report: VerificationReportV1 = serde_json::from_slice(&bytes)?;
    if report.tenant_id != tenant_id || report.receipt_id != receipt_id {
        return Err(ReceiptStoreError::Invalid {
            msg: "stored report key mismatch (possible tenant hash collision)".to_string(),
        });
    }
    Ok(Some(report))
}

fn tenant_dir_name_v1(tenant_id: &str) -> String {
    // Avoid putting raw tenant_id into paths; keep deterministic and low collision risk.
    let h = blake3::hash(tenant_id.as_bytes()).to_hex().to_string();
    format!("tenant-{}", &h[0..16])
}
