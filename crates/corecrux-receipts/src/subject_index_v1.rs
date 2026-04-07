// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::path::{Path, PathBuf};

use crate::store_v1::ReceiptStoreError;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReceiptSubjectIndexV1 {
    pub schema: String,
    #[serde(rename = "tenant_id")]
    pub tenant_id: String,
    pub kind: String, // "answer" | "action"
    #[serde(rename = "subject_id")]
    pub subject_id: String,
    pub latest: ReceiptSubjectLatestV1,
    #[serde(rename = "latest_verified", skip_serializing_if = "Option::is_none")]
    pub latest_verified: Option<ReceiptSubjectLatestV1>,
    #[serde(rename = "latest_audit", skip_serializing_if = "Option::is_none")]
    pub latest_audit: Option<ReceiptSubjectLatestV1>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReceiptSubjectLatestV1 {
    #[serde(rename = "receipt_id")]
    pub receipt_id: String,
    pub mode: String, // "light" | "verified" | "audit" | "unknown"
    #[serde(rename = "ingested_at")]
    pub ingested_at: String, // RFC3339
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectResolveModeV1 {
    Latest,
    Verified,
    Audit,
}

impl SubjectResolveModeV1 {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "latest" => Some(Self::Latest),
            "verified" => Some(Self::Verified),
            "audit" => Some(Self::Audit),
            _ => None,
        }
    }
}

pub fn subject_index_path_v1(root: &Path, tenant_id: &str, kind: &str, subject_id: &str) -> PathBuf {
    let tenant_dir = tenant_dir_name_v1(tenant_id);
    let key = subject_key_hex16(subject_id);
    root.join("v1").join(kind).join(tenant_dir).join(format!("{key}.json"))
}

pub fn update_subject_index_v1(
    root: &Path,
    tenant_id: &str,
    kind: &str,
    subject_id: &str,
    receipt_id: &str,
    mode: &str,
    ingested_at: &str,
) -> Result<PathBuf, ReceiptStoreError> {
    let path = subject_index_path_v1(root, tenant_id, kind, subject_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut cur: ReceiptSubjectIndexV1 = if path.exists() {
        let bytes = std::fs::read(&path)?;
        serde_json::from_slice(&bytes)?
    } else {
        ReceiptSubjectIndexV1 {
            schema: "cuecrux.receipt.subject_index.v1".to_string(),
            tenant_id: tenant_id.to_string(),
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            latest: ReceiptSubjectLatestV1 {
                receipt_id: receipt_id.to_string(),
                mode: mode.to_string(),
                ingested_at: ingested_at.to_string(),
            },
            latest_verified: None,
            latest_audit: None,
        }
    };

    // Verify we're not clobbering the wrong key on hash collision.
    if cur.tenant_id != tenant_id || cur.kind != kind || cur.subject_id != subject_id {
        return Err(ReceiptStoreError::Invalid {
            msg: "subject index key mismatch (possible hash collision)".to_string(),
        });
    }

    let candidate = ReceiptSubjectLatestV1 {
        receipt_id: receipt_id.to_string(),
        mode: mode.to_string(),
        ingested_at: ingested_at.to_string(),
    };

    if candidate.ingested_at > cur.latest.ingested_at {
        cur.latest = candidate.clone();
    }

    match mode {
        "verified" => {
            if cur
                .latest_verified
                .as_ref()
                .is_none_or(|v| candidate.ingested_at > v.ingested_at)
            {
                cur.latest_verified = Some(candidate.clone());
            }
        }
        "audit" => {
            if cur
                .latest_audit
                .as_ref()
                .is_none_or(|v| candidate.ingested_at > v.ingested_at)
            {
                cur.latest_audit = Some(candidate.clone());
            }
        }
        _ => {}
    }

    // Deterministic serialization.
    let bytes = serde_json::to_vec_pretty(&cur)?;
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

pub fn resolve_subject_receipt_id_v1(
    root: &Path,
    tenant_id: &str,
    kind: &str,
    subject_id: &str,
    mode: SubjectResolveModeV1,
) -> Result<Option<String>, ReceiptStoreError> {
    let path = subject_index_path_v1(root, tenant_id, kind, subject_id);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    let cur: ReceiptSubjectIndexV1 = serde_json::from_slice(&bytes)?;
    if cur.tenant_id != tenant_id || cur.kind != kind || cur.subject_id != subject_id {
        return Err(ReceiptStoreError::Invalid {
            msg: "subject index key mismatch (possible tenant hash collision)".to_string(),
        });
    }
    let out = match mode {
        SubjectResolveModeV1::Latest => Some(cur.latest.receipt_id),
        SubjectResolveModeV1::Verified => cur.latest_verified.map(|v| v.receipt_id),
        SubjectResolveModeV1::Audit => cur.latest_audit.map(|v| v.receipt_id),
    };
    Ok(out)
}

fn tenant_dir_name_v1(tenant_id: &str) -> String {
    // Avoid putting raw tenant_id into paths; keep deterministic and low collision risk.
    let h = blake3::hash(tenant_id.as_bytes()).to_hex().to_string();
    format!("tenant-{}", &h[0..16])
}

fn subject_key_hex16(subject_id: &str) -> String {
    let h = blake3::hash(subject_id.as_bytes()).to_hex().to_string();
    h[0..16].to_string()
}
