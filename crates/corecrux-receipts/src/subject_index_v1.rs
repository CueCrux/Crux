// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Per-subject receipt index — maps subject IDs to receipt offsets for O(1) `query_facts`-time verification fetches.

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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn latest(receipt_id: &str, mode: &str, ingested_at: &str) -> ReceiptSubjectLatestV1 {
        ReceiptSubjectLatestV1 {
            receipt_id: receipt_id.to_string(),
            mode: mode.to_string(),
            ingested_at: ingested_at.to_string(),
        }
    }

    /// Write a crafted subject-index file to the on-disk path derived for
    /// `(tenant, path_kind, subject)`, but with an overridden stored `kind`.
    /// This simulates a hash-collision / key-mismatch: the file at the requested
    /// key claims a different logical identity than requested.
    fn write_index_with_kind(root: &Path, tenant: &str, path_kind: &str, subject: &str, stored_kind: &str) {
        let path = subject_index_path_v1(root, tenant, path_kind, subject);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let idx = ReceiptSubjectIndexV1 {
            schema: "cuecrux.receipt.subject_index.v1".to_string(),
            tenant_id: tenant.to_string(),
            kind: stored_kind.to_string(),
            subject_id: subject.to_string(),
            latest: latest("r0", "light", "2026-01-01T00:00:00Z"),
            latest_verified: None,
            latest_audit: None,
        };
        std::fs::write(&path, serde_json::to_vec_pretty(&idx).unwrap()).unwrap();
    }

    // ── key-mismatch collision guards (fail-closed) ─────────────────

    #[test]
    fn update_rejects_key_mismatch_on_kind_only() {
        // Stored kind differs from the requested kind, tenant + subject match:
        // exactly one of the three OR'd conditions is true. The guard must still
        // fail closed. Pins both `||` operators against `&&`.
        let tmp = tempfile::tempdir().unwrap();
        write_index_with_kind(tmp.path(), "t", "answer", "subj", "action");
        let res = update_subject_index_v1(tmp.path(), "t", "answer", "subj", "r1", "light", "2026-02-01T00:00:00Z");
        assert!(matches!(res, Err(ReceiptStoreError::Invalid { .. })));
    }

    #[test]
    fn resolve_rejects_key_mismatch_on_kind_only() {
        let tmp = tempfile::tempdir().unwrap();
        write_index_with_kind(tmp.path(), "t", "answer", "subj", "action");
        let res = resolve_subject_receipt_id_v1(tmp.path(), "t", "answer", "subj", SubjectResolveModeV1::Latest);
        assert!(matches!(res, Err(ReceiptStoreError::Invalid { .. })));
    }

    // ── strictly-newer timestamp guards (`>`, not `>=`/`==`/`<`) ────

    #[test]
    fn update_latest_requires_strictly_newer_timestamp() {
        // Equal ingested_at must NOT overwrite `latest` (pins `>` vs `>=`).
        let tmp = tempfile::tempdir().unwrap();
        update_subject_index_v1(tmp.path(), "t", "answer", "s", "r1", "light", "2026-03-01T00:00:00Z").unwrap();
        update_subject_index_v1(tmp.path(), "t", "answer", "s", "r2", "light", "2026-03-01T00:00:00Z").unwrap();
        let got = resolve_subject_receipt_id_v1(tmp.path(), "t", "answer", "s", SubjectResolveModeV1::Latest).unwrap();
        assert_eq!(got, Some("r1".to_string()));
    }

    #[test]
    fn update_latest_verified_requires_strictly_newer_timestamp() {
        // Pins the verified-branch `>` against `==`, `<`, and `>=`.
        let tmp = tempfile::tempdir().unwrap();
        update_subject_index_v1(tmp.path(), "t", "answer", "s", "v1", "verified", "2026-03-02T00:00:00Z").unwrap();
        // Equal timestamp, different receipt: must not overwrite (kills == and >=).
        update_subject_index_v1(tmp.path(), "t", "answer", "s", "v2", "verified", "2026-03-02T00:00:00Z").unwrap();
        // Strictly older: must not overwrite (kills <).
        update_subject_index_v1(tmp.path(), "t", "answer", "s", "v3", "verified", "2026-03-01T00:00:00Z").unwrap();
        let got =
            resolve_subject_receipt_id_v1(tmp.path(), "t", "answer", "s", SubjectResolveModeV1::Verified).unwrap();
        assert_eq!(got, Some("v1".to_string()));
    }

    #[test]
    fn update_latest_audit_requires_strictly_newer_timestamp() {
        // Pins the audit-branch `>` against `==`, `<`, and `>=`.
        let tmp = tempfile::tempdir().unwrap();
        update_subject_index_v1(tmp.path(), "t", "answer", "s", "a1", "audit", "2026-03-02T00:00:00Z").unwrap();
        update_subject_index_v1(tmp.path(), "t", "answer", "s", "a2", "audit", "2026-03-02T00:00:00Z").unwrap();
        update_subject_index_v1(tmp.path(), "t", "answer", "s", "a3", "audit", "2026-03-01T00:00:00Z").unwrap();
        let got = resolve_subject_receipt_id_v1(tmp.path(), "t", "answer", "s", SubjectResolveModeV1::Audit).unwrap();
        assert_eq!(got, Some("a1".to_string()));
    }
}
