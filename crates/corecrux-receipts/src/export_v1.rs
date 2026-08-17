// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Replay-export bundle writer — packages receipts + verification reports into a portable ZIP.

use std::io::Write as _;

use thiserror::Error;
use zip::write::SimpleFileOptions;

use crate::verify_v1::VerificationReportV1;

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("tar: {0}")]
    Tar(String),
    #[error("zstd: {0}")]
    Zstd(String),
    #[error("precondition failed: {msg}")]
    Precondition { msg: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormatV1 {
    Zip,
    TarZst,
}

impl ExportFormatV1 {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "zip" => Some(Self::Zip),
            "tar.zst" => Some(Self::TarZst),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::TarZst => "tar.zst",
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            Self::Zip => "application/zip",
            // There isn't a universally agreed content-type; keep it simple and explicit.
            Self::TarZst => "application/zstd",
        }
    }

    pub fn filename_ext(&self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::TarZst => "tar.zst",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportRedactionV1 {
    None,
    MetadataOnly,
    TenantSafe,
}

impl ExportRedactionV1 {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "metadata_only" => Some(Self::MetadataOnly),
            "tenant_safe" => Some(Self::TenantSafe),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MetadataOnly => "metadata_only",
            Self::TenantSafe => "tenant_safe",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptExportIncludeV1 {
    Body,
    Sig,
    Verification,
    TraceSummary,
    SubjectLinks,
    LinkedReceipts,
}

impl ReceiptExportIncludeV1 {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "body" => Some(Self::Body),
            "sig" => Some(Self::Sig),
            "verification" => Some(Self::Verification),
            "trace_summary" => Some(Self::TraceSummary),
            "subject_links" => Some(Self::SubjectLinks),
            "linked_receipts" => Some(Self::LinkedReceipts),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Body => "body",
            Self::Sig => "sig",
            Self::Verification => "verification",
            Self::TraceSummary => "trace_summary",
            Self::SubjectLinks => "subject_links",
            Self::LinkedReceipts => "linked_receipts",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiptExportOptionsV1 {
    pub format: ExportFormatV1,
    pub redaction: ExportRedactionV1,
    pub include: Vec<ReceiptExportIncludeV1>,
}

impl Default for ReceiptExportOptionsV1 {
    fn default() -> Self {
        Self {
            format: ExportFormatV1::Zip,
            redaction: ExportRedactionV1::TenantSafe,
            include: Vec::new(), // empty means default include set
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportFileV1 {
    pub path: String,
    pub blake3: String,
    pub size: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReceiptEventHeaderRefV1 {
    #[serde(rename = "headerHash")]
    pub header_hash: String,
    #[serde(rename = "payloadHash")]
    pub payload_hash: String,
    pub seq: u64,
    #[serde(rename = "eventId")]
    pub event_id: String,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReplayExportManifestV1 {
    #[serde(rename = "export_schema")]
    pub export_schema: String,
    #[serde(rename = "generated_at")]
    pub generated_at: String,
    #[serde(rename = "tenant_id")]
    pub tenant_id: String,
    #[serde(rename = "receipt_id")]
    pub receipt_id: String,
    #[serde(rename = "corecrux_build")]
    pub corecrux_build: ExportBuildInfoV1,
    #[serde(rename = "format")]
    pub format: String,
    #[serde(rename = "redaction")]
    pub redaction: String,
    #[serde(rename = "include")]
    pub include: Vec<String>,
    #[serde(rename = "included_files")]
    pub included_files: Vec<ExportFileV1>,
    #[serde(rename = "receipt_refs")]
    pub receipt_refs: ReceiptRefsV1,
    #[serde(rename = "corecrux_event_headers")]
    pub corecrux_event_headers: Vec<ReceiptEventHeaderRefV1>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportBuildInfoV1 {
    pub version: String,
    pub commit: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReceiptRefsV1 {
    #[serde(rename = "receipt_body_payload_hash")]
    pub receipt_body_payload_hash: String,
    #[serde(rename = "receipt_sig_event_ref")]
    pub receipt_sig_event_ref: String,
}

#[derive(Debug, Clone)]
pub struct ReceiptExportBundleV1 {
    pub manifest_json: Vec<u8>,
    pub archive_bytes: Vec<u8>,
    pub content_type: &'static str,
    pub filename_ext: &'static str,
}

pub struct BuildReceiptExportInput<'a> {
    pub generated_at: &'a str,
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub build: &'a corecrux_types::BuildInfo,

    pub body_bytes: &'a [u8],
    pub sig_bytes: &'a [u8],
    pub verification_report: &'a VerificationReportV1,

    pub body_payload_hash_hex: &'a str,
    pub sig_event_ref: &'a str,
    pub event_headers: Vec<ReceiptEventHeaderRefV1>,

    // Optional convenience files; only emitted if requested via include[].
    pub trace_summary_json: Option<&'a [u8]>,
    pub subject_links_json: Option<&'a [u8]>,
    pub lineage_json: Option<&'a [u8]>,
}

pub fn build_receipt_export_v1(
    input: BuildReceiptExportInput<'_>,
    opts: &ReceiptExportOptionsV1,
) -> Result<ReceiptExportBundleV1, ExportError> {
    let body_path = "receipt/body.cbor";
    let sig_path = "receipt/sig.cbor";
    let ver_path = "verification/report.json";
    let trace_path = "projection/trace_summary.json";
    let subject_path = "links/subject.json";
    let lineage_path = "links/lineage.json";

    let mut include = normalized_includes(&opts.include);
    // Ensure include list is stable and serialized deterministically.
    include.sort_by_key(|v| v.as_str());

    let ver_json = serde_json::to_vec_pretty(input.verification_report)?;

    let mut files: Vec<ArchiveEntry<'_>> = Vec::new();
    let mut included_files: Vec<ExportFileV1> = Vec::new();

    for inc in &include {
        match inc {
            ReceiptExportIncludeV1::Body => {
                files.push(ArchiveEntry {
                    path: body_path,
                    bytes: input.body_bytes,
                });
                included_files.push(ExportFileV1 {
                    path: body_path.to_string(),
                    blake3: blake3::hash(input.body_bytes).to_hex().to_string(),
                    size: input.body_bytes.len() as u64,
                });
            }
            ReceiptExportIncludeV1::Sig => {
                files.push(ArchiveEntry {
                    path: sig_path,
                    bytes: input.sig_bytes,
                });
                included_files.push(ExportFileV1 {
                    path: sig_path.to_string(),
                    blake3: blake3::hash(input.sig_bytes).to_hex().to_string(),
                    size: input.sig_bytes.len() as u64,
                });
            }
            ReceiptExportIncludeV1::Verification => {
                files.push(ArchiveEntry {
                    path: ver_path,
                    bytes: &ver_json,
                });
                included_files.push(ExportFileV1 {
                    path: ver_path.to_string(),
                    blake3: blake3::hash(&ver_json).to_hex().to_string(),
                    size: ver_json.len() as u64,
                });
            }
            ReceiptExportIncludeV1::TraceSummary => {
                let bytes = input.trace_summary_json.ok_or_else(|| ExportError::Precondition {
                    msg: "trace_summary requested but unavailable".to_string(),
                })?;
                files.push(ArchiveEntry {
                    path: trace_path,
                    bytes,
                });
                included_files.push(ExportFileV1 {
                    path: trace_path.to_string(),
                    blake3: blake3::hash(bytes).to_hex().to_string(),
                    size: bytes.len() as u64,
                });
            }
            ReceiptExportIncludeV1::SubjectLinks => {
                let bytes = input.subject_links_json.ok_or_else(|| ExportError::Precondition {
                    msg: "subject_links requested but unavailable".to_string(),
                })?;
                files.push(ArchiveEntry {
                    path: subject_path,
                    bytes,
                });
                included_files.push(ExportFileV1 {
                    path: subject_path.to_string(),
                    blake3: blake3::hash(bytes).to_hex().to_string(),
                    size: bytes.len() as u64,
                });
            }
            ReceiptExportIncludeV1::LinkedReceipts => {
                let bytes = input.lineage_json.ok_or_else(|| ExportError::Precondition {
                    msg: "linked_receipts requested but unavailable".to_string(),
                })?;
                files.push(ArchiveEntry {
                    path: lineage_path,
                    bytes,
                });
                included_files.push(ExportFileV1 {
                    path: lineage_path.to_string(),
                    blake3: blake3::hash(bytes).to_hex().to_string(),
                    size: bytes.len() as u64,
                });
            }
        }
    }

    let manifest = ReplayExportManifestV1 {
        export_schema: "cuecrux.replay.export.v1".to_string(),
        generated_at: input.generated_at.to_string(),
        tenant_id: input.tenant_id.to_string(),
        receipt_id: input.receipt_id.to_string(),
        corecrux_build: ExportBuildInfoV1 {
            version: input.build.version.clone(),
            commit: input.build.commit.clone(),
        },
        format: opts.format.as_str().to_string(),
        redaction: opts.redaction.as_str().to_string(),
        include: include.iter().map(|v| v.as_str().to_string()).collect(),
        included_files: included_files.clone(),
        receipt_refs: ReceiptRefsV1 {
            receipt_body_payload_hash: input.body_payload_hash_hex.to_string(),
            receipt_sig_event_ref: input.sig_event_ref.to_string(),
        },
        corecrux_event_headers: input.event_headers,
    };

    // Determinism: the manifest is part of the export bundle and should not change between runs
    // for the same receipt + build. Callers must provide a deterministic generated_at.
    let manifest_json = serde_json::to_vec_pretty(&manifest)?;

    // Deterministic archive build: stable file order, stable timestamps, no implicit metadata.
    let mut archive_entries = Vec::with_capacity(files.len() + 1);
    archive_entries.push(ArchiveEntry {
        path: "manifest.json",
        bytes: &manifest_json,
    });
    // Stable sort by path so include ordering doesn't affect bytes.
    files.sort_by_key(|e| e.path);
    archive_entries.extend(files);

    let archive_bytes = match opts.format {
        ExportFormatV1::Zip => build_zip_deterministic(&archive_entries)?,
        ExportFormatV1::TarZst => build_tar_zst_deterministic(&archive_entries)?,
    };

    Ok(ReceiptExportBundleV1 {
        manifest_json,
        archive_bytes,
        content_type: opts.format.content_type(),
        filename_ext: opts.format.filename_ext(),
    })
}

fn normalized_includes(include: &[ReceiptExportIncludeV1]) -> Vec<ReceiptExportIncludeV1> {
    if include.is_empty() {
        return vec![
            ReceiptExportIncludeV1::Body,
            ReceiptExportIncludeV1::Sig,
            ReceiptExportIncludeV1::Verification,
        ];
    }
    include.to_vec()
}

#[derive(Clone, Copy)]
struct ArchiveEntry<'a> {
    path: &'a str,
    bytes: &'a [u8],
}

fn build_zip_deterministic(entries: &[ArchiveEntry<'_>]) -> Result<Vec<u8>, ExportError> {
    let mut cursor = std::io::Cursor::new(Vec::<u8>::with_capacity(4096));
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);

        // `DateTime::default()` is the ZIP epoch: 1980-01-01 00:00:00.
        let ts = zip::DateTime::default();
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(ts)
            .unix_permissions(0o644);

        for e in entries {
            zw.start_file(e.path, opts)?;
            zw.write_all(e.bytes)?;
        }

        zw.finish()?;
    }
    Ok(cursor.into_inner())
}

fn build_tar_zst_deterministic(entries: &[ArchiveEntry<'_>]) -> Result<Vec<u8>, ExportError> {
    let mut tar_bytes = Vec::<u8>::with_capacity(4096);
    {
        let mut tb = tar::Builder::new(&mut tar_bytes);
        // Determinism: do not emit extended headers or sparse features implicitly.
        tb.mode(tar::HeaderMode::Deterministic);

        for e in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(e.bytes.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();

            tb.append_data(&mut header, e.path, std::io::Cursor::new(e.bytes))
                .map_err(|e| ExportError::Tar(e.to_string()))?;
        }

        tb.finish().map_err(|e| ExportError::Tar(e.to_string()))?;
    }

    let mut enc = zstd::Encoder::new(Vec::new(), /*level=*/ 3).map_err(|e| ExportError::Zstd(e.to_string()))?;
    enc.write_all(&tar_bytes)
        .map_err(|e| ExportError::Zstd(e.to_string()))?;
    enc.finish().map_err(|e| ExportError::Zstd(e.to_string()))
}
