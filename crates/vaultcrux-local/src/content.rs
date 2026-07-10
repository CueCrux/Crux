// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Content manifest loading and signature policy for daemon-local VaultCrux assets.

use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTENT_MANIFEST_SCHEMA_V1: &str = "cuecrux.content.manifest.v1";
pub const CONTENT_SIGNATURE_ALG: &str = "CROWN-Ed25519";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentManifest {
    pub schema: String,
    pub status: String,
    pub issuer: String,
    pub licence: String,
    pub generated_at: String,
    #[serde(default)]
    pub files: Vec<ContentManifestFile>,
    pub signature: ContentSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentManifestFile {
    pub path: String,
    pub blake3: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentSignature {
    pub alg: String,
    pub kid: String,
    #[serde(default)]
    pub public_key_hex: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentLoadReport {
    pub manifest_path: PathBuf,
    pub issuer: String,
    pub verified_signature: bool,
    pub files_verified: usize,
}

#[derive(Debug, Error)]
pub enum ContentManifestError {
    #[error("read content manifest {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("parse content manifest {path}: {source}")]
    Parse { path: PathBuf, source: serde_json::Error },
    #[error("unsupported content manifest schema: {0}")]
    UnsupportedSchema(String),
    #[error("content manifest is unsigned or placeholder-signed")]
    Unsigned,
    #[error("unsupported content signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("content manifest signature is missing public_key_hex")]
    MissingPublicKey,
    #[error("content manifest public key is invalid")]
    InvalidPublicKey,
    #[error("content manifest signature value is invalid")]
    InvalidSignatureValue,
    #[error("content manifest signature verification failed")]
    SignatureVerificationFailed,
    #[error("content manifest file path escapes content root: {0}")]
    FilePathEscapesRoot(String),
    #[error("read content file {path}: {source}")]
    ReadContentFile { path: PathBuf, source: std::io::Error },
    #[error("content file size mismatch for {path}: expected {expected}, got {actual}")]
    FileSizeMismatch { path: String, expected: u64, actual: u64 },
    #[error("content file blake3 mismatch for {path}: expected {expected}, got {actual}")]
    FileHashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
}

#[derive(Serialize)]
struct ManifestSigningPayload<'a> {
    schema: &'a str,
    status: &'a str,
    issuer: &'a str,
    licence: &'a str,
    generated_at: &'a str,
    files: &'a [ContentManifestFile],
}

pub fn load_content_manifest(path: &Path, verify_signatures: bool) -> Result<ContentLoadReport, ContentManifestError> {
    let raw = std::fs::read_to_string(path).map_err(|source| ContentManifestError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let manifest: ContentManifest = serde_json::from_str(&raw).map_err(|source| ContentManifestError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    validate_content_manifest(path, &manifest, verify_signatures)
}

pub fn validate_content_manifest(
    path: &Path,
    manifest: &ContentManifest,
    verify_signatures: bool,
) -> Result<ContentLoadReport, ContentManifestError> {
    if manifest.schema != CONTENT_MANIFEST_SCHEMA_V1 {
        return Err(ContentManifestError::UnsupportedSchema(manifest.schema.clone()));
    }
    if verify_signatures {
        verify_manifest_signature(manifest)?;
    }
    verify_manifest_files(path, manifest)?;
    Ok(ContentLoadReport {
        manifest_path: path.to_path_buf(),
        issuer: manifest.issuer.clone(),
        verified_signature: verify_signatures,
        files_verified: manifest.files.len(),
    })
}

fn verify_manifest_signature(manifest: &ContentManifest) -> Result<(), ContentManifestError> {
    if manifest.status == "placeholder"
        || manifest.signature.kid == "pending"
        || manifest.signature.value == "pending"
        || manifest.signature.value.trim().is_empty()
    {
        return Err(ContentManifestError::Unsigned);
    }
    if manifest.signature.alg != CONTENT_SIGNATURE_ALG {
        return Err(ContentManifestError::UnsupportedSignatureAlgorithm(
            manifest.signature.alg.clone(),
        ));
    }
    let public_key_hex = manifest
        .signature
        .public_key_hex
        .as_deref()
        .ok_or(ContentManifestError::MissingPublicKey)?;
    let public_key_bytes = hex::decode(public_key_hex).map_err(|_err| ContentManifestError::InvalidPublicKey)?;
    let public_key: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_err| ContentManifestError::InvalidPublicKey)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_err| ContentManifestError::InvalidPublicKey)?;
    let signature_bytes =
        hex::decode(&manifest.signature.value).map_err(|_err| ContentManifestError::InvalidSignatureValue)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_err| ContentManifestError::InvalidSignatureValue)?;
    verifying_key
        .verify(&manifest_signing_payload(manifest), &signature)
        .map_err(|_err| ContentManifestError::SignatureVerificationFailed)
}

fn manifest_signing_payload(manifest: &ContentManifest) -> Vec<u8> {
    serde_json::to_vec(&ManifestSigningPayload {
        schema: &manifest.schema,
        status: &manifest.status,
        issuer: &manifest.issuer,
        licence: &manifest.licence,
        generated_at: &manifest.generated_at,
        files: &manifest.files,
    })
    .unwrap_or_default()
}

fn verify_manifest_files(path: &Path, manifest: &ContentManifest) -> Result<(), ContentManifestError> {
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    for file in &manifest.files {
        let file_path = resolve_content_path(root, &file.path)?;
        let bytes = std::fs::read(&file_path).map_err(|source| ContentManifestError::ReadContentFile {
            path: file_path,
            source,
        })?;
        if bytes.len() as u64 != file.size_bytes {
            return Err(ContentManifestError::FileSizeMismatch {
                path: file.path.clone(),
                expected: file.size_bytes,
                actual: bytes.len() as u64,
            });
        }
        let actual_hash = blake3::hash(&bytes).to_hex().to_string();
        if actual_hash != file.blake3 {
            return Err(ContentManifestError::FileHashMismatch {
                path: file.path.clone(),
                expected: file.blake3.clone(),
                actual: actual_hash,
            });
        }
    }
    Ok(())
}

fn resolve_content_path(root: &Path, relative: &str) -> Result<PathBuf, ContentManifestError> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(ContentManifestError::FilePathEscapesRoot(relative.to_string()));
    }
    Ok(root.join(relative_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn unsigned_manifest() -> ContentManifest {
        ContentManifest {
            schema: CONTENT_MANIFEST_SCHEMA_V1.to_string(),
            status: "placeholder".to_string(),
            issuer: "vaultcrux".to_string(),
            licence: "LicenseRef-CueCrux-Content-1.0".to_string(),
            generated_at: "2026-04-30T00:00:00Z".to_string(),
            files: Vec::new(),
            signature: ContentSignature {
                alg: CONTENT_SIGNATURE_ALG.to_string(),
                kid: "pending".to_string(),
                public_key_hex: None,
                value: "pending".to_string(),
            },
        }
    }

    fn signed_manifest_with_file(path: String, blake3: String, size_bytes: u64) -> ContentManifest {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let mut manifest = ContentManifest {
            schema: CONTENT_MANIFEST_SCHEMA_V1.to_string(),
            status: "signed".to_string(),
            issuer: "vaultcrux".to_string(),
            licence: "LicenseRef-CueCrux-Content-1.0".to_string(),
            generated_at: "2026-04-30T00:00:00Z".to_string(),
            files: vec![ContentManifestFile {
                path,
                blake3,
                size_bytes,
            }],
            signature: ContentSignature {
                alg: CONTENT_SIGNATURE_ALG.to_string(),
                kid: "test-content-root-v1".to_string(),
                public_key_hex: Some(hex::encode(signing_key.verifying_key().to_bytes())),
                value: String::new(),
            },
        };
        let signature = signing_key.sign(&manifest_signing_payload(&manifest));
        manifest.signature.value = hex::encode(signature.to_bytes());
        manifest
    }

    #[test]
    fn unsigned_manifest_refuses_when_signature_verification_enabled() {
        let manifest = unsigned_manifest();
        let err = validate_content_manifest(Path::new("MANIFEST.json"), &manifest, true).unwrap_err();
        assert!(matches!(err, ContentManifestError::Unsigned));
    }

    #[test]
    fn unsigned_manifest_can_load_when_signature_verification_disabled() {
        let manifest = unsigned_manifest();
        let report = validate_content_manifest(Path::new("MANIFEST.json"), &manifest, false).unwrap();
        assert!(!report.verified_signature);
        assert_eq!(report.files_verified, 0);
    }

    #[test]
    fn signed_manifest_verifies_file_integrity() {
        let tmp = tempfile::tempdir().unwrap();
        let content_path = tmp.path().join("rubrics").join("coverage.json");
        std::fs::create_dir_all(content_path.parent().unwrap()).unwrap();
        std::fs::write(&content_path, b"{\"ok\":true}\n").unwrap();
        let bytes = std::fs::read(&content_path).unwrap();
        let manifest = signed_manifest_with_file(
            "rubrics/coverage.json".to_string(),
            blake3::hash(&bytes).to_hex().to_string(),
            bytes.len() as u64,
        );

        let report = validate_content_manifest(&tmp.path().join("MANIFEST.json"), &manifest, true).unwrap();
        assert!(report.verified_signature);
        assert_eq!(report.files_verified, 1);
    }

    #[test]
    fn manifest_file_paths_must_stay_under_content_root() {
        let manifest = signed_manifest_with_file("../secret".to_string(), "00".repeat(32), 0);
        let err = validate_content_manifest(Path::new("MANIFEST.json"), &manifest, true).unwrap_err();
        assert!(matches!(err, ContentManifestError::FilePathEscapesRoot(_)));
    }
}
