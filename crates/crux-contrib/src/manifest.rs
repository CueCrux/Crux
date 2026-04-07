// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Contribution manifest schema and builder.
//!
//! Every contribution is a self-contained envelope with content-addressed
//! references, provenance from the local receipt chain, and an ed25519 signature.

use serde::{Deserialize, Serialize};

/// Contribution type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionType {
    Correction,
    Citation,
    GapReport,
    Skill,
}

/// Contributor identity (hashed, not raw tenant ID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contributor {
    pub tenant_id: String,
    pub contributor_alias: Option<String>,
}

/// Content-addressed target reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub artefact_digest: String,
    pub chunk_digest: Option<String>,
    pub corpus_id: String,
    pub quote_hash: Option<String>,
}

/// Local receipt chain entry for provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptChainEntry {
    pub receipt_hash: String,
    pub signed_at: String,
    pub knowledge_state_cursor: serde_json::Value,
}

/// Canonicalization metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canon {
    pub alg: String,
    pub rfc: String,
    pub ver: String,
}

impl Default for Canon {
    fn default() -> Self {
        Self {
            alg: "jcs".to_string(),
            rfc: "8785".to_string(),
            ver: "1".to_string(),
        }
    }
}

/// Provenance block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub local_receipt_chain: Vec<ReceiptChainEntry>,
    pub canon: Canon,
}

/// Complete contribution manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionManifest {
    pub manifest_version: String,
    pub contribution_type: ContributionType,
    pub contributor: Contributor,
    pub target: Target,
    pub payload: serde_json::Value,
    pub provenance: Provenance,
    pub envelope_signature: String,
    pub envelope_hash: String,
}

/// Build a contribution manifest and compute its BLAKE3 hash.
pub fn build_manifest(
    contribution_type: ContributionType,
    contributor: Contributor,
    target: Target,
    payload: serde_json::Value,
    receipt_chain: Vec<ReceiptChainEntry>,
) -> ContributionManifest {
    let manifest = ContributionManifest {
        manifest_version: "1.0".to_string(),
        contribution_type,
        contributor,
        target,
        payload,
        provenance: Provenance {
            local_receipt_chain: receipt_chain,
            canon: Canon::default(),
        },
        envelope_signature: String::new(), // Set after signing
        envelope_hash: String::new(),      // Set after hashing
    };

    // Compute envelope hash
    let canonical = serde_json::to_string(&manifest).unwrap_or_default();
    let hash = blake3::hash(canonical.as_bytes());

    ContributionManifest {
        envelope_hash: format!("blake3:{}", hash.to_hex()),
        ..manifest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_correction_manifest() {
        let manifest = build_manifest(
            ContributionType::Correction,
            Contributor {
                tenant_id: "blake3:abc123".to_string(),
                contributor_alias: Some("test-user".to_string()),
            },
            Target {
                artefact_digest: "blake3:def456".to_string(),
                chunk_digest: Some("blake3:ghi789".to_string()),
                corpus_id: "commons".to_string(),
                quote_hash: None,
            },
            serde_json::json!({
                "correction_type": "factual",
                "proposed_text": "Corrected content",
                "confidence": "high"
            }),
            vec![ReceiptChainEntry {
                receipt_hash: "blake3:chain001".to_string(),
                signed_at: "2026-04-03T10:00:00Z".to_string(),
                knowledge_state_cursor: serde_json::json!({
                    "shard_id": "shard-0001",
                    "epoch": 42
                }),
            }],
        );

        assert_eq!(manifest.manifest_version, "1.0");
        assert!(manifest.envelope_hash.starts_with("blake3:"));
        assert!(!manifest.envelope_hash.is_empty());
    }
}
