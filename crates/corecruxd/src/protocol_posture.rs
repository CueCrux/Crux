// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Protocol-posture surfacer — emits which routes/MCP tools are gated by tier or capability token at runtime.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ContractPosture {
    pub contract: &'static str,
    pub current: String,
    pub target: &'static str,
    pub status: &'static str,
    pub notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_field_names)]
pub struct ProtocolPosture {
    pub session_plan_contract: ContractPosture,
    pub corecrux_retrieval_contract: ContractPosture,
    pub semantic_profile_contract: ContractPosture,
    pub projection_module_contract: ContractPosture,
    pub extension_registry_contract: ContractPosture,
    pub rcx_registry_publish_contract: ContractPosture,
}

impl ProtocolPosture {
    pub fn from_runtime(
        retrieval_segment_count: usize,
        semantic_profile: Option<&corecrux_memory::embeddings::SemanticProfile>,
    ) -> Self {
        Self {
            session_plan_contract: ContractPosture {
                contract: "session_plan_contract",
                current: format!(
                    "cuecrux.shared.session_plan.v2+legacy_decode:crux.session_plan.v{}",
                    crux_session::SESSION_PLAN_VERSION
                ),
                target: "cuecrux.shared.session_plan.v2",
                status: "current",
                notes: vec![
                    "local daemon emits the shared v2 capability graph envelope",
                    "legacy flat capability-graph decode remains available for sealed-plan migration",
                ],
            },
            corecrux_retrieval_contract: ContractPosture {
                contract: "corecrux_retrieval_contract",
                current: if retrieval_segment_count == 0 {
                    "crux.retrieval.bm25.no_segments".to_string()
                } else {
                    format!("crux.retrieval.bm25.ccxi_segments:{retrieval_segment_count}")
                },
                target: "corecrux.retrieval.v6.fingerprinted_segments",
                status: "partial",
                notes: vec![
                    "local daemon exposes BM25 .ccxi search but not v6 segment fingerprints",
                    "fingerprint guard and calibration metadata are still posture-only; mixed-profile search must use rank fusion or rerank",
                ],
            },
            semantic_profile_contract: ContractPosture {
                contract: "semantic_profile_contract",
                current: if let Some(profile) = semantic_profile {
                    format!("{}:{}", profile.schema, profile.profile_id)
                } else {
                    "crux.embeddings.no_semantic_profile".to_string()
                },
                target: "cuecrux.semantic_profile.v1",
                status: if semantic_profile.is_some() { "partial" } else { "missing" },
                notes: if semantic_profile.is_some() {
                    vec![
                        "local embedding config can now produce a stable semantic profile ID",
                        "retrieval responses and sync collection records carry profile/score-space metadata; replay capsules still need to persist it",
                    ]
                } else {
                    vec![
                        "embedding model and dimensions are not configured on this daemon",
                        "BM25 retrieval still labels its score space so future cloud/local merges cannot compare raw scores by accident",
                    ]
                },
            },
            projection_module_contract: ContractPosture {
                contract: "projection_module_contract",
                current: corecrux_projections::PROJECTION_MODULE_VERSION_SCHEMA_V1.to_string(),
                target: "crux.projection_module_version.v1",
                status: "current",
                notes: vec![
                    "projection commits record module id, module version, code hash, schema version, and config hash",
                    "admin projection module routes expose replay availability for active and retained modules",
                    "answer replay validity checks projection module availability separately from historical answer rendering",
                ],
            },
            extension_registry_contract: ContractPosture {
                contract: "extension_registry_contract",
                current: format!(
                    "{}+{}",
                    crux_integrations::INTEGRATION_SCHEMA_V1,
                    crux_integrations::COMMUNITY_REGISTRY_SCHEMA_V1
                ),
                target: "crux.community_extensions.registry_install.v1",
                status: "current",
                notes: vec![
                    "signed manifests and trusted-key validation are local",
                    "install-by-index, manifest_sha256 enforcement, and dynamic MCP ext.* routing are implemented locally",
                    "managed hosted registry curation remains a Pro control-plane capability",
                ],
            },
            rcx_registry_publish_contract: ContractPosture {
                contract: "rcx_registry_publish_contract",
                current: "local.preview_emit.passport_project".to_string(),
                target: "rcx.registry.publish.2026-05-01",
                status: "current",
                notes: vec![
                    "local passport/project publish preview and emit routes build signed 2026-05-01 records",
                    "emit stores a private local publish receipt and can POST to an operator-supplied registry URL",
                ],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_reports_known_protocol_gaps() {
        let posture = ProtocolPosture::from_runtime(2, None);

        assert_eq!(posture.session_plan_contract.status, "current");
        assert_eq!(posture.corecrux_retrieval_contract.status, "partial");
        assert_eq!(
            posture.corecrux_retrieval_contract.current,
            "crux.retrieval.bm25.ccxi_segments:2"
        );
        assert_eq!(posture.semantic_profile_contract.status, "missing");
        assert_eq!(posture.projection_module_contract.status, "current");
        assert_eq!(posture.extension_registry_contract.status, "current");
        assert_eq!(posture.rcx_registry_publish_contract.status, "current");
    }

    #[test]
    fn posture_surfaces_embeddings_without_claiming_profile_parity() {
        let profile = corecrux_memory::embeddings::SemanticProfile::from_embedding_config(
            &corecrux_memory::embeddings::EmbeddingConfig {
                base_url: "http://localhost:11434".to_string(),
                model: "nomic-embed-text".to_string(),
                dimensions: 768,
            },
            0,
        );
        let posture = ProtocolPosture::from_runtime(0, Some(&profile));

        assert!(posture
            .semantic_profile_contract
            .current
            .starts_with("cuecrux.semantic_profile.v1:sp_"));
        assert_eq!(posture.semantic_profile_contract.target, "cuecrux.semantic_profile.v1");
        assert_eq!(posture.semantic_profile_contract.status, "partial");
    }
}
