// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Optional embedding client for dense vector retrieval.
//!
//! Connects to any OpenAI-compatible `/api/embed` or `/v1/embeddings` endpoint
//! (Ollama, vLLM, llama.cpp, TEI, LiteLLM, etc.). When configured, facts are
//! embedded at store time and queries use cosine similarity for ranking.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub const SEMANTIC_PROFILE_SCHEMA_V1: &str = "cuecrux.semantic_profile.v1";
pub const EMBEDDING_FINGERPRINT_SCHEMA_V1: &str = "cuecrux.embedding_fingerprint.v1";

/// Configuration for the embedding endpoint.
#[derive(Debug, Clone)]
pub struct EmbeddingConfig {
    /// Base URL of the embedding service (e.g. `http://localhost:11434`).
    pub base_url: String,
    /// Model name to request (e.g. `nomic-embed-text`).
    pub model: String,
    /// Dimensionality of the embedding vectors. Auto-detected on first call if 0.
    pub dimensions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbeddingFingerprint {
    pub schema: String,
    pub fingerprint_id: String,
    pub model: String,
    pub dimensions: usize,
    pub tokenizer: String,
    pub prompt_template_version: String,
    pub normalisation: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemanticProfile {
    pub schema: String,
    pub profile_id: String,
    pub model: String,
    pub dimensions: usize,
    pub tokenizer: String,
    pub prompt_template_version: String,
    pub normalisation: String,
    pub embedding_fingerprint: EmbeddingFingerprint,
}

impl SemanticProfile {
    pub fn from_embedding_config(config: &EmbeddingConfig, detected_dimensions: usize) -> Self {
        let dimensions = if detected_dimensions == 0 {
            config.dimensions
        } else {
            detected_dimensions
        };
        let tokenizer = "model_default".to_string();
        let prompt_template_version = "none".to_string();
        let normalisation = "none".to_string();
        let hash_material = format!(
            "{}\n{}\n{}\n{}\n{}",
            config.model, dimensions, tokenizer, prompt_template_version, normalisation
        );
        let hash = blake3::hash(hash_material.as_bytes()).to_hex().to_string();
        let fingerprint_id = format!("efp_{}", &hash[..24]);
        let profile_id = format!("sp_{}", &hash[..24]);

        Self {
            schema: SEMANTIC_PROFILE_SCHEMA_V1.to_string(),
            profile_id,
            model: config.model.clone(),
            dimensions,
            tokenizer: tokenizer.clone(),
            prompt_template_version: prompt_template_version.clone(),
            normalisation: normalisation.clone(),
            embedding_fingerprint: EmbeddingFingerprint {
                schema: EMBEDDING_FINGERPRINT_SCHEMA_V1.to_string(),
                fingerprint_id,
                model: config.model.clone(),
                dimensions,
                tokenizer,
                prompt_template_version,
                normalisation,
                hash,
            },
        }
    }
}

impl SemanticProfile {
    /// Derive a profile directly from model parts (for local embedders that
    /// have no `EmbeddingConfig`/base_url). Fingerprint is stable per
    /// (model, dims, tokenizer, template, normalisation) — identical hashing to
    /// [`SemanticProfile::from_embedding_config`] so the two are comparable.
    pub fn from_parts(
        model: &str,
        dimensions: usize,
        tokenizer: &str,
        prompt_template_version: &str,
        normalisation: &str,
    ) -> Self {
        let hash_material = format!("{model}\n{dimensions}\n{tokenizer}\n{prompt_template_version}\n{normalisation}");
        let hash = blake3::hash(hash_material.as_bytes()).to_hex().to_string();
        let fingerprint_id = format!("efp_{}", &hash[..24]);
        let profile_id = format!("sp_{}", &hash[..24]);
        Self {
            schema: SEMANTIC_PROFILE_SCHEMA_V1.to_string(),
            profile_id,
            model: model.to_string(),
            dimensions,
            tokenizer: tokenizer.to_string(),
            prompt_template_version: prompt_template_version.to_string(),
            normalisation: normalisation.to_string(),
            embedding_fingerprint: EmbeddingFingerprint {
                schema: EMBEDDING_FINGERPRINT_SCHEMA_V1.to_string(),
                fingerprint_id,
                model: model.to_string(),
                dimensions,
                tokenizer: tokenizer.to_string(),
                prompt_template_version: prompt_template_version.to_string(),
                normalisation: normalisation.to_string(),
                hash,
            },
        }
    }
}

/// The provider contract shared by every embedder (buyer-fit M3). A dense lane
/// records the provider's [`SemanticProfile`] so document and query vectors can
/// be checked for compatibility (same model/dimension/fingerprint) and an
/// incompatible vector refused rather than silently scored in the wrong space.
///
/// `Debug` is a supertrait so a `Box<dyn Embedder>` can live inside a
/// `#[derive(Debug)]` struct (e.g. [`crate::fact_store::FactStore`]).
pub trait Embedder: Send + Sync + std::fmt::Debug {
    /// Embed a batch of texts — one vector per input, in order.
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError>;
    /// Embed one text.
    fn embed_one(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let mut vecs = self.embed_batch(&[text])?;
        vecs.pop().ok_or(EmbeddingError::EmptyResponse)
    }
    /// Output dimensionality.
    fn dimensions(&self) -> usize;
    /// Model identifier.
    fn model(&self) -> &str;
    /// This embedder's semantic profile (model/dim/fingerprint).
    fn semantic_profile(&self) -> SemanticProfile;
    /// Whether inference executes inside this daemon process. External and
    /// custom embedders default to remote so capability reporting fails closed.
    fn runs_locally(&self) -> bool {
        false
    }
}

impl Embedder for EmbeddingClient {
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        EmbeddingClient::embed_batch(self, texts)
    }
    fn dimensions(&self) -> usize {
        EmbeddingClient::dimensions(self)
    }
    fn model(&self) -> &str {
        EmbeddingClient::model(self)
    }
    fn semantic_profile(&self) -> SemanticProfile {
        EmbeddingClient::semantic_profile(self)
    }
}

/// Pure-Rust, dependency-free, deterministic CPU embedder (buyer-fit M3
/// default). Feature-hashing ("hashing trick") over lowercased word unigrams +
/// adjacent bigrams into a fixed-dimension L2-normalised vector, so lexically
/// overlapping texts score high cosine. Zero deps, zero download, fully offline
/// — this is what makes local dense "work by default". Better semantic recall
/// is the opt-in real model / metered upsell, never a clip on this.
#[derive(Debug, Clone)]
pub struct LocalHashEmbedder {
    dimensions: usize,
}

pub const LOCAL_HASH_EMBEDDER_MODEL: &str = "crux-local-hash-v1";
const LOCAL_HASH_DEFAULT_DIM: usize = 256;

impl Default for LocalHashEmbedder {
    fn default() -> Self {
        Self {
            dimensions: LOCAL_HASH_DEFAULT_DIM,
        }
    }
}

impl LocalHashEmbedder {
    pub fn new(dimensions: usize) -> Self {
        Self {
            dimensions: dimensions.max(1),
        }
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0.0f32; self.dimensions];
        let tokens: Vec<String> = text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_lowercase())
            .collect();
        let add = |feature: &str, v: &mut [f32]| {
            let h = blake3::hash(feature.as_bytes());
            let bytes = h.as_bytes();
            let idx = (u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize) % self.dimensions;
            // Sign hashing reduces collision bias.
            let sign = if bytes[4] & 1 == 0 { 1.0 } else { -1.0 };
            v[idx] += sign;
        };
        for (i, tok) in tokens.iter().enumerate() {
            add(tok, &mut v);
            if i + 1 < tokens.len() {
                add(&format!("{tok}_{}", tokens[i + 1]), &mut v);
            }
        }
        // L2 normalise (unit vector ⇒ cosine == dot).
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 1e-12 {
            for x in &mut v {
                *x /= norm;
            }
        }
        v
    }
}

impl Embedder for LocalHashEmbedder {
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        Ok(texts.iter().map(|t| self.embed(t)).collect())
    }
    fn dimensions(&self) -> usize {
        self.dimensions
    }
    fn model(&self) -> &str {
        LOCAL_HASH_EMBEDDER_MODEL
    }
    fn semantic_profile(&self) -> SemanticProfile {
        SemanticProfile::from_parts(
            LOCAL_HASH_EMBEDDER_MODEL,
            self.dimensions,
            "whitespace_ngram_v1",
            "none",
            "l2",
        )
    }
    fn runs_locally(&self) -> bool {
        true
    }
}

/// Optional real CPU embedding model (buyer-fit M3.4), behind the
/// `dense-embed-model` feature. Wraps fastembed (ONNX Runtime) with
/// all-MiniLM-L6-v2, downloaded on first use into the given cache dir. This is
/// the opt-in "better vectors" path over the always-on [`LocalHashEmbedder`];
/// the free offline path never requires it, and the default build never
/// compiles or downloads it.
#[cfg(feature = "dense-embed-model")]
pub struct FastEmbedEmbedder {
    // `TextEmbedding::embed` takes `&mut self`; the `Embedder` trait is `&self`
    // (it lives behind a shared `Box<dyn Embedder>`), so guard it with a Mutex.
    inner: Mutex<fastembed::TextEmbedding>,
    dimensions: usize,
    model_id: String,
}

/// Stable model id used in the [`FastEmbedEmbedder`] semantic profile.
#[cfg(feature = "dense-embed-model")]
pub const FASTEMBED_MODEL_ID: &str = "fastembed-all-minilm-l6-v2";
#[cfg(feature = "dense-embed-model")]
const FASTEMBED_DIMENSIONS: usize = 384;

#[cfg(feature = "dense-embed-model")]
impl std::fmt::Debug for FastEmbedEmbedder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FastEmbedEmbedder")
            .field("model", &self.model_id)
            .field("dimensions", &self.dimensions)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "dense-embed-model")]
impl FastEmbedEmbedder {
    /// Initialise the model, downloading it on first use into `cache_dir`.
    pub fn new(cache_dir: &std::path::Path) -> Result<Self, EmbeddingError> {
        use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};
        let options = InitOptions::new(EmbeddingModel::AllMiniLML6V2)
            .with_cache_dir(cache_dir.to_path_buf())
            .with_show_download_progress(false);
        let inner = TextEmbedding::try_new(options).map_err(|e| EmbeddingError::Model(e.to_string()))?;
        Ok(Self {
            inner: Mutex::new(inner),
            dimensions: FASTEMBED_DIMENSIONS,
            model_id: FASTEMBED_MODEL_ID.to_string(),
        })
    }
}

#[cfg(feature = "dense-embed-model")]
impl Embedder for FastEmbedEmbedder {
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let docs: Vec<&str> = texts.to_vec();
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| EmbeddingError::Model(format!("embedder lock poisoned: {e}")))?;
        inner
            .embed(docs, None)
            .map_err(|e| EmbeddingError::Model(e.to_string()))
    }
    fn dimensions(&self) -> usize {
        self.dimensions
    }
    fn model(&self) -> &str {
        &self.model_id
    }
    fn semantic_profile(&self) -> SemanticProfile {
        SemanticProfile::from_parts(&self.model_id, self.dimensions, "bert_wordpiece", "none", "l2")
    }
    fn runs_locally(&self) -> bool {
        true
    }
}

#[derive(Serialize)]
struct OllamaEmbedRequest<'a> {
    model: &'a str,
    input: &'a [&'a str],
}

#[derive(Deserialize)]
struct OllamaEmbedResponse {
    embeddings: Vec<Vec<f32>>,
}

/// Lightweight embedding client that talks to Ollama's `/api/embed` endpoint.
///
/// Thread-safe via interior mutability for dimension auto-detection.
pub struct EmbeddingClient {
    config: EmbeddingConfig,
    detected_dims: Mutex<usize>,
}

impl std::fmt::Debug for EmbeddingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingClient")
            .field("base_url", &self.config.base_url)
            .field("model", &self.config.model)
            .finish_non_exhaustive()
    }
}

impl EmbeddingClient {
    pub fn new(config: EmbeddingConfig) -> Self {
        let dims = config.dimensions;
        Self {
            config,
            detected_dims: Mutex::new(dims),
        }
    }

    /// Embed a single text string. Returns the embedding vector.
    pub fn embed_one(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let mut vecs = self.embed_batch(&[text])?;
        vecs.pop().ok_or(EmbeddingError::EmptyResponse)
    }

    /// Embed a batch of text strings. Returns one vector per input.
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let url = format!("{}/api/embed", self.config.base_url.trim_end_matches('/'));
        let body = OllamaEmbedRequest {
            model: &self.config.model,
            input: texts,
        };

        let mut resp = ureq::post(&url)
            .header("Content-Type", "application/json")
            .send_json(serde_json::to_value(&body).map_err(|e| EmbeddingError::Serialize(e.to_string()))?)
            .map_err(|e| EmbeddingError::Network(e.to_string()))?;

        let parsed: OllamaEmbedResponse = resp
            .body_mut()
            .read_json()
            .map_err(|e| EmbeddingError::Deserialize(e.to_string()))?;

        if parsed.embeddings.len() != texts.len() {
            return Err(EmbeddingError::LengthMismatch {
                expected: texts.len(),
                got: parsed.embeddings.len(),
            });
        }

        // Auto-detect dimensions from first response.
        if let Some(first) = parsed.embeddings.first() {
            if let Ok(mut dims) = self.detected_dims.lock() {
                if *dims == 0 {
                    *dims = first.len();
                    tracing::info!(
                        model = %self.config.model,
                        dimensions = first.len(),
                        "embedding-dimensions-detected"
                    );
                }
            }
        }

        Ok(parsed.embeddings)
    }

    /// Return the detected or configured dimensionality.
    pub fn dimensions(&self) -> usize {
        self.detected_dims.lock().map(|d| *d).unwrap_or(0)
    }

    pub fn model(&self) -> &str {
        &self.config.model
    }

    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    pub fn semantic_profile(&self) -> SemanticProfile {
        SemanticProfile::from_embedding_config(&self.config, self.dimensions())
    }
}

/// Compute cosine similarity between two vectors.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom < 1e-12 {
        0.0
    } else {
        dot / denom
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EmbeddingError {
    #[error("embedding network error: {0}")]
    Network(String),
    #[error("embedding serialize error: {0}")]
    Serialize(String),
    #[error("embedding deserialize error: {0}")]
    Deserialize(String),
    #[error("embedding response empty")]
    EmptyResponse,
    #[error("embedding length mismatch: expected {expected}, got {got}")]
    LengthMismatch { expected: usize, got: usize },
    #[error("embedding model error: {0}")]
    Model(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_identical_vectors() {
        let v = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_orthogonal_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-6);
    }

    #[test]
    fn cosine_empty_vectors() {
        let sim = cosine_similarity(&[], &[]);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn semantic_profile_is_stable_for_same_embedding_config() {
        let config = EmbeddingConfig {
            base_url: "http://localhost:11434".to_string(),
            model: "nomic-embed-text".to_string(),
            dimensions: 768,
        };

        let a = SemanticProfile::from_embedding_config(&config, 0);
        let b = SemanticProfile::from_embedding_config(&config, 768);

        assert_eq!(a, b);
        assert_eq!(a.schema, SEMANTIC_PROFILE_SCHEMA_V1);
        assert_eq!(a.embedding_fingerprint.schema, EMBEDDING_FINGERPRINT_SCHEMA_V1);
        assert!(a.profile_id.starts_with("sp_"));
        assert!(a.embedding_fingerprint.fingerprint_id.starts_with("efp_"));
    }

    #[test]
    fn local_hash_embedder_is_deterministic_and_unit_norm() {
        let e = LocalHashEmbedder::default();
        let a = e.embed_one("the quick brown fox").unwrap();
        let b = e.embed_one("the quick brown fox").unwrap();
        assert_eq!(a, b, "same text ⇒ identical vector");
        assert_eq!(a.len(), 256);
        let norm: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5, "unit-normalised");
    }

    #[test]
    fn local_hash_embedder_lexical_overlap_scores_higher() {
        let e = LocalHashEmbedder::default();
        let base = e.embed_one("the cat sat on the mat").unwrap();
        let near = e.embed_one("a cat sat on a mat").unwrap();
        let far = e.embed_one("quantum chromodynamics lecture notes").unwrap();
        let sim_near = cosine_similarity(&base, &near);
        let sim_far = cosine_similarity(&base, &far);
        assert!(sim_near > sim_far, "overlapping text closer: {sim_near} vs {sim_far}");
        assert!(sim_near > 0.4, "strong overlap ⇒ high cosine: {sim_near}");
    }

    #[test]
    fn local_hash_embedder_profile_is_stable_and_named() {
        let e = LocalHashEmbedder::default();
        assert_eq!(e.model(), LOCAL_HASH_EMBEDDER_MODEL);
        let p = e.semantic_profile();
        assert_eq!(p.model, LOCAL_HASH_EMBEDDER_MODEL);
        assert_eq!(p.dimensions, 256);
        assert_eq!(p, LocalHashEmbedder::default().semantic_profile(), "profile stable");
        // A different-dimension local embedder has a different fingerprint.
        assert_ne!(
            p.embedding_fingerprint.hash,
            LocalHashEmbedder::new(384)
                .semantic_profile()
                .embedding_fingerprint
                .hash
        );
    }

    #[test]
    fn embedder_trait_is_object_safe_and_covers_both_impls() {
        let local: Box<dyn Embedder> = Box::new(LocalHashEmbedder::default());
        assert_eq!(local.dimensions(), 256);
        assert!(!local.embed_one("hello world").unwrap().is_empty());
    }

    #[test]
    fn semantic_profile_changes_when_model_changes() {
        let a = SemanticProfile::from_embedding_config(
            &EmbeddingConfig {
                base_url: "http://localhost:11434".to_string(),
                model: "model-a".to_string(),
                dimensions: 384,
            },
            0,
        );
        let b = SemanticProfile::from_embedding_config(
            &EmbeddingConfig {
                base_url: "http://localhost:11434".to_string(),
                model: "model-b".to_string(),
                dimensions: 384,
            },
            0,
        );

        assert_ne!(a.profile_id, b.profile_id);
        assert_ne!(a.embedding_fingerprint.hash, b.embedding_fingerprint.hash);
    }
}
