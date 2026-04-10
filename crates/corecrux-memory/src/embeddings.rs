// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Optional embedding client for dense vector retrieval.
//!
//! Connects to any OpenAI-compatible `/api/embed` or `/v1/embeddings` endpoint
//! (Ollama, vLLM, llama.cpp, TEI, LiteLLM, etc.). When configured, facts are
//! embedded at store time and queries use cosine similarity for ranking.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

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
            .finish()
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

        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(serde_json::to_value(&body).map_err(|e| EmbeddingError::Serialize(e.to_string()))?)
            .map_err(|e| EmbeddingError::Network(e.to_string()))?;

        let parsed: OllamaEmbedResponse = resp
            .into_json()
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
}
